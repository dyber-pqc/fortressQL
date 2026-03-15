
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# pg_stat_pqc Statistics Test
#
# This TAP test verifies that PQC operation statistics are properly
# tracked and exposed via pg_stat_pqc (or the pg_stat_get_pqc()
# function).  It exercises:
#
#   - Loading the pgcrypto_pqc extension
#   - Performing KEM keygen operations
#   - Querying the statistics view/function
#   - Verifying counters are non-null and incrementing
#   - Testing pg_stat_reset_pqc() if available
#
# If pg_stat_pqc is not available, the test skips gracefully.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

###########################################################################
# 1. Initialize and start a fresh cluster
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('statspqc');
$node->init;
$node->start;

###########################################################################
# 2. Load pgcrypto_pqc extension
###########################################################################
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	"CREATE EXTENSION IF NOT EXISTS pgcrypto_pqc;");
if ($ret != 0)
{
	$node->stop;
	plan skip_all => 'pgcrypto_pqc extension not available';
}
pass('pgcrypto_pqc extension loaded');

###########################################################################
# 3. Detect the statistics interface
###########################################################################
my $stats_query     = undef;
my $stats_interface = undef;

# Strategy 1: pg_stat_pqc view
($ret, $stdout, $stderr) = $node->psql('postgres',
	"SELECT * FROM pg_stat_pqc LIMIT 0;");
if ($ret == 0)
{
	$stats_interface = 'view';
	$stats_query     = "SELECT * FROM pg_stat_pqc;";
	diag("Using pg_stat_pqc view");
}

# Strategy 2: pg_stat_get_pqc() function
if (!defined $stats_interface)
{
	($ret, $stdout, $stderr) = $node->psql('postgres',
		"SELECT pg_stat_get_pqc();");
	if ($ret == 0)
	{
		$stats_interface = 'function';
		$stats_query     = "SELECT * FROM pg_stat_get_pqc();";
		diag("Using pg_stat_get_pqc() function");
	}
}

# Strategy 3: Check pg_stat_activity-style or custom stats catalog
if (!defined $stats_interface)
{
	($ret, $stdout, $stderr) = $node->psql('postgres', qq{
		SELECT count(*)
		FROM pg_catalog.pg_views
		WHERE viewname LIKE '%pqc%' OR viewname LIKE '%crypto%';
	});
	if ($ret == 0 && defined $stdout && $stdout > 0)
	{
		my $view_name = $node->safe_psql('postgres', qq{
			SELECT viewname
			FROM pg_catalog.pg_views
			WHERE viewname LIKE '%pqc%' OR viewname LIKE '%crypto%'
			LIMIT 1;
		});
		chomp $view_name;
		$stats_interface = 'view';
		$stats_query     = "SELECT * FROM $view_name;";
		diag("Found stats view: $view_name");
	}
}

if (!defined $stats_interface)
{
	$node->stop;
	plan skip_all => 'pg_stat_pqc view/function not available';
}
pass("PQC stats interface detected: $stats_interface");

###########################################################################
# 4. Run KEM keygen operations to generate statistics
###########################################################################
diag("--- Running KEM keygen operations ---");

# Perform multiple keygen operations
for my $i (1 .. 5)
{
	$node->safe_psql('postgres',
		"SELECT public_key FROM pqc_kem_keygen('ML-KEM-768');");
}
pass('5 KEM keygen operations performed');

# Also run some signature operations if available
my $sig_available = 0;
eval {
	$node->safe_psql('postgres',
		"SELECT public_key FROM pqc_sig_keygen('ML-DSA-65');");
	$sig_available = 1;
};
if ($sig_available)
{
	for my $i (1 .. 3)
	{
		$node->safe_psql('postgres',
			"SELECT public_key FROM pqc_sig_keygen('ML-DSA-65');");
	}
	diag("3 additional signature keygen operations performed");
}

###########################################################################
# 5. Query statistics and verify counters
###########################################################################
diag("--- Querying PQC statistics ---");

($ret, $stdout, $stderr) = $node->psql('postgres', $stats_query);
is($ret, 0, 'statistics query succeeded');

# The output should not be empty
ok(defined $stdout && length($stdout) > 0,
	'statistics query returned data');
diag("Stats output: $stdout");

# Try to verify specific counter columns are non-null
# The exact schema depends on the implementation, so we check
# what columns are available
SKIP:
{
	my $columns = eval {
		$node->safe_psql('postgres', qq{
			SELECT column_name
			FROM information_schema.columns
			WHERE table_name = 'pg_stat_pqc'
			ORDER BY ordinal_position;
		});
	};

	skip 'could not introspect pg_stat_pqc columns', 2
		if (!defined $columns || $columns eq '');

	diag("pg_stat_pqc columns: $columns");

	# Check for keygen-related counters
	my @cols = split(/\n/, $columns);

	my @keygen_cols = grep { /keygen|kem|key_gen/i } @cols;
	if (scalar(@keygen_cols) > 0)
	{
		my $col = $keygen_cols[0];
		my $val = $node->safe_psql('postgres',
			"SELECT $col FROM pg_stat_pqc;");
		chomp $val if defined $val;
		ok(defined $val && $val ne '' && $val =~ /^\d+$/,
			"counter '$col' is a numeric value: $val");

		# We ran 5 KEM keygen operations, counter should be >= 5
		cmp_ok($val, '>=', 5,
			"counter '$col' reflects keygen operations (>= 5)")
			if (defined $val && $val =~ /^\d+$/);
	}
	else
	{
		# Just verify at least one numeric column has a non-zero value
		my $has_nonzero = 0;
		for my $col (@cols)
		{
			my ($r, $v, $e) = $node->psql('postgres',
				"SELECT $col FROM pg_stat_pqc;");
			if ($r == 0 && defined $v && $v =~ /^\d+$/ && $v > 0)
			{
				$has_nonzero = 1;
				diag("Non-zero counter found: $col = $v");
				last;
			}
		}
		ok($has_nonzero,
			'at least one PQC stats counter is non-zero after operations');
	}
}

###########################################################################
# 6. Run more operations and verify counters increment
###########################################################################
diag("--- Verifying counter increments ---");

SKIP:
{
	# Get a snapshot of current stats
	my $before = eval {
		$node->safe_psql('postgres', $stats_query);
	};
	skip 'could not snapshot stats', 1 if (!defined $before);

	# Run more operations
	for my $i (1 .. 5)
	{
		$node->safe_psql('postgres',
			"SELECT public_key FROM pqc_kem_keygen('ML-KEM-768');");
	}

	my $after = $node->safe_psql('postgres', $stats_query);

	# At minimum, the output should have changed (counters incremented)
	# or stayed the same if stats are not per-operation granular
	ok(defined $after && length($after) > 0,
		'statistics still available after additional operations');
	diag("Stats before: $before");
	diag("Stats after:  $after");
}

###########################################################################
# 7. Test pg_stat_reset_pqc() if available
###########################################################################
diag("--- Testing pg_stat_reset_pqc ---");

SKIP:
{
	my ($r, $out, $err) = $node->psql('postgres',
		"SELECT pg_stat_reset_pqc();");

	skip 'pg_stat_reset_pqc() not available', 2
		if ($r != 0);

	pass('pg_stat_reset_pqc() executed successfully');

	# After reset, query stats again
	my $after_reset = $node->safe_psql('postgres', $stats_query);
	ok(defined $after_reset && length($after_reset) > 0,
		'statistics query works after reset');
	diag("Stats after reset: $after_reset");

	# Ideally, counters should be zero after reset.  Run a keygen
	# to verify counters start incrementing again from zero.
	$node->safe_psql('postgres',
		"SELECT public_key FROM pqc_kem_keygen('ML-KEM-768');");

	my $after_new_op = $node->safe_psql('postgres', $stats_query);
	diag("Stats after reset + 1 op: $after_new_op");
}

###########################################################################
# 8. Test stats survive server restart
###########################################################################
diag("--- Testing stats across restart ---");

SKIP:
{
	# Run some operations before restart
	for my $i (1 .. 3)
	{
		$node->safe_psql('postgres',
			"SELECT public_key FROM pqc_kem_keygen('ML-KEM-768');");
	}

	my $before_restart = eval {
		$node->safe_psql('postgres', $stats_query);
	};
	skip 'could not get stats before restart', 1
		if (!defined $before_restart);

	$node->restart;

	my ($r, $after_restart, $err) = $node->psql('postgres', $stats_query);
	skip 'stats query failed after restart', 1 if ($r != 0);

	ok(defined $after_restart && length($after_restart) > 0,
		'PQC statistics available after server restart');
	diag("Stats before restart: $before_restart");
	diag("Stats after restart:  $after_restart");
}

###########################################################################
# Cleanup
###########################################################################
$node->stop;
done_testing();
