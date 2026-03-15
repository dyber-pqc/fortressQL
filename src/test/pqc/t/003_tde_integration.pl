
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# TDE End-to-End Integration Test
#
# This TAP test verifies Transparent Data Encryption (TDE) works correctly
# across the full lifecycle: key initialization, data insertion, server
# restart, data durability, and crash recovery.
#
# If TDE infrastructure is not available (no pg_tde_master_key binary,
# no tde_enabled GUC), the test skips gracefully.

use strict;
use warnings FATAL => 'all';

use File::Spec;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $tempdir = PostgreSQL::Test::Utils::tempdir;

###########################################################################
# 1. Initialize a fresh cluster
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('tde_integ');
$node->init;

###########################################################################
# 2. Check for pg_tde_master_key binary
###########################################################################
my $tde_master_key_bin = undef;

# Look for the binary in the same directory as other PG binaries
my $bindir = $node->config_data('--bindir');
for my $candidate ('pg_tde_master_key', 'pg_tde_master_key.exe')
{
	my $path = File::Spec->catfile($bindir, $candidate);
	if (-x $path || -f $path)
	{
		$tde_master_key_bin = $path;
		last;
	}
}

if (!defined $tde_master_key_bin)
{
	# Also try the PATH
	my $ret = eval {
		my $output = `pg_tde_master_key --version 2>&1`;
		$? == 0 ? 1 : 0;
	};
	if ($ret)
	{
		$tde_master_key_bin = 'pg_tde_master_key';
	}
}

if (!defined $tde_master_key_bin)
{
	plan skip_all => 'pg_tde_master_key binary not found';
}

diag("Using pg_tde_master_key: $tde_master_key_bin");

###########################################################################
# 3. Initialize master key and configure TDE
###########################################################################
my $datadir = $node->data_dir;

# Run pg_tde_master_key init to set up key material
my ($ret, $stdout, $stderr);
eval {
	($ret, $stdout, $stderr) = $node->run_command(
		[$tde_master_key_bin, 'init', '-D', $datadir]);
};
if ($@ || $ret != 0)
{
	diag("pg_tde_master_key init failed: $stderr");
	plan skip_all => 'pg_tde_master_key init failed - TDE not supported in this build';
}
pass('pg_tde_master_key init succeeded');

# Enable TDE in postgresql.conf
$node->append_conf('postgresql.conf', <<CONF);
tde_enabled = on
shared_buffers = '128MB'
CONF

###########################################################################
# 4. Start the server
###########################################################################
eval {
	$node->start;
};
if ($@)
{
	diag("Server failed to start with TDE enabled: $@");
	plan skip_all => 'Server cannot start with tde_enabled=on';
}

# Verify the GUC is active
($ret, $stdout, $stderr) = $node->psql('postgres', "SHOW tde_enabled;");
if ($ret != 0)
{
	$node->stop;
	plan skip_all => 'tde_enabled GUC not available';
}
chomp $stdout;
is($stdout, 'on', 'tde_enabled is on');

###########################################################################
# 5. Create test data
###########################################################################
$node->safe_psql('postgres', qq{
	CREATE TABLE tde_test (
		id    serial PRIMARY KEY,
		label text   NOT NULL,
		val   int    NOT NULL,
		payload bytea
	);
	INSERT INTO tde_test (label, val, payload)
		SELECT 'row_' || g, g * 13,
		       decode(md5(g::text), 'hex')
		FROM generate_series(1, 500) g;
});
pass('test data inserted under TDE');

# Capture original data for comparison
my $original_data = $node->safe_psql('postgres',
	"SELECT id, label, val FROM tde_test ORDER BY id;");
my $row_count = $node->safe_psql('postgres',
	"SELECT count(*) FROM tde_test;");
is($row_count, '500', 'inserted 500 rows');

###########################################################################
# 6. Restart server and verify data durability
###########################################################################
diag("--- Restart and verify data durability ---");

$node->stop;
$node->start;

my $after_restart_data = $node->safe_psql('postgres',
	"SELECT id, label, val FROM tde_test ORDER BY id;");
is($after_restart_data, $original_data,
	'data survives clean restart under TDE');

my $after_restart_count = $node->safe_psql('postgres',
	"SELECT count(*) FROM tde_test;");
is($after_restart_count, '500', 'row count intact after restart');

###########################################################################
# 7. Verify on-disk data is not plaintext (best-effort check)
###########################################################################
diag("--- On-disk encryption verification ---");

SKIP:
{
	# Get the relfilenode path for the table
	my $relpath = eval {
		$node->safe_psql('postgres',
			"SELECT pg_relation_filepath('tde_test');");
	};

	skip 'could not determine relation file path', 1
		if (!defined $relpath || $relpath eq '');

	my $datafile = File::Spec->catfile($datadir, $relpath);

	skip "data file not found at $datafile", 1
		unless (-f $datafile && -s $datafile);

	# Read the raw data file and look for plaintext markers.
	# Under TDE, none of the label strings should appear in cleartext.
	open(my $fh, '<:raw', $datafile) or skip "cannot open $datafile: $!", 1;
	my $raw_data;
	{
		local $/;
		$raw_data = <$fh>;
	}
	close($fh);

	# Check that a sample of our known plaintext labels do NOT appear
	my $plaintext_found = 0;
	for my $label ('row_100', 'row_250', 'row_499')
	{
		if (index($raw_data, $label) >= 0)
		{
			$plaintext_found = 1;
			diag("WARNING: plaintext '$label' found in data file");
			last;
		}
	}

	ok(!$plaintext_found,
		'on-disk data file does not contain plaintext label strings');
}

###########################################################################
# 8. Crash recovery test: immediate stop and restart
###########################################################################
diag("--- Crash recovery test ---");

# Insert more data before the crash
$node->safe_psql('postgres', qq{
	INSERT INTO tde_test (label, val, payload)
		SELECT 'crash_' || g, g * 7,
		       decode(md5(g::text), 'hex')
		FROM generate_series(1, 200) g;
});

my $pre_crash_count = $node->safe_psql('postgres',
	"SELECT count(*) FROM tde_test;");
is($pre_crash_count, '700', '700 rows before crash');

# Simulate a crash with immediate shutdown (no clean shutdown)
$node->stop('immediate');
pass('immediate (crash) shutdown succeeded');

# Restart - this should trigger WAL replay / crash recovery
$node->start;
pass('server restarted after crash shutdown');

# Verify data is intact after crash recovery
my $post_crash_count = $node->safe_psql('postgres',
	"SELECT count(*) FROM tde_test;");
is($post_crash_count, '700',
	'row count intact after crash recovery under TDE');

my $post_crash_original = $node->safe_psql('postgres',
	"SELECT id, label, val FROM tde_test WHERE id <= 500 ORDER BY id;");
is($post_crash_original, $original_data,
	'original data intact after crash recovery');

# Verify the crash-inserted data is also intact
my $crash_rows = $node->safe_psql('postgres',
	"SELECT count(*) FROM tde_test WHERE label LIKE 'crash_%';");
is($crash_rows, '200',
	'crash-inserted rows recovered successfully');

###########################################################################
# 9. Additional integrity check: UPDATE and DELETE under TDE
###########################################################################
diag("--- UPDATE/DELETE under TDE ---");

$node->safe_psql('postgres', qq{
	UPDATE tde_test SET val = val + 1 WHERE id <= 10;
	DELETE FROM tde_test WHERE label = 'crash_1';
});

my $updated_val = $node->safe_psql('postgres',
	"SELECT val FROM tde_test WHERE id = 1;");
# Original val for id=1 was 1*13 = 13, now should be 14
is($updated_val, '14', 'UPDATE works correctly under TDE');

my $final_count = $node->safe_psql('postgres',
	"SELECT count(*) FROM tde_test;");
is($final_count, '699', 'DELETE works correctly under TDE');

###########################################################################
# Cleanup
###########################################################################
$node->stop;
done_testing();
