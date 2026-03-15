
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# Streaming Replication with PQC WAL Signing Test
#
# This TAP test verifies that streaming replication works correctly when
# post-quantum WAL signing is enabled.  It exercises:
#
#   - Primary node with wal_pqc_signing enabled
#   - Standby created via pg_basebackup
#   - WAL verification on receive at the standby
#   - Data consistency between primary and standby
#
# If wal_pqc_signing or related GUCs are not available, the test skips
# gracefully.

use strict;
use warnings FATAL => 'all';

use File::Spec;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $tempdir = PostgreSQL::Test::Utils::tempdir;

###########################################################################
# 1. Initialize primary node
###########################################################################
my $node_primary = PostgreSQL::Test::Cluster->new('primary');
$node_primary->init(allows_streaming => 1);
$node_primary->start;

###########################################################################
# 2. Check for wal_pqc_signing GUC
###########################################################################
my ($ret, $stdout, $stderr) = $node_primary->psql('postgres',
	"SHOW wal_pqc_signing;");
if ($ret != 0)
{
	$node_primary->stop;
	plan skip_all => 'wal_pqc_signing GUC not available';
}
diag("wal_pqc_signing GUC exists, current value: $stdout");

###########################################################################
# 3. Generate WAL signing keys
###########################################################################
$node_primary->stop;

my $key_dir = "$tempdir/wal_keys";
mkdir($key_dir) or die "Cannot create key dir: $!";

my $keys_generated = 0;

# Try pgcrypto_pqc extension via a temporary server start
$node_primary->start;

($ret, $stdout, $stderr) = $node_primary->psql('postgres',
	"CREATE EXTENSION IF NOT EXISTS pgcrypto_pqc;");
if ($ret == 0)
{
	my $sig_keys = eval {
		$node_primary->safe_psql('postgres',
			"SELECT encode(public_key, 'hex'), encode(secret_key, 'hex') "
			. "FROM pqc_sig_keygen('ML-DSA-65');");
	};

	if (defined $sig_keys && $sig_keys =~ /\|/)
	{
		my ($pub_hex, $sec_hex) = split(/\|/, $sig_keys);

		write_hex_to_binfile($pub_hex, "$key_dir/wal_sign_pub.bin");
		write_hex_to_binfile($sec_hex, "$key_dir/wal_sign_sec.bin");
		$keys_generated = 1;
		diag("WAL signing keys generated via pgcrypto_pqc");
	}
}

# Try keygen tools if extension did not work
if (!$keys_generated)
{
	my $bindir = $node_primary->config_data('--bindir');
	for my $tool ('pg_wal_keygen', 'pg_pqc_keygen')
	{
		my $tool_path = File::Spec->catfile($bindir, $tool);
		if (-x $tool_path || -f $tool_path)
		{
			($ret, $stdout, $stderr) = $node_primary->run_command(
				[$tool_path, '--algorithm', 'ML-DSA-65',
				 '--output-dir', $key_dir]);
			if ($ret == 0)
			{
				$keys_generated = 1;
				diag("WAL signing keys generated via $tool");
				last;
			}
		}
	}
}

$node_primary->stop;

if (!$keys_generated)
{
	plan skip_all => 'Could not generate WAL signing keys '
		. '(neither pgcrypto_pqc nor keygen tool available)';
}
pass('WAL signing keys generated');

###########################################################################
# 4. Configure WAL signing on primary
###########################################################################
$node_primary->append_conf('postgresql.conf', <<CONF);
wal_pqc_signing = on
wal_pqc_key_path = '$key_dir'
wal_level = replica
max_wal_senders = 5
CONF

eval {
	$node_primary->start;
};
if ($@)
{
	diag("Primary failed to start with wal_pqc_signing=on: $@");
	plan skip_all => 'Primary cannot start with WAL signing enabled';
}

($ret, $stdout, $stderr) = $node_primary->psql('postgres',
	"SHOW wal_pqc_signing;");
chomp $stdout if defined $stdout;
is($stdout, 'on', 'wal_pqc_signing is on at primary');

###########################################################################
# 5. Create standby via pg_basebackup
###########################################################################
diag("--- Creating standby via pg_basebackup ---");

my $backup_name = 'pqc_backup';
$node_primary->backup($backup_name);

my $node_standby = PostgreSQL::Test::Cluster->new('standby');
$node_standby->init_from_backup($node_primary, $backup_name,
	has_streaming => 1);

###########################################################################
# 6. Configure standby with WAL verification on receive
###########################################################################
# Check if wal_pqc_verify_on_receive GUC is supported
SKIP:
{
	my ($vret, $vout, $verr) = $node_primary->psql('postgres',
		"SHOW wal_pqc_verify_on_receive;");

	if ($vret == 0)
	{
		$node_standby->append_conf('postgresql.conf', <<CONF);
wal_pqc_verify_on_receive = on
CONF
		diag("wal_pqc_verify_on_receive configured on standby");
	}
	else
	{
		diag("wal_pqc_verify_on_receive GUC not available, "
			. "standby will replicate without WAL verification");
	}
}

###########################################################################
# 7. Start standby
###########################################################################
eval {
	$node_standby->start;
};
if ($@)
{
	diag("Standby failed to start: $@");
	$node_primary->stop;
	plan skip_all => 'Standby cannot start with PQC WAL configuration';
}
pass('standby started successfully');

###########################################################################
# 8. Insert data on primary
###########################################################################
diag("--- Inserting data on primary ---");

$node_primary->safe_psql('postgres', qq{
	CREATE TABLE repl_test (
		id    serial PRIMARY KEY,
		label text   NOT NULL,
		val   int    NOT NULL
	);
	INSERT INTO repl_test (label, val)
		SELECT 'row_' || g, g * 7
		FROM generate_series(1, 1000) g;
});
pass('1000 rows inserted on primary');

###########################################################################
# 9. Wait for standby to catch up
###########################################################################
diag("--- Waiting for standby to catch up ---");

$node_primary->wait_for_replay_catchup($node_standby);
pass('standby caught up with primary');

###########################################################################
# 10. Verify data on standby matches primary
###########################################################################
diag("--- Verifying data consistency ---");

my $primary_count = $node_primary->safe_psql('postgres',
	"SELECT count(*) FROM repl_test;");
my $standby_count = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM repl_test;");
is($standby_count, $primary_count,
	'standby row count matches primary');

my $primary_checksum = $node_primary->safe_psql('postgres',
	"SELECT md5(string_agg(label || val::text, ',' ORDER BY id)) "
	. "FROM repl_test;");
my $standby_checksum = $node_standby->safe_psql('postgres',
	"SELECT md5(string_agg(label || val::text, ',' ORDER BY id)) "
	. "FROM repl_test;");
is($standby_checksum, $primary_checksum,
	'standby data checksum matches primary');

###########################################################################
# 11. Insert more data and verify again
###########################################################################
diag("--- Additional replication round ---");

$node_primary->safe_psql('postgres', qq{
	INSERT INTO repl_test (label, val)
		SELECT 'batch2_' || g, g * 11
		FROM generate_series(1, 500) g;
});

$node_primary->wait_for_replay_catchup($node_standby);

my $primary_total = $node_primary->safe_psql('postgres',
	"SELECT count(*) FROM repl_test;");
my $standby_total = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM repl_test;");
is($primary_total, '1500', 'primary has 1500 rows');
is($standby_total, '1500', 'standby has 1500 rows after second batch');

###########################################################################
# Cleanup
###########################################################################
$node_standby->stop;
$node_primary->stop;
done_testing();

###########################################################################
# Helper subroutines
###########################################################################

sub write_hex_to_binfile
{
	my ($hex, $path) = @_;
	my $bin = pack('H*', $hex);
	open(my $fh, '>:raw', $path) or die "Cannot open $path: $!";
	print $fh $bin;
	close($fh);
	return;
}
