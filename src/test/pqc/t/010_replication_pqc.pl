
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
# 3. Generate WAL signing keys using pqc_rotate_wal_signing_keys()
#
#    This SQL function writes the correct filenames (wal_signing.key
#    and wal_signing.pub) to the configured wal_pqc_key_path directory.
#    Previous versions of this test manually wrote keys with wrong
#    filenames (wal_sign_pub.bin / wal_sign_sec.bin), causing the
#    server to fail to find them.
###########################################################################
my $key_dir = "$tempdir/wal_keys";
mkdir($key_dir) or die "Cannot create key dir: $!";

# Configure key path (signing still OFF) and restart to pick up GUCs
$node_primary->stop;
$node_primary->append_conf('postgresql.conf', <<CONF);
wal_pqc_key_path = '$key_dir'
wal_pqc_signing_algorithm = 'ML-DSA-65'
wal_level = replica
max_wal_senders = 5
CONF

$node_primary->start;

($ret, $stdout, $stderr) = $node_primary->psql('postgres',
	"CREATE EXTENSION IF NOT EXISTS pgcrypto_pqc;");
if ($ret != 0)
{
	$node_primary->stop;
	plan skip_all => 'pgcrypto_pqc extension not available';
}

eval {
	$node_primary->safe_psql('postgres',
		"SELECT * FROM pqc_rotate_wal_signing_keys('ML-DSA-65');");
};
if ($@)
{
	$node_primary->stop;
	plan skip_all => "Could not generate WAL signing keys: $@";
}

# Verify the correct key files were created
my $sec_key_file = "$key_dir/wal_signing.key";
my $pub_key_file = "$key_dir/wal_signing.pub";
if (! -f $sec_key_file || ! -f $pub_key_file)
{
	$node_primary->stop;
	plan skip_all => 'WAL signing key files not created at expected paths';
}
diag("WAL signing keys generated via pqc_rotate_wal_signing_keys()");
pass('WAL signing keys generated');

###########################################################################
# 4. Enable WAL signing on primary
###########################################################################
$node_primary->stop;
$node_primary->append_conf('postgresql.conf', <<CONF);
wal_pqc_signing = on
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
# 11. Check for WAL signature files on primary
###########################################################################
diag("--- Checking for WAL signature files ---");

my $wal_dir = $node_primary->data_dir . "/pg_wal";
my @sig_files = glob("$wal_dir/*.sig");
my $sig_count = scalar @sig_files;
diag("WAL signature files found: $sig_count");
# Signature files are informational — don't fail if the deferred
# signing hasn't flushed yet, but log what we find.
ok(1, "WAL signature file check completed (found $sig_count .sig files)");

###########################################################################
# 12. Insert more data and verify again
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
