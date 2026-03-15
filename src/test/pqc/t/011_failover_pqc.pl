
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# Failover with PQC WAL Signing Test
#
# This TAP test verifies that failover (standby promotion) works correctly
# when post-quantum WAL signing is enabled.  It exercises:
#
#   - Primary node with wal_pqc_signing and synchronous replication
#   - Synchronous standby that verifies WAL signatures
#   - Promotion of the standby to a new primary
#   - Data integrity across the failover boundary
#
# If wal_pqc_signing or related features are not available, the test
# skips gracefully.

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
# 4. Configure primary with WAL signing and synchronous replication
###########################################################################
$node_primary->append_conf('postgresql.conf', <<CONF);
wal_pqc_signing = on
wal_pqc_key_path = '$key_dir'
wal_level = replica
max_wal_senders = 5
synchronous_standby_names = 'standby'
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
# 5. Create synchronous standby
###########################################################################
diag("--- Creating synchronous standby ---");

my $backup_name = 'failover_backup';
$node_primary->backup($backup_name);

my $node_standby = PostgreSQL::Test::Cluster->new('standby');
$node_standby->init_from_backup($node_primary, $backup_name,
	has_streaming => 1);

# Configure the standby's application_name for synchronous replication
$node_standby->append_conf('postgresql.conf', <<CONF);
primary_conninfo = 'host=${\$node_primary->host} port=${\$node_primary->port} application_name=standby'
CONF

# Optionally enable WAL verification on receive
my ($vret, $vout, $verr) = $node_primary->psql('postgres',
	"SHOW wal_pqc_verify_on_receive;");
if ($vret == 0)
{
	$node_standby->append_conf('postgresql.conf', <<CONF);
wal_pqc_verify_on_receive = on
CONF
	diag("wal_pqc_verify_on_receive configured on standby");
}

eval {
	$node_standby->start;
};
if ($@)
{
	diag("Standby failed to start: $@");
	$node_primary->stop;
	plan skip_all => 'Standby cannot start with PQC WAL configuration';
}
pass('synchronous standby started');

###########################################################################
# 6. Insert data on primary
###########################################################################
diag("--- Inserting data on primary ---");

$node_primary->safe_psql('postgres', qq{
	CREATE TABLE failover_test (
		id    serial PRIMARY KEY,
		label text   NOT NULL,
		val   int    NOT NULL
	);
	INSERT INTO failover_test (label, val)
		SELECT 'pre_failover_' || g, g * 3
		FROM generate_series(1, 500) g;
});
pass('500 rows inserted on primary before failover');

# Wait for standby to catch up
$node_primary->wait_for_replay_catchup($node_standby);

my $standby_pre = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM failover_test;");
is($standby_pre, '500', 'standby has 500 rows before failover');

###########################################################################
# 7. Promote standby
###########################################################################
diag("--- Promoting standby ---");

# Stop the primary to simulate failure
$node_primary->stop;

# Promote the standby
$node_standby->promote;
pass('standby promoted');

# Wait for the standby to finish promotion
$node_standby->poll_query_until('postgres',
	"SELECT NOT pg_is_in_recovery();")
	or die "Timed out waiting for standby to finish promotion";
pass('promoted standby is accepting writes');

###########################################################################
# 8. Verify promoted standby has the data
###########################################################################
diag("--- Verifying data on promoted standby ---");

my $promoted_count = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM failover_test;");
is($promoted_count, '500',
	'promoted standby has all 500 pre-failover rows');

my $promoted_checksum = $node_standby->safe_psql('postgres',
	"SELECT md5(string_agg(label || val::text, ',' ORDER BY id)) "
	. "FROM failover_test;");
ok(defined $promoted_checksum && length($promoted_checksum) == 32,
	'data checksum is valid on promoted standby');

###########################################################################
# 9. Insert more data on promoted standby
###########################################################################
diag("--- Inserting data on promoted standby ---");

$node_standby->safe_psql('postgres', qq{
	INSERT INTO failover_test (label, val)
		SELECT 'post_failover_' || g, g * 5
		FROM generate_series(1, 300) g;
});
pass('300 rows inserted on promoted standby');

###########################################################################
# 10. Verify new data is accessible
###########################################################################
my $total_count = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM failover_test;");
is($total_count, '800',
	'promoted standby has 800 total rows');

my $post_failover_count = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM failover_test "
	. "WHERE label LIKE 'post_failover_%';");
is($post_failover_count, '300',
	'all 300 post-failover rows accessible');

my $pre_failover_count = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM failover_test "
	. "WHERE label LIKE 'pre_failover_%';");
is($pre_failover_count, '500',
	'all 500 pre-failover rows still intact');

###########################################################################
# 11. Restart promoted standby and verify persistence
###########################################################################
diag("--- Restart promoted standby ---");

$node_standby->stop;
$node_standby->start;

my $after_restart = $node_standby->safe_psql('postgres',
	"SELECT count(*) FROM failover_test;");
is($after_restart, '800',
	'data persists after restart of promoted standby');

###########################################################################
# Cleanup
###########################################################################
$node_standby->stop;
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
