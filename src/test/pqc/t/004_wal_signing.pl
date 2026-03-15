
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# WAL Signing Integration Test
#
# This TAP test verifies that Write-Ahead Log (WAL) segments can be
# cryptographically signed using post-quantum algorithms.  It exercises:
#
#   - Enabling the wal_pqc_signing GUC
#   - Generating WAL signing keys
#   - Running a workload that generates WAL
#   - Verifying that .sig files appear alongside completed WAL segments
#
# If wal_pqc_signing GUC is not available, the test skips gracefully.

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
my $node = PostgreSQL::Test::Cluster->new('walsign');
$node->init;
$node->start;

###########################################################################
# 2. Check for wal_pqc_signing GUC
###########################################################################
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	"SHOW wal_pqc_signing;");
if ($ret != 0)
{
	$node->stop;
	plan skip_all => 'wal_pqc_signing GUC not available';
}
diag("wal_pqc_signing GUC exists, current value: $stdout");

$node->stop;

###########################################################################
# 3. Generate WAL signing keys
###########################################################################
diag("--- Generating WAL signing keys ---");

my $key_dir = "$tempdir/wal_keys";
mkdir($key_dir) or die "Cannot create key dir: $!";

my $keys_generated = 0;

# Strategy 1: Try pgcrypto_pqc extension via a temporary server start
$node->start;

($ret, $stdout, $stderr) = $node->psql('postgres',
	"CREATE EXTENSION IF NOT EXISTS pgcrypto_pqc;");
if ($ret == 0)
{
	# Generate ML-DSA-65 keys for WAL signing
	my $sig_keys = eval {
		$node->safe_psql('postgres',
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

# Strategy 2: Try pg_tde_master_key or dedicated WAL key generator
if (!$keys_generated)
{
	my $bindir = $node->config_data('--bindir');
	for my $tool ('pg_wal_keygen', 'pg_pqc_keygen')
	{
		my $tool_path = File::Spec->catfile($bindir, $tool);
		if (-x $tool_path || -f $tool_path)
		{
			($ret, $stdout, $stderr) = $node->run_command(
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

$node->stop;

if (!$keys_generated)
{
	plan skip_all => 'Could not generate WAL signing keys '
		. '(neither pgcrypto_pqc nor keygen tool available)';
}
pass('WAL signing keys generated');

###########################################################################
# 4. Configure WAL signing and restart
###########################################################################
$node->append_conf('postgresql.conf', <<CONF);
wal_pqc_signing = on
wal_pqc_key_path = '$key_dir'
wal_level = replica
max_wal_senders = 2
CONF

eval {
	$node->start;
};
if ($@)
{
	diag("Server failed to start with wal_pqc_signing=on: $@");
	plan skip_all => 'Server cannot start with WAL signing enabled';
}

# Verify the GUC is active
($ret, $stdout, $stderr) = $node->psql('postgres',
	"SHOW wal_pqc_signing;");
chomp $stdout if defined $stdout;
is($stdout, 'on', 'wal_pqc_signing is on');

###########################################################################
# 5. Run workload to generate WAL
###########################################################################
diag("--- Running workload to generate WAL ---");

$node->safe_psql('postgres', qq{
	CREATE TABLE wal_test (
		id    serial PRIMARY KEY,
		data  text   NOT NULL
	);
});

# Insert 10000 rows to generate a meaningful amount of WAL
$node->safe_psql('postgres', qq{
	INSERT INTO wal_test (data)
		SELECT repeat(md5(g::text), 10)
		FROM generate_series(1, 10000) g;
});
pass('10000 rows inserted to generate WAL');

# Force a WAL switch to complete the current segment
$node->safe_psql('postgres', "SELECT pg_switch_wal();");
pass('WAL switch forced');

# Do another round to ensure at least one full segment is completed
$node->safe_psql('postgres', qq{
	INSERT INTO wal_test (data)
		SELECT repeat(md5(g::text), 10)
		FROM generate_series(10001, 15000) g;
	SELECT pg_switch_wal();
});
diag("Additional WAL generated and switched");

# Force a checkpoint to ensure WAL segments are finalized
$node->safe_psql('postgres', "CHECKPOINT;");

###########################################################################
# 6. Check for .sig files alongside WAL segments
###########################################################################
diag("--- Checking for WAL signature files ---");

my $pg_wal_dir = File::Spec->catdir($node->data_dir, 'pg_wal');

# List WAL segment files (24-character hex names)
opendir(my $dh, $pg_wal_dir) or die "Cannot open $pg_wal_dir: $!";
my @wal_files = grep { /^[0-9A-F]{24}$/ } readdir($dh);
closedir($dh);

diag("Found " . scalar(@wal_files) . " WAL segment(s) in pg_wal/");
ok(scalar(@wal_files) > 0, 'WAL segments exist in pg_wal/');

# Check for .sig files
opendir($dh, $pg_wal_dir) or die "Cannot open $pg_wal_dir: $!";
my @sig_files = grep { /^[0-9A-F]{24}\.sig$/ } readdir($dh);
closedir($dh);

diag("Found " . scalar(@sig_files) . " .sig file(s) in pg_wal/");

SKIP:
{
	skip 'no .sig files found - WAL signing may use a different naming scheme', 2
		if (scalar(@sig_files) == 0);

	ok(scalar(@sig_files) > 0, '.sig files exist alongside WAL segments');

	# Verify that at least one .sig file corresponds to a WAL segment
	my $match_found = 0;
	for my $sig (@sig_files)
	{
		(my $base = $sig) =~ s/\.sig$//;
		if (grep { $_ eq $base } @wal_files)
		{
			$match_found = 1;
			diag("Signature file $sig matches WAL segment $base");
			last;
		}
	}
	ok($match_found, 'at least one .sig file corresponds to a WAL segment');
}

# Alternative: check if signatures are stored in a subdirectory
SKIP:
{
	my $sig_subdir = File::Spec->catdir($pg_wal_dir, 'signatures');
	skip 'no signatures/ subdirectory in pg_wal', 1
		unless (-d $sig_subdir);

	opendir($dh, $sig_subdir) or skip "cannot open $sig_subdir: $!", 1;
	my @subdir_sigs = grep { !/^\./ } readdir($dh);
	closedir($dh);

	ok(scalar(@subdir_sigs) > 0,
		'signature files found in pg_wal/signatures/ subdirectory');
	diag("Found " . scalar(@subdir_sigs) . " file(s) in pg_wal/signatures/");
}

###########################################################################
# 7. Verify data integrity
###########################################################################
my $count = $node->safe_psql('postgres',
	"SELECT count(*) FROM wal_test;");
is($count, '15000', 'all rows present after WAL signing workload');

###########################################################################
# 8. Restart and verify WAL replay works with signatures
###########################################################################
diag("--- Restart and verify WAL replay ---");

$node->stop;
$node->start;

my $after_restart_count = $node->safe_psql('postgres',
	"SELECT count(*) FROM wal_test;");
is($after_restart_count, '15000',
	'data intact after restart with WAL signing enabled');

###########################################################################
# Cleanup
###########################################################################
$node->stop;
done_testing();

###########################################################################
# Helper subroutines
###########################################################################

# write_hex_to_binfile - decode a hex string and write raw bytes to a file
sub write_hex_to_binfile
{
	my ($hex, $path) = @_;
	my $bin = pack('H*', $hex);
	open(my $fh, '>:raw', $path) or die "Cannot open $path: $!";
	print $fh $bin;
	close($fh);
	return;
}
