
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# PQC Backup Round-Trip Test
#
# This TAP test verifies that pg_dump and pg_restore correctly handle
# post-quantum encrypted and signed database backups.  It exercises:
#
#   - ML-KEM-768 encrypted dump/restore round-trip
#   - ML-DSA-65 signed dump/restore round-trip
#   - Combined encryption + signing
#   - Data integrity after restore
#   - Rejection of wrong decryption key
#   - Detection of tampered archive
#
# The test uses the pgcrypto_pqc extension to generate key material,
# writes raw binary keys to temp files, and then passes those files
# to pg_dump / pg_restore via --pqc-* options.
#
# If PQC support is not compiled in (USE_PQC not defined), the test
# skips gracefully.

use strict;
use warnings FATAL => 'all';

use File::Copy;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $tempdir = PostgreSQL::Test::Utils::tempdir;

###########################################################################
# 1. Start a cluster and detect PQC support
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('pqctest');
$node->init;
$node->start;

# Probe whether pg_dump understands --pqc-encrypt.  If the build was
# compiled without USE_PQC, pg_dump will reject the flag immediately.
my ($ret, $stdout, $stderr) = $node->run_command(
	['pg_dump', '--help']);
my $pqc_compiled = ($stdout =~ /--pqc-encrypt/);

if (!$pqc_compiled)
{
	plan skip_all => 'pg_dump not compiled with PQC support';
}

# Try to load the pgcrypto_pqc extension for key generation
($ret, $stdout, $stderr) = $node->psql('postgres',
	"CREATE EXTENSION IF NOT EXISTS pgcrypto_pqc;");
if ($ret != 0)
{
	plan skip_all => 'pgcrypto_pqc extension not available';
}

pass('PQC support detected and pgcrypto_pqc extension loaded');

###########################################################################
# 2. Create test data
###########################################################################
$node->safe_psql('postgres', qq{
	CREATE TABLE pqc_test_data (
		id    serial PRIMARY KEY,
		label text   NOT NULL,
		val   int    NOT NULL
	);
	INSERT INTO pqc_test_data (label, val)
		SELECT 'row_' || g, g * 17
		FROM generate_series(1, 100) g;
});
pass('test data created');

# Capture the original data for later comparison
my $original_data = $node->safe_psql('postgres',
	"SELECT id, label, val FROM pqc_test_data ORDER BY id;");

###########################################################################
# 3. Generate PQC key pairs via pgcrypto_pqc
###########################################################################

# --- KEM keys (ML-KEM-768) ---
my $kem_keys = $node->safe_psql('postgres',
	"SELECT encode(public_key, 'hex'), encode(secret_key, 'hex') "
	. "FROM pqc_kem_keygen('ML-KEM-768');");
my ($kem_pub_hex, $kem_sec_hex) = split(/\|/, $kem_keys);

my $kem_pub_file = "$tempdir/kem_pub.bin";
my $kem_sec_file = "$tempdir/kem_sec.bin";
write_hex_to_binfile($kem_pub_hex, $kem_pub_file);
write_hex_to_binfile($kem_sec_hex, $kem_sec_file);

# Generate a second (wrong) KEM key pair for negative testing
my $kem_keys_wrong = $node->safe_psql('postgres',
	"SELECT encode(public_key, 'hex'), encode(secret_key, 'hex') "
	. "FROM pqc_kem_keygen('ML-KEM-768');");
my (undef, $kem_sec_wrong_hex) = split(/\|/, $kem_keys_wrong);

my $kem_sec_wrong_file = "$tempdir/kem_sec_wrong.bin";
write_hex_to_binfile($kem_sec_wrong_hex, $kem_sec_wrong_file);

# --- Signature keys (ML-DSA-65) ---
my $sig_keys = $node->safe_psql('postgres',
	"SELECT encode(public_key, 'hex'), encode(secret_key, 'hex') "
	. "FROM pqc_sig_keygen('ML-DSA-65');");
my ($sig_pub_hex, $sig_sec_hex) = split(/\|/, $sig_keys);

my $sig_pub_file = "$tempdir/sig_pub.bin";
my $sig_sec_file = "$tempdir/sig_sec.bin";
write_hex_to_binfile($sig_pub_hex, $sig_pub_file);
write_hex_to_binfile($sig_sec_hex, $sig_sec_file);

pass('PQC key pairs generated');

###########################################################################
# 4. Encrypted dump and restore round-trip
###########################################################################
diag("--- Encrypted dump/restore round-trip ---");

my $enc_dump = "$tempdir/enc_dump.backup";

# Dump with PQC encryption (custom format required)
$node->command_ok(
	[
		'pg_dump',
		'-p', $node->port,
		'-h', $node->host,
		'-Fc',
		'--pqc-encrypt',
		'--pqc-encrypt-key', $kem_pub_file,
		'--pqc-encrypt-algorithm', 'ML-KEM-768',
		'-f', $enc_dump,
		'postgres',
	],
	'pg_dump with PQC encryption succeeds');

ok(-f $enc_dump && -s $enc_dump, 'encrypted dump file created and non-empty');

# Create a fresh database for restore
$node->safe_psql('postgres', "CREATE DATABASE restore_enc;");

# Restore with the correct secret key
$node->command_ok(
	[
		'pg_restore',
		'-p', $node->port,
		'-h', $node->host,
		'--pqc-decrypt-key', $kem_sec_file,
		'-d', 'restore_enc',
		$enc_dump,
	],
	'pg_restore with correct PQC decryption key succeeds');

# Verify data integrity
my $restored_data = $node->safe_psql('restore_enc',
	"SELECT id, label, val FROM pqc_test_data ORDER BY id;");
is($restored_data, $original_data,
	'encrypted round-trip: restored data matches original');

###########################################################################
# 5. Wrong decryption key is rejected
###########################################################################
diag("--- Wrong decryption key rejection ---");

$node->safe_psql('postgres', "CREATE DATABASE restore_wrong;");

($ret, $stdout, $stderr) = $node->run_command(
	[
		'pg_restore',
		'-p', $node->port,
		'-h', $node->host,
		'--pqc-decrypt-key', $kem_sec_wrong_file,
		'-d', 'restore_wrong',
		$enc_dump,
	]);
isnt($ret, 0, 'pg_restore with wrong decryption key fails');
like($stderr, qr/error|fatal|fail/i,
	'pg_restore with wrong key produces an error message');

###########################################################################
# 6. Signed dump and restore round-trip
###########################################################################
diag("--- Signed dump/restore round-trip ---");

my $sig_dump = "$tempdir/sig_dump.backup";

# Dump with PQC signature
$node->command_ok(
	[
		'pg_dump',
		'-p', $node->port,
		'-h', $node->host,
		'-Fc',
		'--pqc-sign',
		'--pqc-sign-key', $sig_sec_file,
		'--pqc-sign-algorithm', 'ML-DSA-65',
		'-f', $sig_dump,
		'postgres',
	],
	'pg_dump with PQC signing succeeds');

ok(-f $sig_dump && -s $sig_dump, 'signed dump file created and non-empty');

# Restore and verify signature
$node->safe_psql('postgres', "CREATE DATABASE restore_sig;");

$node->command_ok(
	[
		'pg_restore',
		'-p', $node->port,
		'-h', $node->host,
		'--pqc-verify-key', $sig_pub_file,
		'-d', 'restore_sig',
		$sig_dump,
	],
	'pg_restore with correct PQC verification key succeeds');

# Verify data integrity
my $restored_sig_data = $node->safe_psql('restore_sig',
	"SELECT id, label, val FROM pqc_test_data ORDER BY id;");
is($restored_sig_data, $original_data,
	'signed round-trip: restored data matches original');

###########################################################################
# 7. Tampered archive detection
###########################################################################
diag("--- Tampered archive detection ---");

# Copy the signed dump and corrupt it
my $tampered_dump = "$tempdir/tampered_dump.backup";
copy($sig_dump, $tampered_dump)
	or die "copy failed: $!";

# Flip some bytes in the middle of the archive to simulate tampering
tamper_file($tampered_dump);

$node->safe_psql('postgres', "CREATE DATABASE restore_tamper;");

($ret, $stdout, $stderr) = $node->run_command(
	[
		'pg_restore',
		'-p', $node->port,
		'-h', $node->host,
		'--pqc-verify-key', $sig_pub_file,
		'-d', 'restore_tamper',
		$tampered_dump,
	]);
isnt($ret, 0, 'pg_restore detects tampered signed archive');
like($stderr, qr/error|fatal|fail|signature|verif/i,
	'pg_restore reports error for tampered archive');

###########################################################################
# 8. Combined encryption + signing round-trip
###########################################################################
diag("--- Combined encryption + signing round-trip ---");

my $combo_dump = "$tempdir/combo_dump.backup";

$node->command_ok(
	[
		'pg_dump',
		'-p', $node->port,
		'-h', $node->host,
		'-Fc',
		'--pqc-encrypt',
		'--pqc-encrypt-key', $kem_pub_file,
		'--pqc-encrypt-algorithm', 'ML-KEM-768',
		'--pqc-sign',
		'--pqc-sign-key', $sig_sec_file,
		'--pqc-sign-algorithm', 'ML-DSA-65',
		'-f', $combo_dump,
		'postgres',
	],
	'pg_dump with both PQC encryption and signing succeeds');

ok(-f $combo_dump && -s $combo_dump,
	'combined encrypted+signed dump file created and non-empty');

$node->safe_psql('postgres', "CREATE DATABASE restore_combo;");

$node->command_ok(
	[
		'pg_restore',
		'-p', $node->port,
		'-h', $node->host,
		'--pqc-decrypt-key', $kem_sec_file,
		'--pqc-verify-key', $sig_pub_file,
		'-d', 'restore_combo',
		$combo_dump,
	],
	'pg_restore with both decryption and verification succeeds');

my $restored_combo_data = $node->safe_psql('restore_combo',
	"SELECT id, label, val FROM pqc_test_data ORDER BY id;");
is($restored_combo_data, $original_data,
	'combined round-trip: restored data matches original');

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

# tamper_file - flip bytes in the middle of a file to simulate corruption
sub tamper_file
{
	my ($path) = @_;

	open(my $fh, '+<:raw', $path) or die "Cannot open $path: $!";
	my $size = -s $path;

	# Flip bytes at several positions in the data portion of the archive
	# (skip the first 32 bytes to avoid corrupting the header magic,
	# which would cause a different kind of error)
	my $start = int($size * 0.3);
	for my $offset ($start .. $start + 15)
	{
		seek($fh, $offset, 0);
		my $byte;
		read($fh, $byte, 1);
		$byte = chr(ord($byte) ^ 0xFF);
		seek($fh, $offset, 0);
		print $fh $byte;
	}
	close($fh);
	return;
}
