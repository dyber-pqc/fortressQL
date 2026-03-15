# Test: pg_basebackup TDE key handling
# Verifies that pg_basebackup properly handles TDE encryption keys
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use File::Spec;
use File::Path qw(make_path);

my $node = PostgreSQL::Test::Cluster->new('tde_backup');
$node->init;
$node->start;

# Test 1: Check if --tde-key-handling option is recognized
my ($ret, $stdout, $stderr) = $node->run_command(
	[$node->installed_path('bin/pg_basebackup'), '--help']);
like($stdout, qr/tde-key-handling/,
	'pg_basebackup --help shows --tde-key-handling option');

# Test 2: Verify invalid tde-key-handling value is rejected
my $backup_dir = PostgreSQL::Test::Utils::tempdir . "/backup_test";
($ret, $stdout, $stderr) = $node->run_command(
	[$node->installed_path('bin/pg_basebackup'),
	 '-D', $backup_dir,
	 '--tde-key-handling=invalid']);
isnt($ret, 0, 'invalid --tde-key-handling value rejected');
like($stderr, qr/invalid value/, 'error message for invalid value');

# Test 3: Basic backup works with --tde-key-handling=include
$backup_dir = PostgreSQL::Test::Utils::tempdir . "/backup_include";
($ret, $stdout, $stderr) = $node->run_command(
	[$node->installed_path('bin/pg_basebackup'),
	 '-D', $backup_dir,
	 '--tde-key-handling=include',
	 '--no-sync']);
is($ret, 0, 'pg_basebackup with --tde-key-handling=include succeeds');

# Test 4: Create a fake TDE key directory and verify detection
$node->stop;

# Create fake TDE directory in PGDATA
my $tde_dir = $node->data_dir . '/global/pg_encryption';
make_path($tde_dir);

# Write a minimal fake master key file
open(my $fh, '>', "$tde_dir/master.key") or die "Cannot create fake key: $!";
print $fh "FAKE_MASTER_KEY_FOR_TESTING";
close($fh);
open($fh, '>', "$tde_dir/master.pub") or die "Cannot create fake pub: $!";
print $fh "FAKE_PUBLIC_KEY_FOR_TESTING";
close($fh);

$node->start;

# Test 5: Backup with TDE keys present
$backup_dir = PostgreSQL::Test::Utils::tempdir . "/backup_with_tde";
($ret, $stdout, $stderr) = $node->run_command(
	[$node->installed_path('bin/pg_basebackup'),
	 '-D', $backup_dir,
	 '--no-sync']);
is($ret, 0, 'pg_basebackup succeeds with TDE keys present');

# Verify TDE keys were included
ok(-f "$backup_dir/global/pg_encryption/master.key",
   'master.key included in backup');
ok(-f "$backup_dir/global/pg_encryption/master.pub",
   'master.pub included in backup');

# Test 6: Backup with --tde-key-handling=exclude
$backup_dir = PostgreSQL::Test::Utils::tempdir . "/backup_exclude";
($ret, $stdout, $stderr) = $node->run_command(
	[$node->installed_path('bin/pg_basebackup'),
	 '-D', $backup_dir,
	 '--tde-key-handling=exclude',
	 '--no-sync']);
is($ret, 0, 'pg_basebackup with --tde-key-handling=exclude succeeds');

# Verify TDE keys were removed
SKIP: {
	skip 'TDE key exclusion only works for plain format', 1
		if !-d "$backup_dir/global";
	ok(!-f "$backup_dir/global/pg_encryption/master.key",
	   'master.key excluded from backup with exclude mode');
}

# Test 7: Backup with --tde-key-handling=verify-only
$backup_dir = PostgreSQL::Test::Utils::tempdir . "/backup_verify";
($ret, $stdout, $stderr) = $node->run_command(
	[$node->installed_path('bin/pg_basebackup'),
	 '-D', $backup_dir,
	 '--tde-key-handling=verify-only',
	 '--no-sync']);
is($ret, 0, 'pg_basebackup with --tde-key-handling=verify-only succeeds');

$node->stop;
done_testing();
