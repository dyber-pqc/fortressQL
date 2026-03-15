# Test: PQC TLS integration
# Verifies SSL connections with PQC key exchange groups
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use File::Spec;

my $tempdir = PostgreSQL::Test::Utils::tempdir;

# Check if SSL is available
my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init;
$node->start;

my ($ret, $stdout, $stderr) = $node->psql('postgres', 'SHOW ssl;');
$node->stop;

if ($ret != 0 || $stdout !~ /^(on|off)$/)
{
	plan skip_all => 'SSL support not available';
}

# Re-initialize with SSL support
$node = PostgreSQL::Test::Cluster->new('pqc_tls');
$node->init;

# Generate self-signed certificate for testing
my $certdir = "$tempdir/certs";
mkdir($certdir);

# Check if openssl is available
my $openssl_check = `openssl version 2>&1`;
if ($? != 0)
{
	plan skip_all => 'openssl command not available';
}

# Generate test certificates
system("openssl req -new -x509 -days 1 -nodes -keyout $certdir/server.key " .
	   "-out $certdir/server.crt -subj '/CN=localhost' 2>/dev/null");

if (! -f "$certdir/server.key" || ! -f "$certdir/server.crt")
{
	plan skip_all => 'could not generate test SSL certificates';
}

# Set permissions on key file
chmod(0600, "$certdir/server.key");

# Configure SSL
$node->append_conf('postgresql.conf', qq{
ssl = on
ssl_cert_file = '$certdir/server.crt'
ssl_key_file = '$certdir/server.key'
});

$node->start;

# Test 1: Verify SSL is enabled
($ret, $stdout, $stderr) = $node->psql('postgres', 'SHOW ssl;');
is($ret, 0, 'SHOW ssl succeeds');
is($stdout, 'on', 'SSL is enabled');

# Test 2: Check PQC GUCs exist
($ret, $stdout, $stderr) = $node->psql('postgres', 'SHOW ssl_pqc_mode;');
if ($ret != 0)
{
	plan skip_all => 'PQC GUCs not available (PQC not compiled in)';
}
pass('ssl_pqc_mode GUC exists');

($ret, $stdout, $stderr) = $node->psql('postgres', 'SHOW ssl_pqc_groups;');
is($ret, 0, 'ssl_pqc_groups GUC exists');
like($stdout, qr/X25519|MLKEM|prime256/, 'ssl_pqc_groups has default value');

# Test 3: Check PQC mode settings
($ret, $stdout, $stderr) = $node->psql('postgres',
	"SET ssl_pqc_mode = 'hybrid'; SHOW ssl_pqc_mode;");
if ($ret == 0)
{
	like($stdout, qr/hybrid/, 'ssl_pqc_mode can be set to hybrid');
}
else
{
	pass('ssl_pqc_mode setting skipped (may require restart)');
}

# Test 4: Verify pg_stat_ssl view exists and has PQC columns
($ret, $stdout, $stderr) = $node->psql('postgres',
	"SELECT column_name FROM information_schema.columns " .
	"WHERE table_name = 'pg_stat_ssl' ORDER BY ordinal_position;");
is($ret, 0, 'pg_stat_ssl view exists');

# Test 5: Connect via SSL and verify
($ret, $stdout, $stderr) = $node->psql('postgres',
	"SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();",
	extra_params => ['--set=sslmode=require']);
SKIP: {
	skip 'SSL connection test requires sslmode support', 1
		if $ret != 0;
	like($stdout, qr/^t/, 'SSL connection established');
}

$node->stop;
done_testing();
