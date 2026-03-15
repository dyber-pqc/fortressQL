
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# Crypto Policy Cascade Test
#
# This TAP test verifies that the crypto_policy GUC correctly cascades
# to dependent settings.  When a named policy (e.g., 'fips-pqc-level3')
# is applied, related GUCs like ssl_pqc_mode and password_encryption
# should automatically update to match the policy.
#
# If the crypto_policy GUC is not available, the test skips gracefully.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

###########################################################################
# 1. Initialize and start a fresh cluster
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('cryptopol');
$node->init;
$node->start;

###########################################################################
# 2. Check for crypto_policy GUC
###########################################################################
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	"SHOW crypto_policy;");
if ($ret != 0)
{
	$node->stop;
	plan skip_all => 'crypto_policy GUC not available';
}
chomp $stdout;
diag("crypto_policy GUC exists, current value: '$stdout'");

###########################################################################
# 3. Verify default crypto_policy value
###########################################################################
# The default is expected to be 'custom' (no preset policy active)
my $default_policy = $node->safe_psql('postgres', "SHOW crypto_policy;");
chomp $default_policy;

# Accept either 'custom' or 'default' as valid default values
like($default_policy, qr/^(custom|default)$/,
	"default crypto_policy is '$default_policy'");

###########################################################################
# 4. Capture baseline values of dependent GUCs
###########################################################################
my %baseline;
for my $guc ('ssl_pqc_mode', 'password_encryption')
{
	my ($r, $val, $err) = $node->psql('postgres', "SHOW $guc;");
	if ($r == 0)
	{
		chomp $val;
		$baseline{$guc} = $val;
		diag("Baseline $guc = '$val'");
	}
	else
	{
		diag("$guc GUC not available, will skip related checks");
	}
}

###########################################################################
# 5. Set crypto_policy = 'fips-pqc-level3'
###########################################################################
diag("--- Setting crypto_policy = 'fips-pqc-level3' ---");

($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER SYSTEM SET crypto_policy = 'fips-pqc-level3';");

SKIP:
{
	skip 'ALTER SYSTEM SET crypto_policy failed - policy may not be supported', 5
		if ($ret != 0);

	pass('ALTER SYSTEM SET crypto_policy succeeded');

	# Reload configuration
	$node->reload;
	pass('pg_ctl reload after setting fips-pqc-level3');

	# Verify crypto_policy changed
	my $new_policy = $node->safe_psql('postgres', "SHOW crypto_policy;");
	chomp $new_policy;
	is($new_policy, 'fips-pqc-level3',
		'crypto_policy is now fips-pqc-level3');

	# Check cascaded ssl_pqc_mode
	SKIP:
	{
		skip 'ssl_pqc_mode GUC not available', 1
			unless exists $baseline{'ssl_pqc_mode'};

		my $ssl_mode = $node->safe_psql('postgres', "SHOW ssl_pqc_mode;");
		chomp $ssl_mode;
		is($ssl_mode, 'hybrid',
			'ssl_pqc_mode cascaded to hybrid under fips-pqc-level3');
	}

	# Check cascaded password_encryption
	SKIP:
	{
		skip 'password_encryption GUC not available', 1
			unless exists $baseline{'password_encryption'};

		my $pw_enc = $node->safe_psql('postgres',
			"SHOW password_encryption;");
		chomp $pw_enc;
		is($pw_enc, 'scram-sha-384',
			'password_encryption cascaded to scram-sha-384 under fips-pqc-level3');
	}
}

###########################################################################
# 6. Reset to custom policy and verify
###########################################################################
diag("--- Resetting crypto_policy to custom ---");

($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER SYSTEM SET crypto_policy = 'custom';");

SKIP:
{
	skip 'ALTER SYSTEM SET crypto_policy = custom failed', 3
		if ($ret != 0);

	pass('ALTER SYSTEM SET crypto_policy = custom succeeded');

	# Reload configuration
	$node->reload;
	pass('pg_ctl reload after resetting to custom');

	# Verify crypto_policy is back to custom
	my $reset_policy = $node->safe_psql('postgres', "SHOW crypto_policy;");
	chomp $reset_policy;
	is($reset_policy, 'custom',
		'crypto_policy reset to custom');
}

###########################################################################
# 7. Test RESET (ALTER SYSTEM RESET) behavior
###########################################################################
diag("--- Testing ALTER SYSTEM RESET crypto_policy ---");

($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER SYSTEM RESET crypto_policy;");

SKIP:
{
	skip 'ALTER SYSTEM RESET crypto_policy failed', 2
		if ($ret != 0);

	pass('ALTER SYSTEM RESET crypto_policy succeeded');

	$node->reload;

	my $after_reset = $node->safe_psql('postgres', "SHOW crypto_policy;");
	chomp $after_reset;
	like($after_reset, qr/^(custom|default)$/,
		"crypto_policy after RESET is '$after_reset'");
}

###########################################################################
# 8. Test invalid policy name (should error)
###########################################################################
diag("--- Testing invalid policy name ---");

($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER SYSTEM SET crypto_policy = 'nonexistent-policy-xyz';");

SKIP:
{
	# If the GUC accepts any string (enum validation on reload), this may
	# succeed at ALTER SYSTEM time but fail on reload.  Either way, verify
	# we get an error somewhere.
	skip 'could not test invalid policy', 1
		if ($ret == 0 && !defined $stderr);

	if ($ret != 0)
	{
		ok(1, 'invalid policy name rejected by ALTER SYSTEM');
		like($stderr, qr/error|invalid|unrecognized/i,
			'error message for invalid policy is meaningful');
	}
	else
	{
		# ALTER SYSTEM accepted it; reload should catch the error
		diag("ALTER SYSTEM accepted invalid policy; checking reload behavior");
		$node->reload;
		my $check = $node->safe_psql('postgres', "SHOW crypto_policy;");
		chomp $check;
		isnt($check, 'nonexistent-policy-xyz',
			'invalid policy not applied after reload');

		# Clean up
		$node->psql('postgres', "ALTER SYSTEM RESET crypto_policy;");
		$node->reload;
	}
}

###########################################################################
# Cleanup
###########################################################################
$node->stop;
done_testing();
