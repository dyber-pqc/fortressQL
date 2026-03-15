
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# TLS Connection Baseline Benchmark
#
# This TAP test measures baseline connection establishment time by timing
# repeated psql connect/disconnect cycles.  It does not configure SSL
# (that would require certificate setup) -- it simply measures the
# unencrypted connection overhead as a reference point.
#
# When PQC TLS is eventually configured, a companion test can compare
# against these baseline numbers to quantify the overhead of
# post-quantum key exchange during connection setup.
#
# The test always passes -- it is a benchmark, not a correctness test.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use Time::HiRes qw(gettimeofday tv_interval);

#
# Tunables
#
my $NUM_CONNECTIONS = 100;

###########################################################################
# 1. Initialize and start cluster
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('tls_bench');
$node->init;
$node->start;

pass('cluster started for connection benchmark');

###########################################################################
# 2. Warm up: single connection to ensure shared catalog caches are loaded
###########################################################################
$node->safe_psql('postgres', "SELECT 1;");

###########################################################################
# 3. Time connection/disconnection cycles
###########################################################################
diag("--- Timing $NUM_CONNECTIONS connect/disconnect cycles (no SSL) ---");

my $t0 = [gettimeofday];
my $success_count = 0;

for my $i (1 .. $NUM_CONNECTIONS)
{
	my ($ret, $stdout, $stderr) = $node->psql('postgres', "SELECT 1;");
	if ($ret == 0)
	{
		$success_count++;
	}
	else
	{
		diag("Connection $i failed: $stderr");
	}
}
my $total_elapsed = tv_interval($t0);

is($success_count, $NUM_CONNECTIONS,
	"all $NUM_CONNECTIONS connections succeeded");

###########################################################################
# 4. Calculate and report metrics
###########################################################################
my $avg_ms = ($total_elapsed / $NUM_CONNECTIONS) * 1000;
my $conns_per_sec = $NUM_CONNECTIONS / ($total_elapsed || 0.001);

diag("=== Connection Benchmark Summary ===");
diag(sprintf("  SSL:                  OFF (baseline)"));
diag(sprintf("  Connections:          %d", $NUM_CONNECTIONS));
diag(sprintf("  Total time:           %.3f s", $total_elapsed));
diag(sprintf("  Avg connection time:  %.2f ms", $avg_ms));
diag(sprintf("  Connections/sec:      %.1f", $conns_per_sec));
diag("=====================================");

pass('connection benchmark completed');

###########################################################################
# Cleanup
###########################################################################
$node->stop;
done_testing();
