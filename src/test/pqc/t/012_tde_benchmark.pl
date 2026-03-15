
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# TDE Overhead Benchmark
#
# This TAP test measures transaction throughput with and without TDE.
# It always runs a baseline measurement.  When TDE master key
# infrastructure is available, it would additionally measure TDE-enabled
# performance, but since TDE requires external master key setup this
# test records baseline numbers only and reports them via diag().
#
# Measurements:
#   - pgbench TPC-B-like workload (scale 10, 10 seconds)
#   - pgbench SELECT-only workload (10 seconds)
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
my $SCALE_FACTOR    = 10;
my $DURATION_SECS   = 10;
my $PGBENCH_CLIENTS = 1;

###########################################################################
# 1. Initialize and start cluster
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('tde_bench');
$node->init;
$node->append_conf('postgresql.conf', <<CONF);
shared_buffers = '128MB'
work_mem = '16MB'
fsync = off
full_page_writes = off
CONF
$node->start;

pass('cluster started for TDE benchmark');

###########################################################################
# 2. Detect TDE availability
###########################################################################
my $tde_available = 0;

my ($ret, $stdout, $stderr) = $node->psql('postgres',
	"SHOW tde_enabled;");
if ($ret == 0)
{
	chomp $stdout;
	diag("tde_enabled GUC found, value: $stdout");
	$tde_available = 1 if ($stdout eq 'on');
}
else
{
	diag("tde_enabled GUC not available - running baseline only");
}

###########################################################################
# 3. Initialize pgbench tables (scale 10)
###########################################################################
diag("--- Initializing pgbench (scale $SCALE_FACTOR) ---");

my $t0 = [gettimeofday];
$node->command_ok(
	[
		'pgbench', '-i', '-s', $SCALE_FACTOR,
		'-d', 'postgres',
		'-p', $node->port,
		'-h', $node->host,
	],
	'pgbench initialization (scale 10)');
my $init_elapsed = tv_interval($t0);
diag(sprintf("pgbench init completed in %.1f s", $init_elapsed));

###########################################################################
# 4. TPC-B-like workload (read-write)
###########################################################################
diag("--- pgbench TPC-B-like benchmark ($DURATION_SECS s) ---");

$t0 = [gettimeofday];
$node->pgbench(
	"--no-vacuum --client=$PGBENCH_CLIENTS --time=$DURATION_SECS",
	0,
	[qr/number of transactions actually processed/],
	[],
	'pgbench TPC-B-like workload',
);
my $tpcb_elapsed = tv_interval($t0);

# Extract TPS from pgbench output by running again and capturing output
my ($tpcb_tps_stdout, $tpcb_tps_stderr);
$node->command_checks_all(
	[
		'pgbench',
		'--no-vacuum', "--client=$PGBENCH_CLIENTS",
		"--time=$DURATION_SECS",
		'-d', 'postgres',
		'-p', $node->port,
		'-h', $node->host,
	],
	0,
	[qr/tps/],
	[],
	'pgbench TPC-B capture TPS',
	stdout => \$tpcb_tps_stdout,
	stderr => \$tpcb_tps_stderr,
);

my $tpcb_tps = 'N/A';
if (defined $tpcb_tps_stderr && $tpcb_tps_stderr =~ /tps\s*=\s*([\d.]+)/)
{
	$tpcb_tps = $1;
}
elsif (defined $tpcb_tps_stdout && $tpcb_tps_stdout =~ /tps\s*=\s*([\d.]+)/)
{
	$tpcb_tps = $1;
}

diag(sprintf("TPC-B TPS: %s (duration: %.1f s)", $tpcb_tps, $tpcb_elapsed));
pass('TPC-B benchmark completed');

###########################################################################
# 5. SELECT-only workload (read-heavy)
###########################################################################
diag("--- pgbench SELECT-only benchmark ($DURATION_SECS s) ---");

my ($sel_stdout, $sel_stderr);
$node->command_checks_all(
	[
		'pgbench',
		'--no-vacuum', "--client=$PGBENCH_CLIENTS",
		"--time=$DURATION_SECS", '--select-only',
		'-d', 'postgres',
		'-p', $node->port,
		'-h', $node->host,
	],
	0,
	[qr/tps/],
	[],
	'pgbench SELECT-only capture TPS',
	stdout => \$sel_stdout,
	stderr => \$sel_stderr,
);

my $select_tps = 'N/A';
if (defined $sel_stderr && $sel_stderr =~ /tps\s*=\s*([\d.]+)/)
{
	$select_tps = $1;
}
elsif (defined $sel_stdout && $sel_stdout =~ /tps\s*=\s*([\d.]+)/)
{
	$select_tps = $1;
}

diag(sprintf("SELECT-only TPS: %s", $select_tps));
pass('SELECT-only benchmark completed');

###########################################################################
# 6. Summary report
###########################################################################
diag("=== TDE Overhead Benchmark Summary ===");
diag(sprintf("  TDE active:       %s", $tde_available ? "YES" : "NO (baseline)"));
diag(sprintf("  Scale factor:     %d", $SCALE_FACTOR));
diag(sprintf("  Duration:         %d s per test", $DURATION_SECS));
diag(sprintf("  TPC-B TPS:        %s", $tpcb_tps));
diag(sprintf("  SELECT-only TPS:  %s", $select_tps));
diag("=======================================");

###########################################################################
# Cleanup
###########################################################################
$node->stop;
done_testing();
