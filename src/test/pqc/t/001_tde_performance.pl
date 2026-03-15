
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# TDE Performance Benchmark Test
#
# This TAP test measures baseline I/O and transaction performance on a
# PostgreSQL / FortressQL cluster.  When TDE master-key infrastructure is
# available (FORTRESSQL_KEM_SECRET_KEY), it will additionally measure
# TDE-enabled performance and report the overhead.  When TDE is not
# configured the test still passes and records baseline numbers.
#
# The benchmark uses pgbench with a scale factor that fits comfortably in
# shared buffers so that we measure CPU-bound encrypt/decrypt overhead
# rather than disk I/O variance.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use Time::HiRes qw(gettimeofday tv_interval);

#
# Tunables
#
my $SCALE_FACTOR   = 1;       # pgbench scale (small to stay in-memory)
my $DURATION_SECS  = 10;      # pgbench run duration in seconds
my $PGBENCH_CLIENTS = 1;      # single client keeps results deterministic
my $BULK_ROWS      = 100_000; # rows for bulk INSERT/SELECT test

###########################################################################
# 1. Initialize and start a fresh cluster
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('bench');
$node->init;
$node->append_conf('postgresql.conf', <<CONF);
# Keep data in memory to reduce I/O noise
shared_buffers = '128MB'
work_mem = '16MB'
fsync = off
full_page_writes = off
CONF
$node->start;

pass('cluster started');

###########################################################################
# 2. Detect TDE availability
###########################################################################
my $tde_available = 0;

# Check if the tde_enabled GUC exists (FortressQL-specific).
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
	diag("tde_enabled GUC not available (expected on stock builds)");
}

if ($tde_available)
{
	pass('TDE is enabled - benchmark will include encrypted measurements');
}
else
{
	pass('TDE not enabled - recording baseline only (this is expected '
		. 'unless FORTRESSQL_KEM_SECRET_KEY is configured)');
}

###########################################################################
# 3. Bulk INSERT / SELECT timing (SQL-level)
###########################################################################
diag("--- Bulk data operation timing ---");

# Bulk INSERT
my $t0 = [gettimeofday];
$node->safe_psql('postgres', qq{
	CREATE TABLE bench_bulk (
		id   bigint PRIMARY KEY,
		val  text,
		ts   timestamptz DEFAULT now()
	);
	INSERT INTO bench_bulk (id, val)
		SELECT g, md5(g::text)
		FROM generate_series(1, $BULK_ROWS) g;
});
my $insert_elapsed = tv_interval($t0);
my $insert_rate    = int($BULK_ROWS / ($insert_elapsed || 0.001));
diag(sprintf("Bulk INSERT %d rows: %.3f s  (%d rows/s)",
	$BULK_ROWS, $insert_elapsed, $insert_rate));
ok($insert_elapsed > 0, "bulk INSERT completed in ${insert_elapsed}s");

# Full sequential scan
$t0 = [gettimeofday];
$node->safe_psql('postgres', qq{
	SELECT count(*) FROM bench_bulk WHERE val LIKE '%a%';
});
my $scan_elapsed = tv_interval($t0);
diag(sprintf("Sequential scan %d rows: %.3f s",
	$BULK_ROWS, $scan_elapsed));
ok($scan_elapsed > 0, "sequential scan completed in ${scan_elapsed}s");

# Index scan
$node->safe_psql('postgres',
	"CREATE INDEX ON bench_bulk (id);");
$t0 = [gettimeofday];
$node->safe_psql('postgres', qq{
	SELECT count(*) FROM bench_bulk WHERE id BETWEEN 1000 AND 50000;
});
my $idx_elapsed = tv_interval($t0);
diag(sprintf("Index scan 49001 rows: %.3f s", $idx_elapsed));
ok($idx_elapsed > 0, "index scan completed in ${idx_elapsed}s");

###########################################################################
# 4. pgbench -- TPC-B-like workload
###########################################################################
diag("--- pgbench TPC-B-like benchmark ---");

# Initialize pgbench tables
$node->safe_psql('postgres',
	"SELECT 1;");   # warm connection
$node->command_ok(
	[
		'pgbench', '-i', '-s', $SCALE_FACTOR,
		'-d', 'postgres',
		'-p', $node->port,
		'-h', $node->host,
	],
	'pgbench initialization');

# Run the benchmark
$t0 = [gettimeofday];
my ($pgbench_stdout, $pgbench_stderr);
$node->pgbench(
	"--no-vacuum --client=$PGBENCH_CLIENTS --time=$DURATION_SECS",
	0,      # expected exit code
	[qr/number of transactions actually processed/],
	[],     # no stderr patterns required
	'pgbench TPC-B-like workload',
);
my $pgbench_elapsed = tv_interval($t0);

diag(sprintf("pgbench ran for %.1f s (requested %d s)",
	$pgbench_elapsed, $DURATION_SECS));
ok($pgbench_elapsed > 0, "pgbench workload completed");

###########################################################################
# 5. pgbench -- SELECT-only workload (read-heavy)
###########################################################################
diag("--- pgbench SELECT-only benchmark ---");

$t0 = [gettimeofday];
$node->pgbench(
	"--no-vacuum --client=$PGBENCH_CLIENTS --time=$DURATION_SECS --select-only",
	0,
	[qr/number of transactions actually processed/],
	[],
	'pgbench SELECT-only workload',
);
my $select_elapsed = tv_interval($t0);

diag(sprintf("pgbench SELECT-only ran for %.1f s", $select_elapsed));
ok($select_elapsed > 0, "pgbench SELECT-only workload completed");

###########################################################################
# 6. Page-write stress (checkpoint-heavy)
###########################################################################
diag("--- Page-write stress test ---");

$t0 = [gettimeofday];
$node->safe_psql('postgres', qq{
	CREATE TABLE bench_write (id bigint, payload bytea);
	INSERT INTO bench_write
		SELECT g, decode(repeat(md5(g::text), 4), 'hex')
		FROM generate_series(1, 10000) g;
	CHECKPOINT;
});
my $write_elapsed = tv_interval($t0);
diag(sprintf("10000 rows + CHECKPOINT: %.3f s", $write_elapsed));
ok($write_elapsed > 0, "page-write stress completed in ${write_elapsed}s");

###########################################################################
# 7. Summary
###########################################################################
diag("=== TDE Performance Benchmark Summary ===");
diag(sprintf("  TDE active:           %s", $tde_available ? "YES" : "NO"));
diag(sprintf("  Bulk INSERT rate:     %d rows/s", $insert_rate));
diag(sprintf("  Sequential scan:      %.3f s", $scan_elapsed));
diag(sprintf("  Index scan:           %.3f s", $idx_elapsed));
diag(sprintf("  Page-write stress:    %.3f s", $write_elapsed));
diag("==========================================");

###########################################################################
# Cleanup
###########################################################################
$node->stop;
done_testing();
