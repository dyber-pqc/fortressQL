
# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# TDE Page-Level Benchmark (backend-side)
#
# This test exercises TDE-related data paths from within a running server.
# When TDE is not configured (no master key), the test records baseline
# performance of the page I/O path and passes unconditionally so CI stays
# green.
#
# The workload is deliberately write-heavy to exercise the page encryption
# path: every dirty page write triggers tde_encrypt_page() when TDE is
# enabled.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use Time::HiRes qw(gettimeofday tv_interval);

###########################################################################
# Configuration
###########################################################################
my $PAGE_WRITE_ROWS = 50_000;  # rows to generate write pressure
my $UPDATE_ROUNDS   = 5;       # number of full-table UPDATE passes

###########################################################################
# 1. Start a cluster
###########################################################################
my $node = PostgreSQL::Test::Cluster->new('tde_bench');
$node->init;
$node->append_conf('postgresql.conf', <<CONF);
shared_buffers = '128MB'
fsync = off
full_page_writes = off
checkpoint_timeout = '30min'
CONF
$node->start;
pass('cluster initialized and started');

###########################################################################
# 2. Probe for TDE support
###########################################################################
my $tde_active = 0;
my ($rc, $out, $err) = $node->psql('postgres', "SHOW tde_enabled;");
if ($rc == 0 && $out =~ /on/)
{
	$tde_active = 1;
	diag("TDE is active - encrypted page I/O will be measured");
}
else
{
	diag("TDE not active - measuring unencrypted page I/O baseline");
}
pass("TDE probe complete (active=$tde_active)");

###########################################################################
# 3. Create a write-heavy table
###########################################################################
$node->safe_psql('postgres', qq{
	CREATE TABLE tde_bench (
		id     bigint PRIMARY KEY,
		counter int    DEFAULT 0,
		pad    bytea
	);
});
pass('benchmark table created');

###########################################################################
# 4. Bulk INSERT (page allocation + potential encryption)
###########################################################################
my $t0 = [gettimeofday];
$node->safe_psql('postgres', qq{
	INSERT INTO tde_bench (id, pad)
		SELECT g, decode(repeat(md5(g::text), 8), 'hex')
		FROM generate_series(1, $PAGE_WRITE_ROWS) g;
});
my $insert_time = tv_interval($t0);
my $insert_rate = int($PAGE_WRITE_ROWS / ($insert_time || 0.001));
diag(sprintf("Bulk INSERT %d rows: %.3f s (%d rows/s)",
	$PAGE_WRITE_ROWS, $insert_time, $insert_rate));
ok($insert_time > 0, "bulk INSERT completed");

###########################################################################
# 5. Full-table UPDATE rounds (dirty every page -> encrypt on flush)
###########################################################################
my @update_times;
for my $round (1 .. $UPDATE_ROUNDS)
{
	$t0 = [gettimeofday];
	$node->safe_psql('postgres', qq{
		UPDATE tde_bench SET counter = counter + 1;
	});
	my $elapsed = tv_interval($t0);
	push @update_times, $elapsed;
	diag(sprintf("UPDATE round %d/%d: %.3f s",
		$round, $UPDATE_ROUNDS, $elapsed));
}
my $avg_update = 0;
$avg_update += $_ for @update_times;
$avg_update /= scalar @update_times;
diag(sprintf("Average UPDATE time: %.3f s", $avg_update));
ok($avg_update > 0, "full-table UPDATE rounds completed");

###########################################################################
# 6. CHECKPOINT (flush all dirty pages -> encrypt all)
###########################################################################
$t0 = [gettimeofday];
$node->safe_psql('postgres', "CHECKPOINT;");
my $checkpoint_time = tv_interval($t0);
diag(sprintf("CHECKPOINT: %.3f s", $checkpoint_time));
ok($checkpoint_time >= 0, "CHECKPOINT completed");

###########################################################################
# 7. Sequential scan (page read -> decrypt)
###########################################################################
$t0 = [gettimeofday];
my $cnt = $node->safe_psql('postgres',
	"SELECT count(*) FROM tde_bench WHERE counter = $UPDATE_ROUNDS;");
my $scan_time = tv_interval($t0);
diag(sprintf("Sequential scan (count=%s): %.3f s", $cnt, $scan_time));
is($cnt, $PAGE_WRITE_ROWS,
	"all rows visible after UPDATE rounds");

###########################################################################
# 8. Random I/O via index lookups
###########################################################################
$t0 = [gettimeofday];
$node->safe_psql('postgres', qq{
	SELECT sum(counter)
	FROM tde_bench
	WHERE id IN (
		SELECT (random() * $PAGE_WRITE_ROWS)::bigint
		FROM generate_series(1, 10000)
	);
});
my $random_time = tv_interval($t0);
diag(sprintf("Random index lookups (10000): %.3f s", $random_time));
ok($random_time > 0, "random index lookups completed");

###########################################################################
# 9. Summary
###########################################################################
diag("=== TDE Page I/O Benchmark Summary ===");
diag(sprintf("  TDE active:            %s", $tde_active ? "YES" : "NO"));
diag(sprintf("  Bulk INSERT:           %d rows/s", $insert_rate));
diag(sprintf("  Avg full-table UPDATE: %.3f s", $avg_update));
diag(sprintf("  CHECKPOINT:            %.3f s", $checkpoint_time));
diag(sprintf("  Seq scan:              %.3f s", $scan_time));
diag(sprintf("  Random lookups:        %.3f s", $random_time));
diag("=======================================");

$node->stop;
done_testing();
