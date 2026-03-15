# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 2022-2024, PostgreSQL Global Development Group

pg_tde_master_key_sources = files(
  'pg_tde_master_key.c',
)

if host_system == 'windows'
  pg_tde_master_key_sources += rc_bin_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'pg_tde_master_key',
    '--FILEDESC', 'pg_tde_master_key - FortressQL TDE master key management',])
endif

pg_tde_master_key_deps = [frontend_code]
if liboqs.found()
  pg_tde_master_key_deps += [liboqs, ssl]
endif

pg_tde_master_key = executable('pg_tde_master_key',
  pg_tde_master_key_sources,
  dependencies: pg_tde_master_key_deps,
  kwargs: default_bin_args,
)
bin_targets += pg_tde_master_key
