# Copyright (c) 2024-2026, FortressQL Contributors
# Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group

# FortressQL post-quantum cryptography and TDE integration tests

tests += {
  'name': 'pqc',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'tests': [
      't/001_tde_performance.pl',
      't/002_backup_pqc_roundtrip.pl',
    ],
  },
}
