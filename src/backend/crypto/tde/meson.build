# FortressQL: Transparent Data Encryption (TDE) infrastructure
# Only compiled when PQC support is available (-Dpqc=enabled)

if liboqs.found()
  backend_sources += files(
    'tde_keycache.c',
    'tde_keymanage.c',
    'tde_page.c',
    'tde_wal.c',
  )
endif

# TDE TAP tests (benchmark / integration)
if liboqs.found()
  tests += {
    'name': 'tde',
    'sd': meson.current_source_dir(),
    'bd': meson.current_build_dir(),
    'tap': {
      'tests': [
        't/001_tde_benchmark.pl',
      ],
    },
  }
endif
