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
