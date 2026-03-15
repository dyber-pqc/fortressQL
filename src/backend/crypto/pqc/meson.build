# FortressQL: Post-Quantum Cryptography abstraction layer
# Only compiled when liboqs is available (-Dpqc=enabled)

if liboqs.found()
  backend_sources += files(
    'pqc_common.c',
    'pqc_kem.c',
    'pqc_sig.c',
    'pqc_wal_keys.c',
    'pqc_wal_verify.c',
  )
endif
