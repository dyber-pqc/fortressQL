# FortressQL: Post-Quantum Cryptography extension
# Only built when liboqs is available (-Dpqc=enabled)

if liboqs.found()

pgcrypto_pqc = shared_module('pgcrypto_pqc',
  files('pgcrypto_pqc.c'),
  kwargs: contrib_mod_args + {
    'dependencies': [liboqs, ssl],
  },
)

install_data(
  'pgcrypto_pqc.control',
  'pgcrypto_pqc--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'pgcrypto_pqc',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': [
    'pgcrypto_pqc',
  ],
}

endif
