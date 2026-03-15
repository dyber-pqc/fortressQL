# Copyright (c) 2022-2024, PostgreSQL Global Development Group

subdir('regress')
subdir('isolation')

subdir('authentication')
subdir('recovery')
subdir('subscription')
subdir('modules')

if ssl.found()
  subdir('ssl')
endif

if ldap.found()
  subdir('ldap')
endif

if gssapi.found()
  subdir('kerberos')
endif

if icu.found()
  subdir('icu')
endif

subdir('perl')

# FortressQL PQC / TDE integration tests
if liboqs.found()
  subdir('pqc')
endif
