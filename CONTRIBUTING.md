# Contributing to FortressQL

FortressQL is a PostgreSQL fork adding post-quantum cryptography. Contributions are welcome.

## Getting Started

1. Fork the repository
2. Build with PQC enabled: `meson setup build -Dssl=openssl -Dpqc=enabled`
3. Run tests: `meson test -C build --suite pqc`

## Development Guidelines

- All PQC code must be guarded with `#ifdef USE_PQC` so the fork compiles identically to vanilla PostgreSQL when PQC is disabled
- Follow PostgreSQL coding conventions (C89 style, tabs for indentation, `ereport` for errors)
- New PQC functions should use the abstraction layer in `src/backend/crypto/pqc/` rather than calling liboqs directly
- Add tests for new functionality in the appropriate test suite

## PQC-Specific Areas

| Layer | Directory | Description |
|-------|-----------|-------------|
| Abstraction | `src/backend/crypto/pqc/` | C API wrapping liboqs |
| TLS | `src/backend/libpq/be-secure-openssl.c` | Server-side PQC TLS |
| Client TLS | `src/interfaces/libpq/fe-secure-openssl.c` | Client-side PQC TLS |
| Auth | `src/backend/libpq/auth-pqc.c` | PQC certificate auth |
| SCRAM | `src/backend/libpq/auth-scram.c` | SCRAM-SHA-384 |
| Extension | `contrib/pgcrypto_pqc/` | SQL-callable PQC functions |
| Build | `meson.build` | liboqs detection |

## Submitting Changes

1. Create a feature branch from `main`
2. Write clear commit messages
3. Ensure `meson test --suite pqc` passes
4. Ensure `meson test --suite regress` passes (vanilla compatibility)
5. Open a pull request with a description of the changes

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure of security vulnerabilities.
