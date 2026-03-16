# FortressQL Security Posture

## Overview

This document describes the security posture of FortressQL v1.0, including what
has been validated, what has not, and recommendations for production deployments.

## Cryptographic Foundation

FortressQL relies on two well-audited external libraries for all cryptographic
primitives:

| Library | Version | Audit Status |
|---------|---------|--------------|
| **OpenSSL** | 3.0+ | Extensively audited, FIPS 140-2/3 validated builds available |
| **liboqs** (Open Quantum Safe) | 0.12+ | Academic peer review; not yet FIPS validated |

FortressQL does **not** implement any cryptographic primitives itself. All
ML-KEM, ML-DSA, SLH-DSA, AES-256, and SHA-384 operations are delegated to
liboqs or OpenSSL.

## NIST Standards Compliance

| Standard | Algorithm | FortressQL Usage |
|----------|-----------|------------------|
| FIPS 203 | ML-KEM (512, 768, 1024) | TDE master key wrapping, pgcrypto_pqc KEM, hybrid TLS |
| FIPS 204 | ML-DSA (44, 65, 87) | WAL signing, pgcrypto_pqc signatures, PQC certificate auth |
| FIPS 205 | SLH-DSA (12 variants) | pgcrypto_pqc hash-based signatures |

## What Has Been Validated

### Automated Testing (CI)
- **Build verification** on Ubuntu 24.04, macOS 14, Windows 2022
- **PQC-enabled and PQC-disabled builds** to ensure guards work correctly
- **Regression test suite** covering pgcrypto_pqc operations:
  - KEM round-trip (keygen, encapsulate, decapsulate) for all ML-KEM variants
  - Signature round-trip (keygen, sign, verify) for all ML-DSA variants
  - SLH-DSA variants (where available in liboqs build)
  - Wrong-key rejection (encryption and signatures)
  - Tampered data detection
  - Large message handling (up to 1 MB)
  - Column encryption round-trip
  - Empty/edge-case inputs
- **CodeQL security analysis** on all PQC code paths
- **Smoke tests** validating end-to-end database operations with PQC enabled
- **Performance benchmarks** to detect regressions

### Code Review
- All PQC integration code has been reviewed for:
  - Correct liboqs API usage (key sizes, return value checking)
  - Secure memory handling (`explicit_bzero()` after key use)
  - `#ifdef USE_PQC` guards for vanilla PostgreSQL compatibility
  - Error path cleanup (no key material leaks on failure)

### Key Material Handling
- Master keys are zeroed on process exit via `on_proc_exit` callback
- TDE key cache uses LWLock-protected shared memory
- WAL signing keys validated for correct file permissions (0600)
- TOCTOU-safe file operations for key loading
- Maximum file size sanity checks on key files

## What Has NOT Been Independently Audited

The following areas have **not** received a formal third-party security audit:

1. **PQC integration layer** (`src/backend/crypto/pqc/`) — code-reviewed but
   not pen-tested by an external firm
2. **TDE implementation** (`src/backend/crypto/tde/`) — encryption logic is
   straightforward (AES-256-CTR via OpenSSL EVP) but has not been formally
   verified
3. **WAL signing integration** — signing/verification logic is correct per
   liboqs API usage, but WAL replay attack scenarios have not been formally
   analyzed
4. **Side-channel resistance** — liboqs provides constant-time implementations
   where possible, but FortressQL's key handling code has not been analyzed for
   timing side channels
5. **Memory safety** — no formal verification (e.g., Valgrind analysis, fuzzing
   of PQC code paths) has been performed

## Production Deployment Recommendations

### Before Deploying in Production

1. **Start with hybrid mode** — Set `ssl_pqc_mode = 'hybrid'` to maintain
   classical algorithm fallback while gaining PQC protection
2. **Test your workload** — Run your application's query patterns with PQC
   enabled and measure latency impact
3. **Key management** — Use a proper key management system or HSM for the
   `FORTRESSQL_KEM_SECRET_KEY`. Environment variables are acceptable for
   testing but not production
4. **Backup your keys** — TDE master key loss means permanent data loss.
   Back up KEM secret keys to a separate, secure location
5. **Monitor** — Use `pg_stat_ssl` and `pqc_algorithms()` to verify PQC
   is active

### Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| liboqs not FIPS validated | Medium | Hybrid mode ensures classical algorithms remain as fallback |
| No formal PQC integration audit | Medium | Open-source code, CodeQL analysis, comprehensive test suite |
| Side-channel attacks on key handling | Low | liboqs uses constant-time operations; server access required |
| TDE key in environment variable | High | Use HSM or vault in production; env vars for dev/test only |
| Algorithm deprecation | Low | Crypto agility engine allows policy-driven algorithm changes |

### Recommended Audit Scope for Enterprise Customers

Organizations requiring formal assurance should commission a security audit
covering:

1. **Cryptographic review** — Correct use of liboqs and OpenSSL APIs in
   `src/backend/crypto/pqc/` and `src/backend/crypto/tde/`
2. **Memory analysis** — Valgrind/ASan/MSan sweep of PQC code paths to detect
   use-after-free, uninitialized memory, or key material leaks
3. **Penetration testing** — Focus on authentication bypass (pqc-cert,
   pqc-scram-sha-384), TLS downgrade attacks, and TDE key extraction
4. **Fuzzing** — AFL or libFuzzer on pgcrypto_pqc functions with malformed
   inputs

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1.0 | 2026-03-16 | Initial release with NIST FIPS 203/204/205 support |

## Contact

For security-related inquiries, see [SECURITY.md](../SECURITY.md).
