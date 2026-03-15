# Security Policy

## Reporting Vulnerabilities

FortressQL takes security seriously, especially given its role in post-quantum cryptographic protection.

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing the maintainers directly. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

## Scope

Security issues in the following areas are of particular interest:

- **PQC algorithm integration** — incorrect use of liboqs APIs, key material handling
- **TLS transport** — PQC key exchange negotiation, certificate validation
- **Authentication** — pqc-cert verification bypass, SCRAM-SHA-384 implementation flaws
- **pgcrypto_pqc** — hybrid encryption, key encapsulation, signature verification
- **Memory safety** — secret key material exposure, missing secure wipes

## Supported Versions

| Version | Supported |
|---------|-----------|
| main branch | Yes |

## Cryptographic Standards

FortressQL implements the following NIST standards:
- FIPS 203 (ML-KEM)
- FIPS 204 (ML-DSA)
- FIPS 205 (SLH-DSA)

Issues related to the underlying algorithms should be reported to [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography) or [Open Quantum Safe](https://openquantumsafe.org/).
