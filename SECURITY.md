# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in FortressQL, please report it responsibly:

### Contact

- **Email:** security@dyber.org
- **Subject line:** `[FortressQL Security] <brief description>`
- **PGP:** If you need to encrypt your report, contact us for our PGP public key.

### What to Include

1. **Description** of the vulnerability
2. **Steps to reproduce** (minimal test case if possible)
3. **Impact assessment** — what an attacker could achieve
4. **Affected versions** — which FortressQL versions are impacted
5. **Affected component** — TDE, WAL signing, pgcrypto_pqc, PQC TLS, core, etc.

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development | Within 30 days (critical), 90 days (moderate) |
| Public disclosure | Coordinated with reporter after fix is released |

### Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Remote code execution, key material exposure, TDE bypass | Plaintext key in logs, buffer overflow in PQC code |
| **High** | Authentication bypass, data integrity violation | WAL signature forgery, KEM decapsulation failure |
| **Medium** | Information disclosure, denial of service | Timing side-channel in PQC operations, crash via malformed input |
| **Low** | Minor information leak, non-default configuration issue | Version disclosure, debug info in error messages |

## Scope

Security issues in the following areas are of particular interest:

- **PQC algorithm integration** — incorrect use of liboqs APIs, key material handling
- **Transparent Data Encryption** — key cache security, page encryption/decryption, key rotation
- **WAL signing** — signature generation/verification, tamper detection bypass
- **TLS transport** — PQC key exchange negotiation, hybrid mode downgrade attacks
- **Authentication** — pqc-cert verification bypass, SCRAM implementation
- **pgcrypto_pqc** — hybrid encryption, key encapsulation, signature verification
- **Memory safety** — secret key material exposure, missing secure wipes, use-after-free

## Security Architecture

FortressQL's post-quantum cryptography stack:

- **Key Encapsulation:** ML-KEM-512/768/1024 (FIPS 203) via liboqs
- **Digital Signatures:** ML-DSA-44/65/87 (FIPS 204) via liboqs
- **Hash-Based Signatures:** SLH-DSA (FIPS 205) via liboqs
- **Symmetric Encryption:** AES-256-GCM (TDE) via OpenSSL
- **TLS:** Hybrid classical + PQC key exchange via OpenSSL 3.x

### Cryptographic Dependencies

| Component | Library | Version Policy |
|-----------|---------|----------------|
| PQC algorithms | [liboqs](https://github.com/open-quantum-safe/liboqs) | Track latest stable |
| TLS / AES | OpenSSL | 3.x required |
| Random number generation | OpenSSL CSPRNG | System entropy source |

### Known Limitations

1. **No formal cryptographic audit yet** — the PQC integration has been reviewed internally but has not undergone a third-party cryptographic audit. See [Security Posture](docs/SECURITY_AUDIT.md) for details.
2. **Side-channel resistance** — liboqs algorithms implement constant-time operations where specified by NIST standards, but the FortressQL integration layer (key cache, TDE page encryption) has not been formally analyzed for side-channel leaks.
3. **Key management** — TDE master keys are stored on the filesystem. Hardware Security Module (HSM) integration is planned for a future release.

Issues related to the underlying PQC algorithms should be reported to [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography) or [Open Quantum Safe](https://openquantumsafe.org/).

## Bug Bounty

We do not currently operate a formal bug bounty program. However, we deeply appreciate responsible disclosure and will publicly credit reporters (with permission) in our release notes and security advisories.

## Security Advisories

Security advisories will be published as [GitHub Security Advisories](https://github.com/dyber-pqc/fortressQL/security/advisories) and announced on the project's releases page.
