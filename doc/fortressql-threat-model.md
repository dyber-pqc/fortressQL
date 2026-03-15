# FortressQL Threat Model

This document describes the threat landscape FortressQL addresses, the protection matrix mapping threats to features, the boundaries of what FortressQL does and does not protect against, and compliance mapping to major frameworks.

---

## Table of Contents

1. [Threat Landscape](#threat-landscape)
2. [Protection Matrix](#protection-matrix)
3. [What FortressQL Does NOT Protect Against](#what-fortressql-does-not-protect-against)
4. [Compliance Mapping](#compliance-mapping)

---

## Threat Landscape

### "Harvest Now, Decrypt Later" Attacks

The most pressing quantum threat to databases today is not a direct quantum attack -- it is data collection for future decryption. Adversaries (including nation-state actors) are intercepting and storing encrypted network traffic and encrypted backups today, with the intent to decrypt them once cryptographically relevant quantum computers (CRQCs) become available.

This threat is particularly severe for databases because:

- **Data longevity.** Medical records, financial data, government records, and trade secrets often retain their sensitivity for decades.
- **Network interception is passive.** Organizations may never know their traffic was captured.
- **Backups persist.** Encrypted backups stored offsite or in cloud storage are vulnerable if the encryption key can be broken later.

FortressQL addresses this by applying post-quantum cryptography to data in transit (PQC TLS), data at rest (TDE with ML-KEM), and backups (PQC-encrypted pg_dump).

### Quantum Computing Timeline

Estimates for when CRQCs will be able to break RSA-2048 and ECC-256:

| Source | Estimate | Notes |
|--------|----------|-------|
| NIST (2024) | Within 10-20 years | Basis for CNSA 2.0 migration timeline |
| Global Risk Institute | 11-30% chance by 2033 | Annual quantum threat survey |
| NSA/CNSA 2.0 | Migrate by 2030 (software), 2033 (hardware) | Mandatory for NSS systems |
| BSI (Germany) | Begin migration immediately | PQC should be deployed now |

The consensus is that organizations handling sensitive data should begin migration to PQC now, regardless of when CRQCs arrive. The migration itself takes years, and data encrypted today with classical algorithms is already at risk from harvest-now-decrypt-later attacks.

### CNSA 2.0 Requirements

The NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) mandates the following for National Security Systems (NSS):

| Function | Required Algorithm | CNSA 2.0 Deadline |
|----------|-------------------|-------------------|
| Key establishment | ML-KEM-1024 | 2030 (software), 2033 (browsers/hardware) |
| Digital signatures | ML-DSA-87 or SLH-DSA | 2030 (software) |
| Symmetric encryption | AES-256 | Already required |
| Hashing | SHA-384 or SHA-512 | Already required |

FortressQL supports all CNSA 2.0 required algorithms. The `fips-pqc-level5` crypto policy configures the server to meet CNSA 2.0 requirements.

---

## Protection Matrix

| Threat | FortressQL Feature | Algorithm(s) | NIST Security Level | Protection Details |
|--------|--------------------|-------------|---------------------|-------------------|
| **Data at rest exposure** (disk theft, cloud snapshot compromise) | Transparent Data Encryption (TDE) | AES-256-CTR + ML-KEM-768 key wrapping | Level 3 | Heap pages, indexes, and WAL encrypted at the storage layer. Master key wrapped with ML-KEM so it cannot be unwrapped by a quantum computer. |
| **Data in transit interception** (network sniffing, MITM) | PQC TLS | X25519MLKEM768 (hybrid key exchange) | Level 3 | Hybrid key exchange ensures forward secrecy against both classical and quantum adversaries. Even recorded TLS sessions cannot be decrypted later. |
| **Backup exfiltration** (stolen backup media, cloud compromise) | PQC-Encrypted Backups | ML-KEM-768 + AES-256-GCM | Level 3 | pg_dump output encrypted with ML-KEM. Backups are worthless without the ML-KEM secret key. |
| **Backup tampering** (modified backup injected during restore) | PQC-Signed Backups | ML-DSA-65 | Level 3 | pg_restore verifies ML-DSA signature before applying any data. Tampered backups are rejected. |
| **WAL tampering** (modified WAL injected into replication stream) | WAL Signing | ML-DSA-65 | Level 3 | Every WAL segment is signed. Standbys verify signatures before applying. Prevents rogue WAL injection. |
| **Credential theft** (password hash cracking, offline brute force) | PQC SCRAM-SHA-384 | SCRAM with SHA-384 | Level 3 (hash) | SHA-384 provides 192-bit security against quantum Grover's algorithm (vs. 128-bit for SHA-256). |
| **Certificate forgery** (forged server/client certificates) | PQC Certificate Authentication | ML-DSA-65, SLH-DSA | Level 3 | Post-quantum signatures on certificates prevent quantum-assisted forgery. |
| **Audit log tampering** (cover tracks after breach) | Hybrid Proof Logging | Ed25519 + ML-DSA-65 + SHA-384 hash chain | Level 3 (PQC), plus classical | Dual signatures (classical + PQC) and hash chains make undetected tampering computationally infeasible against both classical and quantum adversaries. |
| **Crypto agility failure** (inability to upgrade algorithms) | Crypto Agility Engine | All supported algorithms | N/A | Single `crypto_policy` setting cascades to all subsystems. Algorithm upgrades do not require application changes. |
| **Replication eavesdropping** (tapping streaming replication) | PQC Cluster Communication | X25519MLKEM768 (via PQC TLS) | Level 3 | Streaming replication inherits PQC TLS. Primary-standby traffic is quantum-resistant. |

### Security Level Reference

| NIST Level | Classical Equivalent | Quantum Resistance | FortressQL Algorithms |
|------------|---------------------|--------------------|-----------------------|
| Level 1 | AES-128 | 64-bit quantum | ML-KEM-512, ML-DSA-44 |
| Level 3 | AES-192 | 128-bit quantum | ML-KEM-768, ML-DSA-65 (default) |
| Level 5 | AES-256 | 192-bit quantum | ML-KEM-1024, ML-DSA-87 |

---

## What FortressQL Does NOT Protect Against

FortressQL provides defense-in-depth at the database layer. It does not replace application security, operating system hardening, or physical security. The following threats are explicitly out of scope.

### SQL Injection

FortressQL encrypts data at rest and in transit, but it does not inspect or sanitize SQL queries. An attacker who exploits a SQL injection vulnerability in your application can read and modify data through the normal query interface. The data is decrypted for authorized queries regardless of how the query was constructed.

**Mitigation:** Use parameterized queries, input validation, and a web application firewall (WAF).

### Application-Level Vulnerabilities

If an application is compromised (for example, through a remote code execution vulnerability), the attacker operates with the application's database credentials. FortressQL cannot distinguish between legitimate application queries and queries issued by an attacker using stolen credentials.

**Mitigation:** Follow least-privilege principles for database roles. Use row-level security. Segment application credentials.

### Physical Access to Running Server Memory

TDE encrypts data on disk, but data must be decrypted in memory for query processing. An attacker with physical access to a running server (or access to a VM's memory via a hypervisor) can extract plaintext data, encryption keys, and credentials from RAM.

**Mitigation:** Use hardware security modules (HSMs) for key storage. Use memory encryption features provided by the CPU (AMD SEV, Intel TDX). Restrict physical and hypervisor access.

### Side-Channel Attacks on liboqs

FortressQL relies on liboqs for PQC algorithm implementations. While liboqs aims for constant-time implementations, side-channel resistance depends on the specific algorithm variant, the CPU architecture, and the compiler. Sophisticated attackers with local access may be able to extract key material through timing, power, or electromagnetic side channels.

**Mitigation:** Keep liboqs updated to the latest version. Run FortressQL on hardware with side-channel mitigations. Monitor the Open Quantum Safe project for advisories.

### Compromised Operating System or Hypervisor

If the OS kernel or hypervisor is compromised, the attacker has full access to the server's memory, disk, and network. All database encryption is rendered moot because the attacker can intercept data before encryption or after decryption.

**Mitigation:** Harden the OS. Apply security patches promptly. Use measured boot and attestation. Use confidential computing (AMD SEV-SNP, Intel TDX).

### Denial of Service

FortressQL does not include specific DDoS mitigation. PQC algorithms have larger key sizes and higher computational costs than classical algorithms, which could amplify the impact of resource exhaustion attacks.

**Mitigation:** Use connection rate limiting, firewalls, and external DDoS protection services. Monitor connection counts and resource usage.

### Insider Threats with Legitimate Access

A database administrator or user with legitimate credentials and SELECT privileges can read any data they are authorized to access. TDE does not enforce access control -- it protects against offline attacks on storage media.

**Mitigation:** Use PostgreSQL's role-based access control, row-level security, and column-level grants. Enable audit logging (`pqc_audit.enabled = on`) to detect unauthorized queries.

### Quantum Attacks on AES-256

Grover's algorithm theoretically reduces AES-256 to 128-bit security against a quantum computer. While 128 bits is still considered secure, it is a reduction from the classical security level. FortressQL uses AES-256-CTR for data encryption and AES-256-GCM for key wrapping, which remain secure against known quantum attacks.

### Implementation Bugs

As with any complex software, FortressQL may contain implementation bugs. The PQC integration adds new code paths that have had less scrutiny than the mature PostgreSQL codebase.

**Mitigation:** Enable `cassert` in non-production environments. Run the full test suite. Report bugs to the FortressQL project.

---

## Compliance Mapping

### SOC 2 Type II

| SOC 2 Trust Service Criteria | FortressQL Feature | Notes |
|-----------------------------|--------------------|-------|
| **CC6.1** Logical and physical access controls | PQC Authentication (pqc-cert, pqc-scram-sha-384) | Quantum-resistant authentication methods |
| **CC6.6** Security measures against threats outside system boundaries | PQC TLS, PQC-Encrypted Backups | Quantum-resistant encryption for data in transit and backup media |
| **CC6.7** Restriction and protection of data in transmission | PQC TLS (hybrid key exchange) | Protects against current and future eavesdropping |
| **CC6.8** Prevention of unauthorized software | WAL Signing | Detects tampered WAL segments in the replication chain |
| **CC7.2** Monitoring of system components | pg_stat_pqc, pg_pqc_compliance_status | Real-time PQC operational metrics and compliance checks |
| **CC8.1** Change management | Crypto Agility Engine | Policy-based cryptographic configuration with audit trail |
| **A1.2** Recovery mechanisms | PQC-Encrypted/Signed Backups, Key Escrow | Quantum-resistant backup integrity and recovery |

### HIPAA

| HIPAA Requirement | Section | FortressQL Feature | Notes |
|------------------|---------|--------------------| ----- |
| Encryption of ePHI at rest | 164.312(a)(2)(iv) | TDE (AES-256-CTR + ML-KEM) | Addressable requirement; TDE satisfies it transparently |
| Encryption of ePHI in transit | 164.312(e)(1) | PQC TLS | Addressable requirement; hybrid mode provides forward secrecy |
| Access controls | 164.312(a)(1) | PQC Authentication | Quantum-resistant authentication exceeds current requirements |
| Audit controls | 164.312(b) | Hybrid Proof Logging | Tamper-evident audit trail with dual signatures |
| Integrity controls | 164.312(c)(1) | WAL Signing, Backup Signing | Detects unauthorized modification of data and backups |
| Contingency plan | 164.308(a)(7) | PQC-Encrypted Backups, Key Escrow | Secure backup and recovery procedures |

### FedRAMP

| FedRAMP Control | Control Family | FortressQL Feature | Impact Level |
|----------------|----------------|--------------------| -------------|
| **SC-8** Transmission Confidentiality and Integrity | System and Communications Protection | PQC TLS | Moderate, High |
| **SC-12** Cryptographic Key Establishment and Management | System and Communications Protection | ML-KEM key management, Key Escrow | Moderate, High |
| **SC-13** Cryptographic Protection | System and Communications Protection | All PQC features | Moderate, High |
| **SC-28** Protection of Information at Rest | System and Communications Protection | TDE | Moderate, High |
| **AU-10** Non-repudiation | Audit and Accountability | Hybrid Proof Logging, WAL Signing | High |
| **AU-14** Session Audit | Audit and Accountability | pqc_audit with dual signatures | High |
| **IA-5** Authenticator Management | Identification and Authentication | PQC SCRAM-SHA-384, pqc-cert | Moderate, High |
| **CP-9** Information System Backup | Contingency Planning | PQC-Encrypted/Signed Backups | Moderate, High |

**Note on FedRAMP PQC:** As of 2025, FedRAMP does not yet mandate PQC. However, NIST SP 800-131A Rev 3 and CNSA 2.0 signal that PQC will become a requirement. Deploying FortressQL positions your system ahead of the mandate.

### CMMC Level 3

| CMMC Practice | Domain | FortressQL Feature | Notes |
|---------------|--------|--------------------| ----- |
| **SC.L2-3.13.8** Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission | System and Communications Protection | PQC TLS | Exceeds current requirements by adding quantum resistance |
| **SC.L2-3.13.16** Protect the confidentiality of CUI at rest | System and Communications Protection | TDE | AES-256 with ML-KEM key wrapping |
| **SC.L3-3.13.15** Employ FIPS-validated cryptography when used to protect CUI | System and Communications Protection | All PQC features use NIST FIPS 203, 204, 205 algorithms | FIPS validation of liboqs pending |
| **AU.L2-3.3.1** Create and retain system audit logs | Audit and Accountability | Hybrid Proof Logging | Tamper-evident with hash chains |
| **AU.L3-3.3.3** Protect audit information from unauthorized access | Audit and Accountability | Dual-signed audit logs | ML-DSA + Ed25519 signatures |
| **IA.L2-3.5.10** Store and transmit only cryptographically-protected passwords | Identification and Authentication | PQC SCRAM-SHA-384 | SHA-384 exceeds CMMC requirements |
| **RE.L2-3.8.9** Protect the confidentiality of backup CUI at storage locations | Recovery | PQC-Encrypted Backups | ML-KEM encrypted, ML-DSA signed |

### Compliance Summary

| Framework | Coverage | FortressQL Crypto Policy |
|-----------|----------|--------------------------|
| SOC 2 Type II | Addresses encryption and monitoring criteria | `transitional` or higher |
| HIPAA | Satisfies addressable encryption, access, audit, and integrity requirements | `fips-pqc-level3` recommended |
| FedRAMP Moderate/High | Addresses SC, AU, IA, CP control families | `fips-pqc-level3` recommended |
| FedRAMP High + CNSA 2.0 | Full CNSA 2.0 algorithm compliance | `fips-pqc-level5` required |
| CMMC Level 3 | Addresses SC, AU, IA, RE practices | `fips-pqc-level3` recommended |

**Important:** FortressQL provides cryptographic mechanisms that support compliance, but compliance requires a holistic program including policies, procedures, training, and continuous monitoring. FortressQL alone does not make a system compliant with any framework.
