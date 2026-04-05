# Security Policy

This document describes the security policy for [zkup-baerae](https://github.com/snp-labs/zkap-circuit), an open-source Rust library for zero-knowledge proof circuits.

---

## 1. Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

You can report security issues through either channel:

- **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/snp-labs/zkap-circuit/security/advisories/new)
- **Email**: **security@snp-labs.io**

Include as much detail as possible: affected component, reproduction steps, potential impact, and any suggested mitigations.

**Response timeline:**

- Acknowledgement within 48 hours of receipt
- Triage and initial assessment within 7 days

---

## 2. Known Advisories

### RUSTSEC-2023-0071 — RSA Marvin Attack (CVSS 5.9)

| Field    | Detail                                                                                    |
|----------|-------------------------------------------------------------------------------------------|
| Advisory | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)                |
| Crate    | `rsa` 0.9.10                                                                              |
| Feature  | `rsa` (opt-in, in the `gadget` crate)                                                     |
| Status   | No upstream fix available; monitoring for updates                                         |

**Description:** A timing side-channel in the `rsa` crate's PKCS#1 v1.5 decryption path allows a remote attacker to recover private key material via the Marvin Attack.

**Impact for this project: LIMITED.**

This library uses RSA for signature verification within ZK circuits. All operations are performed on finite field elements inside the circuit arithmetization; timing of those operations is not directly observable by an external adversary. The native RSA functions exposed by the `gadget` crate are used for testing and witness generation only, not for production cryptographic operations.

**Mitigation:** The `rsa` feature is opt-in and is not enabled by default. Users who do not explicitly enable this feature are not affected. If you enable the `rsa` feature, ensure it is used solely for testing and not in contexts where timing side-channels can be exploited.

---

## 3. Security Design

### Debug Feature Flags

The following Cargo features are available for development and debugging:

- `print-trace`

This flag is **compile-time opt-in** and carries zero overhead in default builds. It is not enabled in CI workflows.

**Warning:** When enabled, this flag can log ZK witness values, which may include secret circuit inputs. It must **never** be enabled in production builds or in published packages. Treat any output produced with this flag as potentially sensitive.

### Configuration Files

The committed `example.json` contains only circuit parameters (such as field sizes and curve identifiers) for local development and holds no secret material.

---

## 4. Dependency Policy

- **Audit:** Run `cargo audit` regularly against the advisory database. In CI, this should be part of the standard check pipeline.
- **Lockfile:** `Cargo.lock` is committed and tracked. Do not ignore or regenerate it without review, as this ensures reproducible builds and makes dependency changes explicit in pull requests.
- **GitHub Actions pinning:** All GitHub Actions steps are pinned to full commit SHAs rather than mutable tags. This prevents supply-chain attacks where a tag is silently moved to a malicious commit.

---

*Last updated: 2026-04-05*
