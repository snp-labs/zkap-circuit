# Security Policy

This document describes the security policy for [zkap-circuit](https://github.com/snp-labs/zkap-circuit), an open-source Rust library for zero-knowledge proof circuits.

---

## 1. Supported Versions

| Version | Supported |
|---------|-----------|
| `develop` (0.1.x, pre-release) | Yes — security fixes applied to `develop` |
| Any prior version | No |

This project has not yet published a stable release to crates.io.
Security updates are applied to the `develop` branch.
There is no long-term support policy at this time.

---

## 2. Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Please report security issues by email:

- **Email**: **security@baerae.com**

Include as much detail as possible: affected component, reproduction steps, potential impact, and any suggested mitigations.

**Response timeline:**

- Acknowledgement within 48 hours of receipt
- Triage and initial assessment within 7 days

---

## 3. Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits via email.
2. We acknowledge within 48 hours and begin triage.
3. We develop and release a fix, coordinating timing with the reporter.
4. We publish a GitHub Security Advisory upon or after the fix.
5. The reporter may disclose publicly 90 days after submission,
   or immediately once a fix has been released — whichever comes first.

We ask that reporters do not disclose vulnerabilities publicly before
a fix is available or the 90-day window has elapsed.

---

## 4. Known Advisories

### RUSTSEC-2024-0388 — `derivative` crate unmaintained

| Field    | Detail                                                                 |
|----------|------------------------------------------------------------------------|
| Advisory | [RUSTSEC-2024-0388](https://rustsec.org/advisories/RUSTSEC-2024-0388.html) |
| Crate    | `derivative` 2.2.0                                                     |
| Feature  | Transitive dependency via `ark-crypto-primitives`, `gadget`, `circuit` |
| Status   | No upstream fix available; monitoring for updates from the arkworks project |

**Description:** The `derivative` crate has been flagged as unmaintained. There is no known active exploit. The risk is that future security issues will go unpatched, and abandoned proc-macro crates carry a supply-chain takeover risk.

**Impact for this project: LOW.**

`derivative` is a transitive dependency pulled in by the arkworks ecosystem (`ark-crypto-primitives`). It is not a direct dependency of this project. Removal requires an upstream fix from arkworks.

**Mitigation:** Monitoring the arkworks project for migration to a maintained alternative (`bon` or `educe`). Added to `.cargo/audit.toml` ignore list with a review date.

### RUSTSEC-2023-0071 — `rsa` crate Marvin Attack (timing side-channel)

| Field    | Detail                                                                 |
|----------|------------------------------------------------------------------------|
| Advisory | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) |
| Crate    | `rsa`                                                                  |
| Status   | No upstream fix available; ignored in `.cargo/audit.toml` with a review date |

**Description:** The `rsa` crate is vulnerable to a key-recovery timing side-channel (the "Marvin Attack") during RSA *private-key* operations (decryption / signing).

**Impact for this project: NOT APPLICABLE.**

This library performs RSA signature **verification** only — it never loads or operates on an RSA private key. The private key that signed a JWT lives at the OAuth identity provider (e.g. Google), never in this code. The side-channel requires a secret exponent, which this project does not possess, so the timing leak has nothing to leak here.

**Mitigation:** Verifier-only usage already eliminates the attack surface. Tracked in `.cargo/audit.toml`; will drop the ignore if/when an upstream fix lands.

### Full list

The two advisories above are the ones that touch this library's security posture directly. The complete set of accepted advisories — including unmaintained transitive dependencies and `wasmtime` (a dev-dependency used only by benches and the parity test, never shipped to production) — is maintained, with per-advisory rationale and review dates, in [`.cargo/audit.toml`](.cargo/audit.toml).

---

## 5. Security Design

### Debug Feature Flags

The following Cargo feature is available for development and debugging:

- `print-trace`

This flag is **compile-time opt-in** and carries zero overhead in default builds. It is not enabled in CI workflows.

When enabled, this feature prints timing/trace information useful for debugging circuit execution. It does **not** print ZK witness values or secret circuit inputs.

### Configuration Files

The committed `example.json` contains only circuit setup parameters and does not contain any secret or sensitive material.

---

*Last updated: 2026-06-22*