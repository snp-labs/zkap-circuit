# Security Policy

This document describes the security policy for [zkap-circuit](https://github.com/snp-labs/zkap-circuit), an open-source Rust library for zero-knowledge proof circuits.

---

## 1. Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (0.1.x, pre-release) | Yes — security fixes applied to `main` |
| Any prior version | No |

This project has not yet published a stable release to crates.io.
Security updates are applied to the `main` branch.
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

1. Reporter submits via GitHub Security Advisories or email.
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

*Last updated: 2026-04-06*