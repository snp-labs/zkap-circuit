# Security Policy

This document describes the security policy for [zkup-baerae](https://github.com/snp-labs/zkap-circuit), an open-source Rust library for zero-knowledge proof circuits.

---

## 1. Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Please report security issues by email:

- **Email**: **security@baerae.com**

Include as much detail as possible: affected component, reproduction steps, potential impact, and any suggested mitigations.

**Response timeline:**

- Acknowledgement within 48 hours of receipt
- Triage and initial assessment within 7 days

---

## 2. Known Advisories

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

## 3. Security Design

### Debug Feature Flags

The following Cargo feature is available for development and debugging:

- `print-trace`

This flag is **compile-time opt-in** and carries zero overhead in default builds. It is not enabled in CI workflows.

When enabled, this feature prints timing/trace information useful for debugging circuit execution. It does **not** print ZK witness values or secret circuit inputs.

### Configuration Files

The committed `example.json` contains only circuit setup parameters and does not contain any secret or sensitive material.

---

*Last updated: 2026-04-06*