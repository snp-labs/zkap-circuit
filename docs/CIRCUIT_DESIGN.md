# Circuit Design

Technical reference for the ZKAP Groth16 circuit's constraint structure,
witness flow, and security properties.

> This document describes *what* the circuit enforces and *why*.
> For crate-level architecture, see [Architecture](../ARCHITECTURE.md).
> For the public API, see [API Reference](API_REFERENCE.md).

## What the Circuit Proves

Given public inputs `[hanchor, h_a, root, h_sign_user_op, jwt_exp, verification_rhs, lhs, h_aud_list]`, the circuit proves in zero knowledge that:

1. **JWT validity** — A JWT token with valid SHA-256 padding and RSA-2048 signature exists as a private witness.
2. **Issuer membership** — The RSA public key belongs to a Merkle tree with the given `root`.
3. **Threshold membership** — The prover knows K of N credentials committed in the anchor (`hanchor`).
4. **Audience membership** — The JWT's `aud` claim matches one entry in the hashed audience allowlist (`h_aud_list`).
5. **Execution binding** — The proof is bound to a specific `h_sign_user_op` and blinding `random`.

None of the JWT contents, RSA keys, or credential identities are revealed.

## Constraint Groups

| Group | Gadgets Used | Purpose |
|-------|-------------|---------|
| JWT parsing | `Base64DecoderGadget`, `slice`, `packing` | Decode Base64 JWT, extract claims, verify `.` separator boundaries |
| SHA-256 | `SHA256Gadget` | Hash the JWT signing input (`header.payload`) for RSA verification |
| RSA-2048 | `BigNatVar`, `SigVerifyGadget` | Verify RSA signature with enforced e=65537 |
| Payload binding | Comparison, offset checks | Bind claimed payload region to actual `.` separator positions |
| Merkle tree | `MerkleCircuitInputVar` | Prove issuer public key is in the tree with root `root` |
| Poseidon anchor | `PoseidonAnchorSchemeGadget`, `VandermondeMatrixVar` | Threshold k-of-N membership proof |
| Audience | Poseidon hash + equality check | Membership in hashed audience allowlist |
| Execution binding | Poseidon hash | Bind proof to `h_sign_user_op` and `random` |

## Witness Structure

```
ZkapCircuitInput<F>
├── CircuitConstants<F>       — Padding tables, forbidden string, config parameters
├── CircuitPublicInputs<F>    — 8 public inputs (see above)
├── JwtWitness                — JWT bytes and structure
│   ├── Base64-encoded header + payload + signature
│   ├── ClaimIndices (aud, exp, iss, nonce, sub byte positions)
│   └── RSA public key (modulus) + signature bytes
├── AnchorWitness<F>          — Threshold anchor data
│   ├── Selector (N-length boolean vector, K bits set)
│   ├── Hashed secrets
│   └── Vandermonde witness (polynomial evaluation proof)
├── MerkleWitness<F>          — Merkle tree proof
│   ├── Authentication path (sibling hashes)
│   └── Leaf index
├── AudienceWitness<F>        — Audience allowlist data
│   ├── Audience hash list (num_audience_limit entries)
│   └── Selected audience index
└── MiscWitness<F>            — Additional values
    ├── exp (JWT expiration as field element)
    ├── random (blinding factor)
    └── nonce
```

## Security Properties

These properties are enforced **inside the circuit** (R1CS constraints), not just checked in application code:

| Property | Enforcement | Source |
|----------|-------------|--------|
| RSA exponent = 65537 | `enforce_equal_when_carried` on e value | `gadget::signature::rsa::constraints` |
| Payload boundary binding | `.` separator positions constrained to match SHA-256 block boundaries | `circuit::token::claimverifier` |
| Payload offset ≥ 1 | Prevents field underflow on subtraction | `circuit::zkap` |
| Payload end ≤ buffer length | Range check prevents buffer overrun | `circuit::zkap` |
| Random ≠ 0 | `random.enforce_not_equal(&zero)` | `circuit::zkap` |
| Selector is boolean with sum = K | Each element ∈ {0,1} and cardinality check | `circuit::zkap` |
| Signer index < N | Range check on current signer position | `circuit::zkap` |
| Forbidden string exclusion | JWT claims verified to not contain `forbidden_string` | `circuit::token::claimverifier` |

## Configuration Impact on Constraints

Circuit constraint count (and therefore proving time and CRS size) scales with `CircuitConfig` parameters:

| Parameter | Affects | Growth pattern |
|-----------|---------|---------------|
| `max_jwt_b64_len` | SHA-256 block count, Base64 decoding table size | More blocks → more SHA-256 rounds |
| `max_payload_b64_len` | Payload extraction and claim search constraints | Larger payload → more comparison constraints |
| `tree_height` | Merkle path verification depth | Linear in height (one hash per level) |
| `n`, `k` | Vandermonde matrix size, anchor polynomial degree | Matrix operations grow with N; polynomial degree = N-K |
| `num_audience_limit` | Audience hash equality checks | Linear in limit |
| `max_*_len` (claim lengths) | Padding and field packing constraints | Linear in max length |

Reducing these parameters produces a smaller circuit with faster proving, at the cost of supporting fewer/shorter inputs.

## Curve and Field

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Pairing curve | BN254 (`ark-bn254`) | EVM-compatible precompiles for on-chain verification |
| Inner curve | Ed-on-BN254 (`ark-ed-on-bn254`) | Efficient in-circuit operations on BN254's scalar field |
| Hash function (in-circuit) | Poseidon | Field-arithmetic-native, minimal constraint overhead |
| Hash function (JWT) | SHA-256 | JWT standard (RS256 = RSASSA-PKCS1-v1_5 with SHA-256) |
| RSA parameters | 2048-bit, e=65537 | Standard JWT signing key size |
| BigNat limb width | 64 bits, 32 limbs | 2048 / 64 = 32 limbs for RSA modulus representation |
