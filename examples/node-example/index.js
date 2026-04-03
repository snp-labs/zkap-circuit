/**
 * zkap-circuit Node.js Example
 *
 * This example demonstrates how to use the NAPI binding to:
 *   1. Compute a Poseidon hash over field elements
 *   2. Derive an anchor (a Poseidon-based polynomial commitment) from user secrets
 *   3. Generate a full Groth16 ZK proof
 *
 * The NAPI binding is built from bindings/napi/ and exposes three functions:
 *   - napiGeneratePoseidonHash(req)  -> { hash: "0x..." }
 *   - napiGenerateAnchor(req)        -> { anchor: ["0x...", ...] }
 *   - napiGenerateProof(req)         -> { proofs, sharedInputs, partialRhsList, jwtExpList }
 *
 * Run `./build.sh --napi-only` from the project root to produce the .node file.
 * The build output is typically located at bindings/napi/zkap_circuit.*.node.
 */

// ---------------------------------------------------------------------------
// Import the native addon.
// Adjust the path to match where your build places the .node file.
// After running `./build.sh --napi-only` the file appears at:
//   bindings/napi/zkap_circuit.<platform>-<arch>.node
// ---------------------------------------------------------------------------
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Update this path to the actual .node file produced by the build.
const binding = require('../../bindings/napi/zkap_circuit.node');

// Destructure the three exported NAPI functions.
const { napiGeneratePoseidonHash, napiGenerateAnchor, napiGenerateProof } = binding;

// ---------------------------------------------------------------------------
// Example 1: Poseidon hash
//
// napiGeneratePoseidonHash accepts:
//   { inputs: string[] }
//
// Each string is a field element encoded as a hex ("0x...") or decimal string
// on the BN-254 scalar field.
//
// Returns:
//   { hash: string }   -- hex-encoded field element, e.g. "0xABCD..."
// ---------------------------------------------------------------------------
function examplePoseidonHash() {
  console.log('--- Example 1: Poseidon hash ---');

  // Two arbitrary field elements represented as decimal strings.
  // In practice these come from hashing real data (JWTs, keys, etc.).
  const req = {
    inputs: [
      '1',   // first field element
      '2',   // second field element
    ],
  };

  const res = napiGeneratePoseidonHash(req);
  // res.hash is a hex string: "0x<field element in BN-254>"
  console.log('Poseidon hash result:', res.hash);
  console.log();
}

// ---------------------------------------------------------------------------
// Example 2: Anchor derivation
//
// An "anchor" is a Poseidon-based polynomial commitment that binds together
// N user identities (aud/iss/sub triples from JWTs) into a single compact
// value.  The circuit later proves that a threshold number (K) of those
// identities are present in a wallet, without revealing which ones.
//
// napiGenerateAnchor accepts:
//   { secrets: Array<{ aud: string, iss: string, sub: string }> }
//
//   - aud: the OAuth audience claim (typically your app's client ID)
//   - iss: the OAuth issuer claim (e.g. "https://accounts.google.com")
//   - sub: the OAuth subject claim (the user's stable unique ID)
//
// The number of secrets must exactly equal the circuit's compile-time N
// constant (set via ZK_PROFILE during `./build.sh`).
//
// Returns:
//   { anchor: string[] }  -- K+1 hex field elements representing the anchor
// ---------------------------------------------------------------------------
function exampleAnchor() {
  console.log('--- Example 2: Anchor derivation ---');

  // Replace with real OAuth claim values from your users' JWTs.
  // N must match the circuit constant (see crates/circuit/src/constants.rs).
  const req = {
    secrets: [
      {
        aud: 'your-google-client-id.apps.googleusercontent.com', // OAuth client ID
        iss: 'https://accounts.google.com',                      // Google OIDC issuer
        sub: '1234567890',                                       // Stable user subject ID
      },
      // Add more entries up to N if your circuit was compiled with N > 1.
    ],
  };

  const res = napiGenerateAnchor(req);
  // res.anchor is an array of K+1 hex-encoded field elements.
  console.log('Anchor (hex field elements):');
  res.anchor.forEach((v, i) => console.log(`  anchor[${i}] = ${v}`));
  console.log();
}

// ---------------------------------------------------------------------------
// Example 3: Full proof generation
//
// napiGenerateProof generates one Groth16 proof per JWT credential supplied.
// It calls generate_baerae_proof() from the zkpasskey-service crate.
//
// Request shape (GenerateProofReq):
//
//   pk_path        string      -- absolute path to the Groth16 proving key file
//                                 produced by `./build.sh --keys-only`
//
//   jwts           string[]    -- raw JWT strings, one per credential to prove
//
//   pk_ops         string[]    -- RSA public key exponent+modulus in hex, one
//                                 per JWT.  Format: "<e_hex>:<n_hex>"
//
//   merkle_paths   string[][]  -- Merkle authentication path for each JWT.
//                                 Outer array indexes credentials; inner array
//                                 lists sibling node hashes (hex) from leaf
//                                 up to the root, one string per tree level.
//
//   leaf_indices   number[]    -- 0-based leaf position in the Merkle tree for
//                                 each credential. JS numbers are safe up to
//                                 2^53; the binding expects u32 values.
//
//   root           string      -- Merkle root hash (hex field element)
//
//   anchor         string[]    -- Anchor array from napiGenerateAnchor (K+1
//                                 hex field elements)
//
//   h_sign_user_op string      -- Poseidon hash of the ERC-4337 UserOperation
//                                 that the wallet is authorizing (hex)
//
//   random         string      -- Random blinding scalar (hex field element).
//                                 Generate securely on the server; never reuse.
//
//   aud_list       string[]    -- OAuth audience strings included in the proof
//                                 (must be the same strings used to build the
//                                 anchor).  Up to NUM_AUDIENCE_LIMIT entries.
//
// Response shape (GenerateProofRes):
//
//   proofs         string[][]  -- Groth16 proof bytes (serialized), one inner
//                                 array per JWT
//   sharedInputs   string[]    -- Public inputs shared across all proofs
//   partialRhsList string[]    -- Intermediate RHS values (one per JWT)
//   jwtExpList     string[]    -- JWT expiry timestamps (one per JWT)
// ---------------------------------------------------------------------------
function exampleGenerateProof() {
  console.log('--- Example 3: Full proof generation ---');
  console.log('(This requires real JWT credentials and a proving key on disk.)');
  console.log();

  // ---------------------------------------------------------------------------
  // Step 1: Build the proof request.
  // All string fields that represent field elements use hex encoding ("0x...").
  // ---------------------------------------------------------------------------
  const req = {
    // Path to the Groth16 proving key generated by `./build.sh --keys-only`.
    // The key file is large (hundreds of MB) and must match the compiled circuit.
    pk_path: '/path/to/proving_key.bin',

    // One raw JWT per credential (the full "header.payload.signature" string).
    jwts: [
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<signature>',
    ],

    // RSA public key for each JWT in "<e_hex>:<n_hex>" format.
    // e is typically 0x10001 (65537).
    // n is the 2048-bit modulus from the identity provider's JWKS endpoint.
    pk_ops: [
      '0x10001:0xc3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2',
    ],

    // Merkle authentication path: one inner array of sibling hashes per JWT.
    // Each inner array contains the sibling at each tree level, leaf to root.
    // These are hex-encoded Poseidon field elements.
    merkle_paths: [
      [
        '0x1a2b3c4d5e6f000000000000000000000000000000000000000000000000abcd',
        '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        // ... one entry per tree level
      ],
    ],

    // 0-based index of the leaf in the Merkle tree for each credential.
    leaf_indices: [0],

    // Merkle root hash (hex Poseidon field element).
    // Computed off-chain when the wallet is registered.
    root: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',

    // Anchor derived by napiGenerateAnchor() for the same set of identities.
    anchor: [
      '0xaaaa000000000000000000000000000000000000000000000000000000000001',
      '0xbbbb000000000000000000000000000000000000000000000000000000000002',
      // K+1 elements total (K is a circuit compile-time constant)
    ],

    // Poseidon hash of the ERC-4337 UserOperation the wallet is signing.
    // Computed as H(userOpHash) on the server before calling this function.
    h_sign_user_op: '0xcafe000000000000000000000000000000000000000000000000000000000001',

    // Uniformly random blinding scalar.  Must be fresh for each proof request.
    // Generate with: crypto.getRandomValues or a secure CSPRNG.
    random: '0xf00d000000000000000000000000000000000000000000000000000000000042',

    // OAuth audience strings used when computing the anchor.
    // Length must not exceed NUM_AUDIENCE_LIMIT (a circuit constant).
    aud_list: [
      'your-google-client-id.apps.googleusercontent.com',
    ],
  };

  // ---------------------------------------------------------------------------
  // Step 2: Call the proof generator.
  // This is CPU-intensive (seconds to minutes depending on hardware).
  // Consider running in a worker thread for production use.
  // ---------------------------------------------------------------------------
  try {
    const res = napiGenerateProof(req);

    // res.proofs[i]         -- serialized Groth16 proof for JWT i
    // res.sharedInputs      -- public inputs shared across all proofs
    // res.partialRhsList[i] -- partial RHS value for JWT i
    // res.jwtExpList[i]     -- expiry timestamp for JWT i
    console.log('Proof generated successfully.');
    console.log('Number of proofs:', res.proofs.length);
    console.log('Shared inputs:', res.sharedInputs);
    console.log('JWT expiry list:', res.jwtExpList);
  } catch (err) {
    // Common errors:
    //   "Invalid pk_path" -- proving key file not found
    //   "Failed to generate proof" -- invalid witness / mismatched constants
    console.error('Proof generation failed:', err.message);
    console.error('Make sure you have run ./build.sh --keys-only and provided real JWTs.');
  }
}

// ---------------------------------------------------------------------------
// Run all examples
// ---------------------------------------------------------------------------
examplePoseidonHash();
exampleAnchor();
exampleGenerateProof();
