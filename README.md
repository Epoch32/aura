# Aura (@epoch32/aura)

Zero-dependency, high-performance **Asymmetric Unkeyed-Resistant Algorithm (AURA)** - an Edge-Native Asymmetric Memory-Hard Function (aMHF) & Hybrid KDF for modern browsers, Cloudflare Workers, Bun, Deno, and Node.js.

[![Tests](https://img.shields.io/badge/tests-19%20passing-brightgreen)](#)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

---

## Documentation & Deep Dives

* **[Academic & Cryptographic Research](docs/RESEARCH.md)** - Theoretical lineage, Argon2 comparison, graph-pebbling bounds, and proofs of asymmetry.
* **[Mathematical Specification](docs/MATH.md)** - 2D cross-block permutation algebra, non-uniform quadratic indexing (TMTO defense), ARX address expansion, and Asymmetric Trapdoor equations.
* **[Engine Architecture & Internals](docs/ENGINE.md)** - Execution pipeline, contiguous ArrayBuffer memory layout, WebCrypto acceleration, and security hardening details.
* **[Extending Modular Interfaces](docs/EXTENDING.md)** - Guide for integrating with WebAuthn PRF passkeys, Cloudflare Workers, and KMS systems.

---

## Highlights

- **Zero Dependencies:** Pure TypeScript implementing 32-bit ARX word mixing and memory DAGs natively with `Uint32Array` and `crypto.subtle`.
- **Argon2id-Style Hybrid Memory Hardness:** Combines **Phase 1 Data-Independent access** (side-channel immune) with **Phase 2 Data-Dependent access** (GPU/ASIC memory bandwidth bound).
- **2D Cross-Block Permutation:** Complete row and column diffusion across all 1024 bytes of each block, defeating divide-and-conquer / bit-slice GPU attacks.
- **Quadratic Index Biasing (TMTO Defense):** Quadratic window mapping heavily biases lookups towards recent blocks, defeating Time-Memory Trade-Off graph-pebbling shortcuts. Address block indexing is bound to the password via H0, preventing precomputed traversal graphs.
- **Asymmetric Trapdoor Shortcut:** Legitimate users holding a passkey PRF key or server KMS key verify in **$< 0.5\text{ ms}$ ($O(1)$)**, while offline attackers are forced to compute the full multi-megabyte memory DAG per attempt.
- **Masked Vault Mode (default):** HKDF keystream blinding that renders offline dictionary verification mathematically impossible without the hardware key. Enabled by default in `sealWithTrapdoor`.
- **Hardened Input Validation:** Enforces minimum salt lengths, bounds PHC parameter values, validates base64url and hex character alphabets, and wipes the memory arena after use.
- **Edge-Ready Performance:** Sub-millisecond cold start (<5ms) with zero WASM blobs or heavy native OpenSSL/Blake2b C bindings.

---

## Installation

```bash
# Bun (via GitHub)
bun add github:epoch32/aura

# npm (via GitHub)
npm install github:epoch32/aura

# pnpm (via GitHub)
pnpm add github:epoch32/aura
```

---

## Performance Benchmark

Verified in the automated test suite (`bun test`):

| Actor | Mode | Key Access | Verification Path | Time |
| :--- | :--- | :--- | :--- | :--- |
| **Legitimate User** | Masked (default) | Hardware Passkey (PRF) | O(1) HMAC anchor check — no MHF | **`< 1 ms`** |
| **Legitimate User** | Unmasked | Hardware Passkey (PRF) | Full MHF re-derivation + HMAC | **`~30–60 ms`** |
| **Offline Attacker** | Masked (default) | None | Blocked — `dagOutput` is ciphertext, anchor requires K | **Impossible** |
| **Offline Attacker** | Unmasked | None | Full MHF re-derivation per attempt | **`~30–60 ms` + 4–8 MB RAM/attempt** |

> **Masked Vault Mode is enabled by default** in `sealWithTrapdoor`. Set `masked: false` only if the trapdoor key is unavailable at verification time.

---

## Quickstart

### 1. Standard Password Hashing & Verification
```typescript
import { Aura } from "@epoch32/aura";

// Hash password with 4MB memory matrix and 2 passes
const hashResult = await Aura.hash("my-super-secret-password", {
  memoryCostKb: 4096,
  timeCost: 2,
  mode: "hybrid",
});

console.log(hashResult.encoded);
// $aura$v=1$m=4096,t=2,p=1,mode=hybrid$salt$hash

// Verify password
const isValid = await Aura.verify("my-super-secret-password", hashResult.encoded);
console.log("Password valid:", isValid); // true
```

### 2. Asymmetric Trapdoor & Masked Vault Mode
```typescript
import { Aura } from "@epoch32/aura";

// Hardware PRF key derived via @epoch32/sigil or KMS
const passkeyPrfKey = crypto.getRandomValues(new Uint8Array(32));

// Seal password with 8MB memory-hard envelope.
// Masked Vault Mode is ON by default — dagOutput is blinded under passkeyPrfKey.
const envelope = await Aura.sealWithTrapdoor("vault-master-secret", passkeyPrfKey, {
  memoryCostKb: 8192,
  timeCost: 2,
  mode: "hybrid",
});

// Fast Path (with Passkey Key): Verifies in < 0.4 ms
const isFastValid = await Aura.verify("vault-master-secret", envelope, passkeyPrfKey);

// Unkeyed Attack: Completely blocked (returns false immediately)
const isAttackBlocked = await Aura.verify("vault-master-secret", envelope); // false
```

---

## Security & Input Validation

AURA enforces the following constraints at the API boundary:

| Guard | Where enforced | Behavior |
| :--- | :--- | :--- |
| Salt ≥ 8 bytes | `hash()`, `sealWithTrapdoor()`, `deriveKey()` | Throws with a descriptive message |
| PHC params in range (`m` 8–65536, `t` 1–64, `p` 1–16) | `verify()` — PHC and envelope paths | Returns `false` |
| PHC `mode` must be `hybrid`, `independent`, or `dependent` | `verify()` — PHC and envelope paths | Returns `false` |
| Hash / dagOutput base64 length ≤ 64 decoded bytes | `verify()` — PHC and envelope paths | Returns `false` |
| Trapdoor key ≥ 16 bytes | `sealWithTrapdoor()`, `TrapdoorEngine` | Throws with a descriptive message |
| Strict base64url alphabet (A–Z, a–z, 0–9, `-`, `_`) | `base64UrlToBytes()` | Throws on illegal characters |
| Strict hex alphabet (0–9, a–f, A–F) | `hexToBytes()` | Throws on illegal characters |
| Memory arena wiped after derivation | `MemoryDag.execute()` | Buffer zeroed before returning |
| `MemoryDag` single-use guard | `MemoryDag.execute()` | Throws on re-use |

Any exception thrown inside `verify()` is caught internally and returns `false`, so callers always receive a boolean.

---

## License

[Mozilla Public License Version 2.0 (MPL-2.0)](LICENSE)
