# Extending Modular Interfaces in AURA

This guide demonstrates how to integrate `@epoch32/aura` with hardware authenticators (WebAuthn PRF via `@epoch32/sigil`), cloud Key Management Services (KMS), and custom edge middleware.

---

## 1. Integrating with WebAuthn PRF (Hardware Passkeys)

To use a user's biometric passkey as the asymmetric trapdoor key:

```typescript
import { Aura } from "@epoch32/aura";
import { Sigil } from "@epoch32/sigil";

// 1. Authenticate user via WebAuthn PRF to derive a 32-byte hardware key
const prfKey = await Sigil.generateSalt();

// 2. Seal sensitive master secret with Passkey Trapdoor.
//    Masked Vault Mode is ON by default — no need to pass masked: true explicitly.
//    Set masked: false only if you cannot supply the prfKey at verify time.
const envelope = await Aura.sealWithTrapdoor(masterPassword, prfKey, {
  memoryCostKb: 8192, // 8 MB memory matrix
  timeCost: 2,
  mode: "hybrid",
});

// 3. Instant verification when user touches biometric authenticator (< 0.5 ms)
const isLegit = await Aura.verify(masterPassword, envelope, prfKey);

// 4. If database is stolen, attacker without prfKey cannot verify (masked mode) or
//    must compute the full 8 MB DAG per guess (unmasked mode).
```

---

## 2. Integrating with Cloudflare Workers & Durable Objects

```typescript
import { Aura, AuraSealedEnvelope, base64UrlToBytes } from "@epoch32/aura";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { password, envelope } = await request.json() as { password: string; envelope: AuraSealedEnvelope };

    // Decode the server KMS key from a base64url-encoded environment variable.
    //
    // DO NOT use: new TextEncoder().encode(env.KMS_SECRET)
    //   → TextEncoder produces ASCII bytes (~6.5 bits/byte), collapsing effective entropy.
    //   → Store KMS_SECRET_B64 as: crypto.getRandomValues(new Uint8Array(32)) → base64url-encode
    //
    // The key must be at least 16 bytes (128 bits); 32 bytes (256 bits) is recommended.
    const serverKmsKey = base64UrlToBytes(env.KMS_SECRET_B64);

    // Fast Path (masked envelope): verifies in ~0.2 ms on Cloudflare Edge Worker
    const isValid = await Aura.verify(password, envelope, serverKmsKey);

    return Response.json({ authenticated: isValid });
  }
};
```

---

## 3. Using `deriveKey` as a Raw KDF

`deriveKey` is the exported raw key derivation primitive, suitable for deriving symmetric encryption keys, HMAC secrets, or other key material from a password:

```typescript
import { Aura, randomBytes } from "@epoch32/aura";

// Salt must be at least 8 bytes; 16 bytes (128 bits) recommended.
// Use randomBytes() to generate a cryptographically secure salt.
const salt = randomBytes(16);

const keyMaterial = await Aura.deriveKey("my-password", salt, {
  memoryCostKb: 4096,
  timeCost: 2,
  outputLength: 32, // up to 64; use HKDF over the result for longer keys
});

// keyMaterial is a 32-byte Uint8Array suitable for AES-256, HMAC-SHA256, etc.
```

> [!IMPORTANT]
> `deriveKey` enforces a minimum salt length of 8 bytes and will throw if a shorter salt is supplied. Store the salt alongside the derived material so verification can reproduce the same output.

---

## 4. Migration & Breaking-Change Notes

The following security fixes introduced **breaking changes** to the hash output. Any credentials hashed before these fixes were applied will produce a different output and **cannot be verified** against the new code:

| Fix | Breaking? | Impact |
| :--- | :--- | :--- |
| `encodeLengthPrefixed` applied to `computeInitialSeed` | ✅ Yes | H0 changes for all inputs → all stored hashes/envelopes are invalidated |
| H0 binding in data-independent address block | ✅ Yes | Memory access pattern changes → all stored hashes/envelopes are invalidated |
| `masked: true` default in `sealWithTrapdoor` | ⚠️ Behaviour | Existing callers not passing `masked` will now produce masked envelopes |
| Salt minimum ≥ 8 bytes enforced in `deriveKey` | ⚠️ Behaviour | Stored hashes with salts < 8 bytes will fail verification (throws → `false`) |
| PHC param bounds enforced in `verify` | Non-breaking | Only rejects crafted/invalid inputs |
| Memory arena zeroed after `execute` | Non-breaking | Output is unchanged; only heap behaviour differs |

**Recommended migration path:** Re-hash all credentials at next successful login using the new code, storing the new PHC string or envelope. Revoke any stored envelopes sealed before the `encodeLengthPrefixed` fix.
