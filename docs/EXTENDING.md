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

// 2. Seal sensitive master secret with Passkey Trapdoor
const envelope = await Aura.sealWithTrapdoor(masterPassword, prfKey, {
  memoryCostKb: 8192, // 8 MB memory matrix
  timeCost: 2,
  mode: "hybrid",
});

// 3. Instant verification when user touches biometric authenticator (< 0.5 ms)
const isLegit = await Aura.verify(masterPassword, envelope, prfKey);

// 4. If database is stolen, attacker without prfKey is forced to compute 8MB DAG per attempt
```

---

## 2. Integrating with Cloudflare Workers & Durable Objects

```typescript
import { Aura, AuraSealedEnvelope } from "@epoch32/aura";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { password, envelope } = await request.json() as { password: string; envelope: AuraSealedEnvelope };

    // Get Server KMS Key
    const serverKmsKey = new TextEncoder().encode(env.KMS_SECRET);

    // Fast Path O(1): Verifies in ~0.2 ms on Cloudflare Edge Worker
    const isValid = await Aura.verify(password, envelope, serverKmsKey);

    return Response.json({ authenticated: isValid });
  }
};
```
