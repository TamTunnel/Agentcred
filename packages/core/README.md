# @tamtunnel/agentcred-core

Passport issuance and verification for AgentCred. Depends on `@tamtunnel/si-wallet-core` for cryptography; adds the passport envelope, canonicalization, the persistent replay store, signed revocation lists, and merchant policy checks. Near-zero runtime dependencies (Node builtins only).

## Passport

```ts
import { issuePassport, verifyPassport } from "@tamtunnel/agentcred-core";

const { passport } = issuePassport({
  merchant: "merchant:acme.example.invalid", // becomes the leaf aud
  amountLimit: 25,
  actions: ["purchase"],
  ttlSec: 900,          // default 15 min, hard cap 4 h
  grantJws,             // owner → agent agency grant
});

const res = verifyPassport(passport, {
  merchantId: "merchant:acme.example.invalid",
  allowedActions: ["purchase"],
  maxAmount: 50,
  allowedCurrencies: ["USD"], // fail closed on any other currency
  maxTtlSec: 1800,
});
// res.ok === true → { agent, owner, actions, amount_limit, expires, ... }
// res.ok === false → { reason }
// NOTE: ok:true is not "charge this card" — bind res.owner to a customer
// account you recognize (self-issued passports verify by design).
```

The envelope is canonical JSON — `{ leaf, leaf_sha256, spend, v }` — and verifiers reject any non-canonical encoding. See the repo README for the full check list.

## Modules

- `passport.ts` — `issuePassport`, `verifyPassport`, `inspectPassport`
- `canonical.ts` — `canonicalize`, `parseCanonical`
- `store.ts` — `SeenJtiStore`: file-backed seen-JTI cache (atomic check-and-mark, TTL pruning)
- `revocation.ts` — `RevocationCache`: disk-cached, signature-verified, issuer-pinned CRLs

State dir: `AGENTCRED_STATE_DIR` (default `~/.agentcred`).
