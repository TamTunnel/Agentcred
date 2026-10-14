# AgentCred — a verifiable transaction passport for AI agents

**[▶ Live demo](https://tamtunnel.github.io/Agentcred/)** · [Explainer video](docs/agentcred-demo.mp4) · [Report a vulnerability](#security-reporting)

Today, when an AI agent shows up to buy something, the merchant has two bad options: block the agent outright, or hand it a credit card number and pray. AgentCred is a third option: the agent presents a **signed, merchant-scoped, expiring passport** — a mandate chain from its owner that says *"this agent may spend up to $25 on purchases at this store for the next 15 minutes"* — and the merchant verifies the cryptography instead of trusting the agent.

No card numbers change hands. No PKI, no certificate authorities, no account system. Just Ed25519 signatures, `did:key` pseudonyms, and a short list of checks any merchant can run offline.

## How it works (the 30-second version)

1. **Owner → agent:** You (the owner) issue your agent an *agency grant*: a signed statement like "spend up to $100 on purchases, good for 30 days."
2. **Agent → passport:** For one checkout, the agent mints a *passport*: a short-lived (minutes), merchant-bound (`aud = merchant id`) mandate chained to that grant, wrapped in a canonical JSON envelope. Each delegation may only **narrow** the scope — less money, fewer actions, shorter expiry.
3. **Merchant verifies:** The merchant checks the signatures, the chain, the merchant binding, the currency binding (`spend.currency` must equal the signed leaf's currency), the expiry, the scope narrowing, a signed revocation list, and a **persistent** replay cache — then approves the payment. Presenting the same passport twice fails, even after a merchant restart.

Nothing in the passport identifies a human: parties are `did:key` pseudonyms. There is deliberately no PII to leak.

## Quick start

Prerequisites: Node ≥ 20.

```bash
git clone https://github.com/TamTunnel/agentcred
cd agentcred
npm install
npm run build
npm test
```

Set up identities and issue your first passport:

```bash
export SI_WALLET_PASSPHRASE="a-strong-passphrase"   # keystore encryption
npx agentcred init                                   # owner + agent DIDs
AGENT_DID=$(npx agentcred did --role agent | jq -r .did)

# Owner grants the agent: up to $100 on purchases, 30 days
GRANT=$(npx agentcred grant --agent-did $AGENT_DID --scope purchase --amount-limit 100 | jq -r .grant)
echo "$GRANT" > /tmp/grant.jwt

# Agent mints a passport: $25 at one merchant, 15 minutes
npx agentcred issue --merchant merchant:acme.example.invalid \
  --amount-limit 25 --actions purchase --grant /tmp/grant.jwt --ttl-sec 900 \
  | tee /tmp/passport.json

# Merchant verifies (exit 0 = approved, exit 1 = declined with a reason)
npx agentcred verify --passport /tmp/passport.json --merchant merchant:acme.example.invalid
```

Verify the same file again and watch it fail closed on replay. Present it to a different `--merchant` and watch the `aud` binding bite.

### Merchant integration (Node)

```ts
import { expressMiddleware } from "@tamtunnel/agentcred-merchant";

app.post("/checkout",
  expressMiddleware({
    merchantId: "merchant:acme.example.invalid",
    allowedActions: ["purchase"],
    maxAmount: 50,
    allowedCurrencies: ["USD"],   // reject passports in any other currency, fail closed
    maxTtlSec: 1800,
  }),
  (req, res) => {
    // req.agentcred = { agent, owner, actions, amount_limit, currency, expires, ... }
    // The passport is cryptographically valid here — but that is not enough.
    // A self-issued passport (attacker as their own owner AND agent) verifies
    // ok:true by design: the signatures really do check out. The merchant must
    // bind `owner` to a customer account it recognizes.
    const customer = lookupCustomerByAgentCredOwner(req.agentcred.owner);
    if (!customer) {
      return res.status(402).json({ ok: false, reason: "unknown AgentCred owner" });
    }
    res.json({ ok: true, charged: req.agentcred.amount_limit, currency: req.agentcred.currency });
  });
```

The agent sends `Authorization: Passport <canonical-json>` (or a `passport` field in the JSON body). Fastify and Hono adapters ship in the same package; the core `verifyPassport()` is pure and dependency-free.

#### Merchant integration checklist

`verifyPassport` returning `ok: true` means *the cryptography checks out and the merchant policy passed* — it does **not** mean "charge this card". Before you fulfill:

1. **Check `result.owner` against your customer registry.** Self-issued passports (attacker as their own owner and agent) verify `ok: true` by design — the signatures are real. Only fulfill for owners you recognize, and charge the matching customer account.
2. **Set `allowedCurrencies`.** Without it, any ISO-4217 currency the grant covers verifies. List exactly the currencies you settle in (e.g. `["USD"]`).
3. **Set `allowedActions` and `maxAmount`.** The passport's scope is an upper bound the *agent's owner* chose; your policy is the upper bound *you* chose. Both must hold.
4. **Pin `merchantId`.** The leaf `aud` must equal your identifier exactly — a passport minted for another merchant never verifies here.
5. **Keep the state dir durable.** Replay protection lives in `<stateDir>/seen-jti.json`; an ephemeral state dir re-opens the replay window on every restart.

### MCP server

```bash
npx agentcred-mcp                      # stdio (default)
AGENTCRED_MCP_TOKEN=secret npx agentcred-mcp --http --port 8787   # streamable HTTP
```

Tools: `issue_passport`, `verify_passport`, `inspect_passport`, `revoke`.

## Architecture

```
agentcred/
├── packages/
│   ├── si-wallet-core/      @tamtunnel/si-wallet-core   — audited crypto core (zero deps)
│   ├── core/                @tamtunnel/agentcred-core   — passports, policy, replay store, CRLs
│   ├── merchant/            @tamtunnel/agentcred-merchant — pure verify + Express/Fastify/Hono
│   ├── mcp/                 @tamtunnel/agentcred-mcp    — MCP server (issue/verify/revoke)
│   └── cli/                 @tamtunnel/agentcred-cli    — `agentcred` CLI
├── demo/                    static demo page (published to GitHub Pages)
└── docs/                    explainer video
```

**`@tamtunnel/si-wallet-core`** is the audited cryptographic core, extracted verbatim from si-wallet-mcp's `lib/wallet.mjs`: Ed25519 `did:key` identities, compact EdDSA JWS, scrypt + AES-256-GCM keystore (mode 600), replay ledger, strict canonical base64url. One implementation, no forks, zero runtime dependencies. (AgentCred-era additions, clearly marked in-source: `signJwsWithRole`, a canonical JWS signer for revocation lists; `normalizeCurrency` plus grant denomination and mint-time currency confinement.)

**`@tamtunnel/agentcred-core`** is where the passport lives:

- **Passport envelope** — canonical JSON: `{ leaf, leaf_sha256, spend, v }`. The leaf is a mandate JWS (`aud` = merchant id, short `exp`); `spend` is the canonical spend scope; `leaf_sha256` binds them so the scope can't be transplanted onto another signature. `spend.currency` must equal the signed leaf's currency claim (verified, fail-closed) — the unsigned envelope can't smuggle a different currency past the signature.
- **Canonicalization** — everything signed or compared is canonicalized (sorted keys, no whitespace) before use; non-canonical encodings are rejected outright.
- **Persistent replay store** — file-backed seen-JTI cache (`~/.agentcred/merchant/seen-jti.json`, mode 600, TTL ≥ max passport expiry, atomic check-and-mark). In-memory-only would be a replay hole after every restart.
- **Signed revocation lists** — the issuer publishes an EdDSA-signed CRL (`{ iss, iat, exp, revoked[], seq }`); verifiers cache it on disk, pin the issuer, and never downgrade the sequence number. The cache keeps every signature-valid list's revoked JTIs regardless of list expiry — an expired list never silently un-revokes history (expiry is an enforcement-time policy, checkable via `listInfo()`). The list defaults to a 366-day lifetime so revocations outlive the longest credentials they can revoke (grants default to 365 days); shorter lifetimes emit a loud warning. Concurrent revokes serialize under a crash-safe file lock, so no revocation is ever lost.
- **Policy checks** — `verifyPassport(passport, policy)` enforces merchant allowlists (actions, currencies), max amounts, and max TTLs on top of the cryptographic checks.

**`@tamtunnel/agentcred-merchant`** wraps `verifyPassport` for web frameworks without importing them (zero runtime dependencies).

### The three security decisions

1. **Replay protection with merchant binding.** Every passport carries a `jti` nonce and `aud` = the merchant's identifier, with expiry measured in minutes. The merchant consumes the JTI in a *file-backed* store (TTL ≥ longest accepted expiry) — a restart doesn't reopen the hole. `aud` mismatch is a hard reject.
2. **Scope confinement down the chain.** Each delegation may only narrow: the verifier checks amount ≤ *every* ancestor's limit, actions ⊆ ancestor scope, and child `exp` ≤ parent `exp`. The scope object is canonicalized (deterministic key ordering) before signing, and non-canonical encodings are rejected at every layer (envelope, JWS segments, CRL payloads).
3. **Key hygiene and revocation without PKI.** Agents use ephemeral per-task keys where possible; short-lived mandates are the primary mechanism (15-minute default, 4-hour hard cap); revocation is an issuer-signed list cached by verifiers — no certificate authorities, no OCSP. Passports carry DIDs only, never PII.

## Live demo

**[https://tamtunnel.github.io/Agentcred/](https://tamtunnel.github.io/Agentcred/)** — pure static files, no backend. Issue a passport in your browser (WebCrypto Ed25519, keys never leave the page), watch the merchant verify it step by step, then attack it: replay, wrong merchant, tampered amount, expired passport, non-canonical encoding, and replay-after-merchant-restart. Every attack is blocked with the reason shown.

> **Illustrative only:** the browser demo reimplements the AgentCred crypto profile from scratch in `demo/crypto.js` / `demo/app.js` — it does **not** run the audited `@tamtunnel/agentcred-core` code path, so it can drift from the packages. Treat it as a visual explainer, not a security reference.

Prefer video? [docs/agentcred-demo.mp4](docs/agentcred-demo.mp4) is a narrated screen recording of the same flow (~3 min, 1080p).

## FAQs

**Isn't this just a JWT with extra steps?**
A JWT says *who you are*. A passport says *what this agent may do, where, for how long, on whose authority* — a signed, narrowing delegation chain with merchant binding, replay protection, and revocation, in one envelope a merchant can verify offline.

**Why not just give the agent a virtual credit card?**
Cards are bearer instruments: whoever holds the number can spend anywhere until you notice. A passport is scoped to one merchant, one amount, a few minutes — and it's single-use by construction.

**What stops the agent copying the passport and spending twice?**
The merchant consumes the passport's `jti` on first use in a persistent store. The second presentation fails closed — even after the merchant restarts, because the store is file-backed. Consumption happens only on *successful* verification: a passport rejected on policy, revocation, or any other check is never burned and can be re-presented (e.g. after the policy is fixed).

**What if the owner wants to cancel mid-flight?**
The owner signs a revocation list covering the passport's (or grant's) `jti`. Verifiers cache the list and reject anything on it. Short expiries bound the worst case anyway.

**Do merchants need to call home to TamTunnel?**
No. Verification is fully offline: signatures, chain, policy, replay store, cached CRL. There is no central server.

**Where do the keys live?**
Owner/agent keys live in an encrypted keystore (`~/.sov-id`, scrypt + AES-256-GCM, mode 600), unlocked by `SI_WALLET_PASSPHRASE`. Agents should mint ephemeral per-task keys where possible; the CLI/MCP use the wallet key for signing.

**Why `did:key` instead of a username?**
DIDs are pseudonymous and self-certifying — the identifier *is* the public key, so there's no registry to run or breach. No PII ever enters a passport.

## Packages

| Package | npm | Description |
|---|---|---|
| `@tamtunnel/si-wallet-core` | workspace-local for now | Audited crypto core, zero deps |
| `@tamtunnel/agentcred-core` | workspace-local for now | Passport issuance/verification |
| `@tamtunnel/agentcred-merchant` | workspace-local for now | Merchant SDK + middleware |
| `@tamtunnel/agentcred-mcp` | workspace-local for now | MCP server |
| `@tamtunnel/agentcred-cli` | workspace-local for now | CLI |

> **Publishing note:** no npm publish credentials were available in the build environment, so all five packages are currently workspace-local (`npm install` in this repo wires them up). Publishing `@tamtunnel/si-wallet-core@0.1.0` first, then the rest, is a maintainer step — see [CHANGELOG](#changelog).

## Contributing

Issues and PRs welcome. Ground rules:

- The crypto core (`packages/si-wallet-core`) is **audited code**: behavioral changes need a security rationale in the PR and must keep the test suite green. Don't fork it — extend at the edges.
- New security-sensitive behavior needs tests that fail without the fix (replay, scope, aud binding, canonicalization, revocation, expiry).
- Run `npm run build` and `npm test` before pushing. TypeScript strict, zero runtime deps in `si-wallet-core`/`core`/`merchant`.
- Never commit realistic-looking keys, tokens, or secrets — GitHub secret scanning will block the push. Use obviously-fake placeholders (`REDACTED`, `example.invalid`).

## Security reporting

Found a vulnerability? **Do not open a public issue.** Email the maintainer privately (see the repo's contact info) with a description and, ideally, a failing test. We aim to acknowledge within 48 hours and will credit reporters who want it.

## Changelog

### Unreleased (adversarial judge-gate fixes)

- **Judge BREAK-2 — currency confinement:** `mintMandate` now refuses a leaf currency the backing grant doesn't cover (a USD grant can't mint a EUR leaf; `currency_exceeded`). `issueGrant` accepts a `currency` (default `"USD"`) so grants are explicitly denominated. `VerifyPolicy` gained `allowedCurrencies: string[]` — when set, a passport in any other currency is rejected, fail closed. CLI `verify` gained `--allowed-currencies`; MCP `verify_passport` accepts `allowedCurrencies`.
- **Judge BREAK-1 — revocation cache trust:** `revokedJtis()` and `listInfo()` now anchor trust on the *signature-verified* `payload.iss`, not the `revocation.json` file key, and require file key === `payload.iss`. A planted entry (attacker-signed CRL stored under the owner's key) is ignored instead of honored — no more selective-DoS.
- **Judge N1 — merchant footgun:** the README merchant example now checks `result.owner` against a customer registry (self-issued passports verify `ok:true` by design) and sets `allowedCurrencies`; a new "merchant integration checklist" covers owner, currency, actions/amount/TTL, `merchantId` pinning, and state-dir durability.
- **Judge N6 — `inspectPassport` fail-closed:** returns `{ ok: false, reason }` on garbage instead of throwing, consistent with `verifyPassport`; new `InspectPassportResult` type. CLI `inspect` exits 1 on failure.

### Unreleased (review-gate fixes)

- **Blocker — currency binding:** `verifyPassport` now enforces `spend.currency ===` the signed leaf's currency claim (fail closed); issuance validates/normalizes currency to ISO 4217 and threads it into the signed mandate instead of hardcoding `"USD"`.
- **Major — revocation robustness:** the CRL cache keeps signature-valid lists' JTIs regardless of list expiry (expired lists no longer silently un-revoke); list lifetime defaults to 366 days with a loud warning for shorter values; both `revoke` surfaces share one file-locked `appendRevocation()` with re-read-after-lock, so concurrent revokes never lose one.
- **Minors:** the wallet-ledger JTI burn moved to after all verification checks pass (policy-rejected passports are re-presentable); `SeenJtiStore` uses a null-prototype object + `hasOwnProperty` (no more `"toString"` false positives, `"__proto__"` storable); file locks carry a `{ pid, ts }` stamp and are only broken when provably stale; MCP `verify_passport` accepts `trustedRevokers`; CLI `revoke` gained `--state-dir`; the browser demo is marked illustrative-only; the wallet replay ledger is lock-protected and TTL-pruned; `b64u` typing made honest.

### 0.1.0 (2026-10-13)

- Initial MVP: monorepo with `si-wallet-core`, `agentcred-core`, `agentcred-merchant`, `agentcred-mcp`, `agentcred-cli`.
- Passport envelope (canonical JSON, `leaf` + `leaf_sha256` + `spend`), merchant `aud` binding, 15-minute default / 4-hour max TTL.
- File-backed replay store, signed revocation lists, scope-narrowing chain validation.
- Static demo page + narrated explainer video.
- 68 tests green (`npm test`).

## License

Apache-2.0 — see [LICENSE](LICENSE).
