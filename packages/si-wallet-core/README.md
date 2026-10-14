# @tamtunnel/si-wallet-core

The audited crypto core behind AgentCred (and si-wallet-mcp): Ed25519 `did:key` identities, compact EdDSA JWS mandates, scrypt + AES-256-GCM encrypted keystore (files mode 600), replay ledger, strict canonical base64url.

Extracted verbatim from si-wallet-mcp's `lib/wallet.mjs` and ported faithfully to TypeScript. **One audited implementation, no forks.** Zero runtime dependencies.

The single AgentCred-era addition is `signJwsWithRole()` — a canonical-payload JWS signer for revocation lists — clearly marked in-source. Everything else is the port.

> **Publishing note:** no npm credentials were available in the build environment, so this package is currently workspace-local. To publish: `npm publish -w @tamtunnel/si-wallet-core` (needs a token with access to the `@tamtunnel` scope).

## API

- `onboard(role)` / `getDid(role)` — create or fetch the `owner`/`agent` identity
- `issueGrant({ agentDid, scope, amountLimit, ttlDays, note })` — owner → agent agency grant
- `mintMandate({ audience, scope, amount, ttlSec, task, grantJws, confirmOverLimit, subjectDid })` — agent mints a task mandate (amounts over $100 need `confirmOverLimit`)
- `verifyMandate({ mandateJws, expectedAudience })` — website-side verification with replay ledger
- `verifyChain({ mandateJws, expectedAudience })` — multi-hop delegation verification
- `pairwiseDid(audience)` — fresh DID per audience, never reused across sites
- `signJwsWithRole(payload, role)` — canonical JWS with a role identity's key
- `fingerprint(did)`, `unb64uStrict(s)`, `WalletError`

State: `SI_WALLET_DIR` (default `~/.sov-id`); passphrase: `SI_WALLET_PASSPHRASE` (or `SOV_ID_PASSPHRASE`).
