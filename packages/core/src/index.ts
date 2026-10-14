// packages/core/src/index.ts — @tamtunnel/agentcred-core
//
// Passport issuance/verification, chain validation, policy types.
// Crypto comes from @tamtunnel/si-wallet-core (audited Ed25519 did:key JWS);
// this package adds the AgentCred envelope, canonicalization, the persistent
// replay store, and signed revocation lists.

export {
  issuePassport,
  inspectPassport,
  verifyPassport,
  verifyRevocationJws,
  PASSPORT_VERSION,
  DEFAULT_PASSPORT_TTL_SEC,
  MAX_PASSPORT_TTL_SEC,
  MIN_PASSPORT_TTL_SEC,
} from "./passport.js";
export type {
  SpendScope,
  PassportEnvelope,
  IssuePassportArgs,
  IssuedPassport,
  VerifyPolicy,
  VerifyPassportResult,
} from "./passport.js";

export { canonicalize, parseCanonical } from "./canonical.js";

export { SeenJtiStore, defaultStateDir } from "./store.js";
export type { SeenJtiStoreOptions } from "./store.js";

export {
  RevocationCache,
  signRevocationList,
} from "./revocation.js";
export type {
  RevocationListPayload,
  RevocationCacheOptions,
} from "./revocation.js";

// Re-export the wallet surface agents need for key management.
export {
  WalletError,
  fingerprint,
  onboard,
  getDid,
  issueGrant,
  pairwiseDid,
  signJwsWithRole,
} from "@tamtunnel/si-wallet-core";
