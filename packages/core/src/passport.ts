// packages/core/src/passport.ts
//
// The AgentCred passport: a verifiable transaction passport for AI agents.
//
// A passport is a canonical JSON envelope:
//
//   {
//     "leaf": "<compact JWS task mandate, aud = merchant id>",
//     "leaf_sha256": "<hex sha256 of the leaf JWS string>",
//     "spend": {
//       "actions": ["purchase", ...],      // sorted, unique
//       "amount_limit": 25,               // minor units? No — major units, USD
//       "currency": "USD",
//       "merchant": "merchant:acme.example.invalid"
//     },
//     "v": 1
//   }
//
// The leaf is issued through the audited si-wallet-core mintMandate path, so
// the mandate chain (owner grant → … → agent mandate) carries the signatures,
// scope narrowing, amount limits and expiry. The envelope binds a canonical,
// deterministic presentation of the spend scope to that leaf; verifiers
// require byte-equality with the canonical form and reject anything else.
//
// No PII ever appears in a passport: parties are did:key pseudonyms.

import crypto from "node:crypto";
import {
  WalletError,
  fingerprint,
  mintMandate,
  markLeafJtiConsumed,
  normalizeCurrency,
  unb64uStrict,
  verifyChain,
} from "@tamtunnel/si-wallet-core";
import { canonicalize } from "./canonical.js";
import { SeenJtiStore, defaultStateDir } from "./store.js";
import { RevocationCache } from "./revocation.js";

// ---------------------------------------------------------------- issuance

export const PASSPORT_VERSION = 1;
export const DEFAULT_PASSPORT_TTL_SEC = 900; // 15 minutes
export const MAX_PASSPORT_TTL_SEC = 4 * 3600; // 4 hours, hard cap
export const MIN_PASSPORT_TTL_SEC = 60;

export interface SpendScope {
  actions: string[];
  amount_limit: number;
  currency: string;
  merchant: string;
}

export interface PassportEnvelope {
  leaf: string;
  leaf_sha256: string;
  spend: SpendScope;
  v: number;
}

export interface IssuePassportArgs {
  /** Merchant identifier; becomes the leaf mandate's `aud`. */
  merchant: string;
  amountLimit: number;
  currency?: string;
  /** Allowed actions, e.g. ["purchase"]. Sorted + deduped at issuance. */
  actions: string[];
  /** Seconds until expiry. Default 900, capped at 4h. */
  ttlSec?: number;
  task?: string;
  /** Agency grant JWS backing the issuing agent (owner → agent). */
  grantJws: string;
  confirmOverLimit?: boolean;
  subjectDid?: string | null;
}

export interface IssuedPassport {
  /** Canonical JSON string — this is what travels to the merchant. */
  passport: string;
  envelope: PassportEnvelope;
  agent: string;
  merchant: string;
  expires: string;
}

function sortedUniqueActions(actions: string[] | string): string[] {
  const list = (Array.isArray(actions) ? actions : String(actions || "").split(","))
    .map((s) => s.trim())
    .filter(Boolean);
  if (!list.length) throw new WalletError("at least one action is required", "bad_args");
  return [...new Set(list)].sort();
}

/**
 * Issue a passport: a merchant-scoped, short-lived, signed mandate chain
 * wrapped in a canonical envelope. The spend scope is canonicalized
 * (deterministic key ordering, sorted actions) before it is bound to the
 * signed leaf.
 */
export function issuePassport(args: IssuePassportArgs): IssuedPassport {
  const {
    merchant,
    amountLimit,
    currency = "USD",
    actions,
    ttlSec = DEFAULT_PASSPORT_TTL_SEC,
    task = "",
    grantJws,
    confirmOverLimit = false,
    subjectDid = null,
  } = args;

  if (!merchant || typeof merchant !== "string")
    throw new WalletError("merchant identifier is required", "bad_args");
  if (!/^[a-z0-9][a-z0-9:._-]{1,120}$/i.test(merchant))
    throw new WalletError("merchant identifier has an invalid shape", "bad_args");
  const amount = Number(amountLimit);
  if (!Number.isFinite(amount) || amount < 0)
    throw new WalletError("amountLimit must be a non-negative number", "bad_args");
  const ttl = Math.floor(Number(ttlSec));
  if (!Number.isFinite(ttl) || ttl < MIN_PASSPORT_TTL_SEC || ttl > MAX_PASSPORT_TTL_SEC)
    throw new WalletError(
      `ttlSec must be between ${MIN_PASSPORT_TTL_SEC} and ${MAX_PASSPORT_TTL_SEC}`,
      "bad_args"
    );
  const sortedActions = sortedUniqueActions(actions);
  // Currency is validated and normalized (3-letter ISO 4217, uppercase) at
  // issuance — never accepted as a free-form string — and threaded into the
  // signed leaf mandate, so the envelope can't carry a different one.
  const currencyCode = normalizeCurrency(currency);

  // Canonical spend scope — key order is alphabetical by construction.
  const spend: SpendScope = {
    actions: sortedActions,
    amount_limit: amount,
    currency: currencyCode,
    merchant,
  };
  const spendCanonical = canonicalize(spend); // throws on non-canonicalizable input

  const minted = mintMandate({
    audience: merchant,
    scope: sortedActions,
    amount,
    currency: currencyCode,
    ttlSec: ttl,
    task,
    grantJws,
    confirmOverLimit,
    subjectDid,
  });

  const envelope: PassportEnvelope = {
    leaf: minted.mandate,
    leaf_sha256: crypto.createHash("sha256").update(minted.mandate).digest("hex"),
    spend: JSON.parse(spendCanonical) as SpendScope,
    v: PASSPORT_VERSION,
  };
  const passport = canonicalize(envelope); // byte-canonical envelope
  return { passport, envelope, agent: minted.agent, merchant, expires: minted.expires };
}

/** Decode a passport envelope without verifying signatures. */
export function inspectPassport(passport: string): PassportEnvelope & { chain: unknown[] } {
  const envelope = parseEnvelope(passport);
  const chain: unknown[] = [];
  let token: string | undefined = envelope.leaf;
  for (let depth = 0; depth <= 8 && token; depth++) {
    const payload = decodePayload(token);
    chain.push({
      depth,
      iss: payload.iss,
      iss_fingerprint: fingerprint(String(payload.iss)),
      sub: payload.sub,
      aud: payload.aud,
      jti: payload.jti,
      scope: payload.claims?.scope,
      amount_limit: payload.claims?.amount_limit,
      exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
    });
    token = payload.grant;
    if (payload.aud === "sovereign-identity/agency") break;
  }
  return { ...envelope, chain };
}

// --------------------------------------------------------------- verification

export interface VerifyPolicy {
  /** The merchant's own identifier. The leaf `aud` must equal it exactly. */
  merchantId: string;
  /** Leaf scope must be a subset of these actions. */
  allowedActions?: string[];
  /** Leaf amount_limit must be ≤ this. */
  maxAmount?: number;
  /** Leaf ttl (exp - iat) must be ≤ this many seconds. */
  maxTtlSec?: number;
  /** DIDs permitted to publish revocation lists. Defaults to [root owner]. */
  trustedRevokers?: string[];
  /** State dir for the seen-jti store and revocation cache. */
  stateDir?: string;
  clockSkewSec?: number;
}

export interface VerifyPassportResult {
  ok: boolean;
  reason?: string;
  agent?: string;
  agent_fingerprint?: string;
  owner?: string;
  owner_fingerprint?: string;
  merchant?: string;
  actions?: string[];
  amount_limit?: number;
  currency?: string;
  task?: string;
  expires?: string;
  hops?: number;
}

function parseEnvelope(passport: string): PassportEnvelope {
  if (typeof passport !== "string" || !passport.length)
    throw new WalletError("empty passport", "bad_passport");
  let envelope: PassportEnvelope;
  try {
    envelope = JSON.parse(passport) as PassportEnvelope;
  } catch {
    throw new WalletError("passport is not valid JSON", "bad_passport");
  }
  // Reject non-canonical encodings: the envelope must already be byte-equal
  // to its canonical form. This kills key-reordering / whitespace malleability.
  if (canonicalize(envelope) !== passport) {
    throw new WalletError(
      "passport envelope is not in canonical form",
      "non_canonical"
    );
  }
  if (envelope.v !== PASSPORT_VERSION)
    throw new WalletError(`unsupported passport version ${envelope.v}`, "bad_passport");
  if (typeof envelope.leaf !== "string" || !envelope.leaf)
    throw new WalletError("passport envelope has no leaf mandate", "bad_passport");
  const digest = crypto.createHash("sha256").update(envelope.leaf).digest("hex");
  if (digest !== envelope.leaf_sha256)
    throw new WalletError("leaf_sha256 does not match the leaf mandate", "bad_passport");
  const spend = envelope.spend;
  if (!spend || typeof spend !== "object")
    throw new WalletError("passport envelope has no spend scope", "bad_passport");
  // The spend scope itself must be canonical (sorted keys, sorted actions).
  if (canonicalize(spend) !== JSON.stringify(spend)) {
    // JSON.stringify preserves the parsed key order; canonicalize sorts it.
    // If they differ, the scope object was not canonically encoded.
    throw new WalletError("spend scope is not canonically encoded", "non_canonical");
  }
  return envelope;
}

function decodePayload(jws: string): Record<string, any> {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new WalletError("malformed JWS", "bad_encoding");
  // unb64uStrict rejects non-canonical base64url before we ever parse.
  return JSON.parse(unb64uStrict(parts[1]).toString("utf8"));
}

/**
 * Verify a passport against a merchant policy. Enforces, in order:
 *  1. canonical envelope encoding (reject anything else),
 *  2. leaf binding (sha256) and spend↔leaf consistency — including
 *     spend.currency === the signed leaf's currency claim (fail closed),
 *  3. full chain signature verification via the audited verifyChain,
 *     with `aud` pinned to this merchant on the leaf,
 *  4. scope confinement down the chain: amount ≤ every ancestor's limit,
 *     child exp ≤ parent exp (verifyChain covers amount/scope/expiry;
 *     the exp-narrowing is enforced here),
 *  5. revocation: no presented or ancestor jti on a signed revocation list,
 *  6. merchant policy: actions allowlist, max amount, max ttl,
 *  7. replay: the leaf jti is consumed in the persistent seen-jti store.
 *
 * Consumption happens only after ALL checks pass: verifyChain is told not
 * to burn the leaf jti in the wallet ledger, and both the wallet-ledger
 * mark and the merchant store mark happen at the very end. A passport
 * rejected on policy or revocation is never consumed and can be
 * re-presented (e.g. after the policy is fixed); presenting the same
 * passport twice after success fails closed.
 */
export function verifyPassport(
  passport: string,
  policy: VerifyPolicy
): VerifyPassportResult {
  const fail = (reason: string): VerifyPassportResult => ({ ok: false, reason });
  try {
    if (!policy || !policy.merchantId)
      throw new WalletError("verify policy requires merchantId", "bad_args");
    const envelope = parseEnvelope(passport);
    const spend = envelope.spend;

    // Spend scope must agree with what the merchant expects of itself.
    if (spend.merchant !== policy.merchantId) {
      return fail(
        `passport is for merchant "${spend.merchant}", this merchant is "${policy.merchantId}"`
      );
    }

    // The audited chain verifier: signatures, per-hop expiry, leaf aud
    // binding, scope⊆parent, amount≤parent. consumeLeafJti:false — the
    // wallet-ledger burn happens only after every check below passes, so a
    // passport rejected on policy is never consumed.
    const chained = verifyChain({
      mandateJws: envelope.leaf,
      expectedAudience: policy.merchantId,
      consumeLeafJti: false,
    });
    if (!chained.ok) return fail("mandate chain: " + chained.reason);

    // Walk the raw payloads for exp-narrowing + jti collection. Signatures
    // were already verified above over these exact token strings.
    const payloads: Record<string, any>[] = [];
    {
      let token: string | undefined = envelope.leaf;
      for (let depth = 0; depth <= 8 && token; depth++) {
        const p = decodePayload(token);
        payloads.push(p);
        if (p.aud === "sovereign-identity/agency") break;
        token = p.grant;
      }
    }
    const leafPayload = payloads[0];
    const leafClaims = leafPayload.claims || {};

    // Spend↔leaf consistency: the canonical scope must match the signed leaf.
    if (leafPayload.aud !== spend.merchant)
      return fail("leaf aud does not match envelope spend.merchant");
    if ((leafClaims.amount_limit || 0) !== spend.amount_limit)
      return fail("leaf amount_limit does not match envelope spend scope");
    // Currency binding: the envelope is unsigned canonical JSON, so a
    // rewritten spend.currency would otherwise verify. The signed leaf's
    // currency claim is the authority — mismatch fails closed.
    if (leafClaims.currency !== spend.currency)
      return fail("leaf currency does not match envelope spend currency");
    const leafActions = [...(leafClaims.scope || [])].sort();
    if (JSON.stringify(leafActions) !== JSON.stringify(spend.actions))
      return fail("leaf scope does not match envelope spend actions");

    // Scope confinement down the chain: child exp ≤ parent exp at every hop.
    for (let i = 0; i + 1 < payloads.length; i++) {
      const child = payloads[i];
      const parent = payloads[i + 1];
      if (
        typeof child.exp === "number" &&
        typeof parent.exp === "number" &&
        child.exp > parent.exp
      ) {
        return fail(
          `scope widening: link ${i} expires after its parent (child exp > parent exp)`
        );
      }
    }

    // Revocation: leaf + every ancestor jti checked against signed lists.
    const stateDir = policy.stateDir || defaultStateDir();
    const trustedRevokers = policy.trustedRevokers || [chained.owner!];
    const cache = new RevocationCache({ dir: stateDir, trustedIssuers: trustedRevokers });
    const revoked = cache.revokedJtis((jws) => verifyRevocationJws(jws));
    const jtis = payloads.map((p) => String(p.jti)).filter(Boolean);
    for (const jti of jtis) {
      if (revoked.has(jti)) return fail(`revoked credential: jti ${jti} is on a signed revocation list`);
    }

    // Merchant policy gates.
    if (
      policy.allowedActions &&
      spend.actions.some((a) => !policy.allowedActions!.includes(a))
    ) {
      return fail(`action not allowed by merchant policy: [${spend.actions}]`);
    }
    if (policy.maxAmount !== undefined && spend.amount_limit > policy.maxAmount) {
      return fail(
        `amount ${spend.amount_limit} exceeds merchant policy max ${policy.maxAmount}`
      );
    }
    if (
      policy.maxTtlSec !== undefined &&
      typeof leafPayload.exp === "number" &&
      typeof leafPayload.iat === "number" &&
      leafPayload.exp - leafPayload.iat > policy.maxTtlSec
    ) {
      return fail("passport ttl exceeds merchant policy maximum");
    }

    // Replay: persistent, file-backed, atomic check-and-mark. This is the
    // merchant's durable line of defense. Both marks happen only now, after
    // every check above has passed — nothing is consumed on failure.
    const leafJti = String(leafPayload.jti);
    try {
      markLeafJtiConsumed(leafJti, Number(leafPayload.exp));
    } catch (e) {
      return fail("replay detected: leaf jti already seen in wallet ledger");
    }
    const seen = new SeenJtiStore({ dir: stateDir });
    if (seen.checkAndMark(leafJti, Number(leafPayload.exp))) {
      return fail("replay detected: passport jti already consumed");
    }

    return {
      ok: true,
      agent: chained.agent,
      agent_fingerprint: fingerprint(chained.agent!),
      owner: chained.owner,
      owner_fingerprint: chained.owner_fingerprint,
      merchant: policy.merchantId,
      actions: spend.actions,
      amount_limit: spend.amount_limit,
      currency: spend.currency,
      task: leafClaims.task || "",
      expires: chained.expires,
      hops: chained.hops,
    };
  } catch (e) {
    if (e instanceof WalletError) return fail(e.message);
    return fail("verification error: " + (e as Error).message);
  }
}

// ------------------------------------------------------- revocation helpers

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58decode(str: string): Buffer {
  let n = 0n;
  for (const c of str) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("invalid base58 character");
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  for (const c of str) {
    if (c !== "1") break;
    zeros++;
  }
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(bytes)]);
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function publicKeyFromDid(did: string): crypto.KeyObject {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did || "");
  if (!m) throw new WalletError(`malformed did:key: ${did}`, "bad_did");
  const raw = b58decode(m[1]);
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01)
    throw new WalletError("did:key is not an Ed25519 key", "bad_did");
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw.subarray(2)]),
    format: "der",
    type: "spki",
  });
}

/** Verify a revocation-list JWS and return its payload. Exported for caches. */
export function verifyRevocationJws(jws: string): {
  iss: string;
  iat: number;
  exp: number;
  revoked: string[];
  seq: number;
} {
  const parts = String(jws || "").trim().split(".");
  if (parts.length !== 3) throw new WalletError("malformed revocation JWS", "bad_encoding");
  const [h, p, s] = parts;
  const header = JSON.parse(unb64uStrict(h).toString("utf8"));
  if (header.alg !== "EdDSA") throw new WalletError("unsupported alg in revocation list", "bad_encoding");
  const payload = JSON.parse(unb64uStrict(p).toString("utf8"));
  // Canonical payload required: re-encode and compare bytes.
  if (canonicalize(payload) !== Buffer.from(unb64uStrict(p)).toString("utf8")) {
    throw new WalletError("revocation list payload is not canonical", "non_canonical");
  }
  const iss = String(header.kid || "").split("#")[0];
  if (!iss || payload.iss !== iss)
    throw new WalletError("revocation list iss/kid mismatch", "bad_revocation");
  const ok = crypto.verify(null, Buffer.from(h + "." + p), publicKeyFromDid(iss), unb64uStrict(s));
  if (!ok) throw new WalletError("revocation list signature invalid", "bad_revocation");
  if (!Array.isArray(payload.revoked)) throw new WalletError("revocation list has no revoked array", "bad_revocation");
  return {
    iss: payload.iss,
    iat: Number(payload.iat),
    exp: Number(payload.exp),
    revoked: payload.revoked.map(String),
    seq: Number(payload.seq) || 0,
  };
}
