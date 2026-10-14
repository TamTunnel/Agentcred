// packages/core/src/revocation.ts
//
// Revocation without PKI: the credential issuer publishes a *signed*
// revocation list (a compact EdDSA JWS over { iss, iat, exp, revoked: [jti] }).
// Verifiers cache the list on disk and reject any passport whose leaf jti —
// or any ancestor mandate/grant jti — appears in it.
//
// Trust model: the verifier configures which issuer DIDs may revoke
// (normally the passport's root owner). A list signed by anyone else is
// ignored. Lists carry their own expiry, but expiry is an *enforcement-time*
// policy, not a storage rule: the cache keeps every signature-valid list's
// revoked jtis regardless of expiry, because dropping an expired list would
// silently un-revoke credentials that may still be valid (the old
// "refuse stale lists" behavior caused exactly that history loss).
// Operators must size the CRL lifetime to cover the longest credential it
// can revoke — the default is 366 days, matching the 365-day grant default.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { WalletError } from "@tamtunnel/si-wallet-core";
import { canonicalize } from "./canonical.js";
import { defaultStateDir } from "./store.js";
import { withFileLock } from "./lock.js";

export interface RevocationListPayload {
  iss: string; // issuer DID (the owner who may revoke)
  iat: number; // issued-at, epoch seconds
  exp: number; // list expiry, epoch seconds
  revoked: string[]; // revoked jti values
  seq: number; // monotonic sequence; higher wins on merge
}

/**
 * Default CRL lifetime. A revocation list must outlive every credential it
 * can revoke: grants default to 365 days, so the CRL defaults to 366.
 * Passing a shorter ttlDays emits a loud warning (see appendRevocation).
 */
export const DEFAULT_REVOKE_TTL_DAYS = 366;
/** Warn when a CRL lives shorter than this many days. */
export const MIN_REVOKE_TTL_DAYS = 366;

const b64u = (v: string | Buffer): string =>
  (Buffer.isBuffer(v) ? v : Buffer.from(v, "utf8")).toString("base64url");

/**
 * Sign a revocation list. Needs the issuer's private key — in practice this
 * runs inside the MCP `revoke` tool or CLI, where the wallet keystore holds it.
 */
export function signRevocationList(
  payload: RevocationListPayload,
  privateKey: crypto.KeyObject,
  kid: string
): string {
  const h = b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid }));
  const p = b64u(canonicalize(payload));
  const sig = crypto.sign(null, Buffer.from(h + "." + p), privateKey);
  return `${h}.${p}.${b64u(sig)}`;
}

export interface RevocationCacheOptions {
  dir?: string;
  /** DIDs allowed to publish revocation lists. Empty = trust none. */
  trustedIssuers?: string[];
}

interface CachedEntry {
  jws: string;
  fetchedAt: number;
}

/**
 * Disk-cached, signature-verified revocation list store.
 * Layout: <dir>/revocation.json -> { "<iss>": { jws, fetchedAt } }
 */
export class RevocationCache {
  private file: string;
  private trustedIssuers: Set<string>;

  constructor(opts: RevocationCacheOptions = {}) {
    const dir = opts.dir || path.join(defaultStateDir(), "merchant");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = path.join(dir, "revocation.json");
    this.trustedIssuers = new Set(opts.trustedIssuers || []);
  }

  setTrustedIssuers(issuers: string[]): void {
    this.trustedIssuers = new Set(issuers);
  }

  private loadAll(): Record<string, CachedEntry> {
    try {
      return JSON.parse(fs.readFileSync(this.file, "utf8"));
    } catch {
      return {};
    }
  }

  private saveAll(all: Record<string, CachedEntry>): void {
    const tmp = this.file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(all), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  /**
   * Store a fetched revocation list after verifying its signature and that
   * its issuer is trusted. Returns the parsed payload. Throws on any failure.
   *
   * A signature-valid list is stored even when expired: storage keeps
   * history, enforcement decides freshness (see listInfo). Only the sequence
   * number can refuse a store — never downgrade.
   */
  ingest(jws: string, verifySignature: (jws: string) => RevocationListPayload): RevocationListPayload {
    const payload = verifySignature(jws);
    if (!this.trustedIssuers.has(payload.iss)) {
      throw new WalletError(`revocation list issuer not trusted: ${payload.iss}`, "untrusted_revoker");
    }
    const now = Math.floor(Date.now() / 1000);
    const all = this.loadAll();
    const prev = all[payload.iss];
    if (prev) {
      // Only replace with a newer sequence; never downgrade. And only a
      // previous list from the SAME issuer counts: a planted entry (file
      // key matches but payload.iss doesn't) can neither contribute its
      // sequence nor block the real issuer's update.
      try {
        const prevPayload = verifySignature(prev.jws);
        if (prevPayload.iss === payload.iss && payload.seq <= prevPayload.seq)
          return prevPayload;
      } catch {
        /* corrupt cache entry: replace it */
      }
    }
    all[payload.iss] = { jws, fetchedAt: now };
    this.saveAll(all);
    return payload;
  }

  /**
   * Freshness of the cached list for one issuer — the enforcement-time half
   * of the expiry policy. Storage (revokedJtis) deliberately ignores this;
   * callers that want "refuse stale lists" semantics check `fresh` here.
   */
  listInfo(
    iss: string,
    verifySignature: (jws: string) => RevocationListPayload
  ): { seq: number; iat: number; exp: number; fresh: boolean } | null {
    const entry = this.loadAll()[iss];
    if (!entry) return null;
    try {
      const payload = verifySignature(entry.jws);
      // The file key is attacker-controlled storage: trust only the
      // signature-verified issuer, and reject key/payload mismatches.
      // A planted entry (someone else's CRL stored under this key) yields
      // no info rather than poisoning enforcement.
      if (payload.iss !== iss) return null;
      if (!this.trustedIssuers.has(payload.iss)) return null;
      const now = Math.floor(Date.now() / 1000);
      return {
        seq: payload.seq,
        iat: payload.iat,
        exp: payload.exp,
        fresh: payload.exp > now,
      };
    } catch {
      return null; // corrupt entry: no usable info
    }
  }

  /**
   * All revoked jtis from signature-valid cached lists of trusted issuers —
   * regardless of list expiry. A revoked jti stays revoked until a newer
   * list says otherwise; an expired list never silently un-revokes history.
   *
   * Trust is anchored on the SIGNATURE-VERIFIED payload.iss, never the file
   * key: revocation.json is local storage an attacker can plant entries in,
   * so an entry whose verified issuer is untrusted — or whose file key does
   * not match the verified issuer — is ignored instead of being honored.
   */
  revokedJtis(verifySignature: (jws: string) => RevocationListPayload): Set<string> {
    const out = new Set<string>();
    const all = this.loadAll();
    for (const [fileKey, entry] of Object.entries(all)) {
      try {
        const payload = verifySignature(entry.jws);
        if (payload.iss !== fileKey) continue; // planted/misfiled entry
        if (!this.trustedIssuers.has(payload.iss)) continue;
        for (const jti of payload.revoked || []) out.add(jti);
      } catch {
        continue; // corrupt entry: ignore, never fail open
      }
    }
    return out;
  }
}

export interface AppendRevocationArgs {
  /** State dir holding revocation.json (same `dir` RevocationCache uses). */
  dir: string;
  /** The jti to revoke (leaf passport or ancestor grant). */
  jti: string;
  /** CRL lifetime in days. Default 366; shorter values warn loudly. */
  ttlDays?: number;
  /** Issuer DID signing the list. */
  issuerDid: string;
  /** Sign the merged payload. Keeps raw key material out of core. */
  sign: (payload: RevocationListPayload) => string;
  /** Signature verification for the cached list. */
  verifySignature: (jws: string) => RevocationListPayload;
  /** Warning sink. Default console.warn. */
  warn?: (msg: string) => void;
}

export interface AppendRevocationResult {
  ok: true;
  revoked: string;
  issuer: string;
  total: number;
  seq: number;
}

/**
 * Append one jti to the issuer's signed revocation list — the single shared
 * implementation used by both the MCP `revoke` tool and the CLI `revoke`
 * command.
 *
 * The whole read-merge-sign-ingest runs under a crash-safe file lock, and
 * the cached list is *re-read after the lock is acquired*, so two concurrent
 * revokes serialize: the loser sees the winner's seq and retries with
 * seq+1 instead of silently overwriting it (the old code's loser ingest
 * was a no-op that still returned ok:true).
 *
 * Merge keeps the previous list's revoked jtis even when that list is
 * expired — storage never drops history; expiry is an enforcement-time
 * concern. ttlDays below MIN_REVOKE_TTL_DAYS emits a loud warning because
 * the CRL would stop covering credentials that are still valid.
 */
export function appendRevocation(args: AppendRevocationArgs): AppendRevocationResult {
  const {
    dir,
    jti,
    ttlDays = DEFAULT_REVOKE_TTL_DAYS,
    issuerDid,
    sign,
    verifySignature,
    warn = (m: string) => console.warn(m),
  } = args;
  if (!jti || typeof jti !== "string")
    throw new WalletError("jti is required", "bad_args");
  if (!issuerDid || typeof issuerDid !== "string")
    throw new WalletError("issuerDid is required", "bad_args");
  const ttl = Number(ttlDays);
  if (!Number.isFinite(ttl) || ttl <= 0)
    throw new WalletError("ttlDays must be a positive number", "bad_args");
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  if (ttl < MIN_REVOKE_TTL_DAYS) {
    warn(
      `WARNING: revocation list ttl ${ttl} day(s) is shorter than ${MIN_REVOKE_TTL_DAYS} days. ` +
        `Revocations may expire while the revoked credentials (grants up to 365 days) are still valid. ` +
        `Prefer ttlDays >= ${MIN_REVOKE_TTL_DAYS}.`
    );
  }

  return withFileLock(path.join(dir, "revocation.lock"), () => {
    const file = path.join(dir, "revocation.json");
    let prevRevoked: string[] = [];
    let prevSeq = 0;
    try {
      const all = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, CachedEntry>;
      const entry = all[issuerDid];
      if (entry) {
        // Signature-valid, regardless of expiry: history is never dropped.
        const prev = verifySignature(entry.jws);
        if (prev.iss === issuerDid) {
          prevRevoked = (prev.revoked || []).map(String);
          prevSeq = Number(prev.seq) || 0;
        }
      }
    } catch {
      /* no usable cached list: start fresh */
    }

    const now = Math.floor(Date.now() / 1000);
    const revoked = [...new Set([...prevRevoked, jti])].sort();
    const seq = prevSeq + 1;
    const payload: RevocationListPayload = {
      iss: issuerDid,
      iat: now,
      exp: now + Math.floor(ttl * 86400),
      revoked,
      seq,
    };
    const jws = sign(payload);

    // Re-verify what we are about to store (paranoia: sign callbacks are
    // caller-supplied), then write the cache entry directly — still inside
    // the lock, so no interleave is possible.
    const stored = verifySignature(jws);
    if (stored.iss !== issuerDid || stored.seq !== seq) {
      throw new WalletError("signed revocation payload does not match", "bad_revocation");
    }
    let all: Record<string, CachedEntry> = {};
    try {
      all = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      all = {};
    }
    all[issuerDid] = { jws, fetchedAt: now };
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(all), { mode: 0o600 });
    fs.renameSync(tmp, file);

    return { ok: true as const, revoked: jti, issuer: issuerDid, total: revoked.length, seq };
  });
}
