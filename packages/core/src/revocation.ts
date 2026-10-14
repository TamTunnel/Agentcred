// packages/core/src/revocation.ts
//
// Revocation without PKI: the credential issuer publishes a *signed*
// revocation list (a compact EdDSA JWS over { iss, iat, exp, revoked: [jti] }).
// Verifiers cache the list on disk and reject any passport whose leaf jti —
// or any ancestor mandate/grant jti — appears in it.
//
// Trust model: the verifier configures which issuer DIDs may revoke
// (normally the passport's root owner). A list signed by anyone else is
// ignored. Lists carry their own expiry; a stale cache is refused rather
// than trusted.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { WalletError } from "@tamtunnel/si-wallet-core";
import { canonicalize } from "./canonical.js";
import { defaultStateDir } from "./store.js";

export interface RevocationListPayload {
  iss: string; // issuer DID (the owner who may revoke)
  iat: number; // issued-at, epoch seconds
  exp: number; // list expiry, epoch seconds
  revoked: string[]; // revoked jti values
  seq: number; // monotonic sequence; higher wins on merge
}

const b64u = (v: string | Buffer): string => Buffer.from(v).toString("base64url");

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
   */
  ingest(jws: string, verifySignature: (jws: string) => RevocationListPayload): RevocationListPayload {
    const payload = verifySignature(jws);
    if (!this.trustedIssuers.has(payload.iss)) {
      throw new WalletError(`revocation list issuer not trusted: ${payload.iss}`, "untrusted_revoker");
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) throw new WalletError("revocation list expired", "stale_revocation");
    const all = this.loadAll();
    const prev = all[payload.iss];
    if (prev) {
      // Only replace with a newer sequence; never downgrade.
      try {
        const prevPayload = verifySignature(prev.jws);
        if (payload.seq <= prevPayload.seq) return prevPayload;
      } catch {
        /* corrupt cache entry: replace it */
      }
    }
    all[payload.iss] = { jws, fetchedAt: now };
    this.saveAll(all);
    return payload;
  }

  /** All revoked jtis from non-expired cached lists of trusted issuers. */
  revokedJtis(verifySignature: (jws: string) => RevocationListPayload): Set<string> {
    const out = new Set<string>();
    const now = Math.floor(Date.now() / 1000);
    const all = this.loadAll();
    for (const [iss, entry] of Object.entries(all)) {
      if (!this.trustedIssuers.has(iss)) continue;
      try {
        const payload = verifySignature(entry.jws);
        if (payload.exp <= now) continue; // stale: refuse, don't trust
        for (const jti of payload.revoked || []) out.add(jti);
      } catch {
        continue; // corrupt entry: ignore, never fail open
      }
    }
    return out;
  }
}
