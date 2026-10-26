// packages/si-wallet-core/src/index.ts
//
// @tamtunnel/si-wallet-core — the audited crypto core extracted verbatim from
// si-wallet-mcp's lib/wallet.mjs (598 lines, audited 2026-09-22 through the
// Redteam adversarial harness build discipline).
//
// One audited implementation, no forks: Ed25519 did:key identities, compact
// EdDSA JWS mandates, scrypt + AES-256-GCM encrypted keystore (mode 600),
// replay ledger, strict canonical base64url. Zero runtime dependencies.
//
// State lives in SI_WALLET_DIR (or ~/.sov-id); the passphrase comes from
// SI_WALLET_PASSPHRASE (or SOV_ID_PASSPHRASE).

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Resolved per call (not at import time) so one process can drive several
// independent wallets — e.g. the Owner → Muse → Hermes delegation demo,
// where each party's keystore lives in its own directory.
const stateDir = (): string =>
  process.env.SI_WALLET_DIR || path.join(os.homedir(), ".sov-id");
const pairwiseDir = (): string => path.join(stateDir(), "pairwise");
const grantsDir = (): string => path.join(stateDir(), "grants");
const replayPath = (): string => path.join(stateDir(), "replay.json");
const AGENCY_AUD = "sovereign-identity/agency";
const OVER_LIMIT_USD = 100;
const CLOCK_SKEW_S = 60;

export class WalletError extends Error {
  code: string;
  constructor(message: string, code = "wallet_error") {
    super(message);
    this.code = code;
  }
}

// ------------------------------------------------------------------ base58

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58encode(buf: Buffer): string {
  let n = 0n;
  for (const b of buf) n = (n << 8n) + BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of buf) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s || "1";
}

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

// ------------------------------------------------------------------ DID

function didFromRawPub(raw32: Buffer): string {
  return "did:key:z" + b58encode(Buffer.concat([Buffer.from([0xed, 0x01]), raw32]));
}

function rawPubFromDid(did: string): Buffer {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did || "");
  if (!m) throw new WalletError(`malformed did:key: ${did}`, "bad_did");
  const raw = b58decode(m[1]);
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
    throw new WalletError("did:key is not an Ed25519 key", "bad_did");
  }
  return raw.subarray(2);
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function publicKeyObjFromDid(did: string): crypto.KeyObject {
  const raw = rawPubFromDid(did);
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function fingerprint(did: string): string {
  return crypto.createHash("sha256").update(did).digest("hex").slice(0, 16);
}

// ------------------------------------------------- strict base64url + JWS

const b64u = (v: string | Buffer): string =>
  (Buffer.isBuffer(v) ? v : Buffer.from(v, "utf8")).toString("base64url");

// JWS compact serialization forbids padding and requires canonical encoding
// (unused trailing bits zero). Node's decoder is lenient, so decode,
// re-encode canonically, and require the original string back exactly.
export function unb64uStrict(s: string): Buffer {
  if (typeof s !== "string" || s.length === 0 || /[^A-Za-z0-9_-]/.test(s)) {
    throw new WalletError("not canonical base64url", "bad_encoding");
  }
  const buf = Buffer.from(s, "base64url");
  if (buf.toString("base64url") !== s) {
    throw new WalletError("not canonical base64url", "bad_encoding");
  }
  return buf;
}

interface JwsParts {
  ok: boolean;
  reason?: string;
  header?: Record<string, unknown>;
  payload?: Record<string, any>;
  issuerDid?: string;
}

function signJws(
  payload: Record<string, unknown>,
  privateKeyObj: crypto.KeyObject,
  kid: string
): string {
  const h = b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid }));
  const p = b64u(JSON.stringify(payload));
  const sig = crypto.sign(null, Buffer.from(h + "." + p), privateKeyObj);
  return `${h}.${p}.${b64u(sig)}`;
}

function verifyJwsInner(jws: string, expectedDid?: string): JwsParts {
  const parts = (jws || "").split(".");
  if (parts.length !== 3)
    return { ok: false, reason: "malformed JWS (want 3 parts)" };
  const [h, p, s] = parts;
  let header: Record<string, unknown>;
  let payload: Record<string, any>;
  try {
    header = JSON.parse(unb64uStrict(h).toString("utf8"));
    payload = JSON.parse(unb64uStrict(p).toString("utf8"));
  } catch {
    return { ok: false, reason: "JWS header/payload is not valid base64url JSON" };
  }
  if (header.alg !== "EdDSA")
    return { ok: false, reason: `unsupported alg ${header.alg}` };
  const kidDid = String(header.kid || "").split("#")[0];
  if (expectedDid && kidDid !== expectedDid)
    return { ok: false, reason: "kid does not match expected issuer DID" };
  let pub: crypto.KeyObject;
  try {
    pub = publicKeyObjFromDid(kidDid);
  } catch (e) {
    return { ok: false, reason: "cannot resolve issuer did:key: " + (e as Error).message };
  }
  const sigOk = crypto.verify(null, Buffer.from(h + "." + p), pub, unb64uStrict(s));
  if (!sigOk) return { ok: false, reason: "signature invalid" };
  return { ok: true, header, payload, issuerDid: kidDid };
}

function verifyJws(jws: string, expectedDid?: string): JwsParts {
  try {
    return verifyJwsInner(jws, expectedDid);
  } catch (e) {
    return { ok: false, reason: "verification error: " + (e as Error).message };
  }
}

// ------------------------------------------------------- encrypted keystore

function ensureDirs(): void {
  for (const d of [stateDir(), pairwiseDir(), grantsDir()]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  }
}

const SCRYPT = { N: 16384, r: 8, p: 1 };

interface KeyEnvelope {
  kdf: string;
  N: number;
  r: number;
  p: number;
  salt: string;
  iv: string;
  authTag: string;
  content: string;
}

function encryptPem(pem: string, password: string): KeyEnvelope {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, SCRYPT);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(pem, "utf8"), cipher.final()]);
  return {
    kdf: "scrypt",
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    authTag: cipher.getAuthTag().toString("hex"),
    content: data.toString("hex"),
  };
}

function decryptPem(env: KeyEnvelope, password: string): string {
  const key = crypto.scryptSync(password, Buffer.from(env.salt, "hex"), 32, {
    N: env.N,
    r: env.r,
    p: env.p,
  });
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(env.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(env.authTag, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(env.content, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

function getPassphrase(): string {
  const pw = process.env.SI_WALLET_PASSPHRASE || process.env.SOV_ID_PASSPHRASE;
  if (!pw)
    throw new WalletError(
      "no wallet passphrase: set SI_WALLET_PASSPHRASE",
      "no_passphrase"
    );
  return pw;
}

function identityPath(role: string): string {
  return path.join(stateDir(), `${role}.json`);
}

interface Identity {
  did: string;
  created: string;
  privateKey: crypto.KeyObject;
}

function loadIdentity(role: string): Identity | null {
  const p = identityPath(role);
  if (!fs.existsSync(p)) return null;
  const file = JSON.parse(fs.readFileSync(p, "utf8"));
  const pem = decryptPem(file.key, getPassphrase());
  const privateKey = crypto.createPrivateKey({ key: pem, format: "pem" });
  return { did: file.did, created: file.created, privateKey };
}

function saveIdentity(role: string, did: string, pem: string): void {
  const file = {
    did,
    created: new Date().toISOString(),
    key: encryptPem(pem, getPassphrase()),
  };
  fs.writeFileSync(identityPath(role), JSON.stringify(file, null, 2), {
    mode: 0o600,
  });
}

function loadReplay(): Record<string, number> {
  try {
    return JSON.parse(fs.readFileSync(replayPath(), "utf8"));
  } catch {
    return {};
  }
}

function saveReplay(r: Record<string, number>): void {
  fs.writeFileSync(replayPath(), JSON.stringify(r), { mode: 0o600 });
}

// ------------------------------------------------- replay ledger locking
//
// The wallet replay ledger (SI_WALLET_DIR/replay.json) is a shared file:
// verifyMandate/verifyChain and any concurrent verifier process must not
// last-write-wins each other. A tiny O_CREAT|O_EXCL lock file stamped with
// { pid, ts } serializes read-modify-write; a lock is broken only when
// provably stale (older than 30s), never a fresh one. Entries are pruned by
// TTL on load — a jti whose exp has passed can never be presented again
// (expiry is checked before the ledger), so dropping it is safe and keeps
// the file bounded.

const REPLAY_LOCK_STALE_MS = 30_000;

function replayLockPath(): string {
  return path.join(stateDir(), "replay.lock");
}

function withReplayLock<T>(fn: () => T): T {
  ensureDirs();
  const lockFile = replayLockPath();
  const start = Date.now();
  while (true) {
    let fd: number | null = null;
    try {
      fd = fs.openSync(lockFile, "wx", 0o600);
      fs.writeSync(fd, JSON.stringify({ pid: process.pid, ts: Date.now() }));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    if (fd !== null) {
      try {
        return fn();
      } finally {
        fs.closeSync(fd);
        try {
          fs.unlinkSync(lockFile);
        } catch {
          /* already gone */
        }
      }
    }
    let ageMs = Infinity;
    try {
      const raw = JSON.parse(fs.readFileSync(lockFile, "utf8")) as { ts?: unknown };
      if (typeof raw?.ts === "number") ageMs = Date.now() - raw.ts;
    } catch {
      /* unreadable: treat as stale */
    }
    if (ageMs > REPLAY_LOCK_STALE_MS) {
      try {
        fs.unlinkSync(lockFile);
      } catch {
        /* raced */
      }
      continue;
    }
    if (Date.now() - start > 120_000) {
      throw new WalletError("timed out waiting for the replay ledger lock", "lock_timeout");
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  }
}

/** Load the ledger, dropping entries whose exp has passed (TTL pruning). */
function loadReplayPruned(): Record<string, number> {
  const raw = loadReplay();
  const now = nowSec();
  // Null-prototype: "__proto__" must be a storable ordinary key (plain-object
  // assignment would hit the prototype setter and silently drop it).
  const r: Record<string, number> = Object.create(null);
  let dirty = false;
  for (const [jti, exp] of Object.entries(raw)) {
    if (typeof exp !== "number" || exp <= now) {
      dirty = true;
      continue;
    }
    r[jti] = exp;
  }
  if (dirty) saveReplay(r);
  return r;
}

/**
 * Consume a leaf jti in the wallet replay ledger: throws WalletError
 * ("replay") when already present, otherwise marks it and persists.
 * Lock-protected and TTL-pruned; the single place any caller burns a jti.
 */
export function markLeafJtiConsumed(jti: string, exp: number): void {
  withReplayLock(() => {
    const replay = loadReplayPruned();
    if (Object.prototype.hasOwnProperty.call(replay, jti)) {
      throw new WalletError("replay detected: leaf jti already seen", "replay");
    }
    replay[jti] = exp;
    saveReplay(replay);
  });
}

const nowSec = (): number => Math.floor(Date.now() / 1000);

// ------------------------------------------------------------------- API

/** Create (or return the existing) owner/agent identity. */
export function onboard(role: string): {
  did: string;
  fingerprint: string;
  existing: boolean;
} {
  ensureDirs();
  if (!["owner", "agent"].includes(role))
    throw new WalletError('role must be "owner" or "agent"', "bad_role");
  const p = identityPath(role);
  if (fs.existsSync(p)) {
    const file = JSON.parse(fs.readFileSync(p, "utf8"));
    return { did: file.did, fingerprint: fingerprint(file.did), existing: true };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  const did = didFromRawPub(raw);
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  saveIdentity(role, did, pem);
  return { did, fingerprint: fingerprint(did), existing: false };
}

/** Return the DID for a role. Throws if the identity does not exist. */
export function getDid(role = "agent"): { did: string; fingerprint: string } {
  const p = identityPath(role);
  if (!fs.existsSync(p))
    throw new WalletError(
      `no ${role} identity; call wallet_onboard first`,
      "no_identity"
    );
  const file = JSON.parse(fs.readFileSync(p, "utf8"));
  return { did: file.did, fingerprint: fingerprint(file.did) };
}

export interface IssueGrantArgs {
  agentDid: string;
  scope: string[] | string;
  amountLimit: number;
  ttlDays?: number;
  note?: string;
  /** ISO 4217 3-letter code the grant is denominated in. Default "USD". */
  currency?: string;
}

/**
 * Owner issues an agency grant to an agent DID.
 * { agentDid, scope: string[], amountLimit, ttlDays = 365, note = "", currency = "USD" }
 */
export function issueGrant({
  agentDid,
  scope,
  amountLimit,
  ttlDays = 365,
  note = "",
  currency = "USD",
}: IssueGrantArgs): {
  grant: string;
  owner: string;
  agent: string;
  scope: string[];
  amount_limit: number;
  expires: string;
} {
  ensureDirs();
  if (!agentDid) throw new WalletError("agentDid is required", "bad_args");
  rawPubFromDid(agentDid); // validates
  const scopes = (Array.isArray(scope) ? scope : String(scope || "").split(","))
    .map((s) => s.trim())
    .filter(Boolean);
  if (!scopes.length) throw new WalletError("at least one scope is required", "bad_args");
  const amount = Number(amountLimit);
  if (!Number.isFinite(amount) || amount < 0)
    throw new WalletError("amountLimit must be a non-negative number", "bad_args");
  const owner = loadIdentity("owner");
  if (!owner)
    throw new WalletError("no owner identity; call wallet_onboard first", "no_identity");

  const iat = nowSec();
  const grant = {
    iss: owner.did,
    sub: agentDid,
    aud: AGENCY_AUD,
    iat,
    exp: iat + Math.floor(Number(ttlDays) * 86400),
    jti: crypto.randomUUID(),
    claims: { scope: scopes, amount_limit: amount, currency: normalizeCurrency(currency), note },
  };
  const jws = signJws(grant, owner.privateKey, owner.did + "#key-1");
  const outPath = path.join(grantsDir(), `${grant.jti}.jwt`);
  fs.writeFileSync(outPath, jws, { mode: 0o600 });
  return {
    grant: jws,
    owner: owner.did,
    agent: agentDid,
    scope: scopes,
    amount_limit: amount,
    expires: new Date(grant.exp * 1000).toISOString(),
  };
}

export interface MintMandateArgs {
  audience: string;
  scope: string[] | string;
  amount?: number;
  /** ISO 4217 3-letter code, normalized to uppercase. Default "USD". */
  currency?: string;
  ttlSec?: number;
  task?: string;
  grantJws: string;
  confirmOverLimit?: boolean;
  subjectDid?: string | null;
}

/**
 * Validate + normalize a currency code: 3-letter ISO 4217, uppercase.
 * Rejects anything else — a free-form currency string is a binding hole
 * (see AgentCred Blocker 1: spend.currency must equal the signed leaf's).
 */
export function normalizeCurrency(currency: string | undefined, dflt = "USD"): string {
  const c = String(currency ?? dflt).trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(c)) {
    throw new WalletError(
      `currency must be a 3-letter ISO 4217 code, got ${JSON.stringify(String(currency))}`,
      "bad_args"
    );
  }
  return c;
}

/**
 * Agent mints a task mandate for a website audience, bound to an agency grant.
 * { audience, scope: string[], amount = 0, ttlSec = 3600, task = "",
 *   grantJws, confirmOverLimit = false, subjectDid = null }
 *
 * subjectDid enables delegation: an intermediate agent (e.g. Muse) mints a
 * mandate whose subject is a downstream agent (e.g. Hermes), narrowing scope
 * and amount relative to its own grant. Defaults to the minter's own DID.
 */
export function mintMandate({
  audience,
  scope,
  amount = 0,
  currency = "USD",
  ttlSec = 3600,
  task = "",
  grantJws,
  confirmOverLimit = false,
  subjectDid = null,
}: MintMandateArgs): {
  mandate: string;
  authorizationHeader: string;
  agent: string;
  subject: string;
  audience: string;
  scope: string[];
  amount_limit: number;
  expires: string;
} {
  ensureDirs();
  if (!audience) throw new WalletError("audience is required", "bad_args");
  const scopes = (Array.isArray(scope) ? scope : String(scope || "").split(","))
    .map((s) => s.trim())
    .filter(Boolean);
  if (!scopes.length) throw new WalletError("at least one scope is required", "bad_args");
  const amt = Number(amount) || 0;
  if (amt > OVER_LIMIT_USD && !confirmOverLimit) {
    throw new WalletError(
      `REFUSED: amount $${amt} exceeds $${OVER_LIMIT_USD} consent limit. ` +
        `Re-call with confirmOverLimit=true only after the owner explicitly approved.`,
      "over_limit"
    );
  }
  if (!grantJws) throw new WalletError("grantJws is required", "bad_args");
  const agent = loadIdentity("agent");
  if (!agent)
    throw new WalletError("no agent identity; call wallet_onboard first", "no_identity");
  const subject = subjectDid || agent.did;
  if (subjectDid) rawPubFromDid(subjectDid); // validates

  const g = verifyJws(String(grantJws).trim());
  if (!g.ok) throw new WalletError("agency grant failed verification: " + g.reason, "bad_grant");
  if (g.payload!.sub !== agent.did)
    throw new WalletError("agency grant is not issued to this agent DID", "bad_grant");
  const overScope = scopes.filter((s) => !((g.payload!.claims.scope as string[]) || []).includes(s));
  if (overScope.length)
    throw new WalletError(`scope [${overScope}] exceeds agency grant scope`, "scope_exceeded");
  if (amt > ((g.payload!.claims.amount_limit as number) || 0))
    throw new WalletError(
      `amount $${amt} exceeds grant limit $${g.payload!.claims.amount_limit}`,
      "amount_exceeded"
    );
  // Currency confinement: a grant denominated in one currency cannot mint a
  // leaf in another. Like scope and amount, currency only narrows down the
  // chain. Grants minted before the currency claim default to USD.
  const leafCurrency = normalizeCurrency(currency);
  const grantCurrency = normalizeCurrency(
    String((g.payload!.claims.currency as string | undefined) ?? "USD")
  );
  if (leafCurrency !== grantCurrency)
    throw new WalletError(
      `currency ${leafCurrency} is not covered by the grant's currency ${grantCurrency}`,
      "currency_exceeded"
    );

  const iat = nowSec();
  const mandate = {
    iss: agent.did,
    sub: subject,
    aud: audience,
    iat,
    exp: iat + Math.floor(Number(ttlSec) || 3600),
    jti: crypto.randomUUID(),
    claims: { task, scope: scopes, amount_limit: amt, currency: leafCurrency },
    grant: String(grantJws).trim(),
  };
  const jws = signJws(mandate, agent.privateKey, agent.did + "#key-1");
  return {
    mandate: jws,
    authorizationHeader: `Mandate ${jws}`,
    agent: agent.did,
    subject,
    audience,
    scope: scopes,
    amount_limit: amt,
    expires: new Date(mandate.exp * 1000).toISOString(),
  };
}

export interface VerifyMandateResult {
  ok: boolean;
  reason?: string;
  agent?: string;
  agent_fingerprint?: string;
  owner?: string;
  owner_fingerprint?: string;
  aud?: string;
  scope?: string[];
  amount_limit?: number;
  task?: string;
  expires?: string;
}

/**
 * Verify a task mandate chain (the website-side checks). Records the JTI in
 * the local replay ledger on success.
 * { mandateJws, expectedAudience = null }
 */
export function verifyMandate({
  mandateJws,
  expectedAudience = null,
}: {
  mandateJws: string;
  expectedAudience?: string | null;
}): VerifyMandateResult {
  ensureDirs();
  const fail = (reason: string): VerifyMandateResult => ({ ok: false, reason });
  const token = String(mandateJws || "").trim();

  const m = verifyJws(token);
  if (!m.ok) return fail("task mandate: " + m.reason);
  const p = m.payload!;
  // Kid/issuer binding (C1): the signature is verified against the JWS kid's
  // key, so the payload's iss must be that same DID — otherwise anyone can
  // sign with their own key and claim to be any victim DID.
  if (m.issuerDid !== p.iss)
    return fail("task mandate JWS kid does not match mandate iss (kid/issuer binding)");
  const now = nowSec();

  if (typeof p.exp !== "number" || p.exp <= now) return fail("task mandate expired");
  if (typeof p.iat === "number" && p.iat > now + CLOCK_SKEW_S)
    return fail("task mandate issued in the future");
  if (expectedAudience && p.aud !== expectedAudience)
    return fail(`audience mismatch: mandate for "${p.aud}", expected "${expectedAudience}"`);

  if (!p.grant) return fail("task mandate carries no agency grant");
  const g = verifyJws(p.grant);
  if (!g.ok) return fail("agency grant: " + g.reason);
  const gp = g.payload!;
  if (g.issuerDid !== gp.iss)
    return fail("agency grant JWS kid does not match grant iss (kid/issuer binding)");
  if (gp.aud !== AGENCY_AUD) return fail("agency grant has wrong audience");
  if (typeof gp.exp !== "number" || gp.exp <= now) return fail("agency grant expired");
  if (gp.sub !== p.iss) return fail("agency grant was not issued to the mandate signer");

  const claims = p.claims || {};
  const gclaims = gp.claims || {};
  const overScope = (claims.scope || []).filter(
    (s: string) => !((gclaims.scope as string[]) || []).includes(s)
  );
  if (overScope.length) return fail(`scope exceeds grant: [${overScope}]`);
  if ((claims.amount_limit || 0) > (gclaims.amount_limit || 0))
    return fail("amount exceeds grant limit");

  // Consume the jti only after every check has passed, atomically under the
  // ledger lock (locked read-modify-write + TTL pruning).
  try {
    markLeafJtiConsumed(String(p.jti), p.exp);
  } catch (e) {
    return fail((e as Error).message);
  }

  return {
    ok: true,
    agent: p.iss,
    agent_fingerprint: fingerprint(p.iss),
    owner: gp.iss,
    owner_fingerprint: fingerprint(gp.iss),
    aud: p.aud,
    scope: claims.scope || [],
    amount_limit: claims.amount_limit || 0,
    task: claims.task || "",
    expires: new Date(p.exp * 1000).toISOString(),
  };
}

export interface ChainLink {
  issuer: string;
  issuer_fingerprint: string;
  subject: string;
  aud: string;
  scope: string[];
  amount_limit: number;
  task?: string;
  agency_grant?: boolean;
  expires: string;
}

export interface VerifyChainResult {
  ok: boolean;
  reason?: string;
  hops?: number;
  agent?: string;
  owner?: string;
  owner_fingerprint?: string;
  aud?: string;
  scope?: string[];
  amount_limit?: number;
  task?: string;
  expires?: string;
  chain?: ChainLink[];
}

/**
 * Verify a multi-hop delegation chain: Owner → … → leaf agent → website.
 *
 * Each link is a mandate whose `grant` field embeds its parent; the root
 * parent is the owner's agency grant (aud "sovereign-identity/agency").
 * At every hop the verifier enforces: parent signature, parent issued to
 * this link's signer, scope subset, amount ≤ parent limit, expiry. The
 * expected audience is enforced on the leaf only; intermediates may target
 * the same audience (task-scoped delegation) or omit the check.
 * Replay protection applies to the presented (leaf) token only: parent
 * mandates and the root agency grant are reusable authority while valid,
 * so one long-lived grant can back many distinct task mandates.
 *
 * Consumption semantics: by default (`consumeLeafJti: true`) the leaf jti is
 * burned in the wallet replay ledger when — and only when — the whole chain
 * verifies. Pass `consumeLeafJti: false` when an outer verifier (e.g.
 * AgentCred's verifyPassport) must run further checks (revocation, merchant
 * policy, its own replay store) first; it then calls markLeafJtiConsumed()
 * itself only after everything passes, so a passport rejected on policy is
 * never burned and can be re-presented.
 * { mandateJws, expectedAudience = null, consumeLeafJti = true }
 */
export function verifyChain({
  mandateJws,
  expectedAudience = null,
  consumeLeafJti = true,
}: {
  mandateJws: string;
  expectedAudience?: string | null;
  consumeLeafJti?: boolean;
}): VerifyChainResult {
  ensureDirs();
  const fail = (reason: string): VerifyChainResult => ({ ok: false, reason });
  const now = nowSec();
  const chain: ChainLink[] = [];
  let leafJti = "";
  let leafExp = 0;

  let token = String(mandateJws || "").trim();
  let expectAud: string | null = expectedAudience;
  for (let depth = 0; depth <= 8; depth++) {
    const m = verifyJws(token);
    if (!m.ok) return fail(`link ${depth}: ${m.reason}`);
    const p = m.payload!;
    if (m.issuerDid !== p.iss)
      return fail(`link ${depth}: JWS kid does not match link iss (kid/issuer binding)`);
    if (typeof p.exp !== "number" || p.exp <= now)
      return fail(`link ${depth}: expired`);
    if (typeof p.iat === "number" && p.iat > now + CLOCK_SKEW_S)
      return fail(`link ${depth}: issued in the future`);
    if (expectAud && p.aud !== expectAud)
      return fail(
        `link ${depth}: audience mismatch (for "${p.aud}", expected "${expectAud}")`
      );
    if (depth === 0) {
      leafJti = String(p.jti);
      leafExp = p.exp;
    }
    if (!p.grant) return fail(`link ${depth}: carries no parent grant/mandate`);

    const g = verifyJws(p.grant);
    if (!g.ok) return fail(`link ${depth}: parent: ${g.reason}`);
    const gp = g.payload!;
    if (g.issuerDid !== gp.iss)
      return fail(`link ${depth}: parent JWS kid does not match parent iss (kid/issuer binding)`);
    if (typeof gp.exp !== "number" || gp.exp <= now)
      return fail(`link ${depth}: parent expired`);
    if (gp.sub !== p.iss)
      return fail(`link ${depth}: parent was not issued to this link's signer`);
    const claims = p.claims || {};
    const gclaims = gp.claims || {};
    const overScope = (claims.scope || []).filter(
      (s: string) => !((gclaims.scope as string[]) || []).includes(s)
    );
    if (overScope.length)
      return fail(`link ${depth}: scope exceeds parent: [${overScope}]`);
    if ((claims.amount_limit || 0) > (gclaims.amount_limit || 0))
      return fail(`link ${depth}: amount exceeds parent limit`);

    chain.push({
      issuer: p.iss,
      issuer_fingerprint: fingerprint(p.iss),
      subject: p.sub,
      aud: p.aud,
      scope: claims.scope || [],
      amount_limit: claims.amount_limit || 0,
      task: claims.task || "",
      expires: new Date(p.exp * 1000).toISOString(),
    });

    if (gp.aud === AGENCY_AUD) {
      // Root: the owner's agency grant. Reusable authority — not consumed.
      chain.push({
        issuer: gp.iss,
        issuer_fingerprint: fingerprint(gp.iss),
        subject: gp.sub,
        aud: gp.aud,
        scope: (gclaims.scope as string[]) || [],
        amount_limit: (gclaims.amount_limit as number) || 0,
        agency_grant: true,
        expires: new Date(gp.exp * 1000).toISOString(),
      });
      // Burn the leaf jti only after the full chain verified — and only when
      // the caller wants verifyChain to own consumption (verifyPassport
      // defers it until revocation/policy/replay checks pass).
      if (consumeLeafJti) {
        try {
          markLeafJtiConsumed(leafJti, leafExp);
        } catch (e) {
          return fail((e as Error).message);
        }
      }
      const leaf = chain[0];
      const root = chain[chain.length - 1];
      return {
        ok: true,
        hops: chain.length - 1,
        agent: leaf.issuer,
        owner: root.issuer,
        owner_fingerprint: root.issuer_fingerprint,
        aud: leaf.aud,
        scope: leaf.scope,
        amount_limit: leaf.amount_limit,
        task: leaf.task,
        expires: leaf.expires,
        chain,
      };
    }
    // Parent is itself a mandate: descend one hop.
    token = p.grant;
    expectAud = null;
  }
  return fail("delegation chain too deep (max 8 links)");
}

/** Create a pairwise DID for one audience (never reuse across sites). */
export function pairwiseDid(audience: string): {
  did: string;
  fingerprint: string;
  audience: string;
} {
  ensureDirs();
  if (!audience) throw new WalletError("audience is required", "bad_args");
  getPassphrase(); // fail fast if no passphrase configured
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  const did = didFromRawPub(raw);
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const file = {
    did,
    aud: audience,
    created: new Date().toISOString(),
    key: encryptPem(pem, getPassphrase()),
  };
  const outPath = path.join(
    pairwiseDir(),
    String(audience).replace(/[^a-z0-9.-]/gi, "_") + ".json"
  );
  fs.writeFileSync(outPath, JSON.stringify(file, null, 2), { mode: 0o600 });
  return { did, fingerprint: fingerprint(did), audience };
}

// ------------------------------------------------- AgentCred-era addition
//
// signJwsWithRole: sign an arbitrary payload with a role identity's private
// key, using the same compact EdDSA JWS profile as the audited code above
// (kid "<did>#key-1", strict canonical base64url segments). The payload is
// canonicalized (sorted keys, no whitespace) before signing so verifiers can
// enforce byte-equality on the encoding.
//
// This is new code added for AgentCred (revocation lists, passport
// envelopes); every pre-existing function above is the faithful port.

function canonicalJson(value: unknown): string {
  const canon = (v: unknown): unknown => {
    if (v === null) return null;
    const t = typeof v;
    if (t === "string" || t === "boolean") return v;
    if (t === "number") {
      if (!Number.isFinite(v as number)) throw new WalletError("non-finite number", "bad_args");
      return v;
    }
    if (Array.isArray(v)) return v.map(canon);
    if (t === "object") {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) {
        out[k] = canon((v as Record<string, unknown>)[k]);
      }
      return out;
    }
    throw new WalletError(`cannot canonicalize ${t}`, "bad_args");
  };
  return JSON.stringify(canon(value));
}

/**
 * Sign an arbitrary canonical payload with the "owner" or "agent" identity.
 * Returns the compact JWS. Throws WalletError when the identity is missing.
 */
export function signJwsWithRole(
  payload: Record<string, unknown>,
  role: "owner" | "agent"
): string {
  ensureDirs();
  const ident = loadIdentity(role);
  if (!ident)
    throw new WalletError(`no ${role} identity; call onboard first`, "no_identity");
  const h = b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: ident.did + "#key-1" }));
  const p = b64u(canonicalJson(payload));
  const sig = crypto.sign(null, Buffer.from(h + "." + p), ident.privateKey);
  return `${h}.${p}.${b64u(sig)}`;
}
