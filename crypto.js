// demo/crypto.js — ILLUSTRATIVE ONLY. Pure, DOM-free AgentCred crypto for
// the static demo. This is a from-scratch reimplementation of the crypto
// profile (Ed25519 did:key, compact EdDSA JWS, canonical JSON, strict
// base64url) for WebCrypto — it does NOT run the audited
// @tamtunnel/agentcred-core code path and can drift from the packages.
// Do not treat it as a security reference; see the README demo section.
//
// Implements the same profile as the Node packages: Ed25519 did:key
// identities, compact EdDSA JWS, canonical JSON envelopes, strict base64url.
// Runs on WebCrypto, so it works with zero backend and zero dependencies.

const te = new TextEncoder();
const td = new TextDecoder();

export function b64uEncode(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url decode: rejects bad chars, padding, non-canonical bits. */
export function b64uDecodeStrict(s) {
  if (typeof s !== "string" || s.length === 0 || /[^A-Za-z0-9_-]/.test(s)) {
    throw new Error("not canonical base64url");
  }
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  if (b64uEncode(bytes) !== s) throw new Error("not canonical base64url");
  return bytes;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function b58encode(buf) {
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

/** Canonical JSON: sorted keys, no whitespace. Throws on unserializables. */
export function canonicalize(value) {
  const canon = (v) => {
    if (v === null) return null;
    const t = typeof v;
    if (t === "string" || t === "boolean") return v;
    if (t === "number") {
      if (!Number.isFinite(v)) throw new Error("non-finite number");
      return v;
    }
    if (Array.isArray(v)) return v.map(canon);
    if (t === "object") {
      const out = {};
      for (const k of Object.keys(v).sort()) {
        if (v[k] === undefined) throw new Error("undefined value");
        out[k] = canon(v[k]);
      }
      return out;
    }
    throw new Error("cannot canonicalize " + t);
  };
  return JSON.stringify(canon(value));
}

export async function sha256hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", te.encode(str));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function didKeyFromRaw(raw32) {
  const prefixed = new Uint8Array(34);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(raw32, 2);
  return "did:key:z" + b58encode(prefixed);
}

export async function genDid() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { ...kp, did: didKeyFromRaw(raw) };
}

export async function signJws(payload, privateKey, kid) {
  const h = b64uEncode(te.encode(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid })));
  const p = b64uEncode(te.encode(canonicalize(payload)));
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, te.encode(h + "." + p))
  );
  return `${h}.${p}.${b64uEncode(sig)}`;
}

function rawFromDid(did) {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did || "");
  if (!m) throw new Error("malformed did:key");
  // base58 decode
  let n = 0n;
  for (const c of m[1]) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("invalid base58");
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  for (const c of m[1]) {
    if (c !== "1") break;
    zeros++;
  }
  const raw = new Uint8Array(zeros + bytes.length);
  raw.set(bytes, zeros);
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01)
    throw new Error("did:key is not an Ed25519 key");
  return raw.slice(2);
}

/** Verify a compact EdDSA JWS; returns { header, payload }. Throws on failure. */
export async function verifyJws(jws) {
  const parts = String(jws).split(".");
  if (parts.length !== 3) throw new Error("malformed JWS");
  const [h, p, s] = parts;
  const header = JSON.parse(td.decode(b64uDecodeStrict(h)));
  const payloadBytes = td.decode(b64uDecodeStrict(p));
  const payload = JSON.parse(payloadBytes);
  if (header.alg !== "EdDSA") throw new Error("unsupported alg " + header.alg);
  if (canonicalize(payload) !== payloadBytes)
    throw new Error("payload is not canonically encoded");
  const kidDid = String(header.kid || "").split("#")[0];
  const raw = rawFromDid(kidDid);
  const pub = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  const sig = b64uDecodeStrict(s);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, te.encode(h + "." + p));
  if (!ok) throw new Error("signature invalid");
  return { header, payload, issuerDid: kidDid };
}

export function fingerprint(did) {
  // sync FNV-ish demo fingerprint (display only; Node uses sha256)
  let h1 = 0x811c9dc5;
  for (const c of did) {
    h1 ^= c.charCodeAt(0);
    h1 = Math.imul(h1, 0x01000193) >>> 0;
  }
  return h1.toString(16).padStart(8, "0");
}
