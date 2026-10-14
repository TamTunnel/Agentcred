// packages/core/test/passport.test.ts — security-critical passport paths.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { setupTestEnv, type TestEnv } from "./helpers.ts";
import {
  onboard,
  issueGrant,
  issuePassport,
  inspectPassport,
  verifyPassport,
  verifyRevocationJws,
  signJwsWithRole,
  canonicalize,
  WalletError,
  RevocationCache,
  SeenJtiStore,
  getDid,
} from "@tamtunnel/agentcred-core";
import { mintMandate } from "@tamtunnel/si-wallet-core";

let env: TestEnv;
let agentDid: string;
let grantJws: string;
let eurGrantJws: string;
const MERCHANT = "merchant:acme.example.invalid";

before(() => {
  env = setupTestEnv();
  onboard("owner");
  const agent = onboard("agent");
  agentDid = agent.did;
  grantJws = issueGrant({
    agentDid,
    scope: ["purchase", "refund"],
    amountLimit: 100,
    ttlDays: 30,
  }).grant;
  eurGrantJws = issueGrant({
    agentDid,
    scope: ["purchase", "refund"],
    amountLimit: 100,
    ttlDays: 30,
    currency: "EUR",
  }).grant;
});

after(() => env.cleanup());

function issueTestPassport(overrides: Record<string, unknown> = {}) {
  return issuePassport({
    merchant: MERCHANT,
    amountLimit: 25,
    actions: ["purchase"],
    ttlSec: 900,
    task: "buy a widget",
    grantJws,
    ...overrides,
  });
}

function policy(overrides: Record<string, unknown> = {}) {
  return { merchantId: MERCHANT, stateDir: env.stateDir, ...overrides };
}

describe("passport happy path", () => {
  it("issues a canonical envelope and verifies ok", () => {
    const issued = issueTestPassport();
    // Envelope must already be byte-canonical.
    assert.equal(canonicalize(JSON.parse(issued.passport)), issued.passport);
    const res = verifyPassport(issued.passport, policy());
    assert.equal(res.ok, true);
    assert.equal(res.merchant, MERCHANT);
    assert.deepEqual(res.actions, ["purchase"]);
    assert.equal(res.amount_limit, 25);
    assert.equal(res.agent, agentDid);
    assert.ok(res.owner);
  });

  it("inspectPassport decodes the chain without verifying", () => {
    const issued = issueTestPassport();
    const decoded = inspectPassport(issued.passport);
    assert.equal(decoded.ok, true);
    if (!decoded.ok) throw new Error("unreachable");
    assert.equal(decoded.v, 1);
    assert.equal(decoded.spend.merchant, MERCHANT);
    assert.ok(Array.isArray(decoded.chain));
    assert.ok(decoded.chain.length >= 2); // leaf + agency grant
  });
});

describe("replay protection", () => {
  it("rejects the second presentation of the same passport", () => {
    const issued = issueTestPassport();
    const first = verifyPassport(issued.passport, policy());
    assert.equal(first.ok, true);
    const second = verifyPassport(issued.passport, policy());
    assert.equal(second.ok, false);
    assert.match(second.reason || "", /replay/i);
  });

  it("replay survives a merchant restart (new store instance, same dir)", () => {
    const issued = issueTestPassport();
    assert.equal(verifyPassport(issued.passport, policy()).ok, true);
    // Simulate a restart: fresh SeenJtiStore over the same state dir.
    const fresh = new SeenJtiStore({ dir: env.stateDir });
    const leaf = JSON.parse(issued.passport).leaf as string;
    const payload = JSON.parse(
      Buffer.from(leaf.split(".")[1], "base64url").toString("utf8")
    );
    assert.equal(fresh.has(String(payload.jti)), true);
  });
});

describe("merchant (aud) binding", () => {
  it("rejects a passport presented to the wrong merchant", () => {
    const issued = issueTestPassport();
    const res = verifyPassport(issued.passport, policy({ merchantId: "merchant:evil.example.invalid" }));
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /merchant|audience/i);
  });

  it("rejects when the envelope merchant disagrees with the policy merchant", () => {
    const issued = issueTestPassport();
    const res = verifyPassport(
      issued.passport,
      policy({ merchantId: "merchant:other.example.invalid" })
    );
    assert.equal(res.ok, false);
  });
});

describe("canonicalization", () => {
  it("rejects a non-canonical envelope encoding (reordered keys)", () => {
    const issued = issueTestPassport();
    const env2 = JSON.parse(issued.passport);
    // Reorder keys: v first — still valid JSON, no longer canonical.
    const reordered = JSON.stringify({
      v: env2.v,
      spend: env2.spend,
      leaf_sha256: env2.leaf_sha256,
      leaf: env2.leaf,
    });
    const res = verifyPassport(reordered, policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /canonical/i);
  });

  it("rejects an envelope with pretty-printed whitespace", () => {
    const issued = issueTestPassport();
    const pretty = JSON.stringify(JSON.parse(issued.passport), null, 2);
    const res = verifyPassport(pretty, policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /canonical/i);
  });

  it("rejects a non-canonically encoded spend scope", () => {
    const issued = issueTestPassport();
    const parsed = JSON.parse(issued.passport);
    // Swap spend key order inside an otherwise canonical envelope.
    const raw = issued.passport.replace(
      `"spend":{"actions":["purchase"],"amount_limit":25,"currency":"USD","merchant":"${MERCHANT}"}`,
      `"spend":{"merchant":"${MERCHANT}","currency":"USD","amount_limit":25,"actions":["purchase"]}`
    );
    assert.notEqual(raw, issued.passport); // sanity: replacement happened
    void parsed;
    const res = verifyPassport(raw, policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /canonical/i);
  });

  it("rejects non-canonical base64url in the leaf JWS", () => {
    const issued = issueTestPassport();
    const parsed = JSON.parse(issued.passport);
    const parts = (parsed.leaf as string).split(".");
    // Append a redundant-but-decodable tweak is impossible with strict
    // decoding; instead flip the payload to garbage base64url.
    parts[1] = parts[1].slice(0, -2) + "%%";
    parsed.leaf = parts.join(".");
    const res = verifyPassport(JSON.stringify(parsed), policy());
    assert.equal(res.ok, false);
  });

  it("canonicalize() sorts keys deterministically and rejects undefined", () => {
    assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
    assert.equal(
      canonicalize({ z: [{ b: 1, a: 0 }], a: null }),
      '{"a":null,"z":[{"a":0,"b":1}]}'
    );
    assert.throws(() => canonicalize({ a: undefined }), /canonicalize/);
  });
});

describe("tamper resistance", () => {
  it("rejects a tampered leaf signature", () => {
    const issued = issueTestPassport();
    const parsed = JSON.parse(issued.passport);
    const parts = (parsed.leaf as string).split(".");
    const sig = parts[2];
    parts[2] = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    parsed.leaf = parts.join(".");
    parsed.leaf_sha256 = crypto.createHash("sha256").update(parsed.leaf).digest("hex");
    const res = verifyPassport(canonicalize(parsed), policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /signature|mandate chain/i);
  });

  it("rejects a leaf_sha256 mismatch", () => {
    const issued = issueTestPassport();
    const parsed = JSON.parse(issued.passport);
    parsed.leaf_sha256 = "0".repeat(64);
    const res = verifyPassport(canonicalize(parsed), policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /leaf_sha256/);
  });

  it("rejects when the envelope spend amount disagrees with the signed leaf", () => {
    const issued = issueTestPassport();
    const parsed = JSON.parse(issued.passport);
    parsed.spend.amount_limit = 24; // attacker lowers the envelope, not the leaf
    const res = verifyPassport(canonicalize(parsed), policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /spend|leaf/i);
  });

  it("rejects when envelope actions disagree with the signed leaf scope", () => {
    const issued = issueTestPassport();
    const parsed = JSON.parse(issued.passport);
    parsed.spend.actions = ["purchase", "refund"];
    const res = verifyPassport(canonicalize(parsed), policy());
    assert.equal(res.ok, false);
  });
});

describe("scope confinement down the chain", () => {
  it("refuses issuance when actions exceed the grant scope", () => {
    assert.throws(
      () => issueTestPassport({ actions: ["purchase", "wire-transfer"] }),
      (e: unknown) => e instanceof WalletError && /scope/i.test(e.message)
    );
  });

  it("refuses issuance when the amount exceeds the grant limit", () => {
    assert.throws(
      () =>
        issueTestPassport({ amountLimit: 150, confirmOverLimit: true }),
      (e: unknown) => e instanceof WalletError && /exceeds grant limit/i.test(e.message)
    );
  });

  it("enforces the $100 owner-consent gate without confirmation", () => {
    assert.throws(
      () => issueTestPassport({ amountLimit: 150 }),
      (e: unknown) => e instanceof WalletError && e.code === "over_limit"
    );
  });

  it("merchant policy allowedActions rejects unlisted actions", () => {
    const issued = issueTestPassport({ actions: ["refund"] });
    const res = verifyPassport(issued.passport, policy({ allowedActions: ["purchase"] }));
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /not allowed/i);
  });

  it("merchant policy maxAmount rejects an over-limit passport", () => {
    const issued = issueTestPassport({ amountLimit: 25 });
    const res = verifyPassport(issued.passport, policy({ maxAmount: 10 }));
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /exceeds merchant policy max/i);
  });

  it("merchant policy maxTtlSec rejects a long-lived passport", () => {
    const issued = issueTestPassport({ ttlSec: 3600 });
    const res = verifyPassport(issued.passport, policy({ maxTtlSec: 300 }));
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /ttl/i);
  });
});

describe("expiry", () => {
  it("rejects an expired leaf", async () => {
    // Build the leaf directly with a 1s ttl, then wrap it by hand.
    const minted = mintMandate({
      audience: MERCHANT,
      scope: ["purchase"],
      amount: 5,
      ttlSec: 1,
      task: "expiry probe",
      grantJws,
    });
    const spend = { actions: ["purchase"], amount_limit: 5, currency: "USD", merchant: MERCHANT };
    const envelope = {
      leaf: minted.mandate,
      leaf_sha256: crypto.createHash("sha256").update(minted.mandate).digest("hex"),
      spend,
      v: 1,
    };
    const passport = canonicalize(envelope);
    await new Promise((r) => setTimeout(r, 1500));
    const res = verifyPassport(passport, policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /expired/i);
  });

  it("rejects issuance with a ttl outside the allowed window", () => {
    assert.throws(() => issueTestPassport({ ttlSec: 30 }), /ttlSec must be between/);
    assert.throws(() => issueTestPassport({ ttlSec: 99999 }), /ttlSec must be between/);
  });
});

describe("revocation", () => {
  it("rejects a passport whose leaf jti is on the owner's signed CRL", () => {
    const issued = issueTestPassport();
    const leafPayload = JSON.parse(
      Buffer.from(JSON.parse(issued.passport).leaf.split(".")[1], "base64url").toString("utf8")
    );
    const owner = getDid("owner");
    const now = Math.floor(Date.now() / 1000);
    const crl = signJwsWithRole(
      { iss: owner.did, iat: now, exp: now + 86400, revoked: [String(leafPayload.jti)], seq: 1 },
      "owner"
    );
    const cache = new RevocationCache({ dir: env.stateDir, trustedIssuers: [owner.did] });
    cache.ingest(crl, (j) => verifyRevocationJws(j));

    const res = verifyPassport(issued.passport, policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /revoked/i);
  });

  it("ignores a revocation list signed by an untrusted issuer", () => {
    const issued = issueTestPassport();
    const leafPayload = JSON.parse(
      Buffer.from(JSON.parse(issued.passport).leaf.split(".")[1], "base64url").toString("utf8")
    );
    // Attacker mints their own identity in a throwaway wallet and signs a
    // CRL covering our jti. The merchant must ignore it.
    const realEvil = fs.mkdtempSync(path.join(os.tmpdir(), "agentcred-evil-"));
    process.env.SI_WALLET_DIR = realEvil;
    process.env.SI_WALLET_PASSPHRASE = "evil-passphrase-REDACTED";
    onboard("owner");
    const evil = getDid("owner");
    const now = Math.floor(Date.now() / 1000);
    const evilCrl = signJwsWithRole(
      { iss: evil.did, iat: now, exp: now + 86400, revoked: [String(leafPayload.jti)], seq: 1 },
      "owner"
    );
    // Restore the real wallet env.
    process.env.SI_WALLET_DIR = env.walletDir;
    process.env.SI_WALLET_PASSPHRASE = "test-passphrase-REDACTED";

    const cache = new RevocationCache({ dir: env.stateDir, trustedIssuers: [getDid("owner").did] });
    assert.throws(() => cache.ingest(evilCrl, (j) => verifyRevocationJws(j)), /not trusted/);
    fs.rmSync(realEvil, { recursive: true, force: true });

    // And the passport still verifies (fresh jti, no trusted revocation).
    const fresh = issueTestPassport();
    assert.equal(verifyPassport(fresh.passport, policy()).ok, true);
  });

  it("verifyRevocationJws rejects a tampered list", () => {
    const owner = getDid("owner");
    const now = Math.floor(Date.now() / 1000);
    const crl = signJwsWithRole(
      { iss: owner.did, iat: now, exp: now + 86400, revoked: ["aaa"], seq: 1 },
      "owner"
    );
    const parts = crl.split(".");
    parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
    assert.throws(() => verifyRevocationJws(parts.join(".")), /signature invalid/);
  });
});

describe("input validation", () => {
  it("rejects garbage passports fail-closed", () => {
    for (const bad of ["", "not json", "{}", "[]", "null"]) {
      const res = verifyPassport(bad, policy());
      assert.equal(res.ok, false, `expected failure for ${JSON.stringify(bad)}`);
    }
  });

  it("requires merchantId in the policy", () => {
    const issued = issueTestPassport();
    const res = verifyPassport(issued.passport, { merchantId: "", stateDir: env.stateDir });
    assert.equal(res.ok, false);
  });

  it("rejects malformed merchant identifiers at issuance", () => {
    assert.throws(() => issueTestPassport({ merchant: "" }), /merchant identifier is required/);
    assert.throws(
      () => issueTestPassport({ merchant: "https://evil.example.invalid/x" }),
      /invalid shape/
    );
  });
});

describe("currency binding (Blocker 1)", () => {
  it("rejects a passport whose envelope currency was rewritten and re-canonicalized", () => {
    const issued = issueTestPassport();
    const parsed = JSON.parse(issued.passport);
    // Attacker rewrites the unsigned envelope's currency and re-canonicalizes.
    parsed.spend.currency = "JPY";
    const res = verifyPassport(canonicalize(parsed), policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /currency/i);
  });

  it("normalizes currency at issuance and threads it into the signed leaf", () => {
    // A EUR leaf needs a EUR-denominated grant (see BREAK-2 currency confinement).
    const issued = issueTestPassport({ currency: "eur", grantJws: eurGrantJws });
    const parsed = JSON.parse(issued.passport);
    assert.equal(parsed.spend.currency, "EUR");
    const leafPayload = JSON.parse(
      Buffer.from(parsed.leaf.split(".")[1], "base64url").toString("utf8")
    );
    assert.equal(leafPayload.claims.currency, "EUR");
    assert.equal(verifyPassport(issued.passport, policy()).ok, true);
  });

  it("rejects non-ISO-4217 currency strings at issuance", () => {
    assert.throws(() => issueTestPassport({ currency: "USDD" }), /currency/i);
    assert.throws(() => issueTestPassport({ currency: "12" }), /currency/i);
    assert.throws(() => issueTestPassport({ currency: "US$" }), /currency/i);
  });
});

describe("currency policy + mint-time confinement (adversarial judge BREAK-2)", () => {
  it("mint-time: a USD grant cannot mint a EUR leaf", () => {
    // The judge's PoC: grant is USD-only, agent issues a EUR passport.
    assert.throws(
      () => issueTestPassport({ currency: "EUR", grantJws }),
      (e: unknown) => e instanceof WalletError && e.code === "currency_exceeded"
    );
  });

  it("mint-time: a EUR grant mints a EUR leaf", () => {
    const issued = issueTestPassport({ currency: "EUR", grantJws: eurGrantJws });
    assert.equal(verifyPassport(issued.passport, policy()).ok, true);
  });

  it("policy: EUR passport against a USD-only merchant policy is rejected", () => {
    const issued = issueTestPassport({ currency: "EUR", grantJws: eurGrantJws });
    const res = verifyPassport(issued.passport, policy({ allowedCurrencies: ["USD"] }));
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /currency/i);
  });

  it("policy: a rejected-on-currency passport is not consumed and can be re-presented", () => {
    const issued = issueTestPassport({ currency: "EUR", grantJws: eurGrantJws });
    const denied = verifyPassport(issued.passport, policy({ allowedCurrencies: ["USD"] }));
    assert.equal(denied.ok, false);
    // Policy fixed to allow EUR: the same passport verifies — nothing burned.
    const accepted = verifyPassport(
      issued.passport,
      policy({ allowedCurrencies: ["USD", "EUR"] })
    );
    assert.equal(accepted.ok, true);
    assert.equal(accepted.currency, "EUR");
  });

  it("policy: allowedCurrencies is case-insensitive; unset means no currency gate", () => {
    const usd = issueTestPassport();
    assert.equal(verifyPassport(usd.passport, policy({ allowedCurrencies: ["usd"] })).ok, true);
    const eur = issueTestPassport({ currency: "EUR", grantJws: eurGrantJws });
    // No allowedCurrencies knob set: currency gate is off (backwards compatible).
    assert.equal(verifyPassport(eur.passport, policy()).ok, true);
  });
});

describe("planted CRL end-to-end (adversarial judge BREAK-1)", () => {
  it("verifyPassport stays ok when an attacker CRL is planted under the owner's file key", () => {
    const dir = env.stateDir + "-planted-e2e";
    const issued = issueTestPassport();
    const leafPayload = JSON.parse(
      Buffer.from(JSON.parse(issued.passport).leaf.split(".")[1], "base64url").toString("utf8")
    );
    const owner = getDid("owner");
    const attacker = getDid("agent");
    const now = Math.floor(Date.now() / 1000);
    // Attacker (as their own DID) signs a CRL covering the victim's leaf jti
    // and plants it under the REAL owner's file key in revocation.json.
    const planted = signJwsWithRole(
      { iss: attacker.did, iat: now, exp: now + 86400, revoked: [String(leafPayload.jti)], seq: 1 },
      "agent"
    );
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "revocation.json"),
      JSON.stringify({ [owner.did]: { jws: planted, fetchedAt: now } }),
      { mode: 0o600 }
    );
    const res = verifyPassport(issued.passport, policy({ stateDir: dir }));
    assert.equal(res.ok, true);
  });
});

describe("inspectPassport failure result (judge note N6)", () => {
  it("returns {ok:false} instead of throwing on garbage", () => {
    for (const bad of ["", "not json", "{}", "[]", "null"]) {
      const res = inspectPassport(bad);
      assert.equal(res.ok, false, `expected failure for ${JSON.stringify(bad)}`);
      assert.ok(typeof (res as { reason?: string }).reason === "string");
    }
  });

  it("returns {ok:true, ...envelope, chain} on a valid passport", () => {
    const issued = issueTestPassport();
    const res = inspectPassport(issued.passport);
    assert.equal(res.ok, true);
    if (!res.ok) throw new Error("unreachable");
    assert.ok(res.chain.length >= 2);
    assert.equal(res.v, 1);
  });
});

describe("expiry narrowing down the chain (Minor 9)", () => {
  it("rejects a passport whose leaf outlives its parent grant", () => {
    // Grant lives ~30 minutes; the passport asks for 1 hour. verifyChain
    // accepts it (the parent is not expired yet) but verifyPassport must
    // enforce child exp <= parent exp at every hop.
    const shortGrant = issueGrant({
      agentDid,
      scope: ["purchase"],
      amountLimit: 100,
      ttlDays: 1 / 48, // 30 minutes
    }).grant;
    const issued = issuePassport({
      merchant: MERCHANT,
      amountLimit: 25,
      actions: ["purchase"],
      ttlSec: 3600,
      grantJws: shortGrant,
    });
    const res = verifyPassport(issued.passport, policy());
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /expires after its parent/i);
  });
});

describe("consumption semantics (Minor 3)", () => {
  it("does not burn a passport rejected on merchant policy — it can be re-presented", () => {
    const issued = issueTestPassport();
    const denied = verifyPassport(issued.passport, policy({ maxAmount: 1 }));
    assert.equal(denied.ok, false);
    assert.match(denied.reason || "", /exceeds merchant policy max/);
    // Policy fixed: the same passport now verifies — neither the merchant
    // store nor the wallet ledger consumed it on the failed attempt.
    const accepted = verifyPassport(issued.passport, policy());
    assert.equal(accepted.ok, true);
  });
});
