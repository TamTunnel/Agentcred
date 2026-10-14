// packages/si-wallet-core/test/crypto.test.ts — behavioral tests for the
// extracted core: strict encodings, issuance, verification, replay, chains.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { setupTestEnv, type TestEnv } from "./helpers.ts";
import {
  WalletError,
  onboard,
  getDid,
  issueGrant,
  mintMandate,
  verifyMandate,
  verifyChain,
  pairwiseDid,
  fingerprint,
  unb64uStrict,
} from "../src/index.ts";

let env: TestEnv;
before(() => {
  env = setupTestEnv();
});
after(() => env.cleanup());

describe("identities", () => {
  it("onboard creates owner+agent did:key identities, idempotent", () => {
    const o1 = onboard("owner");
    const o2 = onboard("owner");
    assert.ok(o1.did.startsWith("did:key:z"));
    assert.equal(o1.did, o2.did);
    assert.equal(o2.existing, true);
    const a = onboard("agent");
    assert.ok(a.did.startsWith("did:key:z"));
    assert.notEqual(a.did, o1.did);
  });

  it("getDid throws for a missing identity", async () => {
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const real = process.env.SI_WALLET_DIR!;
    process.env.SI_WALLET_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "agentcred-empty-"));
    assert.throws(() => getDid("agent"), (e: unknown) => e instanceof WalletError && e.code === "no_identity");
    fs.rmSync(process.env.SI_WALLET_DIR, { recursive: true, force: true });
    process.env.SI_WALLET_DIR = real;
  });

  it("fingerprint is a deterministic 16-hex string", () => {
    const { did } = getDid("agent");
    assert.match(fingerprint(did), /^[0-9a-f]{16}$/);
    assert.equal(fingerprint(did), fingerprint(did));
  });

  it("pairwiseDid mints a fresh did per audience", () => {
    const p1 = pairwiseDid("site-a.example.invalid");
    const p2 = pairwiseDid("site-a.example.invalid");
    assert.notEqual(p1.did, p2.did); // never reuse across sites
  });
});

describe("unb64uStrict", () => {
  it("accepts canonical base64url", () => {
    const buf = unb64uStrict("aGVsbG8");
    assert.equal(buf.toString(), "hello");
  });

  it("rejects padding, bad chars, and non-canonical trailing bits", () => {
    assert.throws(() => unb64uStrict("aGVsbG8="), /canonical base64url/);
    assert.throws(() => unb64uStrict("aGVsbG8!"), /canonical base64url/);
    assert.throws(() => unb64uStrict(""), /canonical base64url/);
    // "AB": 'B' = 000001 leaves nonzero trailing bits; re-encodes as "AA".
    assert.throws(() => unb64uStrict("AB"), /canonical base64url/);
  });
});

describe("grants and mandates", () => {
  let agentDid: string;
  let grantJws: string;

  it("issueGrant validates its inputs", () => {
    agentDid = getDid("agent").did;
    assert.throws(() => issueGrant({ agentDid: "bogus", scope: ["x"], amountLimit: 1 }), /bad_did|malformed/);
    assert.throws(() => issueGrant({ agentDid, scope: [], amountLimit: 1 }), /at least one scope/);
    assert.throws(() => issueGrant({ agentDid, scope: ["x"], amountLimit: -5 }), /non-negative/);
    const g = issueGrant({ agentDid, scope: ["purchase"], amountLimit: 100, ttlDays: 30 });
    grantJws = g.grant;
    assert.equal(g.grant.split(".").length, 3);
  });

  it("mintMandate enforces the $100 consent gate and grant scope", () => {
    assert.throws(
      () => mintMandate({ audience: "x", scope: ["purchase"], amount: 150, grantJws }),
      (e: unknown) => e instanceof WalletError && e.code === "over_limit"
    );
    assert.throws(
      () => mintMandate({ audience: "x", scope: ["wire"], amount: 10, grantJws }),
      (e: unknown) => e instanceof WalletError && e.code === "scope_exceeded"
    );
    assert.throws(
      () =>
        mintMandate({ audience: "x", scope: ["purchase"], amount: 50, grantJws: "garbage" }),
      (e: unknown) => e instanceof WalletError && e.code === "bad_grant"
    );
  });

  it("verifyMandate happy path, then replay", () => {
    const m = mintMandate({
      audience: "merchant:shop.example.invalid",
      scope: ["purchase"],
      amount: 20,
      ttlSec: 600,
      task: "test",
      grantJws,
    });
    const v1 = verifyMandate({ mandateJws: m.mandate, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(v1.ok, true);
    assert.equal(v1.agent, agentDid);
    const v2 = verifyMandate({ mandateJws: m.mandate, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(v2.ok, false);
    assert.match(v2.reason || "", /replay/);
  });

  it("verifyMandate rejects audience mismatch and tampering", () => {
    const m = mintMandate({
      audience: "merchant:shop.example.invalid",
      scope: ["purchase"],
      amount: 5,
      ttlSec: 600,
      grantJws,
    });
    const wrong = verifyMandate({ mandateJws: m.mandate, expectedAudience: "merchant:other.example.invalid" });
    assert.equal(wrong.ok, false);
    assert.match(wrong.reason || "", /audience mismatch/);
    const parts = m.mandate.split(".");
    parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
    const tampered = verifyMandate({ mandateJws: parts.join("."), expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(tampered.ok, false);
  });

  it("verifyMandate rejects expired mandates", async () => {
    const m = mintMandate({
      audience: "merchant:shop.example.invalid",
      scope: ["purchase"],
      amount: 5,
      ttlSec: 1,
      grantJws,
    });
    await new Promise((r) => setTimeout(r, 1200));
    const v = verifyMandate({ mandateJws: m.mandate });
    assert.equal(v.ok, false);
    assert.match(v.reason || "", /expired/);
  });
});

describe("verifyChain delegation", () => {
  it("verifies a 2-hop Owner → A → B chain with narrowing", async () => {
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const realWallet = process.env.SI_WALLET_DIR!;
    const realPw = process.env.SI_WALLET_PASSPHRASE!;

    // Wallet B: downstream agent.
    const dirB = fs.mkdtempSync(path.join(os.tmpdir(), "agentcred-chain-b-"));
    process.env.SI_WALLET_DIR = dirB;
    const didB = onboard("agent").did;

    // Wallet A (original): owner grant → A, A delegates to B.
    process.env.SI_WALLET_DIR = realWallet;
    const didA = getDid("agent").did;
    const grantA = issueGrant({ agentDid: didA, scope: ["purchase", "refund"], amountLimit: 100, ttlDays: 30 }).grant;
    const link1 = mintMandate({
      audience: "merchant:shop.example.invalid",
      scope: ["purchase"],
      amount: 50,
      ttlSec: 1800,
      grantJws: grantA,
      subjectDid: didB,
    }).mandate;

    // Wallet B: B mints the leaf against A's mandate, narrowing further.
    process.env.SI_WALLET_DIR = dirB;
    const leaf = mintMandate({
      audience: "merchant:shop.example.invalid",
      scope: ["purchase"],
      amount: 20,
      ttlSec: 900,
      grantJws: link1,
    }).mandate;

    process.env.SI_WALLET_DIR = realWallet;
    process.env.SI_WALLET_PASSPHRASE = realPw;
    const res = verifyChain({ mandateJws: leaf, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(res.ok, true);
    assert.equal(res.hops, 2);
    assert.equal(res.agent, didB);
    assert.deepEqual(res.scope, ["purchase"]);
    assert.equal(res.amount_limit, 20);
    fs.rmSync(dirB, { recursive: true, force: true });
  });
});
