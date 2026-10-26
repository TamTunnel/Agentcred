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
  signJwsWithRole,
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

describe("kid/issuer binding (C1)", () => {
  const now = () => Math.floor(Date.now() / 1000);
  function honestGrant(): string {
    const agentDid = getDid("agent").did;
    return issueGrant({ agentDid, scope: ["purchase"], amountLimit: 100, ttlDays: 30 }).grant;
  }
  function honestMandate(): string {
    return mintMandate({
      audience: "merchant:shop.example.invalid",
      scope: ["purchase"],
      amount: 20,
      ttlSec: 600,
      grantJws: honestGrant(),
    }).mandate;
  }

  it("verifyMandate accepts an honest mandate (no false positive)", () => {
    onboard("owner");
    onboard("agent");
    const v = verifyMandate({ mandateJws: honestMandate(), expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(v.ok, true);
  });

  it("verifyMandate rejects a mandate whose kid does not match iss", () => {
    const victim = getDid("owner").did;
    const iat = now();
    // Signed with the agent's key (kid = agent DID) but claims iss = victim.
    const forged = signJwsWithRole({
      iss: victim,
      sub: victim,
      aud: "merchant:shop.example.invalid",
      iat, exp: iat + 600, jti: "kid-binding-forged-1",
      claims: { task: "forged", scope: ["purchase"], amount_limit: 20, currency: "USD" },
      grant: honestGrant(),
    }, "agent");
    const v1 = verifyMandate({ mandateJws: forged, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(v1.ok, false);
    assert.match(v1.reason || "", /kid does not match/);
    // Rejected forgery must not burn its jti: same reason twice.
    const v2 = verifyMandate({ mandateJws: forged, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(v2.ok, false);
    assert.match(v2.reason || "", /kid does not match/);
  });

  it("verifyMandate rejects a grant whose kid does not match grant iss", () => {
    const ownerDid = getDid("owner").did;
    const agentDid = getDid("agent").did;
    const iat = now();
    // Grant claims iss = owner but is signed with the agent's key.
    const forgedGrant = signJwsWithRole({
      iss: ownerDid, sub: agentDid, aud: "sovereign-identity/agency",
      iat, exp: iat + 86400, jti: "kid-binding-forged-grant-1",
      claims: { scope: ["purchase"], amount_limit: 100, currency: "USD" },
    }, "agent");
    const mandate = signJwsWithRole({
      iss: agentDid, sub: agentDid, aud: "merchant:shop.example.invalid",
      iat, exp: iat + 600, jti: "kid-binding-forged-2",
      claims: { task: "forged-grant", scope: ["purchase"], amount_limit: 20, currency: "USD" },
      grant: forgedGrant,
    }, "agent");
    const v = verifyMandate({ mandateJws: mandate, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(v.ok, false);
    assert.match(v.reason || "", /kid does not match/);
  });

  it("verifyChain rejects a forged leaf link", () => {
    const victim = getDid("owner").did;
    const iat = now();
    const forgedLeaf = signJwsWithRole({
      iss: victim, sub: victim, aud: "merchant:shop.example.invalid",
      iat, exp: iat + 600, jti: "kid-binding-forged-chain-1",
      claims: { task: "forged", scope: ["purchase"], amount_limit: 20, currency: "USD" },
      grant: honestGrant(),
    }, "agent");
    const res = verifyChain({ mandateJws: forgedLeaf, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /kid does not match/);
  });

  it("verifyChain rejects a forged parent grant (parent binding check)", () => {
    onboard("owner");
    onboard("agent");
    const ownerDid = getDid("owner").did;
    const agentDid = getDid("agent").did;
    const iat = now();
    // Parent grant claims iss = owner but is signed with the agent's key;
    // sub is aligned to the leaf iss so kid binding is the decisive check.
    const forgedGrant = signJwsWithRole({
      iss: ownerDid, sub: agentDid, aud: "sovereign-identity/agency",
      iat, exp: iat + 86400, jti: "kid-binding-forged-parent-1",
      claims: { scope: ["purchase"], amount_limit: 100, currency: "USD" },
    }, "agent");
    // Leaf is honest (agent-signed, iss = agent) but carries the forged grant.
    const leaf = mintMandate({
      audience: "merchant:shop.example.invalid",
      scope: ["purchase"],
      amount: 20,
      ttlSec: 600,
      grantJws: forgedGrant,
    }).mandate;
    const res = verifyChain({ mandateJws: leaf, expectedAudience: "merchant:shop.example.invalid" });
    assert.equal(res.ok, false);
    assert.match(res.reason || "", /parent JWS kid does not match parent iss/);
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

describe("currency threading (Blocker 1)", () => {
  let agentDid: string;
  let grantJws: string;
  before(() => {
    agentDid = getDid("agent").did;
    grantJws = issueGrant({ agentDid, scope: ["purchase"], amountLimit: 100, ttlDays: 30 }).grant;
  });

  function leafClaims(mandate: string): Record<string, any> {
    return JSON.parse(Buffer.from(mandate.split(".")[1], "base64url").toString("utf8")).claims;
  }

  function grantClaims(grant: string): Record<string, any> {
    return JSON.parse(Buffer.from(grant.split(".")[1], "base64url").toString("utf8")).claims;
  }

  it("mintMandate normalizes and signs the requested currency on a matching grant", () => {
    const eurGrant = issueGrant({
      agentDid,
      scope: ["purchase"],
      amountLimit: 100,
      ttlDays: 30,
      currency: "EUR",
    }).grant;
    const m = mintMandate({
      audience: "merchant:x.example.invalid",
      scope: ["purchase"],
      amount: 10,
      currency: "eur",
      grantJws: eurGrant,
    });
    assert.equal(leafClaims(m.mandate).currency, "EUR");
  });

  it("mintMandate refuses a leaf currency the grant does not cover (BREAK-2)", () => {
    // Grants are denominated; a USD grant cannot mint a EUR leaf.
    assert.throws(
      () =>
        mintMandate({
          audience: "merchant:x.example.invalid",
          scope: ["purchase"],
          amount: 10,
          currency: "EUR",
          grantJws, // USD-denominated grant
        }),
      (e: unknown) => e instanceof WalletError && e.code === "currency_exceeded"
    );
  });

  it("issueGrant denominates the grant in the requested currency (default USD)", () => {
    const g = issueGrant({ agentDid, scope: ["purchase"], amountLimit: 100, ttlDays: 30 });
    assert.equal(grantClaims(g.grant).currency, "USD");
    const eurg = issueGrant({
      agentDid,
      scope: ["purchase"],
      amountLimit: 100,
      ttlDays: 30,
      currency: "eur",
    });
    assert.equal(grantClaims(eurg.grant).currency, "EUR");
    assert.throws(
      () => issueGrant({ agentDid, scope: ["purchase"], amountLimit: 100, currency: "USDD" }),
      /currency/i
    );
  });

  it("mintMandate defaults currency to USD", () => {
    const m = mintMandate({
      audience: "merchant:x.example.invalid",
      scope: ["purchase"],
      amount: 10,
      grantJws,
    });
    assert.equal(leafClaims(m.mandate).currency, "USD");
  });

  it("mintMandate rejects non-ISO-4217 currency strings", () => {
    for (const bad of ["USDD", "12", "US$", ""]) {
      assert.throws(
        () =>
          mintMandate({
            audience: "merchant:x.example.invalid",
            scope: ["purchase"],
            amount: 10,
            currency: bad,
            grantJws,
          }),
        /currency/i,
        `expected rejection for ${JSON.stringify(bad)}`
      );
    }
  });
});

describe("verifyChain consumption control (Minor 3)", () => {
  it("consumeLeafJti:false leaves the ledger untouched; default burns it", () => {
    const agentDid = getDid("agent").did;
    const grant = issueGrant({ agentDid, scope: ["purchase"], amountLimit: 100, ttlDays: 30 }).grant;
    const mk = () =>
      mintMandate({
        audience: "merchant:defer.example.invalid",
        scope: ["purchase"],
        amount: 5,
        ttlSec: 600,
        grantJws: grant,
      }).mandate;

    // Deferred consumption: verifying twice is fine — nothing was burned.
    const deferred = mk();
    assert.equal(
      verifyChain({ mandateJws: deferred, expectedAudience: "merchant:defer.example.invalid", consumeLeafJti: false }).ok,
      true
    );
    assert.equal(
      verifyChain({ mandateJws: deferred, expectedAudience: "merchant:defer.example.invalid", consumeLeafJti: false }).ok,
      true
    );

    // Default: first verify burns the leaf jti, second fails as replay.
    const burned = mk();
    assert.equal(
      verifyChain({ mandateJws: burned, expectedAudience: "merchant:defer.example.invalid" }).ok,
      true
    );
    const again = verifyChain({ mandateJws: burned, expectedAudience: "merchant:defer.example.invalid" });
    assert.equal(again.ok, false);
    assert.match(again.reason || "", /replay/);
  });
});

describe("replay ledger pruning (Minor 10)", () => {
  it("expired ledger entries are pruned on the next mark", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const walletDir = process.env.SI_WALLET_DIR!;
    const replayFile = path.join(walletDir, "replay.json");
    const stale: Record<string, number> = {};
    try {
      Object.assign(stale, JSON.parse(fs.readFileSync(replayFile, "utf8")));
    } catch {
      /* no ledger yet */
    }
    const past = Math.floor(Date.now() / 1000) - 100;
    stale["jti-stale-prune-me"] = past;
    fs.writeFileSync(replayFile, JSON.stringify(stale), { mode: 0o600 });

    const agentDid = getDid("agent").did;
    const grant = issueGrant({ agentDid, scope: ["purchase"], amountLimit: 100, ttlDays: 30 }).grant;
    const m = mintMandate({
      audience: "merchant:prune.example.invalid",
      scope: ["purchase"],
      amount: 5,
      ttlSec: 600,
      grantJws: grant,
    });
    assert.equal(
      verifyChain({ mandateJws: m.mandate, expectedAudience: "merchant:prune.example.invalid" }).ok,
      true
    );
    const after = JSON.parse(fs.readFileSync(replayFile, "utf8")) as Record<string, number>;
    assert.ok(!Object.prototype.hasOwnProperty.call(after, "jti-stale-prune-me"), "stale entry pruned");
    const leafJti: string = JSON.parse(
      Buffer.from(m.mandate.split(".")[1], "base64url").toString("utf8")
    ).jti;
    assert.ok(Object.prototype.hasOwnProperty.call(after, leafJti), "fresh mark kept");
  });
});
