// packages/core/test/revocation.test.ts — signed CRL lifecycle.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { setupTestEnv, type TestEnv } from "./helpers.ts";
import {
  onboard,
  getDid,
  signJwsWithRole,
  verifyRevocationJws,
  RevocationCache,
  appendRevocation,
} from "@tamtunnel/agentcred-core";

const run = promisify(execFile);
// The built core dist (absolute file URL): child processes import this
// directly so concurrent-revoke tests exercise the real shipped code.
const CORE_DIST = new URL("../../core/dist/index.js", import.meta.url).href;

let env: TestEnv;
let ownerDid: string;
let agentDid: string;
before(() => {
  env = setupTestEnv();
  onboard("owner");
  onboard("agent");
  ownerDid = getDid("owner").did;
  agentDid = getDid("agent").did;
});
after(() => env.cleanup());

/** Attacker-signed CRL: valid signature, but iss = the attacker's DID. */
function attackerCrl(revoked: string[], seq = 1) {
  const now = Math.floor(Date.now() / 1000);
  return signJwsWithRole(
    { iss: agentDid, iat: now, exp: now + 86400, revoked, seq },
    "agent"
  );
}

/** Plant a raw revocation.json entry, bypassing ingest()'s trust check. */
function plantCrlEntry(dir: string, fileKey: string, jws: string) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "revocation.json"),
    JSON.stringify({ [fileKey]: { jws, fetchedAt: Math.floor(Date.now() / 1000) } }),
    { mode: 0o600 }
  );
}

function makeCrl(revoked: string[], seq: number, expOffset = 86400) {
  const now = Math.floor(Date.now() / 1000);
  return signJwsWithRole(
    { iss: ownerDid, iat: now, exp: now + expOffset, revoked, seq },
    "owner"
  );
}

describe("RevocationCache", () => {
  it("ingests a valid list and reports its jtis", () => {
    const cache = new RevocationCache({ dir: env.stateDir, trustedIssuers: [ownerDid] });
    const payload = cache.ingest(makeCrl(["jti-a", "jti-b"], 1), (j) => verifyRevocationJws(j));
    assert.deepEqual(payload.revoked, ["jti-a", "jti-b"]);
    const revoked = cache.revokedJtis((j) => verifyRevocationJws(j));
    assert.ok(revoked.has("jti-a") && revoked.has("jti-b"));
  });

  it("never downgrades to an older sequence", () => {
    const dir = env.stateDir + "-seq";
    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    cache.ingest(makeCrl(["jti-new"], 5), (j) => verifyRevocationJws(j));
    const kept = cache.ingest(makeCrl(["jti-old"], 3), (j) => verifyRevocationJws(j));
    assert.deepEqual(kept.revoked, ["jti-new"]);
    assert.ok(!cache.revokedJtis((j) => verifyRevocationJws(j)).has("jti-old"));
  });

  it("rejects lists from untrusted issuers", () => {
    const cache = new RevocationCache({ dir: env.stateDir, trustedIssuers: [] });
    assert.throws(
      () => cache.ingest(makeCrl(["x"], 1), (j) => verifyRevocationJws(j)),
      /not trusted/
    );
  });

  it("stores signature-valid lists even when expired (storage != enforcement)", () => {
    // Design: expiry is an enforcement-time policy, not a storage rule.
    // Dropping an expired list silently un-revokes credentials that may
    // still be valid, so the cache keeps the jtis; callers check freshness
    // via listInfo().
    const dir = env.stateDir + "-expired-store";
    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    const payload = cache.ingest(makeCrl(["x"], 9, -10), (j) => verifyRevocationJws(j));
    assert.deepEqual(payload.revoked, ["x"]);
    assert.ok(cache.revokedJtis((j) => verifyRevocationJws(j)).has("x"));
    const info = cache.listInfo(ownerDid, (j) => verifyRevocationJws(j));
    assert.ok(info);
    assert.equal(info!.fresh, false);
  });

  it("verifyRevocationJws refuses re-encoded (non-canonical) payloads", () => {
    const crl = makeCrl(["x"], 1);
    const [h, p, s] = crl.split(".");
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    // Re-encode with shuffled keys under the original signature: the bytes no
    // longer match what was signed, so verification must refuse it. There is
    // no way to produce a validly-signed non-canonical payload through the
    // canonical signer.
    const shuffled = Buffer.from(
      JSON.stringify({
        seq: payload.seq,
        revoked: payload.revoked,
        iss: payload.iss,
        iat: payload.iat,
        exp: payload.exp,
      })
    ).toString("base64url");
    assert.throws(() => verifyRevocationJws(`${h}.${shuffled}.${s}`), /canonical|signature/);
  });
});

describe("planted CRL (adversarial judge BREAK-1)", () => {
  it("revokedJtis ignores an attacker-signed CRL planted under the owner's file key", () => {
    // PoC: attacker signs { iss: <attacker-did>, revoked: ["victim-jti"] }
    // and plants it as { [<real-owner-did>]: { jws } } in revocation.json.
    // Trust must come from the SIGNATURE-VERIFIED payload.iss, not the file key.
    const dir = env.stateDir + "-planted";
    plantCrlEntry(dir, ownerDid, attackerCrl(["victim-jti"]));
    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    const revoked = cache.revokedJtis((j) => verifyRevocationJws(j));
    assert.ok(!revoked.has("victim-jti"), "planted attacker CRL must be ignored");
  });

  it("revokedJtis still honors the real owner's CRL alongside the planted entry", () => {
    const dir = env.stateDir + "-planted-mixed";
    plantCrlEntry(dir, ownerDid, attackerCrl(["victim-jti"]));
    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    // Legit owner list lands under the same file via the honest ingest path.
    cache.ingest(makeCrl(["real-jti"], 1), (j) => verifyRevocationJws(j));
    const revoked = cache.revokedJtis((j) => verifyRevocationJws(j));
    assert.ok(!revoked.has("victim-jti"));
    assert.ok(revoked.has("real-jti"));
  });

  it("listInfo rejects a file-key/payload-iss mismatch", () => {
    const dir = env.stateDir + "-planted-info";
    plantCrlEntry(dir, ownerDid, attackerCrl(["victim-jti"]));
    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    assert.equal(cache.listInfo(ownerDid, (j) => verifyRevocationJws(j)), null);
  });

  it("listInfo still reports the real owner's list", () => {
    const dir = env.stateDir + "-info-ok";
    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    cache.ingest(makeCrl(["jti-a"], 7), (j) => verifyRevocationJws(j));
    const info = cache.listInfo(ownerDid, (j) => verifyRevocationJws(j));
    assert.ok(info);
    assert.equal(info!.seq, 7);
    assert.equal(info!.fresh, true);
  });
});

describe("appendRevocation (Major 2)", () => {
  function append(dir: string, jti: string, ttlDays = 366, warnings: string[] = []) {
    return appendRevocation({
      dir,
      jti,
      ttlDays,
      issuerDid: ownerDid,
      verifySignature: (j) => verifyRevocationJws(j),
      sign: (p) => signJwsWithRole({ ...p }, "owner"),
      warn: (m) => warnings.push(m),
    });
  }

  it("CRL expiry-drop: revoking again after the list expired keeps the old jti", () => {
    const dir = env.stateDir + "-expirydrop";
    fs.mkdirSync(dir, { recursive: true });
    const now = Math.floor(Date.now() / 1000);
    // Simulate a previously cached list that has since expired.
    const expired = signJwsWithRole(
      { iss: ownerDid, iat: now - 100000, exp: now - 50000, revoked: ["jti-old"], seq: 1 },
      "owner"
    );
    fs.writeFileSync(
      path.join(dir, "revocation.json"),
      JSON.stringify({ [ownerDid]: { jws: expired, fetchedAt: now - 100000 } })
    );

    const warnings: string[] = [];
    const res = append(dir, "jti-new", 366, warnings);
    assert.equal(res.ok, true);
    assert.equal(res.seq, 2);
    assert.equal(warnings.length, 0);

    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    const revoked = cache.revokedJtis((j) => verifyRevocationJws(j));
    assert.ok(revoked.has("jti-old"), "old jti must survive list expiry");
    assert.ok(revoked.has("jti-new"));
  });

  it("merges accumulated history across sequential revokes", () => {
    const dir = env.stateDir + "-accumulate";
    append(dir, "jti-1");
    const res = append(dir, "jti-2");
    assert.equal(res.seq, 2);
    assert.equal(res.total, 2);
    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    const revoked = cache.revokedJtis((j) => verifyRevocationJws(j));
    assert.ok(revoked.has("jti-1") && revoked.has("jti-2"));
  });

  it("warns loudly when ttlDays is shorter than the coverage minimum (366)", () => {
    const dir = env.stateDir + "-warn";
    const warnings: string[] = [];
    append(dir, "jti-w", 30, warnings);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /366/);
  });

  it("validates its inputs", () => {
    assert.throws(
      () => append(env.stateDir + "-bad", "", 366),
      /jti is required/
    );
    assert.throws(
      () => append(env.stateDir + "-bad", "jti-x", 0),
      /ttlDays must be a positive number/
    );
  });

  it("concurrent revokes both land (file lock + re-read-after-lock, seq keeps increasing)", async () => {
    const dir = env.stateDir + "-concurrent";
    fs.mkdirSync(dir, { recursive: true });
    // Two separate node processes race to revoke against the same dir.
    // Without the lock + re-read, the loser would read seq 0, sign seq 1,
    // and silently overwrite the winner — one jti lost, both reporting ok.
    const childCode = `
      import(${JSON.stringify(CORE_DIST)}).then(async (core) => {
        const [dir, jti] = process.argv.slice(1);
        const res = core.appendRevocation({
          dir,
          jti,
          ttlDays: 366,
          issuerDid: ${JSON.stringify(ownerDid)},
          verifySignature: (j) => core.verifyRevocationJws(j),
          sign: (p) => core.signJwsWithRole({ ...p }, "owner"),
          warn: () => {},
        });
        console.log(JSON.stringify(res));
      }).catch((e) => { console.error(e); process.exit(1); });
    `;
    const spawnRevoke = (jti: string) =>
      run(process.execPath, ["--input-type=module", "-e", childCode, dir, jti], {
        env: process.env,
      });
    const [r1, r2] = await Promise.all([
      spawnRevoke("jti-race-a"),
      spawnRevoke("jti-race-b"),
    ]);
    const res1 = JSON.parse(r1.stdout);
    const res2 = JSON.parse(r2.stdout);
    assert.equal(res1.ok, true);
    assert.equal(res2.ok, true);

    const cache = new RevocationCache({ dir, trustedIssuers: [ownerDid] });
    const revoked = cache.revokedJtis((j) => verifyRevocationJws(j));
    assert.ok(revoked.has("jti-race-a"), "loser's jti must not be lost");
    assert.ok(revoked.has("jti-race-b"), "winner's jti must not be lost");
    const info = cache.listInfo(ownerDid, (j) => verifyRevocationJws(j));
    assert.equal(info && info.seq, 2, "seq must advance once per revoke");
  });
});
