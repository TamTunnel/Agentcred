// packages/core/test/revocation.test.ts — signed CRL lifecycle.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { setupTestEnv, type TestEnv } from "./helpers.ts";
import {
  onboard,
  getDid,
  signJwsWithRole,
  verifyRevocationJws,
  RevocationCache,
} from "@tamtunnel/agentcred-core";

let env: TestEnv;
let ownerDid: string;
before(() => {
  env = setupTestEnv();
  onboard("owner");
  ownerDid = getDid("owner").did;
});
after(() => env.cleanup());

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

  it("rejects expired lists at ingest", () => {
    const cache = new RevocationCache({ dir: env.stateDir, trustedIssuers: [ownerDid] });
    assert.throws(
      () => cache.ingest(makeCrl(["x"], 9, -10), (j) => verifyRevocationJws(j)),
      /expired/
    );
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
