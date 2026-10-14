// packages/cli/test/cli.test.ts — end-to-end CLI: init → grant → issue →
// verify → inspect → revoke. Spawns the real CLI in an isolated env.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const CLI = new URL("../src/cli.ts", import.meta.url).pathname;
const MERCHANT = "merchant:acme.example.invalid";

let env: Record<string, string>;
let base: string;
before(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "agentcred-cli-"));
  env = {
    ...process.env,
    SI_WALLET_DIR: path.join(base, "wallet"),
    SI_WALLET_PASSPHRASE: "test-passphrase-REDACTED",
    AGENTCRED_STATE_DIR: path.join(base, "state"),
  } as Record<string, string>;
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

async function cli(...args: string[]) {
  return run(process.execPath, [CLI, ...args], { env });
}

function parseStdout(r: { stdout: string }) {
  return JSON.parse(r.stdout);
}

describe("agentcred CLI", () => {
  let agentDid: string;
  let grantJws: string;
  let passport: string;

  it("init creates owner+agent identities", async () => {
    const r = parseStdout(await cli("init"));
    assert.equal(r.ok, true);
    assert.ok(r.owner.did.startsWith("did:key:z"));
    assert.ok(r.agent.did.startsWith("did:key:z"));
    agentDid = r.agent.did;
  });

  it("grant issues an agency grant", async () => {
    const r = parseStdout(
      await cli(
        "grant",
        "--agent-did", agentDid,
        "--scope", "purchase",
        "--amount-limit", "50"
      )
    );
    assert.equal(r.ok, true);
    grantJws = r.grant;
    assert.equal(r.grant.split(".").length, 3);
  });

  it("issue mints a passport", async () => {
    const grantFile = path.join(base, "grant.jwt");
    fs.writeFileSync(grantFile, grantJws);
    const r = parseStdout(
      await cli(
        "issue",
        "--merchant", MERCHANT,
        "--amount-limit", "25",
        "--actions", "purchase",
        "--grant", grantFile,
        "--ttl-sec", "900"
      )
    );
    assert.equal(r.ok, true);
    passport = r.passport;
    assert.ok(passport.includes('"v":1'));
  });

  it("verify accepts the passport once, then reports replay", async () => {
    const passFile = path.join(base, "passport.json");
    fs.writeFileSync(passFile, passport);
    const r1 = parseStdout(await cli("verify", "--passport", passFile, "--merchant", MERCHANT));
    assert.equal(r1.ok, true);
    assert.equal(r1.merchant, MERCHANT);
    // Second presentation: the CLI exits 1 with a replay report on stdout.
    const err = await cli("verify", "--passport", passFile, "--merchant", MERCHANT).then(
      () => { throw new Error("expected the replayed verify to fail"); },
      (e) => e
    );
    const r2 = JSON.parse(err.stdout);
    assert.equal(r2.ok, false);
    assert.match(r2.reason, /replay/i);
  });

  it("verify rejects the wrong merchant with a nonzero exit", async () => {
    // Fresh passport so replay state does not interfere.
    const grantFile = path.join(base, "grant.jwt");
    const r = parseStdout(
      await cli("issue", "--merchant", MERCHANT, "--amount-limit", "5",
        "--actions", "purchase", "--grant", grantFile)
    );
    const passFile = path.join(base, "passport2.json");
    fs.writeFileSync(passFile, r.passport);
    await assert.rejects(
      cli("verify", "--passport", passFile, "--merchant", "merchant:wrong.example.invalid"),
      /Command failed/
    );
  });

  it("inspect decodes without verifying", async () => {
    const passFile = path.join(base, "passport.json");
    const r = parseStdout(await cli("inspect", "--passport", passFile));
    assert.equal(r.ok, true);
    assert.equal(r.spend.merchant, MERCHANT);
    assert.ok(r.chain.length >= 2);
  });

  it("revoke adds the jti to the owner's signed CRL", async () => {
    const passFile = path.join(base, "passport.json");
    const envelope = JSON.parse(fs.readFileSync(passFile, "utf8"));
    const leaf = JSON.parse(Buffer.from(envelope.leaf.split(".")[1], "base64url").toString("utf8"));
    const r = parseStdout(await cli("revoke", "--jti", leaf.jti));
    assert.equal(r.ok, true);
    assert.equal(r.revoked, leaf.jti);
    // The passport is already consumed, but revocation is recorded: a fresh
    // passport for a *different* jti still verifies.
    const grantFile = path.join(base, "grant.jwt");
    const r2 = parseStdout(
      await cli("issue", "--merchant", MERCHANT, "--amount-limit", "5",
        "--actions", "purchase", "--grant", grantFile)
    );
    const passFile2 = path.join(base, "passport3.json");
    fs.writeFileSync(passFile2, r2.passport);
    const v = parseStdout(await cli("verify", "--passport", passFile2, "--merchant", MERCHANT));
    assert.equal(v.ok, true);
  });

  it("unknown commands fail with usage", async () => {
    await assert.rejects(cli("bogus-command"), /Command failed/);
  });
});
