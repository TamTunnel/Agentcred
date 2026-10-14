// packages/merchant/test/middleware.test.ts
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  verifyPassport,
  expressMiddleware,
  fastifyPlugin,
  honoMiddleware,
} from "../src/index.ts";
import {
  onboard,
  issueGrant,
  issuePassport,
} from "@tamtunnel/agentcred-core";

const MERCHANT = "merchant:acme.example.invalid";
let stateDir: string;
let grantJws: string;

function freshEnv() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "agentcred-merchant-"));
  const walletDir = path.join(base, "wallet");
  stateDir = path.join(base, "state");
  fs.mkdirSync(walletDir, { recursive: true });
  fs.mkdirSync(stateDir, { recursive: true });
  process.env.SI_WALLET_DIR = walletDir;
  process.env.SI_WALLET_PASSPHRASE = "test-passphrase-REDACTED";
  process.env.AGENTCRED_STATE_DIR = stateDir;
  return () => fs.rmSync(base, { recursive: true, force: true });
}

let cleanup: () => void;
before(() => {
  cleanup = freshEnv();
  onboard("owner");
  const agent = onboard("agent");
  grantJws = issueGrant({ agentDid: agent.did, scope: ["purchase"], amountLimit: 50, ttlDays: 30 }).grant;
});
after(() => cleanup());

function makePassport() {
  return issuePassport({
    merchant: MERCHANT,
    amountLimit: 25,
    actions: ["purchase"],
    ttlSec: 900,
    grantJws,
  }).passport;
}

const policy = () => ({ merchantId: MERCHANT, stateDir });

describe("verifyPassport (pure)", () => {
  it("accepts a valid passport and rejects a replay", () => {
    const p = makePassport();
    assert.equal(verifyPassport(p, policy()).ok, true);
    const replay = verifyPassport(p, policy());
    assert.equal(replay.ok, false);
    assert.match(replay.reason || "", /replay/i);
  });
});

describe("expressMiddleware", () => {
  function mockRes() {
    const res: Record<string, any> = {};
    res.statusCode = 0;
    res.body = null;
    res.status = (c: number) => ((res.statusCode = c), res);
    res.json = (b: unknown) => ((res.body = b), res);
    return res;
  }

  it("calls next() and stashes the result on success", () => {
    const mw = expressMiddleware(policy());
    const req: Record<string, any> = {
      headers: { authorization: `Passport ${makePassport()}` },
    };
    const res = mockRes();
    let nexted = false;
    mw(req, res, () => (nexted = true));
    assert.equal(nexted, true);
    assert.equal(req.agentcred.ok, true);
    assert.equal(req.agentcred.merchant, MERCHANT);
  });

  it("402s on a missing passport", () => {
    const mw = expressMiddleware(policy());
    const res = mockRes();
    let nexted = false;
    mw({ headers: {} }, res, () => (nexted = true));
    assert.equal(nexted, false);
    assert.equal(res.statusCode, 402);
    assert.match(res.body.reason, /missing/i);
  });

  it("402s on a replayed passport", () => {
    const mw = expressMiddleware(policy());
    const p = makePassport();
    const headers = { authorization: `Passport ${p}` };
    let n1 = false;
    mw({ headers }, mockRes(), () => (n1 = true));
    assert.equal(n1, true);
    const res = mockRes();
    let n2 = false;
    mw({ headers }, res, () => (n2 = true));
    assert.equal(n2, false);
    assert.equal(res.statusCode, 402);
    assert.match(res.body.reason, /replay/i);
  });

  it("reads the passport from the JSON body as a fallback", () => {
    const mw = expressMiddleware(policy());
    const req: Record<string, any> = { headers: {}, body: { passport: makePassport() } };
    const res = mockRes();
    let nexted = false;
    mw(req, res, () => (nexted = true));
    assert.equal(nexted, true);
  });
});

describe("fastifyPlugin", () => {
  it("registers an onRequest hook that verifies", () => {
    const plugin = fastifyPlugin(policy());
    let hook: Function | null = null;
    const fastify: Record<string, any> = {
      addHook: (name: string, fn: Function) => {
        assert.equal(name, "onRequest");
        hook = fn;
      },
    };
    let done = false;
    plugin(fastify, {}, () => (done = true));
    assert.equal(done, true);
    assert.ok(hook);

    const reply: Record<string, any> = {
      code: (c: number) => ({ send: (b: unknown) => ((reply.statusCode = c), (reply.body = b)) }),
    };
    const req: Record<string, any> = {
      headers: { authorization: `Passport ${makePassport()}` },
    };
    let nexted = false;
    (hook as Function)(req, reply, () => (nexted = true));
    assert.equal(nexted, true);
    assert.equal(req.agentcred.ok, true);

    // Replay through the same hook fails.
    let nexted2 = false;
    (hook as Function)(req, reply, () => (nexted2 = true));
    assert.equal(nexted2, false);
    assert.equal(reply.statusCode, 402);
  });
});

describe("honoMiddleware", () => {
  function mockCtx(passport: string | null) {
    const store: Record<string, unknown> = {};
    return {
      req: {
        header: (name: string) =>
          name === "authorization" && passport ? `Passport ${passport}` : "",
      },
      set: (k: string, v: unknown) => (store[k] = v),
      get: (k: string) => store[k],
      json: (b: unknown, status: number) => ({ status, body: b }),
      _store: store,
    };
  }

  it("verifies and continues, storing the result", async () => {
    const mw = honoMiddleware(policy());
    const c = mockCtx(makePassport());
    let nexted = false;
    await mw(c, async () => { nexted = true; });
    assert.equal(nexted, true);
    assert.equal((c._store.agentcred as any).ok, true);
  });

  it("returns 402 JSON when the passport is missing or replayed", async () => {
    const mw = honoMiddleware(policy());
    const missing = await mw(mockCtx(null), async () => {});
    assert.equal(missing.status, 402);

    const p = makePassport();
    let ok1 = false;
    await mw(mockCtx(p), async () => { ok1 = true; });
    assert.equal(ok1, true);
    let ok2 = false;
    const replayed = await mw(mockCtx(p), async () => { ok2 = true; });
    assert.equal(ok2, false);
    assert.equal((replayed as any).status, 402);
    assert.match((replayed as any).body.reason, /replay/i);
  });
});
