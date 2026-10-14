// packages/core/test/store.test.ts — SeenJtiStore persistence + pruning.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { setupTestEnv, type TestEnv } from "./helpers.ts";
import { SeenJtiStore } from "@tamtunnel/agentcred-core";

let env: TestEnv;
before(() => {
  env = setupTestEnv();
});
after(() => env.cleanup());

describe("SeenJtiStore", () => {
  it("checkAndMark is atomic: first sight false, replay true", () => {
    const s = new SeenJtiStore({ dir: env.stateDir });
    const exp = Math.floor(Date.now() / 1000) + 3600;
    assert.equal(s.checkAndMark("jti-1", exp), false);
    assert.equal(s.checkAndMark("jti-1", exp), true);
    assert.equal(s.has("jti-1"), true);
    assert.equal(s.has("jti-never-seen"), false);
  });

  it("survives process restart via the same directory", () => {
    const a = new SeenJtiStore({ dir: env.stateDir });
    const exp = Math.floor(Date.now() / 1000) + 3600;
    assert.equal(a.checkAndMark("jti-restart", exp), false);
    const b = new SeenJtiStore({ dir: env.stateDir }); // "restart"
    assert.equal(b.checkAndMark("jti-restart", exp), true);
    assert.equal(b.size() >= 1, true);
  });

  it("prunes entries whose exp + ttl floor has passed", () => {
    const s = new SeenJtiStore({ dir: env.stateDir, ttlFloorSec: 0 });
    const past = Math.floor(Date.now() / 1000) - 10;
    // Directly write a stale entry, then reload through a fresh instance.
    s.checkAndMark("jti-stale", past);
    const fresh = new SeenJtiStore({ dir: env.stateDir, ttlFloorSec: 0 });
    assert.equal(fresh.has("jti-stale"), false);
  });

  it("keeps entries until exp + ttlFloorSec even after expiry", () => {
    const s = new SeenJtiStore({ dir: env.stateDir, ttlFloorSec: 86400 });
    const past = Math.floor(Date.now() / 1000) - 10;
    s.checkAndMark("jti-recent-exp", past);
    const fresh = new SeenJtiStore({ dir: env.stateDir, ttlFloorSec: 86400 });
    assert.equal(fresh.has("jti-recent-exp"), true);
  });

  it("tolerates a corrupt store file by starting empty", () => {
    const corruptDir = path.join(env.stateDir, "corrupt");
    fs.mkdirSync(corruptDir, { recursive: true });
    fs.writeFileSync(path.join(corruptDir, "seen-jti.json"), "{not json");
    const s = new SeenJtiStore({ dir: corruptDir });
    assert.equal(s.size(), 0);
    assert.equal(s.checkAndMark("jti-after-corrupt", Math.floor(Date.now() / 1000) + 60), false);
  });
});

describe("SeenJtiStore prototype safety (Minor 4)", () => {
  it("prototype-named jtis are not false positives", () => {
    const dir = env.stateDir + "-proto";
    const s = new SeenJtiStore({ dir });
    const exp = Math.floor(Date.now() / 1000) + 3600;
    // "toString" lives on Object.prototype: `in` would always report it as
    // already seen. hasOwnProperty must not.
    assert.equal(s.has("toString"), false);
    assert.equal(s.checkAndMark("toString", exp), false); // first sight: not a replay
    assert.equal(s.has("toString"), true);
    assert.equal(s.checkAndMark("toString", exp), true); // now genuinely seen
    assert.equal(s.checkAndMark("__proto__", exp), false);
    assert.equal(s.checkAndMark("__proto__", exp), true);
    // The persisted file round-trips without prototype pollution.
    const fresh = new SeenJtiStore({ dir });
    assert.equal(fresh.has("__proto__"), true);
    assert.equal(fresh.has("toString"), true);
  });
});
