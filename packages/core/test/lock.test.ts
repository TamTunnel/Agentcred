// packages/core/test/lock.test.ts — crash-safe lock semantics (Minor 5).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { setupTestEnv, type TestEnv } from "./helpers.ts";
import { withFileLock } from "@tamtunnel/agentcred-core";

const run = promisify(execFile);
const CORE_DIST = new URL("../../core/dist/index.js", import.meta.url).href;

let env: TestEnv;
before(() => {
  env = setupTestEnv();
});
after(() => env.cleanup());

describe("withFileLock", () => {
  it("breaks a provably-stale lock instead of deadlocking", () => {
    const dir = path.join(env.stateDir, "lock-stale");
    fs.mkdirSync(dir, { recursive: true });
    const lockFile = path.join(dir, "x.lock");
    // Simulate a crashed holder: 60s-old timestamp, no live process.
    fs.writeFileSync(lockFile, JSON.stringify({ pid: 999999999, ts: Date.now() - 60000 }));
    const started = Date.now();
    const out = withFileLock(lockFile, () => "acquired");
    assert.equal(out, "acquired");
    assert.ok(Date.now() - started < 5000, "stale lock must be broken without a long wait");
    assert.ok(!fs.existsSync(lockFile), "lock released after the critical section");
  });

  it("breaks an unparseable (legacy/foreign) lock file", () => {
    const dir = path.join(env.stateDir, "lock-legacy");
    fs.mkdirSync(dir, { recursive: true });
    const lockFile = path.join(dir, "x.lock");
    fs.writeFileSync(lockFile, ""); // empty: no stamp, cannot be a live holder
    assert.equal(withFileLock(lockFile, () => 42), 42);
  });

  it("does not evict a fresh lock held by another process", async () => {
    const dir = path.join(env.stateDir, "lock-fresh");
    fs.mkdirSync(dir, { recursive: true });
    const lockFile = path.join(dir, "x.lock");
    // Child holds the lock for ~2s. The parent must wait for the release,
    // not break the fresh lock — the old code would have broken it.
    const holderCode = `
      import(${JSON.stringify(CORE_DIST)}).then(async (core) => {
        core.withFileLock(${JSON.stringify(lockFile)}, () => {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2000);
          return "held";
        });
      }).catch((e) => { console.error(e); process.exit(1); });
    `;
    const child = run(process.execPath, ["--input-type=module", "-e", holderCode]);
    // Wait until the child actually holds the lock (the file only exists
    // while held), so the parent is guaranteed to contend with it.
    const t0 = Date.now();
    while (!fs.existsSync(lockFile) && Date.now() - t0 < 10000) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(fs.existsSync(lockFile), "child never took the lock");
    const started = Date.now();
    const out = withFileLock(lockFile, () => "parent-acquired");
    const waited = Date.now() - started;
    await child;
    assert.equal(out, "parent-acquired");
    assert.ok(waited >= 1000, `parent must have waited for release (waited ${waited}ms)`);
  });

  it("serializes concurrent writers", async () => {
    const dir = path.join(env.stateDir, "lock-concurrent");
    fs.mkdirSync(dir, { recursive: true });
    const lockFile = path.join(dir, "x.lock");
    const counterFile = path.join(dir, "counter.txt");
    fs.writeFileSync(counterFile, "0");
    const workerCode = `
      import(${JSON.stringify(CORE_DIST)}).then(async (core) => {
        const fs = await import("node:fs");
        for (let i = 0; i < 20; i++) {
          core.withFileLock(${JSON.stringify(lockFile)}, () => {
            const n = Number(fs.readFileSync(${JSON.stringify(counterFile)}, "utf8"));
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
            fs.writeFileSync(${JSON.stringify(counterFile)}, String(n + 1));
          });
        }
      }).catch((e) => { console.error(e); process.exit(1); });
    `;
    await Promise.all(
      [0, 1, 2].map(() =>
        run(process.execPath, ["--input-type=module", "-e", workerCode])
      )
    );
    assert.equal(fs.readFileSync(counterFile, "utf8"), "60");
  });
});
