// packages/core/src/store.ts
//
// File-backed seen-jti cache. An in-memory-only replay cache is a replay hole
// after every merchant restart, so seen JTIs persist to disk with a TTL at
// least as long as the longest passport the merchant will ever accept.
//
// Layout: <dir>/seen-jti.json  ->  { "<jti>": <exp epoch seconds>, ... }
// The file is written mode 600. Expired entries are pruned on load and on
// every mark. A process-wide lock file serializes concurrent writers.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function defaultStateDir(): string {
  return (
    process.env.AGENTCRED_STATE_DIR || path.join(os.homedir(), ".agentcred")
  );
}

export interface SeenJtiStoreOptions {
  dir?: string;
  /** TTL floor in seconds; entries are kept until max(exp, now + ttlFloor). */
  ttlFloorSec?: number;
}

export class SeenJtiStore {
  private file: string;
  private lockFile: string;
  private ttlFloorSec: number;

  constructor(opts: SeenJtiStoreOptions = {}) {
    const dir = opts.dir || path.join(defaultStateDir(), "merchant");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = path.join(dir, "seen-jti.json");
    this.lockFile = path.join(dir, "seen-jti.lock");
    this.ttlFloorSec = opts.ttlFloorSec ?? 86400; // ≥ max passport expiry
  }

  /**
   * Serialize writers with an atomic lock file (O_CREAT|O_EXCL). Spins briefly;
   * the critical section is a tiny JSON read-modify-write.
   */
  private withLock<T>(fn: () => T): T {
    const deadline = Date.now() + 5000;
    while (true) {
      let fd: number | null = null;
      try {
        fd = fs.openSync(this.lockFile, "wx", 0o600);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
      if (fd !== null) {
        try {
          return fn();
        } finally {
          fs.closeSync(fd);
          try {
            fs.unlinkSync(this.lockFile);
          } catch {
            /* already gone */
          }
        }
      }
      if (Date.now() > deadline) {
        // Stale lock (crashed holder): break it rather than deadlock.
        try {
          fs.unlinkSync(this.lockFile);
        } catch {
          /* raced */
        }
        continue;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }

  private load(): Record<string, number> {
    let data: Record<string, number> = {};
    try {
      data = JSON.parse(fs.readFileSync(this.file, "utf8"));
    } catch {
      data = {};
    }
    const now = Math.floor(Date.now() / 1000);
    let dirty = false;
    for (const [jti, exp] of Object.entries(data)) {
      // Keep until exp passes AND the TTL floor has elapsed since we saw it.
      if (typeof exp !== "number" || exp + this.ttlFloorSec < now) {
        delete data[jti];
        dirty = true;
      }
    }
    if (dirty) this.save(data);
    return data;
  }

  private save(data: Record<string, number>): void {
    const tmp = this.file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  /** True if this jti was already consumed (replay). */
  has(jti: string): boolean {
    return this.withLock(() => jti in this.load());
  }

  /**
   * Atomically check-and-mark: returns false (and marks) on first sight,
   * true when the jti was already seen — i.e. a replay.
   */
  checkAndMark(jti: string, exp: number): boolean {
    return this.withLock(() => {
      const data = this.load();
      if (jti in data) return true;
      data[jti] = exp;
      this.save(data);
      return false;
    });
  }

  size(): number {
    return this.withLock(() => Object.keys(this.load()).length);
  }
}
