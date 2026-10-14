// packages/core/src/lock.ts
//
// Crash-safe file lock shared by the replay store and the revocation cache.
//
// The lock file carries a JSON payload { pid, ts } written immediately after
// the atomic O_CREAT|O_EXCL create. A contender may only break a lock whose
// recorded age exceeds `staleAfterMs` — never a fresh lock, even after
// waiting. Breaking a young lock while its holder is still in the critical
// section (e.g. slow disk) would let two processes enter it at once.
//
// A crashed holder stops refreshing nothing — the timestamp is written once,
// so any lock older than `staleAfterMs` is provably abandoned (the critical
// sections guarded here are tiny read-modify-writes).

import fs from "node:fs";
import { WalletError } from "@tamtunnel/si-wallet-core";

export const STALE_LOCK_AFTER_MS = 30_000;
const MAX_WAIT_MS = 120_000;

export interface FileLockOptions {
  /** Break a lock only when older than this. Default 30s. */
  staleAfterMs?: number;
}

/**
 * Run `fn` with exclusive ownership of `lockFile`. The lock file is created
 * mode 600, stamped with { pid, ts }, and removed afterwards.
 */
export function withFileLock<T>(
  lockFile: string,
  fn: () => T,
  opts: FileLockOptions = {}
): T {
  const staleAfterMs = opts.staleAfterMs ?? STALE_LOCK_AFTER_MS;
  const start = Date.now();
  while (true) {
    let fd: number | null = null;
    try {
      fd = fs.openSync(lockFile, "wx", 0o600);
      // Stamp immediately: a contender must be able to tell a fresh lock
      // from an abandoned one the moment it sees the file.
      fs.writeSync(fd, JSON.stringify({ pid: process.pid, ts: Date.now() }));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    if (fd !== null) {
      try {
        return fn();
      } finally {
        fs.closeSync(fd);
        try {
          fs.unlinkSync(lockFile);
        } catch {
          /* already gone */
        }
      }
    }
    // Someone else holds it. Break it only if provably stale; otherwise wait.
    // An unreadable or unparseable lock file is treated as infinitely old —
    // every writer stamps JSON, so a foreign/legacy file cannot be live.
    let ageMs = Infinity;
    try {
      const raw = JSON.parse(fs.readFileSync(lockFile, "utf8")) as { ts?: unknown };
      if (typeof raw?.ts === "number") ageMs = Date.now() - raw.ts;
    } catch {
      /* unreadable: treat as stale */
    }
    if (ageMs > staleAfterMs) {
      try {
        fs.unlinkSync(lockFile);
      } catch {
        /* raced with the holder's own release */
      }
      continue;
    }
    if (Date.now() - start > MAX_WAIT_MS) {
      throw new WalletError(
        `timed out waiting for lock ${lockFile} (holder still active)`,
        "lock_timeout"
      );
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  }
}
