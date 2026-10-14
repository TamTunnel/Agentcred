// packages/si-wallet-core/test/helpers.ts — isolated env per test file.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface TestEnv {
  walletDir: string;
  cleanup: () => void;
}

export function setupTestEnv(): TestEnv {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "agentcred-test-"));
  const walletDir = path.join(base, "wallet");
  fs.mkdirSync(walletDir, { recursive: true });
  process.env.SI_WALLET_DIR = walletDir;
  process.env.SI_WALLET_PASSPHRASE = "test-passphrase-REDACTED";
  return { walletDir, cleanup: () => fs.rmSync(base, { recursive: true, force: true }) };
}
