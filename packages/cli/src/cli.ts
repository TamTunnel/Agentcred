#!/usr/bin/env node
// packages/cli/src/cli.ts — `agentcred` issuance/inspection CLI.
//
//   agentcred init [--passphrase-env VAR]
//   agentcred did [--role owner|agent]
//   agentcred grant --agent-did <did> --scope purchase --amount-limit 50
//   agentcred issue --merchant <id> --amount-limit 25 --actions purchase \
//       --grant <file|jws> [--ttl-sec 900] [--task "..."]
//   agentcred verify --passport <file|json> --merchant <id> [--max-amount N]
//   agentcred inspect --passport <file|json>
//   agentcred revoke --jti <jti>
//
// Keystore passphrase comes from SI_WALLET_PASSPHRASE (or SOV_ID_PASSPHRASE),
// state dir from AGENTCRED_STATE_DIR (default ~/.agentcred).

import fs from "node:fs";
import {
  WalletError,
  onboard,
  getDid,
  issueGrant,
  issuePassport,
  inspectPassport,
  verifyPassport,
  verifyRevocationJws,
  signJwsWithRole,
  RevocationCache,
  defaultStateDir,
  fingerprint,
} from "@tamtunnel/agentcred-core";

function usage(): never {
  console.error(`agentcred — AgentCred passport CLI

Usage:
  agentcred init                              create owner+agent identities
  agentcred did [--role owner|agent]          show a DID
  agentcred grant --agent-did DID --scope S[,S] --amount-limit N [--ttl-days D] [--note T]
  agentcred issue --merchant ID --amount-limit N --actions A[,A] --grant FILE|JWS
                  [--ttl-sec S] [--task T] [--currency USD] [--confirm-over-limit]
  agentcred verify --passport FILE|JSON --merchant ID [--max-amount N]
                   [--allowed-actions A[,A]] [--max-ttl-sec S] [--state-dir D]
  agentcred inspect --passport FILE|JSON      decode without verifying
  agentcred revoke --jti JTI [--ttl-days D]   owner revokes a jti (signed CRL)

Env: SI_WALLET_PASSPHRASE (keystore), SI_WALLET_DIR (keystore dir),
     AGENTCRED_STATE_DIR (replay store + revocation cache).`);
  process.exit(2);
}

function parseArgs(argv: string[]): { cmd: string; opts: Record<string, string | boolean> } {
  const [cmd, ...rest] = argv;
  if (!cmd) usage();
  const opts: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next === undefined || next.startsWith("--")) {
        opts[key] = true;
      } else {
        opts[key] = next;
        i++;
      }
    } else {
      usage();
    }
  }
  return { cmd, opts };
}

function need(opts: Record<string, string | boolean>, k: string): string {
  const v = opts[k];
  if (typeof v !== "string" || !v) {
    console.error(`missing required --${k}`);
    usage();
  }
  return v as string;
}

/** Accept either a path to a file or the raw value. */
function readMaybeFile(v: string): string {
  if (v.length < 4096) {
    try {
      if (fs.existsSync(v) && fs.statSync(v).isFile()) {
        return fs.readFileSync(v, "utf8").trim();
      }
    } catch {
      /* fall through: treat as raw value */
    }
  }
  return v.trim();
}

function out(obj: unknown): void {
  console.log(JSON.stringify(obj, null, 2));
}

async function main(): Promise<void> {
  const { cmd, opts } = parseArgs(process.argv.slice(2));
  try {
    switch (cmd) {
      case "init": {
        const owner = onboard("owner");
        const agent = onboard("agent");
        out({ ok: true, owner, agent });
        break;
      }
      case "did": {
        const role = (opts["role"] as string) || "agent";
        out({ ok: true, ...getDid(role) });
        break;
      }
      case "grant": {
        const res = issueGrant({
          agentDid: need(opts, "agent-did"),
          scope: need(opts, "scope"),
          amountLimit: Number(need(opts, "amount-limit")),
          ttlDays: opts["ttl-days"] ? Number(opts["ttl-days"]) : 365,
          note: (opts["note"] as string) || "",
        });
        out({ ok: true, ...res });
        break;
      }
      case "issue": {
        const actions = need(opts, "actions").split(",");
        const res = issuePassport({
          merchant: need(opts, "merchant"),
          amountLimit: Number(need(opts, "amount-limit")),
          currency: (opts["currency"] as string) || "USD",
          actions,
          ttlSec: opts["ttl-sec"] ? Number(opts["ttl-sec"]) : 900,
          task: (opts["task"] as string) || "",
          grantJws: readMaybeFile(need(opts, "grant")),
          confirmOverLimit: opts["confirm-over-limit"] === true,
        });
        out({ ok: true, passport: res.passport, agent: res.agent, merchant: res.merchant, expires: res.expires });
        break;
      }
      case "verify": {
        const allowed = opts["allowed-actions"]
          ? String(opts["allowed-actions"]).split(",").map((s) => s.trim()).filter(Boolean)
          : undefined;
        const res = verifyPassport(readMaybeFile(need(opts, "passport")), {
          merchantId: need(opts, "merchant"),
          allowedActions: allowed,
          maxAmount: opts["max-amount"] !== undefined ? Number(opts["max-amount"]) : undefined,
          maxTtlSec: opts["max-ttl-sec"] !== undefined ? Number(opts["max-ttl-sec"]) : undefined,
          stateDir: (opts["state-dir"] as string) || undefined,
        });
        out(res);
        process.exitCode = res.ok ? 0 : 1;
        break;
      }
      case "inspect": {
        out({ ok: true, ...inspectPassport(readMaybeFile(need(opts, "passport"))) });
        break;
      }
      case "revoke": {
        const jti = need(opts, "jti");
        const ttlDays = opts["ttl-days"] ? Number(opts["ttl-days"]) : 30;
        const owner = getDid("owner");
        const now = Math.floor(Date.now() / 1000);
        const dir = defaultStateDir();
        const cache = new RevocationCache({ dir, trustedIssuers: [owner.did] });
        const revoked = new Set<string>(cache.revokedJtis((j) => verifyRevocationJws(j)));
        let seq = 0;
        try {
          const raw = JSON.parse(fs.readFileSync(`${dir}/revocation.json`, "utf8"));
          if (raw[owner.did]) seq = verifyRevocationJws(raw[owner.did].jws).seq;
        } catch {
          /* none cached */
        }
        revoked.add(jti);
        const payload = {
          iss: owner.did,
          iat: now,
          exp: now + Math.floor(ttlDays * 86400),
          revoked: [...revoked].sort(),
          seq: seq + 1,
        };
        const jws = signJwsWithRole(payload, "owner");
        cache.ingest(jws, (j) => verifyRevocationJws(j));
        out({ ok: true, revoked: jti, issuer: owner.did, issuer_fingerprint: fingerprint(owner.did), total: revoked.size, seq: seq + 1 });
        break;
      }
      default:
        console.error(`unknown command: ${cmd}`);
        usage();
    }
  } catch (e) {
    const code = e instanceof WalletError ? e.code : "internal_error";
    console.error(JSON.stringify({ ok: false, code, error: (e as Error).message }));
    process.exit(1);
  }
}

main();
