// packages/mcp/test/server.test.ts — stdio smoke test for the AgentCred MCP
// server: initialize handshake, tools/list, and a tools/call round-trip.
// Spawns the real server in an isolated env.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SERVER = new URL("../src/server.ts", import.meta.url).pathname;

let base: string;
before(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "agentcred-mcp-"));
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

interface RpcClient {
  call: (method: string, params?: unknown) => Promise<any>;
  notify: (method: string, params?: unknown) => void;
  close: () => void;
}

function startServer(): Promise<{ client: RpcClient; proc: ChildProcess }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [SERVER], {
      stdio: ["pipe", "pipe", "inherit"],
      env: {
        ...process.env,
        SI_WALLET_DIR: path.join(base, "wallet"),
        SI_WALLET_PASSPHRASE: "test-passphrase-REDACTED",
        AGENTCRED_STATE_DIR: path.join(base, "state"),
      },
    });
    let rid = 0;
    let buf = "";
    const pending = new Map<number, (msg: any) => void>();
    proc.stdout!.on("data", (d: Buffer) => {
      buf += d.toString();
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) continue;
        let msg: any;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.id !== undefined && pending.has(msg.id)) {
          pending.get(msg.id)!(msg);
          pending.delete(msg.id);
        }
      }
    });
    proc.on("error", reject);
    const client: RpcClient = {
      call: (method, params) =>
        new Promise((res, rej) => {
          const id = ++rid;
          const timer = setTimeout(() => {
            pending.delete(id);
            rej(new Error(`rpc timeout: ${method}`));
          }, 15000);
          pending.set(id, (msg) => {
            clearTimeout(timer);
            if (msg.error) rej(new Error(JSON.stringify(msg.error)));
            else res(msg.result);
          });
          proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        }),
      notify: (method, params) => {
        proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
      },
      close: () => proc.kill(),
    };
    // Wait for the process to be responsive: poll initialize.
    const ready = async () => {
      for (let n = 0; n < 50; n++) {
        try {
          await client.call("initialize", {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "agentcred-test", version: "0.1.0" },
          });
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 200));
        }
      }
      throw new Error("server never became ready");
    };
    ready()
      .then(() => resolve({ client, proc }))
      .catch(reject);
  });
}

describe("agentcred-mcp (stdio)", () => {
  it("handshakes, lists 4 tools, and round-trips verify_passport", async () => {
    const { client } = await startServer();
    try {
      const init = await client.call("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "agentcred-test", version: "0.1.0" },
      });
      assert.ok(init.serverInfo);
      assert.equal(init.serverInfo.name, "agentcred");
      client.notify("notifications/initialized");

      const tools = await client.call("tools/list", {});
      const names = tools.tools.map((t: any) => t.name).sort();
      assert.deepEqual(names, [
        "inspect_passport",
        "issue_passport",
        "revoke",
        "verify_passport",
      ]);

      // verify_passport with garbage fails closed (ok:false, not a crash).
      const bad = await client.call("tools/call", {
        name: "verify_passport",
        arguments: { passport: "garbage", merchantId: "merchant:x.example.invalid" },
      });
      const parsed = JSON.parse(bad.content[0].text);
      assert.equal(parsed.ok, false);

      // issue_passport without a wallet identity returns a structured error.
      const issue = await client.call("tools/call", {
        name: "issue_passport",
        arguments: {
          merchant: "merchant:shop.example.invalid",
          amountLimit: 10,
          actions: ["purchase"],
          grantJws: "bogus",
        },
      });
      const issueParsed = JSON.parse(issue.content[0].text);
      assert.equal(issueParsed.ok, false);
      assert.ok(issueParsed.code || issueParsed.error);
    } finally {
      client.close();
    }
  });
});
