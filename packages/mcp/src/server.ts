// packages/mcp/src/server.ts — AgentCred as an MCP server.
//
// Tools:
//   issue_passport  — agent (or owner on its behalf) mints a merchant-scoped,
//                     short-lived passport against an agency grant.
//   verify_passport — merchant-side verification against a policy.
//   revoke          — owner adds a passport/grant jti to the signed
//                     revocation list.
//
// Transports mirror si-wallet-mcp: stdio by default, streamable HTTP with
// `node src/server.ts --http --port 8787` (requires AGENTCRED_MCP_TOKEN).
//
// Whoever can reach this process can ask it to sign: run one server per user,
// on hardware the user controls.

import http from "node:http";
import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";
import {
  WalletError,
  getDid,
  issuePassport,
  inspectPassport,
  verifyPassport,
  verifyRevocationJws,
  signJwsWithRole,
  RevocationCache,
  defaultStateDir,
} from "@tamtunnel/agentcred-core";
import fs from "node:fs";

const VERSION = "0.1.0";

function makeServer() {
  const server = new McpServer(
    { name: "agentcred", version: VERSION },
    { capabilities: {} }
  );

  const ok = (data: unknown): CallToolResult => ({
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  });
  const wrap =
    (fn: (args: any) => unknown) =>
    async (args: any): Promise<CallToolResult> => {
      try {
        return ok(await fn(args));
      } catch (e) {
        const code = e instanceof WalletError ? e.code : "internal_error";
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ ok: false, code, error: (e as Error).message }),
            },
          ],
          isError: true,
        };
      }
    };

  server.registerTool(
    "issue_passport",
    {
      description:
        "Issue an AgentCred passport: a merchant-scoped, short-lived signed mandate chain " +
        "the agent presents at checkout instead of a card. Needs SI_WALLET_PASSPHRASE and an " +
        "agency grant (owner → this agent).",
      inputSchema: z.object({
        merchant: z.string().describe("Merchant identifier, e.g. merchant:acme.example.invalid"),
        amountLimit: z.number().nonnegative().describe("Max spend, major currency units"),
        currency: z.string().default("USD"),
        actions: z.array(z.string()).min(1).describe("Allowed actions, e.g. [\"purchase\"]"),
        ttlSec: z.number().int().min(60).max(4 * 3600).default(900)
          .describe("Passport lifetime in seconds (60–14400)"),
        task: z.string().default("").describe("Human-readable task description (not signed policy)"),
        grantJws: z.string().describe("Agency grant JWS backing this agent"),
        confirmOverLimit: z.boolean().default(false)
          .describe("Required when amountLimit exceeds the $100 consent threshold"),
      }),
    },
    wrap(async (a) => issuePassport(a))
  );

  server.registerTool(
    "verify_passport",
    {
      description:
        "Verify an AgentCred passport against a merchant policy. Consumes the passport's " +
        "jti in the persistent replay store on success — presenting it twice fails.",
      inputSchema: z.object({
        passport: z.string().describe("Canonical passport JSON from issue_passport"),
        merchantId: z.string().describe("This merchant's own identifier (aud binding)"),
        allowedActions: z.array(z.string()).optional(),
        maxAmount: z.number().nonnegative().optional(),
        maxTtlSec: z.number().int().positive().optional(),
        stateDir: z.string().optional().describe("Override for the replay/CRL state dir"),
      }),
    },
    wrap(async (a) => {
      const { passport, ...policy } = a;
      return verifyPassport(passport, policy);
    })
  );

  server.registerTool(
    "inspect_passport",
    {
      description:
        "Decode a passport envelope and its mandate chain without verifying signatures. " +
        "Shows agent/owner DIDs, scope, amounts and expiry per hop. No PII is ever present.",
      inputSchema: z.object({
        passport: z.string(),
      }),
    },
    wrap(async ({ passport }) => inspectPassport(passport))
  );

  server.registerTool(
    "revoke",
    {
      description:
        "Owner revokes a passport (or grant) by jti: appends it to the owner's SIGNED " +
        "revocation list. Verifiers whose trustedRevokers include the owner reject the " +
        "jti from then on. Needs SI_WALLET_PASSPHRASE and the owner identity.",
      inputSchema: z.object({
        jti: z.string().describe("The jti to revoke (leaf passport or ancestor grant)"),
        ttlDays: z.number().positive().default(30)
          .describe("How long the revocation list itself stays valid"),
        stateDir: z.string().optional(),
      }),
    },
    wrap(async ({ jti, ttlDays, stateDir }) => {
      const owner = getDid("owner");
      const now = Math.floor(Date.now() / 1000);
      const dir = stateDir || defaultStateDir();
      // Merge with the cached list so revocations accumulate (seq++ wins).
      const cache = new RevocationCache({ dir, trustedIssuers: [owner.did] });
      const revoked = new Set<string>(cache.revokedJtis((j) => verifyRevocationJws(j)));
      let seq = 0;
      try {
        const raw = JSON.parse(fs.readFileSync(`${dir}/revocation.json`, "utf8"));
        if (raw[owner.did]) seq = verifyRevocationJws(raw[owner.did].jws).seq;
      } catch {
        /* no cached list yet */
      }
      revoked.add(jti);
      const payload = {
        iss: owner.did,
        iat: now,
        exp: now + Math.floor(ttlDays * 86400),
        revoked: [...revoked].sort(),
        seq: seq + 1,
      };
      // Signed with the owner's key through the audited core's canonical
      // signer — raw key material never leaves the encrypted keystore.
      const jws = signJwsWithRole(payload, "owner");
      cache.ingest(jws, (j) => verifyRevocationJws(j));
      return { ok: true, revoked: jti, issuer: owner.did, total: revoked.size, seq: seq + 1 };
    })
  );

  return server;
}

async function main() {
  const args = process.argv.slice(2);
  const server = makeServer();
  if (args.includes("--http")) {
    const port = Number(process.env.AGENTCRED_MCP_PORT || 8787);
    const token = process.env.AGENTCRED_MCP_TOKEN;
    if (!token) {
      console.error("AGENTCRED_MCP_TOKEN is required for --http mode");
      process.exit(1);
    }
    const handler = createMcpHandler(() => makeServer());
    const readBody = (req: http.IncomingMessage): Promise<Buffer> =>
      new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        req.on("data", (c) => chunks.push(c));
        req.on("end", () => resolve(Buffer.concat(chunks)));
        req.on("error", reject);
      });
    const srv = http.createServer(async (req, res) => {
      try {
        if (req.headers.authorization !== `Bearer ${token}`) {
          res.writeHead(401).end("unauthorized");
          return;
        }
        const body = await readBody(req);
        const webReq = new Request(`http://127.0.0.1:${port}${req.url || "/mcp"}`, {
          method: req.method,
          headers: req.headers as unknown as HeadersInit,
          body: body.length ? new Uint8Array(body) : undefined,
        });
        const webRes: Response = await handler.fetch(webReq);
        const headers: Record<string, string> = {};
        webRes.headers.forEach((v, k) => {
          headers[k] = v;
        });
        res.writeHead(webRes.status, headers);
        res.end(Buffer.from(await webRes.arrayBuffer()));
      } catch (e) {
        res.writeHead(500).end("internal error");
      }
    });
    srv.listen(port, "127.0.0.1", () =>
      console.error(`agentcred-mcp listening on 127.0.0.1:${port}`)
    );
  } else {
    await server.connect(new StdioServerTransport());
  }
}

// ESM entry-point guard that also works under node --test imports.
const isMain =
  process.argv[1] &&
  import.meta.url.endsWith(process.argv[1].split("/").pop() || "");
if (isMain) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

export { makeServer };
