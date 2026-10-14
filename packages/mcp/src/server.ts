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
  appendRevocation,
  defaultStateDir,
} from "@tamtunnel/agentcred-core";

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
        "Verify an AgentCred passport against a merchant policy. Consumption semantics: " +
        "on success the leaf jti is consumed in BOTH the merchant's persistent replay store " +
        "and the wallet replay ledger — presenting it twice fails. On failure (bad signature, " +
        "revocation, policy reject, replay) nothing is consumed, so a passport rejected on " +
        "policy can be re-presented; only a successful verification burns it.",
      inputSchema: z.object({
        passport: z.string().describe("Canonical passport JSON from issue_passport"),
        merchantId: z.string().describe("This merchant's own identifier (aud binding)"),
        allowedActions: z.array(z.string()).optional(),
        maxAmount: z.number().nonnegative().optional(),
        maxTtlSec: z.number().int().positive().optional(),
        trustedRevokers: z.array(z.string()).optional()
          .describe("DIDs allowed to publish revocation lists (default: the passport's root owner)"),
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
        "jti from then on. The list defaults to a 366-day lifetime so revocations " +
        "outlive the longest credentials they can revoke; a shorter ttlDays warns loudly. " +
        "Needs SI_WALLET_PASSPHRASE and the owner identity.",
      inputSchema: z.object({
        jti: z.string().describe("The jti to revoke (leaf passport or ancestor grant)"),
        ttlDays: z.number().positive().default(366)
          .describe("How long the revocation list itself stays valid (default 366; shorter warns)"),
        stateDir: z.string().optional(),
      }),
    },
    wrap(async ({ jti, ttlDays, stateDir }) => {
      const owner = getDid("owner");
      const dir = stateDir || defaultStateDir();
      // Shared, file-locked append: concurrent revokes serialize, history is
      // merged even from expired cached lists, and seq always increases.
      return appendRevocation({
        dir,
        jti,
        ttlDays,
        issuerDid: owner.did,
        verifySignature: (j) => verifyRevocationJws(j),
        // Signed with the owner's key through the audited core's canonical
        // signer — raw key material never leaves the encrypted keystore.
        sign: (payload) => signJwsWithRole({ ...payload }, "owner"),
      });
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
