// packages/merchant/src/index.ts — @tamtunnel/agentcred-merchant
//
// The merchant SDK. Dependency-free and tiny: one pure `verifyPassport()`
// plus thin middleware adapters for Express, Fastify and Hono. The adapters
// are written against each framework's (req, res, next) shape without
// importing the framework, so this package has zero runtime dependencies.
//
// The agent presents its passport as:
//
//   Authorization: Passport <canonical-json-envelope>
//
// or, for form/JSON checkouts, as `passport` in the parsed body.

import {
  verifyPassport as verifyPassportCore,
  inspectPassport,
  WalletError,
  defaultStateDir,
} from "@tamtunnel/agentcred-core";
import type {
  VerifyPolicy,
  VerifyPassportResult,
} from "@tamtunnel/agentcred-core";

export type { VerifyPolicy, VerifyPassportResult };
export { WalletError, inspectPassport, defaultStateDir };

/** Pure verification: no I/O beyond the state dir (replay store + CRL cache). */
export function verifyPassport(
  passport: string,
  policy: VerifyPolicy
): VerifyPassportResult {
  return verifyPassportCore(passport, policy);
}

// ------------------------------------------------------------------ helpers

function extractPassport(req: {
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
}): string | null {
  const headers = req.headers || {};
  const rawAuth = headers["authorization"] ?? headers["Authorization"];
  const auth = Array.isArray(rawAuth) ? rawAuth[0] : rawAuth;
  if (typeof auth === "string") {
    const m = /^\s*Passport\s+(.+)\s*$/i.exec(auth);
    if (m) return m[1];
  }
  const body = req.body as Record<string, unknown> | undefined;
  if (body && typeof body.passport === "string" && body.passport) {
    return body.passport;
  }
  return null;
}

export interface VerifiedPassportRequest {
  agentcred?: VerifyPassportResult & { ok: true };
}

// ------------------------------------------------------- framework adapters

export interface MerchantMiddlewareOptions extends VerifyPolicy {
  /** Where to stash the verified result on the request. Default "agentcred". */
  requestKey?: string;
  /** Map a failed verification to an HTTP status. Default 402. */
  failureStatus?: number;
}

/**
 * Express / Connect middleware.
 * On success: req[requestKey] = verification result, next().
 * On failure: 402 (or failureStatus) JSON { ok:false, reason }.
 */
export function expressMiddleware(opts: MerchantMiddlewareOptions) {
  const key = opts.requestKey || "agentcred";
  const failureStatus = opts.failureStatus || 402;
  return function agentcredAuth(
    req: Record<string, any>,
    res: Record<string, any>,
    next: (err?: unknown) => void
  ): void {
    const token = extractPassport(req);
    if (!token) {
      res.status(failureStatus).json({ ok: false, reason: "missing AgentCred passport" });
      return;
    }
    const result = verifyPassport(token, opts);
    if (!result.ok) {
      res.status(failureStatus).json({ ok: false, reason: result.reason });
      return;
    }
    req[key] = result;
    next();
  };
}

/**
 * Fastify plugin. Registers an `onRequest` hook; verified result lands on
 * `request[requestKey]`. Failures reply 402 JSON.
 */
export function fastifyPlugin(opts: MerchantMiddlewareOptions) {
  const key = opts.requestKey || "agentcred";
  const failureStatus = opts.failureStatus || 402;
  return function agentcredFastify(
    fastify: Record<string, any>,
    _opts: unknown,
    done: () => void
  ): void {
    fastify.addHook(
      "onRequest",
      (req: Record<string, any>, reply: Record<string, any>, next: (err?: unknown) => void) => {
        const token = extractPassport(req);
        if (!token) {
          reply.code(failureStatus).send({ ok: false, reason: "missing AgentCred passport" });
          return;
        }
        const result = verifyPassport(token, opts);
        if (!result.ok) {
          reply.code(failureStatus).send({ ok: false, reason: result.reason });
          return;
        }
        req[key] = result;
        next();
      }
    );
    done();
  };
}

/**
 * Hono middleware. Reads the Authorization header, verifies, stores the
 * result with `c.set(key, result)`, and continues. Failures return 402 JSON.
 */
export function honoMiddleware(opts: MerchantMiddlewareOptions) {
  const key = opts.requestKey || "agentcred";
  const failureStatus = opts.failureStatus || 402;
  return async function agentcredHono(c: Record<string, any>, next: () => Promise<void>) {
    const auth = c.req.header("authorization") || "";
    const token = extractPassport({ headers: { authorization: auth } });
    if (!token) {
      return c.json({ ok: false, reason: "missing AgentCred passport" }, failureStatus);
    }
    const result = verifyPassport(token, opts);
    if (!result.ok) {
      return c.json({ ok: false, reason: result.reason }, failureStatus);
    }
    c.set(key, result);
    await next();
  };
}
