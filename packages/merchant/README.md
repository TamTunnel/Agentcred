# @tamtunnel/agentcred-merchant

Merchant SDK for AgentCred: a pure `verifyPassport()` plus dependency-free middleware for Express, Fastify, and Hono. Zero runtime dependencies.

```ts
import { expressMiddleware } from "@tamtunnel/agentcred-merchant";

app.post("/checkout",
  expressMiddleware({
    merchantId: "merchant:acme.example.invalid", // leaf aud must equal this
    allowedActions: ["purchase"],
    maxAmount: 50,
    allowedCurrencies: ["USD"],               // fail closed on any other currency
    maxTtlSec: 1800,
    stateDir: "/var/lib/agentcred",              // replay store + CRL cache
  }),
  (req, res) => {
    // ok:true means the crypto checks out — NOT "charge this card".
    // Self-issued passports verify by design: bind req.agentcred.owner
    // to a customer account you recognize before fulfilling.
    const customer = lookupCustomerByAgentCredOwner(req.agentcred.owner);
    if (!customer) return res.status(402).json({ ok: false, reason: "unknown owner" });
    res.json({ ok: true, charged: req.agentcred.amount_limit });
  });
```

The agent presents its passport as `Authorization: Passport <canonical-json>` or as a `passport` field in the JSON body. On success the verified result lands on `req.agentcred` (configurable via `requestKey`); failures get a `402` JSON `{ ok: false, reason }` (status configurable via `failureStatus`).

`fastifyPlugin(opts)` and `honoMiddleware(opts)` take the same options.
