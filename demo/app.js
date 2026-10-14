// demo/app.js — DOM wiring for the static AgentCred demo.
// Everything runs client-side: keys are ephemeral, no backend, no network.

import {
  genDid,
  signJws,
  verifyJws,
  canonicalize,
  sha256hex,
  fingerprint,
} from "./crypto.js";

const MERCHANT = "merchant:demo-store.example.invalid";
const AGENCY_AUD = "sovereign-identity/agency";
const SEEN_KEY = "agentcred-demo-seen-v1";

const $ = (id) => document.getElementById(id);
const nowSec = () => Math.floor(Date.now() / 1000);
const shortDid = (did) => (did ? did.slice(0, 20) + "…" + did.slice(-6) : "—");

const state = {
  owner: null,
  agent: null,
  grantJws: null,
  passport: null,
  envelope: null,
  memSeen: new Set(), // "merchant" in-memory replay cache (lost on restart)
};

function loadSeen() {
  try {
    return new Set(JSON.parse(localStorage.getItem(SEEN_KEY) || "[]"));
  } catch {
    return new Set();
  }
}
function saveSeen(set) {
  localStorage.setItem(SEEN_KEY, JSON.stringify([...set]));
}

function log(html, cls = "") {
  const el = document.createElement("div");
  el.className = "logline " + cls;
  el.innerHTML = html;
  $("log").prepend(el);
}

function step(name, ok, detail = "") {
  return { name, ok, detail };
}

function renderSteps(steps, verdict) {
  const box = $("verifyResult");
  box.innerHTML =
    `<div class="verdict ${verdict.ok ? "ok" : "bad"}">${verdict.ok ? "✓ PASSPORT ACCEPTED" : "✗ PASSPORT REJECTED"}<div class="reason">${verdict.reason || ""}</div></div>` +
    `<ul class="steps">` +
    steps
      .map(
        (s) =>
          `<li class="${s.ok ? "ok" : "bad"}"><span class="mark">${s.ok ? "✓" : "✗"}</span> ${s.name}${s.detail ? `<div class="detail">${s.detail}</div>` : ""}</li>`
      )
      .join("") +
    `</ul>`;
  box.classList.remove("hidden");
}

// ------------------------------------------------------------ issuance

async function issuePassport({ ttlSec = 900, amount = 25, actions = ["purchase"], expired = false } = {}) {
  const owner = await genDid();
  const agent = await genDid(); // ephemeral per-task agent key
  const now = nowSec();
  const grantPayload = {
    iss: owner.did,
    sub: agent.did,
    aud: AGENCY_AUD,
    iat: now,
    exp: now + 30 * 86400,
    jti: crypto.randomUUID(),
    claims: { scope: ["purchase", "refund"], amount_limit: 100, currency: "USD" },
  };
  const grantJws = await signJws(grantPayload, owner.privateKey, owner.did + "#key-1");
  const exp = expired ? now - 10 : now + ttlSec;
  const mandatePayload = {
    iss: agent.did,
    sub: agent.did,
    aud: MERCHANT,
    iat: now,
    exp,
    jti: crypto.randomUUID(),
    claims: { task: "buy a demo widget", scope: [...actions].sort(), amount_limit: amount, currency: "USD" },
    grant: grantJws,
  };
  const leaf = await signJws(mandatePayload, agent.privateKey, agent.did + "#key-1");
  const spend = {
    actions: [...actions].sort(),
    amount_limit: amount,
    currency: "USD",
    merchant: MERCHANT,
  };
  const envelope = {
    leaf,
    leaf_sha256: await sha256hex(leaf),
    spend,
    v: 1,
  };
  const passport = canonicalize(envelope);
  return { owner, agent, grantJws, leaf, envelope, passport, mandatePayload };
}

// --------------------------------------------------------- verification

async function verifyPassport(passportStr, merchantId, { consume = true } = {}) {
  const steps = [];
  const fail = (reason) => ({ ok: false, reason, steps });
  try {
    let envelope;
    try {
      envelope = JSON.parse(passportStr);
    } catch {
      return fail("passport is not valid JSON");
    }
    if (canonicalize(envelope) !== passportStr) {
      steps.push(step("Canonical envelope encoding", false, "keys reordered or whitespace added — rejected"));
      return fail("passport envelope is not in canonical form");
    }
    steps.push(step("Canonical envelope encoding", true, "byte-equal to canonical form"));

    if (envelope.v !== 1) return fail("unsupported passport version");
    if ((await sha256hex(envelope.leaf)) !== envelope.leaf_sha256) {
      steps.push(step("Leaf binding (sha256)", false, "envelope does not match the leaf mandate"));
      return fail("leaf_sha256 does not match the leaf mandate");
    }
    steps.push(step("Leaf binding (sha256)", true));

    const spend = envelope.spend;
    if (spend.merchant !== merchantId) {
      steps.push(step("Merchant (aud) binding", false, `passport is for "${spend.merchant}"`));
      return fail(`audience mismatch: passport for "${spend.merchant}", this merchant is "${merchantId}"`);
    }
    steps.push(step("Merchant (aud) binding", true, `aud = ${merchantId}`));

    // Leaf signature + chain walk.
    const now = nowSec();
    let leaf;
    try {
      leaf = await verifyJws(envelope.leaf);
    } catch (e) {
      steps.push(step("Leaf signature (Ed25519 did:key)", false, e.message));
      return fail("leaf signature invalid: " + e.message);
    }
    steps.push(step("Leaf signature (Ed25519 did:key)", true, `iss ${shortDid(leaf.payload.iss)}`));
    const lp = leaf.payload;
    if (typeof lp.exp !== "number" || lp.exp <= now) {
      steps.push(step("Expiry", false, "leaf mandate has expired"));
      return fail("passport expired");
    }
    if (typeof lp.iat === "number" && lp.iat > now + 60) {
      steps.push(step("Expiry", false, "issued in the future"));
      return fail("passport issued in the future");
    }
    steps.push(step("Expiry", true, "valid until " + new Date(lp.exp * 1000).toLocaleTimeString()));

    // Spend ↔ leaf consistency (the canonical scope must match the signed leaf).
    const lc = lp.claims || {};
    const leafActions = [...(lc.scope || [])].sort();
    if (lp.aud !== spend.merchant || (lc.amount_limit || 0) !== spend.amount_limit ||
        JSON.stringify(leafActions) !== JSON.stringify(spend.actions)) {
      steps.push(step("Spend scope ↔ signed leaf", false, "envelope scope disagrees with the signed mandate"));
      return fail("envelope spend scope does not match the signed leaf");
    }
    steps.push(step("Spend scope ↔ signed leaf", true, `${spend.actions.join(", ")} ≤ $${spend.amount_limit}`));

    // Chain: grant signature, linkage, narrowing.
    let parentJws = lp.grant;
    if (!parentJws) {
      steps.push(step("Mandate chain", false, "leaf carries no grant"));
      return fail("leaf carries no agency grant");
    }
    let parent;
    try {
      parent = await verifyJws(parentJws);
    } catch (e) {
      steps.push(step("Mandate chain", false, "grant signature invalid: " + e.message));
      return fail("grant signature invalid");
    }
    const gp = parent.payload;
    const chainProblems = [];
    if (gp.aud !== AGENCY_AUD) chainProblems.push("grant has wrong audience");
    if (typeof gp.exp !== "number" || gp.exp <= now) chainProblems.push("grant expired");
    if (gp.sub !== lp.iss) chainProblems.push("grant was not issued to the leaf signer");
    const gscope = (gp.claims && gp.claims.scope) || [];
    const over = (lc.scope || []).filter((s) => !gscope.includes(s));
    if (over.length) chainProblems.push("scope exceeds grant: " + over.join(","));
    if ((lc.amount_limit || 0) > ((gp.claims && gp.claims.amount_limit) || 0))
      chainProblems.push("amount exceeds grant limit");
    if (typeof lp.exp === "number" && typeof gp.exp === "number" && lp.exp > gp.exp)
      chainProblems.push("child expiry exceeds parent expiry");
    if (chainProblems.length) {
      steps.push(step("Mandate chain", false, chainProblems.join("; ")));
      return fail("mandate chain: " + chainProblems.join("; "));
    }
    steps.push(step("Mandate chain", true, `owner ${shortDid(gp.iss)} → agent ${shortDid(lp.iss)} · scope narrows, amount narrows, expiry narrows`));

    // Replay: persistent (localStorage, survives "restart") + in-memory.
    const seen = loadSeen();
    const jti = String(lp.jti);
    if (seen.has(jti) || state.memSeen.has(jti)) {
      steps.push(step("Replay protection", false, "this passport's jti was already consumed"));
      return fail("replay detected: passport jti already consumed");
    }
    steps.push(step("Replay protection", true, "jti not seen before — consuming it"));
    if (consume) {
      seen.add(jti);
      saveSeen(seen);
      state.memSeen.add(jti);
    }

    return {
      ok: true,
      reason: `agent ${shortDid(lp.iss)} may spend up to $${spend.amount_limit} ${spend.currency} on ${spend.actions.join(", ")}`,
      steps,
      detail: { agent: lp.iss, owner: gp.iss, spend },
    };
  } catch (e) {
    return fail("verification error: " + e.message);
  }
}

// ------------------------------------------------------------------ UI

function showPassport(p) {
  $("passportOut").textContent = p.passport;
  $("passportBox").classList.remove("hidden");
  $("chainOut").innerHTML =
    `<div class="hop"><span class="who">owner</span><code>${shortDid(p.owner.did)}</code><span class="fp">fp ${fingerprint(p.owner.did)}</span></div>` +
    `<div class="arrow">▼ grant: purchase, refund · ≤ $100</div>` +
    `<div class="hop"><span class="who">agent (ephemeral)</span><code>${shortDid(p.agent.did)}</code><span class="fp">fp ${fingerprint(p.agent.did)}</span></div>` +
    `<div class="arrow">▼ mandate: ${p.envelope.spend.actions.join(", ")} · ≤ $${p.envelope.spend.amount_limit} · 15 min · aud ${MERCHANT}</div>`;
  $("attackBox").classList.remove("hidden");
  log(`issued passport <code>${p.passport.slice(0, 48)}…</code> for <b>${MERCHANT}</b>`, "good");
}

$("issueBtn").addEventListener("click", async () => {
  $("issueBtn").disabled = true;
  try {
    const p = await issuePassport();
    Object.assign(state, { owner: p.owner, agent: p.agent, grantJws: p.grantJws, passport: p.passport, envelope: p.envelope });
    showPassport(p);
  } catch (e) {
    log("issuance failed: " + e.message, "bad");
  }
  $("issueBtn").disabled = false;
});

$("verifyBtn").addEventListener("click", async () => {
  if (!state.passport) return log("issue a passport first", "bad");
  const res = await verifyPassport(state.passport, MERCHANT);
  renderSteps(res.steps, res);
  log(res.ok ? "merchant: <b>payment approved</b>" : "merchant: <b>payment declined</b> — " + res.reason, res.ok ? "good" : "bad");
});

$("replayBtn").addEventListener("click", async () => {
  if (!state.passport) return log("issue a passport first", "bad");
  log("attacker replays the exact same passport…");
  const res = await verifyPassport(state.passport, MERCHANT);
  renderSteps(res.steps, res);
  log(res.ok ? "<b>unexpected: replay accepted</b>" : "replay attack <b>blocked</b> — " + res.reason, res.ok ? "bad" : "good");
});

$("wrongMerchantBtn").addEventListener("click", async () => {
  if (!state.passport) return log("issue a passport first", "bad");
  log("passport presented to a different merchant…");
  const res = await verifyPassport(state.passport, "merchant:evil.example.invalid");
  renderSteps(res.steps, res);
  log(res.ok ? "<b>unexpected: accepted by wrong merchant</b>" : "wrong-merchant <b>blocked</b> — " + res.reason, res.ok ? "bad" : "good");
});

$("tamperBtn").addEventListener("click", async () => {
  if (!state.passport) return log("issue a passport first", "bad");
  log("attacker edits the envelope: $25 → $500…");
  const env = JSON.parse(state.passport);
  env.spend.amount_limit = 500;
  const res = await verifyPassport(canonicalize(env), MERCHANT);
  renderSteps(res.steps, res);
  log(res.ok ? "<b>unexpected: tampered amount accepted</b>" : "tampering <b>blocked</b> — " + res.reason, res.ok ? "bad" : "good");
});

$("expiredBtn").addEventListener("click", async () => {
  log("issuing an already-expired passport…");
  const p = await issuePassport({ expired: true });
  const res = await verifyPassport(p.passport, MERCHANT);
  renderSteps(res.steps, res);
  log(res.ok ? "<b>unexpected: expired accepted</b>" : "expired passport <b>blocked</b> — " + res.reason, res.ok ? "bad" : "good");
});

$("nonCanonBtn").addEventListener("click", async () => {
  if (!state.passport) return log("issue a passport first", "bad");
  log("attacker reorders the envelope keys (same data, non-canonical bytes)…");
  const env = JSON.parse(state.passport);
  const reordered = JSON.stringify({ v: env.v, spend: env.spend, leaf_sha256: env.leaf_sha256, leaf: env.leaf });
  const res = await verifyPassport(reordered, MERCHANT);
  renderSteps(res.steps, res);
  log(res.ok ? "<b>unexpected: non-canonical accepted</b>" : "non-canonical encoding <b>blocked</b> — " + res.reason, res.ok ? "bad" : "good");
});

$("restartBtn").addEventListener("click", async () => {
  state.memSeen.clear();
  log("merchant restarted — in-memory cache wiped, disk cache intact. Replaying the passport…");
  if (!state.passport) return log("issue a passport first", "bad");
  const res = await verifyPassport(state.passport, MERCHANT);
  renderSteps(res.steps, res);
  log(res.ok ? "<b>unexpected: replay accepted after restart</b>" : "replay after restart <b>blocked</b> — the file-backed cache held", res.ok ? "bad" : "good");
});

$("resetBtn").addEventListener("click", () => {
  localStorage.removeItem(SEEN_KEY);
  state.memSeen.clear();
  state.passport = null;
  $("passportBox").classList.add("hidden");
  $("attackBox").classList.add("hidden");
  $("verifyResult").classList.add("hidden");
  $("verifyResult").innerHTML = "";
  log("demo reset — keys discarded, merchant caches cleared");
});

log("demo ready — everything below runs in your browser, no backend.");
