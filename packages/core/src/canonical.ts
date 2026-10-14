// packages/core/src/canonical.ts
//
// Deterministic canonicalization for everything AgentCred signs.
// Canonical JSON: object keys sorted lexicographically (by UTF-16 code unit),
// no whitespace, arrays keep order. Numbers must be finite; undefined,
// functions and symbols are rejected outright — a scope object that cannot be
// canonicalized cannot be signed.

export function canonicalize(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function canonicalValue(value: unknown): unknown {
  if (value === null) return null;
  const t = typeof value;
  if (t === "string" || t === "boolean") return value;
  if (t === "number") {
    if (!Number.isFinite(value as number))
      throw new Error("cannot canonicalize non-finite number");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (t === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[k];
      if (v === undefined) throw new Error(`cannot canonicalize: key "${k}" is undefined`);
      out[k] = canonicalValue(v);
    }
    return out;
  }
  throw new Error(`cannot canonicalize value of type ${t}`);
}

/** Parse JSON and require it to already be in canonical form. */
export function parseCanonical(json: string): unknown {
  const parsed: unknown = JSON.parse(json);
  if (canonicalize(parsed) !== json) {
    throw new Error("payload is not in canonical form (keys must be sorted, no whitespace)");
  }
  return parsed;
}
