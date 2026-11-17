// Veil core: pure functions, no Firebase. Masking plan -> masked text -> leak guard -> unmask.
// Everything here runs locally in the browser; nothing in this file touches the network.

export const CATEGORIES = ["PERSON", "ORG", "EMAIL", "PHONE", "ADDRESS", "ID", "ACCOUNT", "MONEY", "SECRET", "DATE"];

// Deterministic detectors: a safety net that runs even when Gemini Nano is unavailable.
const DETECTORS = [
  ["EMAIL", /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g],
  ["SECRET", /\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b/g],
  ["SECRET", /\bAKIA[0-9A-Z]{16}\b/g],
  ["SECRET", /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g],
  ["SECRET", /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
  ["ACCOUNT", /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g], // IBAN
  ["ACCOUNT", /\b(?:\d[ -]?){13,19}\b/g], // card-like digit runs (Luhn-checked below)
  ["PHONE", /(?:\+|00)\d{1,3}[\s-]?(?:\(?\d{1,4}\)?[\s-]?){2,5}\d{2,4}\b/g],
  ["PHONE", /\b0\d{1,2}[\s-]?\d{3}[\s-]?\d{4}\b/g],
  ["ID", /\b784-?\d{4}-?\d{7}-?\d\b/g], // UAE Emirates ID
  ["ID", /\b\d{3}-\d{2}-\d{4}\b/g], // US SSN shape
  ["MONEY", /\b(?:AED|USD|EUR|GBP|SAR|\$|€|£)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:k|m|million|bn))?\b/gi],
  ["MONEY", /\b\d[\d,]*(?:\.\d+)?\s?(?:AED|USD|EUR|GBP|SAR|dirhams?|dollars?)\b/gi],
];

function luhn(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = +digits[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

/** Regex detections as {text, type, source:'rules'}. */
export function detectWithRules(text, enabled = CATEGORIES) {
  const out = [];
  for (const [type, re] of DETECTORS) {
    if (!enabled.includes(type)) continue;
    for (const m of text.matchAll(re)) {
      const t = m[0].trim();
      if (type === "ACCOUNT" && /^[\d -]+$/.test(t) && !luhn(t.replace(/\D/g, ""))) continue;
      if (t.length >= 3) out.push({ text: t, type, source: "rules" });
    }
  }
  return out;
}

/** Keep only model spans that really occur in the text, with a known category. */
export function sanitizeModelSpans(text, spans, enabled = CATEGORIES) {
  if (!Array.isArray(spans)) return [];
  const out = [];
  for (const s of spans) {
    const t = typeof s?.text === "string" ? s.text.trim() : "";
    const type = typeof s?.type === "string" ? s.type.toUpperCase() : "";
    if (t.length < 2 || !CATEGORIES.includes(type) || !enabled.includes(type)) continue;
    if (!text.includes(t)) continue; // the model may not invent or paraphrase
    out.push({ text: t, type, source: "nano" });
  }
  return out;
}

/**
 * Build a masking plan: unique secrets -> stable tokens like [PERSON_1].
 * Longer spans win so "Sara Al Mansoori" is masked before "Sara".
 */
export function buildPlan(spans) {
  const seen = new Map();
  for (const s of [...spans].sort((a, b) => b.text.length - a.text.length)) {
    const key = s.text.toLowerCase();
    if (!seen.has(key)) seen.set(key, s);
  }
  const counters = {};
  const entries = [];
  for (const s of seen.values()) {
    counters[s.type] = (counters[s.type] || 0) + 1;
    entries.push({ token: `[${s.type}_${counters[s.type]}]`, text: s.text, type: s.type, source: s.source });
  }
  return entries;
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function mask(text, plan) {
  let out = text;
  for (const e of [...plan].sort((a, b) => b.text.length - a.text.length)) {
    out = out.replace(new RegExp(escapeRe(e.text), "gi"), e.token);
  }
  return out;
}

/** Throws if any original secret would still leave the device. */
export function leakCheck(outbound, plan) {
  const lower = outbound.toLowerCase();
  const leaked = plan.filter((e) => lower.includes(e.text.toLowerCase()));
  if (leaked.length) {
    const err = new Error(`Leak guard blocked the request: ${leaked.length} masked value(s) still present.`);
    err.leaked = leaked;
    throw err;
  }
  return true;
}

/** Put the real values back. Tokens the cloud invented are reported, not guessed. */
export function unmask(text, plan) {
  const byToken = new Map(plan.map((e) => [e.token.toUpperCase(), e.text]));
  const unknown = new Set();
  const restored = text.replace(/\[([A-Z]+)_(\d+)\]/gi, (m) => {
    const v = byToken.get(m.toUpperCase());
    if (v === undefined) { unknown.add(m); return m; }
    return v;
  });
  return { text: restored, unknownTokens: [...unknown] };
}

export function countByType(plan) {
  return plan.reduce((acc, e) => ((acc[e.type] = (acc[e.type] || 0) + 1), acc), {});
}

// Prompts kept here so tests and the README quote the exact strings.
export const NANO_DETECT_PROMPT = (text, enabled) =>
  `Find every piece of sensitive information in the TEXT below.
Categories: ${enabled.join(", ")}.
PERSON = names of people. ORG = company or organization names. ADDRESS = street addresses or buildings.
ID = passport, national ID, employee or case numbers. ACCOUNT = bank, card or customer account numbers.
MONEY = specific amounts. SECRET = passwords, API keys, tokens. DATE = specific dates.
Copy each value exactly as it appears in the text. Do not include generic words.

TEXT:
"""
${text}
"""`;

export const NANO_SCHEMA = {
  type: "object",
  properties: {
    entities: {
      type: "array",
      items: {
        type: "object",
        properties: { text: { type: "string" }, type: { type: "string", enum: CATEGORIES } },
        required: ["text", "type"],
      },
    },
  },
  required: ["entities"],
};

export const TASKS = {
  reply: "Draft a clear, polite reply to this message.",
  summary: "Summarize this in 3 to 5 bullet points.",
  actions: "Extract the action items as a checklist with owners and deadlines where stated.",
  formal: "Rewrite this in a more formal, professional tone.",
  arabic: "Translate this into Modern Standard Arabic.",
};

export const CLOUD_SYSTEM = `You work on text where private values were replaced on the user's device with placeholders like [PERSON_1], [EMAIL_2], [MONEY_1].
Rules: keep every placeholder exactly as written, including brackets, wherever its value is needed. Never guess, invent or describe what a placeholder hides. Do not create new placeholders.`;
