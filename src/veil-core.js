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
  ["ID", /\b(?:MRN|PAT|CASE|REF|EMP|POLICY)[-\s]?\d{5,10}\b/g], // Medical/case/reference IDs
  ["MONEY", /\b(?:AED|USD|EUR|GBP|SAR|\$|€|£)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:k|m|million|bn))?\b/gi],
  ["MONEY", /\b\d[\d,]*(?:\.\d+)?\s?(?:AED|USD|EUR|GBP|SAR|dirhams?|dollars?)\b/gi],
  ["DATE", /\b\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?(?:\s+\d{4})?\b/g],
  ["DATE", /\b(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4}|\s+\d{4})\b/g],
  ["DATE", /\b\d{4}-\d{2}-\d{2}\b/g],
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

// Name and company cues: a backstop for when the small on-device model misses one.
// Each rule's first capture group is the value. Masking too much is safer than leaking.
const NAME = "[A-Z][a-z'’-]+(?:[ \\t]+(?:Al|Bin|bin|El|de|van|[A-Z][a-z'’-]+)){0,3}";
const CONTEXT_RULES = [
  ["PERSON", new RegExp(`\\b(?:Hi|Hello|Dear|Hey)\\s+(${NAME})`, "g")],
  ["PERSON", new RegExp(`(?:Best|Regards|Kind regards|Best regards|Thanks|Thank you|Sincerely|Cheers),?[ \\t]*\\n[ \\t]*(${NAME})`, "g")],
  ["PERSON", new RegExp(`\\b(?:Mr|Mrs|Ms|Dr|Eng)\\.?\\s+(${NAME})`, "g")],
  ["PERSON", new RegExp(`\\b(?:Patient|Client|Signatory|Contact|Beneficiary|Attn|Attention|Prepared\\s+for):[ \\t]*(${NAME})`, "g")],
  ["ORG", /\b((?:[A-Z][A-Za-z&'’-]+[ \t]+){1,3}(?:Medical Center|LLC|Ltd|Inc|FZE|FZCO|FZ-LLC|PJSC|Group|Holdings|Logistics|Bank|Capital|Partners|Technologies|Solutions|Properties|Clinic|Hospital|Healthcare|Ventures|Advisory|LLP|Corp|Corporation|Industries|Investments))\b/g],
];

/** Regex detections as {text, type, source:'rules'}. */
export function detectWithRules(text, enabled = CATEGORIES) {
  const out = [];
  for (const [type, re] of CONTEXT_RULES) {
    if (!enabled.includes(type)) continue;
    for (const m of text.matchAll(re)) {
      const t = (m[1] || "").trim();
      if (t.length >= 3) out.push({ text: t, type, source: "rules" });
    }
  }
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
    if (t.length < 3 || !CATEGORIES.includes(type) || !enabled.includes(type)) continue;
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

// Whole-value matches only: "Ali" must not match inside "Alison" or "Bali".
function valueRe(value, flags = "i") {
  const pre = /^\w/.test(value) ? "(?<![\\w])" : "";
  const post = /\w$/.test(value) ? "(?![\\w])" : "";
  return new RegExp(pre + escapeRe(value) + post, flags);
}

export function mask(text, plan) {
  let out = text;
  for (const e of [...plan].sort((a, b) => b.text.length - a.text.length)) {
    out = out.replace(valueRe(e.text, "gi"), e.token);
  }
  return out;
}

/** Throws if any original secret would still leave the device. */
export function leakCheck(outbound, plan) {
  const leaked = plan.filter((e) => valueRe(e.text).test(outbound));
  if (leaked.length) {
    const err = new Error(`Leak guard blocked the request: ${leaked.length} masked value(s) still present.`);
    err.leaked = leaked;
    throw err;
  }
  return true;
}

/**
 * Put the real values back and return structured segments for safe UI highlighting.
 * Tokens the cloud invented are reported as unknown, never guessed.
 */
export function unmaskSegments(text, plan) {
  const byToken = new Map(plan.map((e) => [e.token.toUpperCase(), e]));
  const unknown = new Set();
  const segments = [];
  const re = /\[([A-Z]+)_(\d+)\]/gi;
  let last = 0;
  let restoredCount = 0;
  let out = "";
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) {
      const plain = text.slice(last, m.index);
      segments.push({ kind: "text", value: plain });
      out += plain;
    }
    const token = m[0];
    const entry = byToken.get(token.toUpperCase());
    if (!entry) {
      unknown.add(token);
      segments.push({ kind: "unknown", token, value: token });
      out += token;
    } else {
      restoredCount += 1;
      segments.push({ kind: "restored", token: entry.token, type: entry.type, value: entry.text });
      out += entry.text;
    }
    last = re.lastIndex;
  }
  if (last < text.length) {
    const tail = text.slice(last);
    segments.push({ kind: "text", value: tail });
    out += tail;
  }
  return { text: out, segments, unknownTokens: [...unknown], restoredCount };
}

/** Put the real values back. Tokens the cloud invented are reported, not guessed. */
export function unmask(text, plan) {
  const { text: restored, unknownTokens } = unmaskSegments(text, plan);
  return { text: restored, unknownTokens };
}

/** Split masked text into plain text and placeholder tokens for color-coded display. */
export function tokenizeMaskedText(text) {
  const segments = [];
  const re = /\[([A-Z]+)_(\d+)\]/gi;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) segments.push({ kind: "text", value: text.slice(last, m.index) });
    segments.push({ kind: "token", token: m[0], type: m[1].toUpperCase() });
    last = re.lastIndex;
  }
  if (last < text.length) segments.push({ kind: "text", value: text.slice(last) });
  return segments;
}

export function countByType(plan) {
  return plan.reduce((acc, e) => ((acc[e.type] = (acc[e.type] || 0) + 1), acc), {});
}

/** Build the exact Firestore zero-text receipt payload (strictly counts & sources only). */
export function buildReceiptPayload({ task, plan, detectorSource, reasonerSource, outboundChars, unknownTokensCount }) {
  return {
    task,
    counts: countByType(plan),
    masked: plan.length,
    detector: detectorSource === "rules_only" ? "rules_only" : "on_device",
    reasoner: reasonerSource === "on_device" ? "on_device" : "in_cloud",
    outboundChars,
    leakGuard: "pass",
    unknownTokens: unknownTokensCount,
  };
}

// One-click enterprise industry presets (Finance, Healthcare, Legal) for instant zero-friction evaluation.
export const PRESETS = [
  {
    id: "finance",
    label: "UAE Finance Wire",
    industry: "Finance",
    defaultTask: "reply",
    text: `Hi Sara Al Mansoori,

Following our call, Falcon Logistics agrees to the revised rate. Please wire AED 48,500 to IBAN AE07 0331 2345 6789 0123 456 before 3 December 2026.

The staging key for the tracking API is sk_demoNOTAREALKEY7Hq2Lyj9WDar, please rotate it after the migration.

If anything changes, call me on +971 50 123 4567 or email omar.khalid@falconlogistics.ae.

Best,
Omar Khalid
Head of Finance, Falcon Logistics`,
  },
  {
    id: "healthcare",
    label: "Healthcare Clinic Intake",
    industry: "Healthcare",
    defaultTask: "summary",
    text: `Patient: Layla Al Nuaimi
Emirates ID: 784-1988-7654321-4
Medical Record: MRN-849201
Phone: +971 55 892 3410 | Email: layla.nuaimi@example.ae
Attending Physician: Dr. Tariq Mansour, Al Noor Medical Center
Visit Date: 18 November 2026

Clinical Notes: Follow-up for gestational iron-deficiency anemia and mild hypertension. Prescribed ferrous sulfate 325mg daily and requested lipid panel recheck in 4 weeks.

Billing: Self-pay balance of AED 1,850 due after insurance pre-authorization. Please prepare a clear, reassuring follow-up summary for the patient.`,
  },
  {
    id: "legal",
    label: "Legal M&A NDA",
    industry: "Legal",
    defaultTask: "actions",
    text: `MUTUAL NON-DISCLOSURE AGREEMENT - TERM SHEET SUMMARY

Disclosing Party: Gulf Horizon Technologies LLC (Signatory: Nadia Al Qasimi, General Counsel, nadia.qasimi@gulfhorizon.ae)
Receiving Party: Crescent Capital Partners (Signatory: David Chen, Managing Director, d.chen@crescentcap.com)

Proposed Acquisition Valuation: USD 14,500,000 (AED 53,250,000 escrow deposit held at Emirates NBD Bank, IBAN AE46 0260 0010 1555 2890 101).
Exclusivity Window: 1 December 2026 through 15 February 2027.
Data Room Access Token: rk_demoNOTAREALTOKEN9mK4xP2vQ8wR

Key Obligations: 3-year confidentiality covenant, non-solicitation of key engineering staff for 18 months, and DIFC Courts governing jurisdiction. Please extract binding obligations and closing milestones.`,
  },
];

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
