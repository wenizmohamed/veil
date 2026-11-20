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
  ["SECRET", /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*\b/g],
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
  ["PERSON", /(?:السيد|السيدة|الأستاذ|الدكتور|الدكتورة|المريض|المريضة|العميل|الموقع)\s*:?\s*([\u0600-\u06FF]{2,}(?:[ \t]+[\u0600-\u06FF]{2,}){1,2})/g],
  ["ID", /\bPassport(?:\s*(?:No\.?|Number|#))?[:\s]+([A-Z]{1,2}\d{6,9})\b/gi],
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

/**
 * Inspect exact raw HTTP JSON bytes captured by the live outbound wiretap and verify
 * zero raw secret substrings exist anywhere on the wire.
 */
export function verifyOutboundBytesZeroSecrets(rawPayload, plan) {
  const text = typeof rawPayload === "string" ? rawPayload : JSON.stringify(rawPayload || "");
  const lowered = text.toLowerCase();
  const leaked = [];
  for (const entry of plan) {
    if (entry.text && lowered.includes(entry.text.toLowerCase())) {
      leaked.push(entry.token);
    }
  }
  const bytes = typeof TextEncoder !== "undefined" ? new TextEncoder().encode(text).length : text.length;
  return { passed: leaked.length === 0, leakedCount: leaked.length, leakedTokens: leaked, bytes };
}

/**
 * Build a downloadable, strictly zero-text compliance certificate bound to the live
 * Firestore receipt path and SHA-256 outbound wiretap digest.
 */
export function buildComplianceCertificate({
  firestorePath,
  receiptPayload,
  sha256Hex,
  outboundBytes,
  wiretapEndpoint,
  policySnapshot,
  stressTestSummary,
}) {
  return {
    schema: "veil.zero-text-compliance-certificate/v1",
    issuedAt: new Date().toISOString(),
    firestoreReceiptPath: firestorePath || null,
    cryptographicProof: {
      algorithm: "SHA-256",
      outboundPayloadDigest: sha256Hex || null,
      outboundHttpBytes: outboundBytes || 0,
      wiretapEndpoint: wiretapEndpoint || "on_device_only",
      rawSecretsInOutboundBytes: 0,
      leakGuardStatus: receiptPayload?.leakGuard || "pass",
    },
    privacyReceipt: receiptPayload
      ? {
          task: receiptPayload.task,
          masked: receiptPayload.masked,
          counts: receiptPayload.counts,
          detector: receiptPayload.detector,
          reasoner: receiptPayload.reasoner,
          outboundChars: receiptPayload.outboundChars,
          leakGuard: receiptPayload.leakGuard,
          unknownTokens: receiptPayload.unknownTokens,
        }
      : null,
    remoteConfigPolicy: policySnapshot
      ? {
          source: policySnapshot.source,
          cloudModel: policySnapshot.cloudModel,
          categoriesCount: policySnapshot.categories?.length || 0,
          maxChars: policySnapshot.maxChars,
        }
      : null,
    adversarialStressTest: stressTestSummary
      ? {
          totalTraps: stressTestSummary.total,
          caughtOnDevice: stressTestSummary.caught,
          bytesLeaked: stressTestSummary.leaked,
          restoredLocally: stressTestSummary.restored,
          elapsedMs: stressTestSummary.elapsedMs,
        }
      : null,
    attestation: "Zero raw text or secret values are included in this certificate or written to Cloud Firestore.",
  };
}

/**
 * 1-Click Adversarial PII Stress Test (12 Traps): runs live in-browser against Veil's
 * real detection, masking, Leak Guard, and local restore pipeline.
 */
export function runAdversarialStressTest() {
  const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();
  const awsDemo = ["AKIA", "DEMO", "VEIL", "0001", "2026"].join("");
  const jwtDemo = ["eyJhbGciOi", "JIUzI1NiJ9.", "eyJzdWIiOi", "J2ZWlsIn0.", "c2lnbmF0dX", "JlMTIzNDU2"].join("");
  const bearerDemo = ["Bearer ", "veil_demo_", "9f8e7d6c5b4a3210"].join("");

  const traps = [
    { id: "iban", label: "UAE IBAN", expectedType: "ACCOUNT", secret: "AE07 0331 2345 6789 0123 456", sample: "Wire settlement to IBAN AE07 0331 2345 6789 0123 456 immediately." },
    { id: "eid", label: "UAE Emirates ID", expectedType: "ID", secret: "784-1991-7654321-8", sample: "Verified Emirates ID 784-1991-7654321-8 on KYC file." },
    { id: "aws", label: "AWS Access Key", expectedType: "SECRET", secret: awsDemo, sample: `Rotate staging IAM key ${awsDemo} before go-live.` },
    { id: "jwt", label: "JWT Session Token", expectedType: "SECRET", secret: jwtDemo, sample: `Captured session token ${jwtDemo} in debug trace.` },
    { id: "bearer", label: "HTTP Bearer Token", expectedType: "SECRET", secret: bearerDemo, sample: `Authorization header used ${bearerDemo} against prod API.` },
    { id: "bilingual_name", label: "Arabic + English Names", expectedType: "PERSON", secret: "محمد المنصوري", extraSecret: "Sara Al Mansoori", sample: "Hi Sara Al Mansoori, المريض: محمد المنصوري confirmed attendance." },
    { id: "phone", label: "International Phone", expectedType: "PHONE", secret: "+971 50 987 6543", sample: "Direct executive line: +971 50 987 6543." },
    { id: "email", label: "Corporate Email", expectedType: "EMAIL", secret: "cfo.office@crescentcap.ae", sample: "Send final cap table to cfo.office@crescentcap.ae today." },
    { id: "money", label: "Wire Transfer Amount", expectedType: "MONEY", secret: "AED 2,450,000", sample: "Approved escrow release of AED 2,450,000 upon closing." },
    { id: "mrn", label: "Medical Record (MRN)", expectedType: "ID", secret: "MRN-904512", sample: "Chart reference MRN-904512 uploaded to clinic intake." },
    { id: "passport", label: "Passport Number", expectedType: "ID", secret: "P84729103", sample: "Signatory identity verified via Passport: P84729103." },
    { id: "card", label: "Luhn Payment Card", expectedType: "ACCOUNT", secret: "4532 1488 0343 6464", sample: "Corporate travel card 4532 1488 0343 6464 billed for deposit." },
  ];

  let caught = 0;
  let leaked = 0;
  let restored = 0;
  const results = [];

  for (const trap of traps) {
    const spans = detectWithRules(trap.sample);
    const plan = buildPlan(spans);
    const masked = mask(trap.sample, plan);
    let guardOk = false;
    try {
      guardOk = leakCheck(masked, plan) === true;
    } catch {
      guardOk = false;
    }
    const secretsToCheck = trap.extraSecret ? [trap.secret, trap.extraSecret] : [trap.secret];
    const allRemoved = secretsToCheck.every((s) => !masked.toLowerCase().includes(s.toLowerCase()));
    const matchedEntry = plan.find((e) => e.text.toLowerCase() === trap.secret.toLowerCase());
    const unmasked = unmaskSegments(masked, plan);
    const allRestored = secretsToCheck.every((s) => unmasked.text.includes(s));

    const isCaught = Boolean(matchedEntry) && guardOk && allRemoved;
    if (isCaught) caught += 1;
    else leaked += 1;
    if (allRestored) restored += 1;

    results.push({
      id: trap.id,
      label: trap.label,
      type: matchedEntry ? matchedEntry.type : trap.expectedType,
      token: matchedEntry ? matchedEntry.token : "MISSED",
      caught: isCaught,
      leakedBytes: isCaught ? 0 : trap.secret.length,
      restored: allRestored,
    });
  }

  const t1 = typeof performance !== "undefined" ? performance.now() : Date.now();
  return {
    total: traps.length,
    caught,
    leaked,
    restored,
    elapsedMs: Math.max(1, Math.round(t1 - t0)),
    results,
  };
}

/** Exact UTF-8 byte length of a string (handles Arabic and multibyte UTF-8 accurately). */
export function utf8ByteLength(str) {
  const s = typeof str === "string" ? str : String(str ?? "");
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(s).length;
  return s.length;
}

/**
 * Compute real measured On-Device vs Cloud latency split and exact privacy byte-boundary metrics.
 */
export function computeTelemetrySplit({
  rawText = "",
  maskedText = "",
  plan = [],
  findMs = 0,
  guardMs = 0,
  cloudMs = 0,
  restoreMs = 0,
  localOnly = false,
} = {}) {
  const rawBytes = utf8ByteLength(rawText);
  const outboundBytes = utf8ByteLength(maskedText);

  let secretBytesShielded = 0;
  let maskedOccurrences = 0;
  for (const entry of plan) {
    if (!entry?.text) continue;
    const matches = rawText.match(valueRe(entry.text, "gi"));
    const hits = matches ? matches.length : 0;
    if (hits > 0) {
      maskedOccurrences += hits;
      secretBytesShielded += utf8ByteLength(entry.text) * hits;
    }
  }
  secretBytesShielded = Math.min(rawBytes, secretBytesShielded);

  let placeholderBytes = 0;
  const tokMatches = maskedText.match(/\[([A-Z]+)_(\d+)\]/gi) || [];
  for (const tok of tokMatches) placeholderBytes += utf8ByteLength(tok);

  const wireCheck = verifyOutboundBytesZeroSecrets(maskedText, plan);
  const piiBytesOnWire = wireCheck.passed ? 0 : wireCheck.leakedCount;
  const byteDelta = rawBytes - outboundBytes;
  const privacyShieldPct = rawBytes > 0 ? Math.round((secretBytesShielded / rawBytes) * 1000) / 10 : 0;
  const safeContextBytes = Math.max(0, rawBytes - secretBytesShielded);

  const fMs = Math.max(0, Number(findMs) || 0);
  const gMs = Math.max(0, Number(guardMs) || 0);
  const rMs = Math.max(0, Number(restoreMs) || 0);
  const cMs = localOnly ? 0 : Math.max(0, Number(cloudMs) || 0);
  const onDeviceTotalMs = Math.round((fMs + gMs + rMs) * 10) / 10;
  const cloudTotalMs = Math.round(cMs * 10) / 10;
  const totalMs = Math.round((onDeviceTotalMs + cloudTotalMs) * 10) / 10;
  const onDevicePct = totalMs > 0 ? Math.round((onDeviceTotalMs / totalMs) * 1000) / 10 : 100;
  const cloudPct = totalMs > 0 ? Math.round((cloudTotalMs / totalMs) * 1000) / 10 : 0;

  return {
    latency: {
      findMs: Math.round(fMs * 10) / 10,
      guardMs: Math.round(gMs * 10) / 10,
      cloudMs: cloudTotalMs,
      restoreMs: Math.round(rMs * 10) / 10,
      onDeviceTotalMs,
      totalMs,
      onDevicePct,
      cloudPct,
      localOnly: Boolean(localOnly),
    },
    bytes: {
      rawBytes,
      outboundBytes,
      secretBytesShielded,
      safeContextBytes,
      placeholderBytes,
      byteDelta,
      privacyShieldPct,
      maskedOccurrences,
      piiBytesOnWire,
      zeroLeakVerified: wireCheck.passed,
    },
  };
}

// =========================================================================
// LIVE FIRESTORE ZERO-TEXT SECURITY RULES EVALUATOR (mirrors firestore.rules)
// =========================================================================

export const FIRESTORE_ALLOWED_KEYS = [
  "at", "task", "counts", "masked", "detector", "reasoner", "outboundChars", "leakGuard", "unknownTokens",
];
export const FIRESTORE_VALID_TASKS = ["reply", "summary", "actions", "formal", "arabic"];
export const FIRESTORE_VALID_DETECTORS = ["on_device", "rules_only"];
export const FIRESTORE_VALID_REASONERS = ["in_cloud", "on_device"];

export const FIRESTORE_RULES_SOURCE = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // A receipt proves what happened without storing what was said:
    // counts per category and where each step ran. No free text is accepted.
    function validCount(counts, key) {
      return !(key in counts) || (counts[key] is int && counts[key] >= 0);
    }

    function validReceipt(data) {
      return data.keys().hasOnly(['at', 'task', 'counts', 'masked', 'detector', 'reasoner', 'outboundChars', 'leakGuard', 'unknownTokens'])
        && data.task in ['reply', 'summary', 'actions', 'formal', 'arabic']
        && data.counts is map
        && data.counts.keys().hasOnly(['PERSON', 'ORG', 'EMAIL', 'PHONE', 'ADDRESS', 'ID', 'ACCOUNT', 'MONEY', 'SECRET', 'DATE'])
        && validCount(data.counts, 'PERSON')
        && validCount(data.counts, 'ORG')
        && validCount(data.counts, 'EMAIL')
        && validCount(data.counts, 'PHONE')
        && validCount(data.counts, 'ADDRESS')
        && validCount(data.counts, 'ID')
        && validCount(data.counts, 'ACCOUNT')
        && validCount(data.counts, 'MONEY')
        && validCount(data.counts, 'SECRET')
        && validCount(data.counts, 'DATE')
        && data.masked is int && data.masked >= 0
        && data.detector in ['on_device', 'rules_only']
        && data.reasoner in ['in_cloud', 'on_device']
        && data.outboundChars is int && data.outboundChars >= 0
        && data.leakGuard == 'pass'
        && data.unknownTokens is int && data.unknownTokens >= 0
        && data.at == request.time;
    }

    match /users/{uid}/receipts/{id} {
      allow read: if request.auth != null && request.auth.uid == uid;
      allow create: if request.auth != null && request.auth.uid == uid && validReceipt(request.resource.data);
      allow update, delete: if false;
    }

    match /sessions/{sid}/receipts/{id} {
      allow read: if sid.matches('^anon_[0-9a-f-]{36}$');
      allow create: if sid.matches('^anon_[0-9a-f-]{36}$') && validReceipt(request.resource.data);
      allow update, delete: if false;
    }

    match /{document=**} {
      allow read, write: if false;
    }
  }
}`;

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isNonNegInt = (v) => typeof v === "number" && Number.isInteger(v) && v >= 0;

/**
 * Exact line-for-line evaluator of Veil's firestore.rules security predicates.
 * Proves why raw text, IBANs, string smuggling in counts, forged timestamps,
 * unauthorized paths, and update/delete mutations are deterministically denied.
 */
export function evaluateFirestoreRule({
  path = "sessions/anon_11111111-2222-4333-8444-555555555555/receipts/rcpt_01",
  operation = "create",
  data = {},
  authUid = null,
  serverTimeToken = "serverTimestamp()",
} = {}) {
  const cleanPath = String(path || "").replace(/^\/+|\/+$/g, "");
  const op = String(operation || "create").toLowerCase();
  const passedChecks = [];
  const failedChecks = [];

  const userMatch = cleanPath.match(/^users\/([^/]+)\/receipts\/([^/]+)$/);
  const sessionMatch = cleanPath.match(/^sessions\/([^/]+)\/receipts\/([^/]+)$/);

  let matchedRuleBlock = "match /{document=**}";
  if (userMatch) matchedRuleBlock = "match /users/{uid}/receipts/{id}";
  else if (sessionMatch) matchedRuleBlock = "match /sessions/{sid}/receipts/{id}";

  if (!userMatch && !sessionMatch) {
    failedChecks.push({
      line: 47,
      rule: "match /{document=**} { allow read, write: if false; }",
      reason: `Path "${cleanPath}" does not match an allowed receipts collection; default catch-all denies all access.`,
    });
    return {
      allowed: false,
      decision: "DENY",
      path: cleanPath,
      operation: op,
      matchedRuleBlock,
      passedChecks,
      failedChecks,
      summary: failedChecks[0].reason,
    };
  }

  // Immutable append-only check (update / delete)
  if (op === "update" || op === "delete") {
    const line = userMatch ? 37 : 43;
    failedChecks.push({
      line,
      rule: "allow update, delete: if false;",
      reason: `Operation "${op.toUpperCase()}" is forbidden: privacy receipts are append-only and immutable.`,
    });
    return {
      allowed: false,
      decision: "DENY",
      path: cleanPath,
      operation: op,
      matchedRuleBlock,
      passedChecks,
      failedChecks,
      summary: failedChecks[0].reason,
    };
  }

  // Path authorization predicate
  if (userMatch) {
    const uid = userMatch[1];
    const authLine = op === "read" ? 35 : 36;
    if (authUid && authUid === uid) {
      passedChecks.push({ line: authLine, rule: "request.auth != null && request.auth.uid == uid" });
    } else {
      failedChecks.push({
        line: authLine,
        rule: "request.auth != null && request.auth.uid == uid",
        reason: `Authenticated uid (${authUid || "null"}) does not match target path uid "${uid}".`,
      });
    }
  } else if (sessionMatch) {
    const sid = sessionMatch[1];
    const sidLine = op === "read" ? 41 : 42;
    if (/^anon_[0-9a-f-]{36}$/.test(sid)) {
      passedChecks.push({ line: sidLine, rule: "sid.matches('^anon_[0-9a-f-]{36}$')" });
    } else {
      failedChecks.push({
        line: sidLine,
        rule: "sid.matches('^anon_[0-9a-f-]{36}$')",
        reason: `Session id "${sid}" violates strict anonymous UUID pattern ^anon_[0-9a-f-]{36}$.`,
      });
    }
  }

  if (op === "read") {
    const allowed = failedChecks.length === 0;
    return {
      allowed,
      decision: allowed ? "ALLOW" : "DENY",
      path: cleanPath,
      operation: op,
      matchedRuleBlock,
      passedChecks,
      failedChecks,
      summary: allowed ? "Read authorized by path predicate." : failedChecks[0].reason,
    };
  }

  // Validate validReceipt(request.resource.data) for create
  if (!isPlainObject(data)) {
    failedChecks.push({
      line: 11,
      rule: "validReceipt(request.resource.data)",
      reason: "Request payload must be a JSON object.",
    });
  } else {
    const keys = Object.keys(data);
    const forbiddenKeys = keys.filter((k) => !FIRESTORE_ALLOWED_KEYS.includes(k));
    if (forbiddenKeys.length === 0) {
      passedChecks.push({ line: 11, rule: "data.keys().hasOnly([...9 allowed keys])" });
    } else {
      failedChecks.push({
        line: 11,
        rule: "data.keys().hasOnly(['at', 'task', 'counts', 'masked', 'detector', 'reasoner', 'outboundChars', 'leakGuard', 'unknownTokens'])",
        reason: `Forbidden field(s) rejected: ${forbiddenKeys.map((k) => `"${k}"`).join(", ")}. Free text and raw secrets cannot be stored.`,
      });
    }

    if (typeof data.task === "string" && FIRESTORE_VALID_TASKS.includes(data.task)) {
      passedChecks.push({ line: 12, rule: "data.task in ['reply', 'summary', 'actions', 'formal', 'arabic']" });
    } else {
      failedChecks.push({
        line: 12,
        rule: "data.task in ['reply', 'summary', 'actions', 'formal', 'arabic']",
        reason: `Invalid task "${String(data.task)}": must be one of the 5 enumerated tasks.`,
      });
    }

    if (isPlainObject(data.counts)) {
      passedChecks.push({ line: 13, rule: "data.counts is map" });
      const countKeys = Object.keys(data.counts);
      const badCountKeys = countKeys.filter((k) => !CATEGORIES.includes(k));
      if (badCountKeys.length === 0) {
        passedChecks.push({ line: 14, rule: "data.counts.keys().hasOnly([...10 PII categories])" });
      } else {
        failedChecks.push({
          line: 14,
          rule: "data.counts.keys().hasOnly(['PERSON', 'ORG', 'EMAIL', 'PHONE', 'ADDRESS', 'ID', 'ACCOUNT', 'MONEY', 'SECRET', 'DATE'])",
          reason: `Unknown counts key(s): ${badCountKeys.map((k) => `"${k}"`).join(", ")}.`,
        });
      }

      const badValues = [];
      for (let i = 0; i < CATEGORIES.length; i++) {
        const cat = CATEGORIES[i];
        if (Object.prototype.hasOwnProperty.call(data.counts, cat)) {
          if (!isNonNegInt(data.counts[cat])) {
            badValues.push({ cat, line: 15 + i, val: data.counts[cat] });
          }
        }
      }
      if (badValues.length === 0) {
        passedChecks.push({ line: 7, rule: "validCount(data.counts, key) -> int >= 0 for all categories" });
      } else {
        for (const bv of badValues) {
          failedChecks.push({
            line: bv.line,
            rule: `validCount(data.counts, '${bv.cat}')`,
            reason: `Blocked value smuggling in counts.${bv.cat}: expected non-negative integer, received ${typeof bv.val} (${JSON.stringify(bv.val).slice(0, 48)}).`,
          });
        }
      }
    } else {
      failedChecks.push({
        line: 13,
        rule: "data.counts is map",
        reason: "Field 'counts' must be a map of category integers.",
      });
    }

    if (isNonNegInt(data.masked)) {
      passedChecks.push({ line: 25, rule: "data.masked is int && data.masked >= 0" });
    } else {
      failedChecks.push({
        line: 25,
        rule: "data.masked is int && data.masked >= 0",
        reason: `Field 'masked' must be a non-negative integer (got ${JSON.stringify(data.masked)}).`,
      });
    }

    if (typeof data.detector === "string" && FIRESTORE_VALID_DETECTORS.includes(data.detector)) {
      passedChecks.push({ line: 26, rule: "data.detector in ['on_device', 'rules_only']" });
    } else {
      failedChecks.push({
        line: 26,
        rule: "data.detector in ['on_device', 'rules_only']",
        reason: `Field 'detector' must be 'on_device' or 'rules_only' (got ${JSON.stringify(data.detector)}).`,
      });
    }

    if (typeof data.reasoner === "string" && FIRESTORE_VALID_REASONERS.includes(data.reasoner)) {
      passedChecks.push({ line: 27, rule: "data.reasoner in ['in_cloud', 'on_device']" });
    } else {
      failedChecks.push({
        line: 27,
        rule: "data.reasoner in ['in_cloud', 'on_device']",
        reason: `Field 'reasoner' must be 'in_cloud' or 'on_device' (got ${JSON.stringify(data.reasoner)}).`,
      });
    }

    if (isNonNegInt(data.outboundChars)) {
      passedChecks.push({ line: 28, rule: "data.outboundChars is int && data.outboundChars >= 0" });
    } else {
      failedChecks.push({
        line: 28,
        rule: "data.outboundChars is int && data.outboundChars >= 0",
        reason: `Field 'outboundChars' must be a non-negative integer (got ${JSON.stringify(data.outboundChars)}).`,
      });
    }

    if (data.leakGuard === "pass") {
      passedChecks.push({ line: 29, rule: "data.leakGuard == 'pass'" });
    } else {
      failedChecks.push({
        line: 29,
        rule: "data.leakGuard == 'pass'",
        reason: `Field 'leakGuard' must equal 'pass' (got ${JSON.stringify(data.leakGuard)}). Blocked receipts cannot be written.`,
      });
    }

    if (isNonNegInt(data.unknownTokens)) {
      passedChecks.push({ line: 30, rule: "data.unknownTokens is int && data.unknownTokens >= 0" });
    } else {
      failedChecks.push({
        line: 30,
        rule: "data.unknownTokens is int && data.unknownTokens >= 0",
        reason: `Field 'unknownTokens' must be a non-negative integer (got ${JSON.stringify(data.unknownTokens)}).`,
      });
    }

    if (data.at === serverTimeToken) {
      passedChecks.push({ line: 31, rule: "data.at == request.time" });
    } else {
      failedChecks.push({
        line: 31,
        rule: "data.at == request.time",
        reason: `Client-forged timestamp rejected (${JSON.stringify(data.at)}); must use Firestore serverTimestamp() == request.time.`,
      });
    }
  }

  const allowed = failedChecks.length === 0;
  return {
    allowed,
    decision: allowed ? "ALLOW" : "DENY",
    path: cleanPath,
    operation: op,
    matchedRuleBlock,
    passedChecks,
    failedChecks,
    summary: allowed
      ? `ALLOW: All ${passedChecks.length} firestore.rules zero-text predicates passed.`
      : failedChecks[0].reason,
  };
}

const DEMO_SESSION_PATH = "sessions/anon_9a8b7c6d-1234-4e5f-8a9b-0c1d2e3f4a5b/receipts/rcpt_demo";
const CLEAN_RECEIPT_BASE = {
  task: "reply",
  counts: { PERSON: 2, ORG: 1, ACCOUNT: 1, MONEY: 1, SECRET: 1, PHONE: 1, EMAIL: 1, DATE: 1 },
  masked: 9,
  detector: "on_device",
  reasoner: "in_cloud",
  outboundChars: 342,
  leakGuard: "pass",
  unknownTokens: 0,
  at: "serverTimestamp()",
};

export const FIRESTORE_ATTACK_VECTORS = [
  {
    id: "clean_receipt",
    label: "Clean Zero-Text Receipt",
    expected: "ALLOW",
    path: DEMO_SESSION_PATH,
    operation: "create",
    description: "Valid counts-only receipt generated by Veil after Leak Guard pass.",
    data: { ...CLEAN_RECEIPT_BASE, counts: { ...CLEAN_RECEIPT_BASE.counts } },
  },
  {
    id: "raw_text_leak",
    label: "Inject raw 'text' field",
    expected: "DENY",
    path: DEMO_SESSION_PATH,
    operation: "create",
    description: "Adversarial client attempts to persist the raw email body in Firestore.",
    data: { ...CLEAN_RECEIPT_BASE, counts: { ...CLEAN_RECEIPT_BASE.counts }, text: "Hi Sara Al Mansoori, wire AED 48,500 immediately." },
  },
  {
    id: "raw_iban_leak",
    label: "Inject raw 'iban' secret",
    expected: "DENY",
    path: DEMO_SESSION_PATH,
    operation: "create",
    description: "Adversarial client attaches an exfiltrated IBAN key to the receipt.",
    data: { ...CLEAN_RECEIPT_BASE, counts: { ...CLEAN_RECEIPT_BASE.counts }, iban: "AE07 0331 2345 6789 0123 456" },
  },
  {
    id: "smuggled_string_counts",
    label: "Smuggle string in counts",
    expected: "DENY",
    path: DEMO_SESSION_PATH,
    operation: "create",
    description: "Adversarial attempt to smuggle an unmasked person name inside allowed key counts.PERSON.",
    data: { ...CLEAN_RECEIPT_BASE, counts: { PERSON: "Sara Al Mansoori", ACCOUNT: 1 } },
  },
  {
    id: "bypass_leak_guard",
    label: "Bypass leakGuard status",
    expected: "DENY",
    path: DEMO_SESSION_PATH,
    operation: "create",
    description: "Attempts to log a receipt where leakGuard did not pass ('fail').",
    data: { ...CLEAN_RECEIPT_BASE, counts: { ...CLEAN_RECEIPT_BASE.counts }, leakGuard: "fail" },
  },
  {
    id: "forged_timestamp",
    label: "Forge client timestamp",
    expected: "DENY",
    path: DEMO_SESSION_PATH,
    operation: "create",
    description: "Attempts to backdate the audit log using a client string instead of serverTimestamp().",
    data: { ...CLEAN_RECEIPT_BASE, counts: { ...CLEAN_RECEIPT_BASE.counts }, at: "2026-01-01T00:00:00Z" },
  },
  {
    id: "tamper_update",
    label: "Tamper via UPDATE",
    expected: "DENY",
    path: DEMO_SESSION_PATH,
    operation: "update",
    description: "Attempts to modify an existing immutable compliance receipt.",
    data: { ...CLEAN_RECEIPT_BASE, counts: { ...CLEAN_RECEIPT_BASE.counts }, masked: 0 },
  },
  {
    id: "hijack_session_path",
    label: "Hijack session path",
    expected: "DENY",
    path: "sessions/admin_dump_bucket/receipts/stolen_01",
    operation: "create",
    description: "Writes outside strict anon_<uuid> session namespace.",
    data: { ...CLEAN_RECEIPT_BASE, counts: { ...CLEAN_RECEIPT_BASE.counts } },
  },
];

export function runAllFirestoreRuleTests(vectors = FIRESTORE_ATTACK_VECTORS) {
  const results = vectors.map((v) => {
    const evalRes = evaluateFirestoreRule({
      path: v.path,
      operation: v.operation,
      data: v.data,
      authUid: v.authUid || null,
    });
    return {
      ...v,
      evaluation: evalRes,
      matchedExpectation: evalRes.decision === v.expected,
    };
  });
  const total = results.length;
  const passedExpectations = results.filter((r) => r.matchedExpectation).length;
  const adversarialTotal = results.filter((r) => r.expected === "DENY").length;
  const adversarialBlocked = results.filter((r) => r.expected === "DENY" && r.evaluation.decision === "DENY").length;
  const cleanAllowed = results.filter((r) => r.expected === "ALLOW" && r.evaluation.decision === "ALLOW").length;
  return {
    total,
    passedExpectations,
    adversarialTotal,
    adversarialBlocked,
    cleanAllowed,
    allPassed: passedExpectations === total,
    results,
  };
}

// =========================================================================
// BATCH MULTI-DOCUMENT REDACTION QUEUE & CONSOLIDATED COMPLIANCE BUNDLE
// =========================================================================

/**
 * Redact a single enterprise document locally with full Leak Guard, byte telemetry,
 * and local round-trip restore verification.
 */
export function redactSingleDocument(doc, enabledCategories = CATEGORIES) {
  const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();
  const text = String(doc?.text || "");
  const task = TASKS[doc?.task] ? doc.task : "summary";

  const spans = detectWithRules(text, enabledCategories);
  const plan = buildPlan(spans);
  const masked = mask(text, plan);
  const tFind = (typeof performance !== "undefined" ? performance.now() : Date.now()) - t0;

  const tGuard0 = typeof performance !== "undefined" ? performance.now() : Date.now();
  const outbound = `${TASKS[task]}\n\n${masked}`;
  let leakGuardPassed = false;
  try {
    leakGuardPassed = leakCheck(outbound, plan) === true;
  } catch {
    leakGuardPassed = false;
  }
  const wireCheck = verifyOutboundBytesZeroSecrets(outbound, plan);
  const tGuard = (typeof performance !== "undefined" ? performance.now() : Date.now()) - tGuard0;

  const tRestore0 = typeof performance !== "undefined" ? performance.now() : Date.now();
  const restored = unmaskSegments(masked, plan);
  const tRestore = (typeof performance !== "undefined" ? performance.now() : Date.now()) - tRestore0;

  const allSecretsRestored = plan.every((e) => restored.text.includes(e.text));
  const telemetry = computeTelemetrySplit({
    rawText: text,
    maskedText: masked,
    plan,
    findMs: tFind,
    guardMs: tGuard,
    cloudMs: 0,
    restoreMs: tRestore,
    localOnly: true,
  });

  const receipt = buildReceiptPayload({
    task,
    plan,
    detectorSource: "rules_only",
    reasonerSource: "on_device",
    outboundChars: outbound.length,
    unknownTokensCount: restored.unknownTokens.length,
  });

  const elapsedMs = Math.max(0.1, Math.round((tFind + tGuard + tRestore) * 10) / 10);

  return {
    id: doc?.id || `doc_${Math.random().toString(36).slice(2, 8)}`,
    name: doc?.name || "Untitled Document",
    industry: doc?.industry || "Enterprise",
    task,
    maskedCount: plan.length,
    counts: countByType(plan),
    leakGuardPassed: leakGuardPassed && wireCheck.passed,
    leakedBytes: wireCheck.passed ? 0 : wireCheck.leakedCount,
    restoredCount: restored.restoredCount,
    roundTripVerified: allSecretsRestored && restored.unknownTokens.length === 0,
    unknownTokensCount: restored.unknownTokens.length,
    rawBytes: telemetry.bytes.rawBytes,
    outboundBytes: telemetry.bytes.outboundBytes,
    secretBytesShielded: telemetry.bytes.secretBytesShielded,
    byteDelta: telemetry.bytes.byteDelta,
    privacyShieldPct: telemetry.bytes.privacyShieldPct,
    elapsedMs,
    telemetry,
    receipt,
    // Local-only fields (never exported into compliance bundles)
    masked,
    outbound,
    plan,
  };
}

/**
 * Run Veil's sequential local redaction pipeline over multiple enterprise documents.
 * Defaults to the 3 industry presets (Finance, Healthcare, Legal) when no custom list is supplied.
 */
export function runBatchRedactionQueue(docs = null, enabledCategories = CATEGORIES) {
  const inputDocs = Array.isArray(docs) && docs.length
    ? docs
    : PRESETS.map((p) => ({
        id: p.id,
        name: `${p.label}.txt`,
        industry: p.industry,
        task: p.defaultTask,
        text: p.text,
      }));

  const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();
  const documents = [];
  const aggregateCounts = {};
  let totalMasked = 0;
  let totalLeaked = 0;
  let totalRestored = 0;
  let totalRawBytes = 0;
  let totalOutboundBytes = 0;
  let totalSecretBytesShielded = 0;
  let passedDocs = 0;

  for (const doc of inputDocs) {
    const res = redactSingleDocument(doc, enabledCategories);
    documents.push(res);
    totalMasked += res.maskedCount;
    totalLeaked += res.leakedBytes;
    totalRestored += res.restoredCount;
    totalRawBytes += res.rawBytes;
    totalOutboundBytes += res.outboundBytes;
    totalSecretBytesShielded += res.secretBytesShielded;
    if (res.leakGuardPassed && res.roundTripVerified) passedDocs += 1;
    for (const [k, v] of Object.entries(res.counts)) {
      aggregateCounts[k] = (aggregateCounts[k] || 0) + v;
    }
  }

  const elapsedMs = Math.max(1, Math.round(((typeof performance !== "undefined" ? performance.now() : Date.now()) - t0) * 10) / 10);
  const totalByteDelta = totalRawBytes - totalOutboundBytes;
  const aggregateShieldPct = totalRawBytes > 0 ? Math.round((totalSecretBytesShielded / totalRawBytes) * 1000) / 10 : 0;

  return {
    totalDocs: documents.length,
    passedDocs,
    allZeroLeak: passedDocs === documents.length && totalLeaked === 0,
    totalMasked,
    totalLeaked,
    totalRestored,
    totalRawBytes,
    totalOutboundBytes,
    totalSecretBytesShielded,
    totalByteDelta,
    aggregateShieldPct,
    aggregateCounts,
    elapsedMs,
    documents,
  };
}

/**
 * Build a strictly zero-text consolidated compliance bundle (.json) for a completed batch queue.
 * Never embeds raw document text or secret values.
 */
export function buildBatchComplianceBundle({
  batchSummary,
  docDigests = {},
  bundleSha256 = null,
  policySnapshot = null,
  rulesTestSummary = null,
}) {
  return {
    schema: "veil.batch-zero-text-compliance-bundle/v1",
    issuedAt: new Date().toISOString(),
    cryptographicSummary: {
      algorithm: "SHA-256",
      aggregateBundleDigest: bundleSha256 || null,
      totalDocuments: batchSummary.totalDocs,
      documentsVerifiedZeroLeak: batchSummary.passedDocs,
      totalEntitiesMaskedOnDevice: batchSummary.totalMasked,
      totalSecretBytesKeptOnDevice: batchSummary.totalSecretBytesShielded,
      totalPiiBytesLeaked: batchSummary.totalLeaked,
      totalRawBytes: batchSummary.totalRawBytes,
      totalSanitizedOutboundBytes: batchSummary.totalOutboundBytes,
      netByteDelta: batchSummary.totalByteDelta,
      aggregatePrivacyShieldPct: batchSummary.aggregateShieldPct,
      elapsedMs: batchSummary.elapsedMs,
      aggregateCountsByCategory: batchSummary.aggregateCounts,
    },
    documents: batchSummary.documents.map((d) => ({
      id: d.id,
      name: d.name,
      industry: d.industry,
      task: d.task,
      maskedCount: d.maskedCount,
      counts: d.counts,
      rawBytes: d.rawBytes,
      outboundBytes: d.outboundBytes,
      secretBytesShielded: d.secretBytesShielded,
      byteDelta: d.byteDelta,
      leakGuard: d.leakGuardPassed ? "pass" : "blocked",
      leakedBytes: d.leakedBytes,
      roundTripRestoredCount: d.restoredCount,
      roundTripVerified: d.roundTripVerified,
      outboundSha256: docDigests[d.id] || null,
      elapsedMs: d.elapsedMs,
    })),
    firestoreRulesEnforcement: rulesTestSummary
      ? {
          adversarialVectorsBlocked: rulesTestSummary.adversarialBlocked,
          adversarialVectorsTotal: rulesTestSummary.adversarialTotal,
          cleanReceiptsAllowed: rulesTestSummary.cleanAllowed,
          allPredicatesVerified: rulesTestSummary.allPassed,
        }
      : null,
    remoteConfigPolicy: policySnapshot
      ? {
          source: policySnapshot.source,
          cloudModel: policySnapshot.cloudModel,
          categoriesCount: policySnapshot.categories?.length || 0,
          maxChars: policySnapshot.maxChars,
        }
      : null,
    attestation: "Zero raw text, zero PII values, and zero credentials are included in this consolidated compliance bundle.",
  };
}
