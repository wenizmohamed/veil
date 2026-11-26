import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  detectWithRules, sanitizeModelSpans, buildPlan, mask, unmask, unmaskSegments,
  tokenizeMaskedText, buildReceiptPayload, verifyOutboundBytesZeroSecrets,
  buildComplianceCertificate, runAdversarialStressTest,
  utf8ByteLength, computeTelemetrySplit,
  evaluateFirestoreRule, runAllFirestoreRuleTests,
  FIRESTORE_RULES_SOURCE, FIRESTORE_ATTACK_VECTORS,
  redactSingleDocument, runBatchRedactionQueue, buildBatchComplianceBundle,
  leakCheck, countByType, PRESETS, TASKS,
} from "../src/veil-core.js";

const EMAIL = `Hi Sara Al Mansoori,
Please wire AED 48,500 to IBAN AE07 0331 2345 6789 0123 456 before Thursday.
Call me on +971 50 123 4567 or reply to sara.m@falconlogistics.ae.
Staging key: sk_demoNOTAREALKEY7Hq2Lyj9WDar
Emirates ID on file: 784-1990-1234567-1`;

describe("rules detector", () => {
  const found = detectWithRules(EMAIL);
  const has = (type, text) => found.some((f) => f.type === type && f.text.includes(text));
  it("finds email, phone, IBAN, money, key, Emirates ID", () => {
    expect(has("EMAIL", "sara.m@falconlogistics.ae")).toBe(true);
    expect(has("PHONE", "+971 50 123 4567")).toBe(true);
    expect(has("ACCOUNT", "AE07 0331")).toBe(true);
    expect(has("MONEY", "AED 48,500")).toBe(true);
    expect(has("SECRET", "sk_demoNOTAREALKEY")).toBe(true);
    expect(has("ID", "784-1990-1234567-1")).toBe(true);
  });
  it("rejects digit runs that fail Luhn", () => {
    expect(detectWithRules("order 1234 5678 9012 3456", ["ACCOUNT"])).toHaveLength(0);
    expect(detectWithRules("card 4111 1111 1111 1111", ["ACCOUNT"])).toHaveLength(1);
  });
});

describe("model spans", () => {
  it("drops spans the model invented or paraphrased", () => {
    const spans = sanitizeModelSpans(EMAIL, [
      { text: "Sara Al Mansoori", type: "PERSON" },
      { text: "Sarah Mansour", type: "PERSON" },
      { text: "Falcon Logistics", type: "ORG" },
      { text: "x", type: "PERSON" },
      { text: "Thursday", type: "WEATHER" },
    ]);
    expect(spans.map((s) => s.text)).toEqual(["Sara Al Mansoori"]);
  });
});

describe("mask / leak guard / unmask", () => {
  const spans = [...detectWithRules(EMAIL), ...sanitizeModelSpans(EMAIL, [
    { text: "Sara Al Mansoori", type: "PERSON" }, { text: "Sara", type: "PERSON" }])];
  const plan = buildPlan(spans);
  const masked = mask(EMAIL, plan);

  it("removes every secret from the outbound text", () => {
    for (const e of plan) expect(masked.toLowerCase()).not.toContain(e.text.toLowerCase());
    expect(leakCheck(masked, plan)).toBe(true);
    expect(masked).toContain("[PERSON_1]");
  });
  it("masks the longer name before the shorter one", () => {
    expect(plan.find((e) => e.token === "[PERSON_1]").text).toBe("Sara Al Mansoori");
  });
  it("blocks a request that still carries a secret", () => {
    expect(() => leakCheck(masked + " sara.m@falconlogistics.ae", plan)).toThrow(/Leak guard/);
  });
  it("restores values locally and reports invented tokens", () => {
    const reply = "Dear [PERSON_1], I will send [MONEY_1] today. Thanks, [PERSON_9]";
    const { text, unknownTokens } = unmask(reply, plan);
    expect(text).toContain("Dear Sara Al Mansoori");
    expect(text).toContain("AED 48,500");
    expect(unknownTokens).toEqual(["[PERSON_9]"]);
  });
  it("counts by category without exposing values", () => {
    const counts = countByType(plan);
    expect(counts.PERSON).toBe(2);
    expect(Object.values(counts).every(Number.isInteger)).toBe(true);
  });
});

describe("name and company backstop", () => {
  const MAIL = `Hi Sara Al Mansoori,\n\nFollowing our call, Falcon Logistics agrees.\n\nBest,\nOmar Khalid\nHead of Finance, Falcon Logistics`;
  const found = detectWithRules(MAIL);
  const texts = found.filter((f) => f.type === "PERSON" || f.type === "ORG").map((f) => f.text);
  it("catches names from greetings and sign-offs, and company names by suffix", () => {
    expect(texts).toContain("Sara Al Mansoori");
    expect(texts).toContain("Omar Khalid");
    expect(texts).toContain("Falcon Logistics");
  });
  it("masks the signature name so it never reaches the cloud", () => {
    const plan = buildPlan(found);
    expect(mask(MAIL, plan)).not.toMatch(/Omar|Khalid|Sara|Falcon/);
  });
  it("ignores lowercase greetings", () => {
    expect(detectWithRules("Hi team,\nthanks all", ["PERSON"])).toHaveLength(0);
  });
});

describe("whole-value masking", () => {
  it("does not mask a short value inside a longer word", () => {
    const plan = buildPlan([{ text: "Ali", type: "PERSON", source: "nano" }]);
    expect(mask("Ali met Alison in Bali.", plan)).toBe("[PERSON_1] met Alison in Bali.");
  });
  it("drops model spans shorter than three characters", () => {
    expect(sanitizeModelSpans("Wire to AE07 0331", [{ text: "AE", type: "ADDRESS" }])).toHaveLength(0);
  });
});

describe("industry presets — zero leaks across Finance, Healthcare, Legal", () => {
  const mustMaskByPreset = {
    finance: [
      "Sara Al Mansoori",
      "Omar Khalid",
      "Falcon Logistics",
      "AED 48,500",
      "AE07 0331 2345 6789 0123 456",
      "3 December 2026",
      "sk_demoNOTAREALKEY7Hq2Lyj9WDar",
      "+971 50 123 4567",
      "omar.khalid@falconlogistics.ae",
    ],
    healthcare: [
      "Layla Al Nuaimi",
      "784-1988-7654321-4",
      "MRN-849201",
      "+971 55 892 3410",
      "layla.nuaimi@example.ae",
      "Tariq Mansour",
      "Al Noor Medical Center",
      "18 November 2026",
      "AED 1,850",
    ],
    legal: [
      "Gulf Horizon Technologies LLC",
      "Nadia Al Qasimi",
      "nadia.qasimi@gulfhorizon.ae",
      "Crescent Capital Partners",
      "David Chen",
      "d.chen@crescentcap.com",
      "USD 14,500,000",
      "AED 53,250,000",
      "Emirates NBD Bank",
      "AE46 0260 0010 1555 2890 101",
      "1 December 2026",
      "15 February 2027",
      "rk_demoNOTAREALTOKEN9mK4xP2vQ8wR",
    ],
  };

  it("ships all 3 enterprise industry presets with valid default tasks", () => {
    expect(PRESETS.map((p) => p.id)).toEqual(["finance", "healthcare", "legal"]);
    for (const preset of PRESETS) {
      expect(TASKS[preset.defaultTask]).toBeTruthy();
    }
  });

  for (const preset of PRESETS) {
    it(`masks every sensitive entity in "${preset.label}" with 0 leaks`, () => {
      const spans = detectWithRules(preset.text);
      const plan = buildPlan(spans);
      const masked = mask(preset.text, plan);
      const outbound = `${TASKS[preset.defaultTask]}\n\n${masked}`;

      expect(leakCheck(outbound, plan)).toBe(true);
      for (const secret of mustMaskByPreset[preset.id]) {
        expect(outbound.toLowerCase()).not.toContain(secret.toLowerCase());
      }
      // Round-trip restore puts every masked value back locally
      const { text: restored, unknownTokens, restoredCount } = unmaskSegments(masked, plan);
      expect(unknownTokens).toHaveLength(0);
      expect(restoredCount).toBeGreaterThanOrEqual(mustMaskByPreset[preset.id].length);
      for (const secret of mustMaskByPreset[preset.id]) {
        expect(restored).toContain(secret);
      }
    });
  }
});

describe("visual token highlighting & Firestore zero-text payload", () => {
  it("tokenizes masked text into typed badges for UI highlighting", () => {
    const segs = tokenizeMaskedText("Wire [MONEY_1] to [ACCOUNT_1] for [PERSON_1].");
    const tokens = segs.filter((s) => s.kind === "token");
    expect(tokens).toEqual([
      { kind: "token", token: "[MONEY_1]", type: "MONEY" },
      { kind: "token", token: "[ACCOUNT_1]", type: "ACCOUNT" },
      { kind: "token", token: "[PERSON_1]", type: "PERSON" },
    ]);
  });

  it("builds a strict zero-text Firestore receipt matching firestore.rules", () => {
    const preset = PRESETS[0];
    const plan = buildPlan(detectWithRules(preset.text));
    const masked = mask(preset.text, plan);
    const payload = buildReceiptPayload({
      task: "reply",
      plan,
      detectorSource: "rules_only",
      reasonerSource: "in_cloud",
      outboundChars: masked.length,
      unknownTokensCount: 0,
    });
    expect(Object.keys(payload).sort()).toEqual([
      "counts", "detector", "leakGuard", "masked", "outboundChars", "reasoner", "task", "unknownTokens",
    ]);
    expect(payload.leakGuard).toBe("pass");
    const serialized = JSON.stringify(payload).toLowerCase();
    for (const entry of plan) {
      expect(serialized).not.toContain(entry.text.toLowerCase());
    }
  });
});

describe("12-trap adversarial PII stress test & wiretap cryptographic proof", () => {
  it("catches and restores 12/12 adversarial PII traps on-device with 0 bytes leaked", () => {
    const summary = runAdversarialStressTest();
    expect(summary.total).toBe(12);
    expect(summary.caught).toBe(12);
    expect(summary.leaked).toBe(0);
    expect(summary.restored).toBe(12);
    for (const r of summary.results) {
      expect(r.caught).toBe(true);
      expect(r.leakedBytes).toBe(0);
      expect(r.restored).toBe(true);
    }
  });

  it("verifies raw outbound HTTP JSON bytes contain 0 secret substrings and flags leaks", () => {
    const preset = PRESETS[0];
    const plan = buildPlan(detectWithRules(preset.text));
    const masked = mask(preset.text, plan);
    const cleanHttpJson = JSON.stringify({ contents: [{ role: "user", parts: [{ text: masked }] }] });
    const cleanRes = verifyOutboundBytesZeroSecrets(cleanHttpJson, plan);
    expect(cleanRes.passed).toBe(true);
    expect(cleanRes.leakedCount).toBe(0);
    expect(cleanRes.bytes).toBeGreaterThan(50);

    const dirtyHttpJson = JSON.stringify({ contents: [{ role: "user", parts: [{ text: masked + " AE07 0331 2345 6789 0123 456" }] }] });
    const dirtyRes = verifyOutboundBytesZeroSecrets(dirtyHttpJson, plan);
    expect(dirtyRes.passed).toBe(false);
    expect(dirtyRes.leakedCount).toBe(1);
  });

  it("builds a zero-text compliance certificate bound to Firestore receipt path and SHA-256 digest", () => {
    const preset = PRESETS[0];
    const plan = buildPlan(detectWithRules(preset.text));
    const masked = mask(preset.text, plan);
    const receiptPayload = buildReceiptPayload({
      task: "reply",
      plan,
      detectorSource: "rules_only",
      reasonerSource: "in_cloud",
      outboundChars: masked.length,
      unknownTokensCount: 0,
    });
    const cert = buildComplianceCertificate({
      firestorePath: "sessions/anon_test/receipts/abc123",
      receiptPayload,
      sha256Hex: "a".repeat(64),
      outboundBytes: 420,
      wiretapEndpoint: "firebasevertexai.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent",
      policySnapshot: { source: "remote", cloudModel: "gemini-3.5-flash-lite", categories: ["PERSON"], maxChars: 6000 },
      stressTestSummary: runAdversarialStressTest(),
    });
    expect(cert.schema).toBe("veil.zero-text-compliance-certificate/v1");
    expect(cert.firestoreReceiptPath).toBe("sessions/anon_test/receipts/abc123");
    expect(cert.cryptographicProof.outboundPayloadDigest).toHaveLength(64);
    expect(cert.adversarialStressTest.caughtOnDevice).toBe(12);
    const json = JSON.stringify(cert).toLowerCase();
    for (const entry of plan) {
      expect(json).not.toContain(entry.text.toLowerCase());
    }
  });
});

describe("Firestore zero-text security rules evaluator (exact firestore.rules parity)", () => {
  const validPath = "sessions/anon_9a8b7c6d-1234-4e5f-8a9b-0c1d2e3f4a5b/receipts/rcpt_1";
  const validData = {
    task: "reply",
    counts: { PERSON: 2, ACCOUNT: 1, MONEY: 1 },
    masked: 4,
    detector: "on_device",
    reasoner: "in_cloud",
    outboundChars: 240,
    leakGuard: "pass",
    unknownTokens: 0,
    at: "serverTimestamp()",
  };

  it("matches the actual firestore.rules file on disk verbatim", () => {
    const diskRules = fs.readFileSync(path.resolve(process.cwd(), "firestore.rules"), "utf8").replace(/\r\n/g, "\n").trim();
    expect(FIRESTORE_RULES_SOURCE.replace(/\r\n/g, "\n").trim()).toBe(diskRules);
  });

  it("passes all 8 built-in security rule vectors (7/7 adversarial leaks denied, 1/1 clean allowed)", () => {
    const suite = runAllFirestoreRuleTests();
    expect(suite.total).toBe(8);
    expect(suite.adversarialTotal).toBe(7);
    expect(suite.adversarialBlocked).toBe(7);
    expect(suite.cleanAllowed).toBe(1);
    expect(suite.allPassed).toBe(true);
    expect(FIRESTORE_ATTACK_VECTORS).toHaveLength(8);
  });

  it("denies raw text field injection on line 11 hasOnly predicate", () => {
    const res = evaluateFirestoreRule({
      path: validPath,
      operation: "create",
      data: { ...validData, text: "raw secret email body" },
    });
    expect(res.allowed).toBe(false);
    expect(res.decision).toBe("DENY");
    expect(res.failedChecks.some((c) => c.line === 11 && c.reason.includes('"text"'))).toBe(true);
  });

  it("denies raw IBAN key exfiltration on line 11 hasOnly predicate", () => {
    const res = evaluateFirestoreRule({
      path: validPath,
      operation: "create",
      data: { ...validData, iban: "AE07 0331 2345 6789 0123 456" },
    });
    expect(res.allowed).toBe(false);
    expect(res.failedChecks.some((c) => c.line === 11 && c.reason.includes('"iban"'))).toBe(true);
  });

  it("denies unmasked string smuggling inside allowed counts map keys", () => {
    const res = evaluateFirestoreRule({
      path: validPath,
      operation: "create",
      data: { ...validData, counts: { PERSON: "Sara Al Mansoori", ACCOUNT: 1 } },
    });
    expect(res.allowed).toBe(false);
    expect(res.failedChecks.some((c) => c.line === 15 && c.reason.includes("counts.PERSON"))).toBe(true);
  });

  it("denies negative or non-integer counts and invalid category keys", () => {
    const negRes = evaluateFirestoreRule({
      path: validPath,
      operation: "create",
      data: { ...validData, counts: { MONEY: -3 } },
    });
    expect(negRes.allowed).toBe(false);

    const badKeyRes = evaluateFirestoreRule({
      path: validPath,
      operation: "create",
      data: { ...validData, counts: { RAW_TEXT: 1 } },
    });
    expect(badKeyRes.allowed).toBe(false);
    expect(badKeyRes.failedChecks.some((c) => c.line === 14)).toBe(true);
  });

  it("denies bypassed leakGuard, invalid task/detector/reasoner, and forged client timestamps", () => {
    expect(evaluateFirestoreRule({ path: validPath, data: { ...validData, leakGuard: "blocked" } }).allowed).toBe(false);
    expect(evaluateFirestoreRule({ path: validPath, data: { ...validData, task: "exfiltrate" } }).allowed).toBe(false);
    expect(evaluateFirestoreRule({ path: validPath, data: { ...validData, detector: "in_cloud" } }).allowed).toBe(false);
    expect(evaluateFirestoreRule({ path: validPath, data: { ...validData, reasoner: "third_party" } }).allowed).toBe(false);
    expect(evaluateFirestoreRule({ path: validPath, data: { ...validData, at: "2026-11-20T00:00:00Z" } }).allowed).toBe(false);
  });

  it("enforces immutable append-only receipts (denies update and delete)", () => {
    const upd = evaluateFirestoreRule({ path: validPath, operation: "update", data: validData });
    const del = evaluateFirestoreRule({ path: validPath, operation: "delete", data: validData });
    expect(upd.allowed).toBe(false);
    expect(upd.failedChecks[0].line).toBe(43);
    expect(del.allowed).toBe(false);
    expect(del.failedChecks[0].line).toBe(43);
  });

  it("enforces authenticated uid ownership on /users/{uid}/receipts/{id} and catch-all deny elsewhere", () => {
    const own = evaluateFirestoreRule({
      path: "users/uid_alice_123/receipts/r1",
      operation: "create",
      authUid: "uid_alice_123",
      data: validData,
    });
    expect(own.allowed).toBe(true);

    const hijack = evaluateFirestoreRule({
      path: "users/uid_alice_123/receipts/r1",
      operation: "create",
      authUid: "uid_mallory_999",
      data: validData,
    });
    expect(hijack.allowed).toBe(false);

    const unauthRead = evaluateFirestoreRule({
      path: "users/uid_alice_123/receipts/r1",
      operation: "read",
      authUid: null,
    });
    expect(unauthRead.allowed).toBe(false);

    const rogueCollection = evaluateFirestoreRule({
      path: "leaked_prompts/doc1",
      operation: "create",
      data: validData,
    });
    expect(rogueCollection.allowed).toBe(false);
    expect(rogueCollection.failedChecks[0].line).toBe(47);
  });
});

describe("batch multi-document redaction queue & consolidated compliance bundle", () => {
  it("redacts all 3 enterprise documents sequentially with 0 bytes leaked and 100% round-trip restore", () => {
    const batch = runBatchRedactionQueue();
    expect(batch.totalDocs).toBe(3);
    expect(batch.passedDocs).toBe(3);
    expect(batch.allZeroLeak).toBe(true);
    expect(batch.totalLeaked).toBe(0);
    expect(batch.totalMasked).toBeGreaterThanOrEqual(25);
    expect(batch.totalSecretBytesShielded).toBeGreaterThan(200);
    for (const d of batch.documents) {
      expect(d.leakGuardPassed).toBe(true);
      expect(d.roundTripVerified).toBe(true);
      expect(d.leakedBytes).toBe(0);
    }
  });

  it("handles custom multi-document batches including bilingual Arabic + English PII", () => {
    const customDocs = [
      { id: "c1", name: "arabic-intake.txt", industry: "Clinic", task: "summary", text: "المريض: محمد المنصوري | Emirates ID: 784-1992-1234567-9 | Phone: +971 50 444 5566" },
      { id: "c2", name: "wire-note.txt", industry: "Treasury", task: "formal", text: "Dear Omar Khalid, please wire USD 120,000 to AE07 0331 2345 6789 0123 456." },
    ];
    const batch = runBatchRedactionQueue(customDocs);
    expect(batch.totalDocs).toBe(2);
    expect(batch.passedDocs).toBe(2);
    expect(batch.allZeroLeak).toBe(true);
    expect(batch.documents[0].outbound).not.toContain("محمد المنصوري");
    expect(batch.documents[0].outbound).not.toContain("784-1992-1234567-9");
    expect(batch.documents[1].outbound).not.toContain("USD 120,000");
  });

  it("redacts a single document and populates a strict zero-text Firestore receipt", () => {
    const docRes = redactSingleDocument({ id: "single", name: "nda.txt", industry: "Legal", task: "actions", text: PRESETS[2].text });
    expect(docRes.leakGuardPassed).toBe(true);
    expect(docRes.receipt.leakGuard).toBe("pass");
    expect(docRes.receipt.task).toBe("actions");
    const evalReceipt = evaluateFirestoreRule({
      path: "sessions/anon_9a8b7c6d-1234-4e5f-8a9b-0c1d2e3f4a5b/receipts/batch_1",
      operation: "create",
      data: { ...docRes.receipt, at: "serverTimestamp()" },
    });
    expect(evalReceipt.allowed).toBe(true);
  });

  it("builds a consolidated compliance bundle JSON with strictly 0 raw secrets across all documents", () => {
    const batch = runBatchRedactionQueue();
    const rulesSuite = runAllFirestoreRuleTests();
    const bundle = buildBatchComplianceBundle({
      batchSummary: batch,
      docDigests: { finance: "1".repeat(64), healthcare: "2".repeat(64), legal: "3".repeat(64) },
      bundleSha256: "f".repeat(64),
      policySnapshot: { source: "remote", cloudModel: "gemini-3.5-flash-lite", categories: ["PERSON"], maxChars: 6000 },
      rulesTestSummary: rulesSuite,
    });
    expect(bundle.schema).toBe("veil.batch-zero-text-compliance-bundle/v1");
    expect(bundle.cryptographicSummary.documentsVerifiedZeroLeak).toBe(3);
    expect(bundle.cryptographicSummary.totalPiiBytesLeaked).toBe(0);
    expect(bundle.firestoreRulesEnforcement.adversarialVectorsBlocked).toBe(7);

    const serialized = JSON.stringify(bundle).toLowerCase();
    for (const d of batch.documents) {
      for (const entry of d.plan) {
        expect(serialized).not.toContain(entry.text.toLowerCase());
      }
    }
  });
});

describe("on-device vs cloud telemetry & privacy byte-split analytics", () => {
  it("computes accurate UTF-8 byte lengths for ASCII and multibyte Arabic text", () => {
    expect(utf8ByteLength("Veil")).toBe(4);
    expect(utf8ByteLength("محمد")).toBe(8);
  });

  it("computes measured hybrid latency split and exact secret byte shielding", () => {
    const text = PRESETS[0].text;
    const plan = buildPlan(detectWithRules(text));
    const masked = mask(text, plan);
    const split = computeTelemetrySplit({
      rawText: text,
      maskedText: masked,
      plan,
      findMs: 2.5,
      guardMs: 0.5,
      cloudMs: 297.0,
      restoreMs: 0.0,
      localOnly: false,
    });
    expect(split.latency.onDeviceTotalMs).toBe(3);
    expect(split.latency.cloudMs).toBe(297);
    expect(split.latency.totalMs).toBe(300);
    expect(split.latency.onDevicePct).toBe(1);
    expect(split.latency.cloudPct).toBe(99);
    expect(split.bytes.rawBytes).toBe(utf8ByteLength(text));
    expect(split.bytes.outboundBytes).toBe(utf8ByteLength(masked));
    expect(split.bytes.secretBytesShielded).toBeGreaterThan(80);
    expect(split.bytes.piiBytesOnWire).toBe(0);
    expect(split.bytes.zeroLeakVerified).toBe(true);
    expect(split.bytes.byteDelta).toBe(split.bytes.rawBytes - split.bytes.outboundBytes);
  });

  it("forces cloudMs to 0 and onDevicePct to 100 in local-only mode", () => {
    const split = computeTelemetrySplit({
      rawText: "Hello world without PII",
      maskedText: "Hello world without PII",
      plan: [],
      findMs: 1.2,
      guardMs: 0.3,
      cloudMs: 420,
      restoreMs: 0.5,
      localOnly: true,
    });
    expect(split.latency.cloudMs).toBe(0);
    expect(split.latency.onDevicePct).toBe(100);
    expect(split.latency.cloudPct).toBe(0);
    expect(split.bytes.secretBytesShielded).toBe(0);
    expect(split.bytes.privacyShieldPct).toBe(0);
  });

  it("flags unmasked secrets if a dirty outbound text is passed to telemetry split", () => {
    const plan = [{ token: "[ACCOUNT_1]", text: "AE07 0331 2345 6789 0123 456", type: "ACCOUNT", source: "rules" }];
    const split = computeTelemetrySplit({
      rawText: "Wire to AE07 0331 2345 6789 0123 456",
      maskedText: "Wire to AE07 0331 2345 6789 0123 456",
      plan,
      findMs: 1,
      guardMs: 0.2,
      cloudMs: 0,
      restoreMs: 0,
      localOnly: true,
    });
    expect(split.bytes.zeroLeakVerified).toBe(false);
    expect(split.bytes.piiBytesOnWire).toBe(1);
  });
});

describe("MV3 Chrome Extension & README link parity", () => {
  it("ships a valid Manifest V3 Chrome Extension with sidePanel and contextMenus", () => {
    const manifestPath = path.resolve(process.cwd(), "extension/public/manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toContain("sidePanel");
    expect(manifest.permissions).toContain("contextMenus");
    expect(manifest.side_panel?.default_path).toBe("sidepanel.html");
  });

  it("links the submitted Devpost v3 demo video in README.md", () => {
    const readme = fs.readFileSync(path.resolve(process.cwd(), "README.md"), "utf8");
    expect(readme).toContain("https://youtu.be/z2dt5Z9dvWA");
    expect(readme).not.toContain("eHMcEEeoXLA");
  });
});
