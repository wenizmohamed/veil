import { describe, it, expect } from "vitest";
import {
  detectWithRules, sanitizeModelSpans, buildPlan, mask, unmask, unmaskSegments,
  tokenizeMaskedText, buildReceiptPayload, leakCheck, countByType, PRESETS, TASKS,
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
