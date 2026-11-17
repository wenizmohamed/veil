import { describe, it, expect } from "vitest";
import { detectWithRules, sanitizeModelSpans, buildPlan, mask, unmask, leakCheck, countByType } from "../src/veil-core.js";

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
