import { GoogleGenAI } from "@google/genai";

const ALLOWED_MODELS = new Set([
  "gemini-4-hydrogen",
  "gemini-4-neon",
  "gemini-4-argon",
  "gemini-3.8-flash",
  "gemini-3.5-flash-lite",
]);

function generateWithBudget(ai, { model, contents, systemInstruction, temperature, maxOutputTokens }, ms) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new Error(`sdk_timeout_${ms}ms`)), ms);
  return ai.models.generateContent({
    model,
    contents,
    config: {
      ...(systemInstruction ? { systemInstruction } : {}),
      temperature,
      maxOutputTokens,
      abortSignal: ac.signal,
    },
  }).finally(() => clearTimeout(timer));
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: "GEMINI_API_KEY is not configured on this deployment." });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const prompt = String(body.prompt || "").trim();
    if (!prompt || prompt.length > 16000) {
      return res.status(400).json({ error: "Invalid prompt length." });
    }

    const requestedModel = String(body.model || "gemini-4-hydrogen").trim();
    const primaryModel = ALLOWED_MODELS.has(requestedModel) ? requestedModel : "gemini-4-hydrogen";
    const systemInstruction = typeof body.systemInstruction === "string" ? body.systemInstruction : undefined;
    const temperature = typeof body.temperature === "number" ? body.temperature : 0.4;
    const maxOutputTokens = typeof body.maxOutputTokens === "number" ? Math.min(8192, Math.max(64, body.maxOutputTokens)) : 2048;

    const ai = new GoogleGenAI({ apiKey });
    const modelsToTry = primaryModel === "gemini-3.5-flash-lite"
      ? ["gemini-3.5-flash-lite"]
      : [primaryModel, "gemini-3.5-flash-lite"];

    let lastErr = null;
    for (let i = 0; i < modelsToTry.length; i++) {
      const m = modelsToTry[i];
      const budgetMs = m === "gemini-3.5-flash-lite" ? 4500 : 4000;
      try {
        const resp = await generateWithBudget(
          ai,
          { model: m, contents: prompt, systemInstruction, temperature, maxOutputTokens },
          budgetMs
        );
        const text = (resp?.text || "").trim();
        if (text.length > 0) {
          return res.status(200).json({
            text,
            modelUsed: m,
            sdk: "@google/genai",
            failedOver: m !== primaryModel,
          });
        }
      } catch (err) {
        lastErr = err;
      }
    }

    return res.status(502).json({
      error: lastErr?.message || "Gemini SDK relay failed to produce output.",
    });
  } catch (err) {
    return res.status(500).json({ error: err?.message || "Unexpected server error." });
  }
}
