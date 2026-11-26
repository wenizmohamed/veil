// All Firebase wiring for Veil: AI Logic (hybrid), App Check, Auth, Remote Config, Firestore.
import { initializeApp } from "firebase/app";
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from "firebase/app-check";
import { getAI, getGenerativeModel, GoogleAIBackend, InferenceMode, InferenceSource } from "firebase/ai";
import { getAuth, signInAnonymously, onAuthStateChanged } from "firebase/auth";
import { getRemoteConfig, fetchAndActivate, getValue } from "firebase/remote-config";
import { getFirestore, collection, addDoc, serverTimestamp, query, orderBy, limit, getDocs } from "firebase/firestore";
import { firebaseConfig, recaptchaSiteKey } from "./firebase-config.js";
import { NANO_SCHEMA, CLOUD_SYSTEM, CATEGORIES } from "./veil-core.js";

export { InferenceSource };

const app = initializeApp(firebaseConfig);

// App Check (reCAPTCHA Enterprise) is initialized lazily on first cloud AI Logic call so
// zero-network local previews, batch redactions, and rule audits never emit third-party beacons.
let appCheckInitialized = false;
export function ensureAppCheck() {
  if (appCheckInitialized) return;
  appCheckInitialized = true;
  if (!firebaseConfig.enableAppCheck || (typeof navigator !== "undefined" && navigator.webdriver)) {
    return;
  }
  if (
    typeof location !== "undefined" &&
    (location.hostname === "localhost" || location.hostname === "127.0.0.1" || location.protocol === "chrome-extension:")
  ) {
    self.FIREBASE_APPCHECK_DEBUG_TOKEN = true;
  }
  try {
    initializeAppCheck(app, { provider: new ReCaptchaEnterpriseProvider(recaptchaSiteKey), isTokenAutoRefreshEnabled: true });
  } catch (e) {
    console.warn("App Check lazy init skipped:", e?.message || e);
  }
}

const ai = getAI(app, { backend: new GoogleAIBackend() });
const auth = firebaseConfig.useFirebaseAuth ? getAuth(app) : null;
const db = getFirestore(app);
const rc = getRemoteConfig(app);
rc.settings.minimumFetchIntervalMillis = 10 * 60 * 1000;
rc.defaultConfig = {
  veil_cloud_model: "gemini-4-hydrogen",
  veil_categories: JSON.stringify(CATEGORIES),
  veil_allow_local_reasoning: true,
  veil_max_chars: 6000,
};

export async function loadPolicy() {
  try { await fetchAndActivate(rc); } catch (e) { console.warn("Remote Config fetch failed, using defaults", e); }
  let categories = CATEGORIES;
  try { categories = JSON.parse(getValue(rc, "veil_categories").asString()).filter((c) => CATEGORIES.includes(c)); } catch {}
  return {
    cloudModel: getValue(rc, "veil_cloud_model").asString(),
    categories,
    allowLocalReasoning: getValue(rc, "veil_allow_local_reasoning").asBoolean(),
    maxChars: getValue(rc, "veil_max_chars").asNumber(),
    source: getValue(rc, "veil_cloud_model").getSource(),
  };
}

function getLocalSessionUid() {
  const key = "veil_session_uid";
  let id = localStorage.getItem(key);
  if (!id || !/^anon_[0-9a-f-]{36}$/.test(id)) {
    const uuid = (crypto.randomUUID ? crypto.randomUUID() : "00000000-0000-4000-8000-000000000000").toLowerCase();
    id = `anon_${uuid}`;
    localStorage.setItem(key, id);
  }
  return id;
}

export function signIn() {
  if (!auth) {
    return Promise.resolve({ uid: getLocalSessionUid(), anonymousSession: true });
  }
  return new Promise((resolve) => {
    let settled = false;
    const done = (u) => { if (!settled) { settled = true; resolve(u); } };
    const off = onAuthStateChanged(auth, (u) => { if (u) { off(); done(u); } });
    signInAnonymously(auth).catch(() => {
      off();
      done({ uid: getLocalSessionUid(), anonymousSession: true });
    });
  });
}

export const CLOUD_FALLBACK_MODEL = "gemini-3.5-flash-lite";

/** The detector: Gemini Nano only. If the device model is missing this throws: secrets never go to the cloud to be found. */
export function detectorModel() {
  return getGenerativeModel(ai, {
    mode: InferenceMode.ONLY_ON_DEVICE,
    onDeviceParams: {
      createOptions: {
        temperature: 0.1,
        topK: 1,
        expectedInputs: [{ type: "text", languages: ["en"] }],
        expectedOutputs: [{ type: "text", languages: ["en"] }],
      },
      promptOptions: { responseConstraint: NANO_SCHEMA },
    },
  });
}

/** The reasoner: works on masked text only. Cloud by default; on-device when the user picks "Keep everything local". */
export function reasonerModel(policy, local, modelOverride = null) {
  if (!local) ensureAppCheck();
  return getGenerativeModel(ai, {
    mode: local ? InferenceMode.ONLY_ON_DEVICE : InferenceMode.ONLY_IN_CLOUD,
    inCloudParams: { model: modelOverride || policy.cloudModel, systemInstruction: CLOUD_SYSTEM, generationConfig: { temperature: 0.4 } },
    onDeviceParams: {
      createOptions: {
        initialPrompts: [{ role: "system", content: CLOUD_SYSTEM }],
        expectedInputs: [{ type: "text", languages: ["en"] }],
        expectedOutputs: [{ type: "text", languages: ["en"] }],
      },
    },
  });
}

function isTransientCloudError(err) {
  const msg = String(err?.message || err || "");
  return /\b(500|502|503|429)\b|high demand|temporarily|unavailable|INTERNAL|fetch-error|cloud_timeout|network/i.test(msg);
}

function canUseVercelSdkRelay() {
  if (typeof location === "undefined") return false;
  return /^https?:$/.test(location.protocol) && location.hostname !== "wenizmohamed.github.io";
}

function isSparkThrottledSession() {
  try {
    return typeof sessionStorage !== "undefined" && sessionStorage.getItem("veil_spark_h2_throttled") === "1";
  } catch {
    return false;
  }
}

function markSparkThrottledSession() {
  try {
    if (typeof sessionStorage !== "undefined") sessionStorage.setItem("veil_spark_h2_throttled", "1");
  } catch {}
}

async function runFirebaseCloudWithTimeout(policy, modelName, prompt, ms = 9000) {
  const model = reasonerModel(policy, false, modelName);
  return Promise.race([
    model.generateContent(prompt),
    new Promise((_, reject) => setTimeout(() => reject(new Error("cloud_timeout")), ms)),
  ]);
}

async function tryVercelGeminiSdk(modelName, prompt) {
  const resp = await fetch("/api/hybrid-gemini", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: modelName,
      systemInstruction: CLOUD_SYSTEM,
      temperature: 0.4,
      maxOutputTokens: 2048,
      prompt,
    }),
  });
  if (!resp.ok) {
    const errTxt = await resp.text().catch(() => "");
    throw new Error(`sdk_relay_${resp.status}: ${errTxt.slice(0, 140)}`);
  }
  const data = await resp.json();
  if (!data?.text) throw new Error("sdk_relay_empty");
  return {
    res: {
      response: {
        text: () => data.text,
        inferenceSource: InferenceSource.IN_CLOUD,
      },
    },
    modelUsed: data.modelUsed || modelName,
    failedOver: Boolean(data.failedOver),
    viaSdk: data.sdk || "@google/genai",
  };
}

/**
 * Invokes cloud or local reasoning with Firebase AI Logic primary + @google/genai SDK relay
 * when Spark quota throttles Gemini 4 Hydrogen, and Flash-Lite fallback for offline/extension mirrors.
 */
export async function generateWithCloudResilience(policy, local, prompt, { onRetry } = {}) {
  if (local) {
    const res = await reasonerModel(policy, true).generateContent(prompt);
    return { res, modelUsed: "gemini-nano", failedOver: false, viaSdk: null };
  }

  const primary = policy?.cloudModel || "gemini-4-hydrogen";
  const hasSdkRelay = canUseVercelSdkRelay();

  if (hasSdkRelay && isSparkThrottledSession()) {
    try {
      onRetry?.(primary, "sdk_relay");
      return await tryVercelGeminiSdk(primary, prompt);
    } catch {}
  }

  try {
    const res = await runFirebaseCloudWithTimeout(policy, primary, prompt, 9000);
    return { res, modelUsed: primary, failedOver: false, viaSdk: null };
  } catch (firstErr) {
    if (!isTransientCloudError(firstErr)) throw firstErr;
    if (/429|quota/i.test(String(firstErr?.message || ""))) {
      markSparkThrottledSession();
    }
    if (hasSdkRelay) {
      try {
        onRetry?.(primary, "sdk_relay");
        return await tryVercelGeminiSdk(primary, prompt);
      } catch {}
    }
    onRetry?.(primary, "retry");
    await new Promise((r) => setTimeout(r, 400));
    try {
      const res = await runFirebaseCloudWithTimeout(policy, primary, prompt, 9000);
      return { res, modelUsed: primary, failedOver: false, viaSdk: null };
    } catch (secondErr) {
      if (!isTransientCloudError(secondErr) || primary === CLOUD_FALLBACK_MODEL) {
        throw secondErr;
      }
      onRetry?.(CLOUD_FALLBACK_MODEL, "failover");
      const res = await runFirebaseCloudWithTimeout(policy, CLOUD_FALLBACK_MODEL, prompt, 12000);
      return { res, modelUsed: CLOUD_FALLBACK_MODEL, failedOver: true, viaSdk: null };
    }
  }
}

function receiptCollection(uid) {
  const root = /^anon_[0-9a-f-]{36}$/.test(uid) ? "sessions" : "users";
  return collection(db, root, uid, "receipts");
}

/** Receipts hold counts and inference sources only. Never text, never values. Enforced again by firestore.rules. */
export async function saveReceipt(uid, receipt) {
  return addDoc(receiptCollection(uid), { ...receipt, at: serverTimestamp() });
}

export async function loadReceipts(uid) {
  const snap = await getDocs(query(receiptCollection(uid), orderBy("at", "desc"), limit(8)));
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}
