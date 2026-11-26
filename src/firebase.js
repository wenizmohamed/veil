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
  return /\b(500|502|503|429)\b|high demand|temporarily|unavailable|INTERNAL|fetch-error|network/i.test(msg);
}

/**
 * Invokes cloud or local reasoning with automatic transient retry + failover to Spark-safe Flash-Lite
 * when the primary Gemini 4 Hydrogen model hits upstream high-demand spikes.
 */
export async function generateWithCloudResilience(policy, local, prompt, { onRetry } = {}) {
  if (local) {
    const res = await reasonerModel(policy, true).generateContent(prompt);
    return { res, modelUsed: "gemini-nano", failedOver: false };
  }

  const primary = policy?.cloudModel || "gemini-4-hydrogen";
  try {
    const res = await reasonerModel(policy, false, primary).generateContent(prompt);
    return { res, modelUsed: primary, failedOver: false };
  } catch (firstErr) {
    if (!isTransientCloudError(firstErr)) throw firstErr;
    onRetry?.(primary, "retry");
    await new Promise((r) => setTimeout(r, 550));
    try {
      const res = await reasonerModel(policy, false, primary).generateContent(prompt);
      return { res, modelUsed: primary, failedOver: false };
    } catch (secondErr) {
      if (!isTransientCloudError(secondErr) || primary === CLOUD_FALLBACK_MODEL) {
        throw secondErr;
      }
      onRetry?.(CLOUD_FALLBACK_MODEL, "failover");
      const res = await reasonerModel(policy, false, CLOUD_FALLBACK_MODEL).generateContent(prompt);
      return { res, modelUsed: CLOUD_FALLBACK_MODEL, failedOver: true };
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
