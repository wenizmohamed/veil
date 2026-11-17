import "./style.css";
import {
  detectWithRules, sanitizeModelSpans, buildPlan, mask, leakCheck, unmask, countByType,
  NANO_DETECT_PROMPT, TASKS,
} from "./veil-core.js";
import { loadPolicy, signIn, detectorModel, reasonerModel, saveReceipt, loadReceipts, InferenceSource } from "./firebase.js";

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const SAMPLE = `Hi Sara Al Mansoori,

Following our call, Falcon Logistics agrees to the revised rate. Please wire AED 48,500 to IBAN AE07 0331 2345 6789 0123 456 before Thursday 3 December.

The staging key for the tracking API is sk_demoNOTAREALKEY7Hq2Lyj9WDar, please rotate it after the migration.

If anything changes, call me on +971 50 123 4567 or email omar.khalid@falconlogistics.ae.

Best,
Omar Khalid
Head of Finance, Falcon Logistics`;

let policy, user, detector, deviceReady = false;

const state = { plan: [], masked: "", detectorSource: null };

function setStep(n, status, note = "") {
  const el = document.querySelector(`[data-step="${n}"]`);
  el.dataset.status = status;
  el.querySelector(".note").textContent = note;
}
function badge(source) {
  return source === InferenceSource.ON_DEVICE || source === "on_device"
    ? `<span class="badge dev">On device · Gemini Nano</span>`
    : source === "rules_only" ? `<span class="badge rules">On device · rules only</span>`
    : `<span class="badge cloud">In cloud · ${esc(policy.cloudModel)}</span>`;
}

function renderPlan() {
  $("#plan").innerHTML = state.plan.length
    ? state.plan.map((e) => `<li><code>${esc(e.token)}</code><span>${esc(e.text)}</span><em>${e.source === "nano" ? "Nano" : "rule"}</em></li>`).join("")
    : `<li class="empty">Nothing sensitive found.</li>`;
  $("#planCount").textContent = state.plan.length;
}

async function ensureDevice() {
  if (deviceReady || !detector) return deviceReady;
  try {
    await detector.initializeDeviceModel((p) => setStep(1, "busy", `Downloading Gemini Nano… ${Math.round(p * 100)}%`));
    deviceReady = true;
  } catch (e) {
    console.warn("On-device model unavailable", e);
  }
  return deviceReady;
}

function chunks(text, max) {
  const out = []; let cur = "";
  for (const para of text.split(/\n{2,}/)) {
    if ((cur + "\n\n" + para).length > max && cur) { out.push(cur); cur = ""; }
    cur = cur ? cur + "\n\n" + para : para;
    while (cur.length > max) { out.push(cur.slice(0, max)); cur = cur.slice(max); }
  }
  if (cur) out.push(cur);
  return out;
}

let confirmRulesOnly = false;

async function detect(text) {
  const rules = detectWithRules(text, policy.categories);
  let nano = [];
  state.detectorSource = "rules_only";
  if (await ensureDevice()) {
    try {
      // Gemini Nano has a small context window: read the text in paragraph-sized chunks.
      for (const chunk of chunks(text, 900)) {
        const res = await detector.generateContent(NANO_DETECT_PROMPT(chunk, policy.categories));
        const parsed = JSON.parse(res.response.text());
        nano.push(...sanitizeModelSpans(chunk, parsed.entities, policy.categories));
        state.detectorSource = res.response.inferenceSource || "on_device";
      }
    } catch (e) {
      console.warn("Nano detection failed; rules only", e);
      if (!nano.length) state.detectorSource = "rules_only";
    }
  }
  return [...nano, ...rules];
}

async function run() {
  const text = $("#input").value.trim();
  const task = $("#task").value;
  const local = $("#local").checked;
  $("#out").innerHTML = ""; $("#cloudSaw").textContent = ""; $("#error").textContent = "";
  if (!text) return;
  if (text.length > policy.maxChars) { $("#error").textContent = `Text is over the ${policy.maxChars}-character limit set in Remote Config.`; return; }
  $("#run").disabled = true;

  try {
    // 1. Find secrets on the device.
    setStep(1, "busy", "Gemini Nano is reading your text on this device…");
    const spans = await detect(text);
    state.plan = buildPlan(spans);
    state.masked = mask(text, state.plan);
    renderPlan();
    setStep(1, "done", state.detectorSource === "rules_only"
      ? "Gemini Nano is not available in this browser, so only the built-in rules ran. Nothing was sent anywhere."
      : `${state.plan.length} values masked on this device.`);
    $("#detectorBadge").innerHTML = badge(state.detectorSource);

    if (state.detectorSource === "rules_only" && !local && !confirmRulesOnly) {
      confirmRulesOnly = true;
      setStep(2, "error", "Paused: names and companies were not checked.");
      $("#error").textContent = "Gemini Nano isn't available here, so only emails, phones, IDs, accounts, amounts and keys were masked. Names and company names were NOT checked. Review the masked list, then press Run again to send anyway, or tick \"Keep everything local\".";
      $("#run").textContent = "Send anyway";
      return;
    }
    confirmRulesOnly = false; $("#run").textContent = "Run privately";

    // 2. Leak guard before anything leaves.
    const outbound = `${TASKS[task]}\n\n${state.masked}`;
    leakCheck(outbound, state.plan);
    setStep(2, "done", "Leak guard passed: none of the masked values are in the request.");
    $("#cloudSaw").textContent = outbound;

    // 3. Reason over masked text.
    setStep(3, "busy", local ? "Working on this device…" : "Gemini in the cloud is working on the masked text…");
    const reasoner = reasonerModel(policy, local);
    const res = await reasoner.generateContent(outbound);
    const source = res.response.inferenceSource || (local ? "on_device" : "in_cloud");
    const draft = res.response.text();
    setStep(3, "done", local ? "Answered on this device." : "Answered by the cloud model. It only ever saw placeholders.");
    $("#reasonerBadge").innerHTML = badge(source);
    $("#cloudSaid").textContent = draft;

    // 4. Restore locally.
    const { text: restored, unknownTokens } = unmask(draft, state.plan);
    $("#out").innerHTML = esc(restored).replace(/\n/g, "<br>");
    setStep(4, "done", unknownTokens.length
      ? `Restored on this device. ${unknownTokens.length} placeholder(s) the model made up were left as is: ${unknownTokens.join(", ")}`
      : "Real values restored on this device.");

    // 5. Receipt: counts and sources only.
    if (user) {
      await saveReceipt(user.uid, {
        task, counts: countByType(state.plan), masked: state.plan.length,
        detector: state.detectorSource === "rules_only" ? "rules_only" : "on_device",
        reasoner: source === "on_device" ? "on_device" : "in_cloud",
        outboundChars: outbound.length, leakGuard: "pass", unknownTokens: unknownTokens.length,
      });
      renderReceipts();
    }
  } catch (e) {
    console.error(e);
    $("#error").textContent = e.leaked
      ? `${e.message} Nothing was sent.`
      : `Something went wrong: ${e.message}`;
    document.querySelectorAll('[data-status="busy"]').forEach((el) => (el.dataset.status = "error"));
  } finally {
    $("#run").disabled = false;
  }
}

async function renderReceipts() {
  try {
    const rows = await loadReceipts(user.uid);
    $("#receipts").innerHTML = rows.length ? rows.map((r) => `<li>
      <b>${esc(r.task)}</b> · ${r.masked} masked
      <span>${Object.entries(r.counts || {}).map(([k, v]) => `${esc(k)} ${v}`).join(" · ")}</span>
      <span class="src">${r.detector === "on_device" ? "detect: device" : "detect: rules"} → ${r.reasoner === "on_device" ? "answer: device" : "answer: cloud"} · ${r.outboundChars} chars out</span></li>`).join("")
      : `<li class="empty">No receipts yet.</li>`;
  } catch (e) { console.warn("receipts", e); }
}

async function boot() {
  $("#input").value = SAMPLE;
  $("#task").innerHTML = Object.entries({ reply: "Draft a reply", summary: "Summarize", actions: "Extract action items", formal: "Make it formal", arabic: "Translate to Arabic" })
    .map(([k, v]) => `<option value="${k}">${v}</option>`).join("");
  policy = await loadPolicy();
  $("#policy").textContent = `Policy from Remote Config (${policy.source}): cloud model ${policy.cloudModel}, ${policy.categories.length} categories, ${policy.maxChars} char limit.`;
  if (!policy.allowLocalReasoning) { $("#local").checked = false; $("#local").disabled = true; }
  detector = detectorModel();
  try { user = await signIn(); renderReceipts(); } catch (e) { console.warn("auth", e); }
  const hasPromptApi = typeof self.LanguageModel !== "undefined";
  $("#device").innerHTML = hasPromptApi
    ? `<span class="badge dev">Gemini Nano API present</span> First run may download the model.`
    : `<span class="badge rules">No on-device model in this browser</span> Veil still masks with its rules and never sends raw text.`;
  $("#run").addEventListener("click", run);
}

boot();
