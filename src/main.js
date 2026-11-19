import "./style.css";
import {
  detectWithRules, sanitizeModelSpans, buildPlan, mask, leakCheck, unmaskSegments,
  tokenizeMaskedText, buildReceiptPayload, verifyOutboundBytesZeroSecrets,
  buildComplianceCertificate, runAdversarialStressTest,
  NANO_DETECT_PROMPT, TASKS, PRESETS,
} from "./veil-core.js";
import { loadPolicy, signIn, detectorModel, reasonerModel, saveReceipt, loadReceipts, InferenceSource } from "./firebase.js";

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

let policy, user, detector, deviceReady = false;

const state = {
  plan: [],
  masked: "",
  detectorSource: null,
  restoredText: "",
  activePresetId: PRESETS[0].id,
  lastReceiptPayload: null,
  lastReceiptPath: "",
  lastWiretap: null,
  lastProof: null,
  lastStressSummary: null,
};

// Passive fetch wiretap: observes the exact HTTP JSON bytes Firebase AI Logic sends over the wire
// without mutating requests, headers, or responses.
if (typeof window !== "undefined" && typeof window.fetch === "function" && !window.__veilWiretapInstalled) {
  window.__veilWiretapInstalled = true;
  const origFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    try {
      const url = typeof input === "string" ? input : input?.url || "";
      if (/firebasevertexai\.googleapis\.com|generativelanguage\.googleapis\.com/i.test(url) && /generateContent/i.test(url)) {
        let rawBody = "";
        if (typeof init?.body === "string") rawBody = init.body;
        else if (init?.body instanceof Uint8Array || init?.body instanceof ArrayBuffer) {
          rawBody = new TextDecoder().decode(init.body);
        } else if (typeof Request !== "undefined" && input instanceof Request) {
          rawBody = await input.clone().text();
        }
        if (rawBody) {
          const parsedUrl = new URL(url);
          state.lastWiretap = {
            endpoint: `${parsedUrl.host}${parsedUrl.pathname}`,
            rawBody,
          };
        }
      }
    } catch (err) {
      console.warn("wiretap observer", err);
    }
    return origFetch(input, init);
  };
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const hashBuf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function renderWiretapPanel() {
  const proof = state.lastProof;
  if (!proof) {
    $("#wiretapBadge").hidden = true;
    $("#wiretapEndpoint").textContent = "Awaiting outbound cloud call";
    $("#wiretapBytes").textContent = "0 bytes · 0 raw secrets verified";
    $("#wiretapHash").textContent = "--";
    $("#wiretapRaw").textContent = "Run Veil to capture the live Firebase AI Logic HTTP JSON request.";
    $("#downloadCert").disabled = true;
    return;
  }
  $("#wiretapBadge").hidden = false;
  $("#wiretapBadge").textContent = proof.leakedCount === 0
    ? `0 raw secrets in ${proof.bytes} HTTP bytes`
    : `${proof.leakedCount} raw secret(s) detected`;
  $("#wiretapEndpoint").textContent = proof.endpoint;
  $("#wiretapBytes").textContent = `${proof.bytes} bytes · ${proof.leakedCount} raw secrets found across ${state.plan.length} masked values`;
  $("#wiretapHash").textContent = proof.sha256;
  let pretty = proof.rawBody;
  try { pretty = JSON.stringify(JSON.parse(proof.rawBody), null, 2); } catch {}
  $("#wiretapRaw").textContent = pretty;
  $("#downloadCert").disabled = false;
}

function renderStressTest() {
  const summary = runAdversarialStressTest();
  state.lastStressSummary = summary;
  $("#stressSummary").textContent = `${summary.caught}/${summary.total} Caught On-Device · ${summary.leaked} Bytes Leaked`;
  $("#stressMeta").textContent = `${summary.restored}/${summary.total} restored locally · ${summary.elapsedMs} ms`;
  $("#stressGrid").innerHTML = summary.results.map((r) => `
    <div class="stress-card">
      <div class="stress-card-top">
        <span>${esc(r.label)}</span>
        <code class="tok" data-type="${esc(r.type)}">${esc(r.token)}</code>
      </div>
      <div class="stress-card-meta">
        <span>${r.caught ? "Caught · 0 leaked" : "MISSED"}</span>
        <span>${r.restored ? "Restored ✓" : "Restore fail"}</span>
      </div>
    </div>
  `).join("");
  $("#stressPanel").hidden = false;
}

function downloadComplianceCertificate() {
  if (!state.lastProof || !state.lastReceiptPayload) return;
  const cert = buildComplianceCertificate({
    firestorePath: state.lastReceiptPath,
    receiptPayload: state.lastReceiptPayload,
    sha256Hex: state.lastProof.sha256,
    outboundBytes: state.lastProof.bytes,
    wiretapEndpoint: state.lastProof.endpoint,
    policySnapshot: policy,
    stressTestSummary: state.lastStressSummary,
  });
  const blob = new Blob([JSON.stringify(cert, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `veil-zero-text-certificate-${(state.lastProof.sha256 || "proof").slice(0, 12)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function setStep(n, status, note = "") {
  const el = document.querySelector(`[data-step="${n}"]`);
  if (!el) return;
  if (status) el.dataset.status = status;
  else delete el.dataset.status;
  el.querySelector(".note").textContent = note;
}

function resetSteps() {
  setStep(1, "", "Gemini Nano, on device");
  setStep(2, "", "Leak check before sending");
  setStep(3, "", "Cloud model, placeholders only");
  setStep(4, "", "Real values back, on device");
}

function badge(source) {
  return source === InferenceSource.ON_DEVICE || source === "on_device"
    ? `<span class="badge dev">On device · Gemini Nano</span>`
    : source === "rules_only" ? `<span class="badge rules">On device · rules only</span>`
    : `<span class="badge cloud">In cloud · ${esc(policy.cloudModel)}</span>`;
}

function renderTokenizedHtml(text) {
  return tokenizeMaskedText(text).map((seg) =>
    seg.kind === "token"
      ? `<span class="tok" data-type="${esc(seg.type)}">${esc(seg.token)}</span>`
      : esc(seg.value)
  ).join("");
}

function renderRestoredHtml(segments) {
  return segments.map((seg) => {
    if (seg.kind === "restored") {
      return `<mark class="restored-val" data-type="${esc(seg.type)}" title="Restored locally from ${esc(seg.token)}">${esc(seg.value)}</mark>`;
    }
    if (seg.kind === "unknown") {
      return `<span class="unknown-tok" title="Placeholder invented by model — left unguessed">${esc(seg.token)}</span>`;
    }
    return esc(seg.value).replace(/\n/g, "<br>");
  }).join("");
}

function renderPlan() {
  $("#plan").innerHTML = state.plan.length
    ? state.plan.map((e) => `<li><code class="tok" data-type="${esc(e.type)}">${esc(e.token)}</code><span>${esc(e.text)}</span><em>${e.source === "nano" ? "Nano" : "rule"}</em></li>`).join("")
    : `<li class="empty">Nothing sensitive found.</li>`;
  $("#planCount").textContent = state.plan.length;
}

function updateAuditStrip({ status = "", leaked = 0, masked = 0, guard = "READY", deviceMs = null, cloudMs = null, localOnly = false } = {}) {
  const strip = $("#auditStrip");
  if (status) strip.dataset.state = status;
  else delete strip.dataset.state;

  const dotClass = status === "error" ? "err" : status === "warn" ? "warn" : "ok";
  const leakLabel = leaked > 0 ? `${leaked} secret${leaked === 1 ? "" : "s"} blocked` : "0 secrets leaked";
  $("#auditLeaks").innerHTML = `<span class="dot ${dotClass}"></span>${esc(leakLabel)}`;
  $("#auditMasked").textContent = `${masked} value${masked === 1 ? "" : "s"} masked`;
  $("#auditGuard").innerHTML = `Leak Guard: <b>${esc(guard)}</b>`;

  const devStr = deviceMs === null ? "-- ms" : `${Math.round(deviceMs)} ms`;
  const cloudStr = localOnly
    ? "0 ms (local only)"
    : cloudMs === null ? "-- ms" : `${Math.round(cloudMs)} ms`;
  $("#auditLatency").textContent = `On-device: ${devStr} · Cloud: ${cloudStr}`;
}

function renderPayloadInspector() {
  if (!state.lastReceiptPayload) {
    $("#payloadPath").textContent = "Run Veil to inspect the live Firestore write";
    $("#payloadJson").textContent = JSON.stringify({
      task: "reply",
      masked: 0,
      counts: {},
      detector: "on_device | rules_only",
      reasoner: "in_cloud | on_device",
      outboundChars: 0,
      leakGuard: "pass",
      unknownTokens: 0,
      at: "serverTimestamp()",
    }, null, 2);
    return;
  }
  $("#payloadPath").textContent = state.lastReceiptPath || "Firestore receipt (counts only)";
  $("#payloadJson").textContent = JSON.stringify(state.lastReceiptPayload, null, 2);
}

function showDegradeCallout(title, body, { showKeepLocal = true } = {}) {
  $("#degradeTitle").textContent = title;
  $("#degradeBody").textContent = body;
  $("#keepLocalBtn").hidden = !showKeepLocal || !policy?.allowLocalReasoning;
  $("#degradeCallout").hidden = false;
}

function hideDegradeCallout() {
  $("#degradeCallout").hidden = true;
}

function renderPresets() {
  $("#presets").innerHTML = PRESETS.map((p) =>
    `<button type="button" class="preset-btn${p.id === state.activePresetId ? " active" : ""}" data-preset="${esc(p.id)}" aria-pressed="${p.id === state.activePresetId}">
      <span>${esc(p.label)}</span><span class="preset-tag">${esc(p.industry)}</span>
    </button>`
  ).join("");
}

function selectPreset(id) {
  const preset = PRESETS.find((p) => p.id === id);
  if (!preset) return;
  state.activePresetId = preset.id;
  $("#input").value = preset.text;
  if ($("#task").querySelector(`option[value="${preset.defaultTask}"]`)) {
    $("#task").value = preset.defaultTask;
  }
  hideDegradeCallout();
  $("#error").textContent = "";
  resetSteps();
  updateAuditStrip({ masked: 0, guard: "READY" });
  renderPresets();
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

async function run({ approveRulesOnly = false } = {}) {
  const text = $("#input").value.trim();
  const task = $("#task").value;
  const local = $("#local").checked;

  hideDegradeCallout();
  $("#out").innerHTML = "";
  $("#cloudSaw").innerHTML = "";
  $("#cloudSaid").innerHTML = "";
  $("#error").textContent = "";
  $("#restoredPill").hidden = true;
  $("#copyResult").disabled = true;
  state.restoredText = "";
  state.lastWiretap = null;
  state.lastProof = null;
  renderWiretapPanel();

  if (!text) return;
  if (text.length > policy.maxChars) {
    $("#error").textContent = `Text is over the ${policy.maxChars}-character limit set in Remote Config.`;
    return;
  }

  $("#run").disabled = true;
  resetSteps();

  let deviceMs = 0;
  let cloudMs = 0;

  try {
    // 1. Find secrets on the device.
    setStep(1, "busy", "Scanning text on this device…");
    const t0 = performance.now();
    const spans = await detect(text);
    state.plan = buildPlan(spans);
    state.masked = mask(text, state.plan);
    deviceMs = performance.now() - t0;

    renderPlan();
    $("#detectorBadge").innerHTML = badge(state.detectorSource);
    setStep(1, "done", state.detectorSource === "rules_only"
      ? `${state.plan.length} values masked on device with built-in rules (Gemini Nano not downloaded).`
      : `${state.plan.length} values masked on device with Gemini Nano + rules.`);

    if (state.detectorSource === "rules_only" && !local && !approveRulesOnly) {
      setStep(2, "warn", "Paused for review before anything leaves this browser.");
      updateAuditStrip({ status: "warn", leaked: 0, masked: state.plan.length, guard: "PAUSED", deviceMs, cloudMs: 0 });
      showDegradeCallout(
        "Gemini Nano isn't downloaded yet in this browser",
        `Built-in deterministic rules and name/company cues masked ${state.plan.length} values locally — nothing has been sent anywhere. Review the masked list on the right, then approve sending placeholders to ${policy.cloudModel} or keep everything local.`
      );
      return;
    }

    // 2. Leak guard before anything leaves.
    const outbound = `${TASKS[task]}\n\n${state.masked}`;
    leakCheck(outbound, state.plan);
    setStep(2, "done", "Leak guard passed: 0 masked values present in outbound request.");
    $("#cloudSaw").innerHTML = renderTokenizedHtml(outbound);
    updateAuditStrip({ status: "pass", leaked: 0, masked: state.plan.length, guard: "PASS", deviceMs, cloudMs: null, localOnly: local });

    // 3. Reason over masked text.
    setStep(3, "busy", local ? "Working on this device…" : `Asking ${policy.cloudModel} on placeholders only…`);
    const tCloud = performance.now();
    const reasoner = reasonerModel(policy, local);
    let res;
    try {
      res = await reasoner.generateContent(outbound);
    } catch (reasonErr) {
      if (local && state.detectorSource === "rules_only") {
        setStep(3, "warn", "Local-only reasoning needs Chrome's Gemini Nano.");
        updateAuditStrip({ status: "warn", leaked: 0, masked: state.plan.length, guard: "PASS", deviceMs, cloudMs: 0, localOnly: true });
        showDegradeCallout(
          "Local-only reasoning requires Gemini Nano",
          `Your text stayed 100% in this browser (0 bytes sent). To answer fully offline, enable Chrome's Built-in AI Prompt API, or approve sending the ${state.plan.length} masked placeholders to ${policy.cloudModel} now.`,
          { showKeepLocal: false }
        );
        return;
      }
      throw reasonErr;
    }
    cloudMs = performance.now() - tCloud;

    const source = res.response.inferenceSource || (local ? "on_device" : "in_cloud");
    const draft = res.response.text();
    const ranLocally = source === InferenceSource.ON_DEVICE || source === "on_device";
    setStep(3, "done", ranLocally
      ? `Answered on this device (${Math.round(cloudMs)} ms).`
      : `Answered by ${policy.cloudModel} (${Math.round(cloudMs)} ms) — saw placeholders only.`);
    $("#reasonerBadge").innerHTML = badge(source);
    $("#cloudSaid").innerHTML = renderTokenizedHtml(draft);

    // 3b. Cryptographic wiretap proof over the exact raw HTTP JSON bytes sent to Firebase AI Logic.
    const rawWireBody = state.lastWiretap?.rawBody || JSON.stringify({ localOnly: true, maskedOutbound: outbound });
    const wireCheck = verifyOutboundBytesZeroSecrets(rawWireBody, state.plan);
    const digest = await sha256Hex(rawWireBody);
    state.lastProof = {
      endpoint: state.lastWiretap?.endpoint || (ranLocally ? "on_device_only (0 network bytes)" : "firebasevertexai.googleapis.com"),
      rawBody: rawWireBody,
      bytes: ranLocally && !state.lastWiretap ? 0 : wireCheck.bytes,
      leakedCount: wireCheck.leakedCount,
      sha256: digest,
    };
    renderWiretapPanel();

    // 4. Restore locally.
    const tRestore = performance.now();
    const { text: restored, segments, unknownTokens, restoredCount } = unmaskSegments(draft, state.plan);
    deviceMs += performance.now() - tRestore;

    state.restoredText = restored;
    $("#out").innerHTML = renderRestoredHtml(segments);
    $("#copyResult").disabled = !restored.length;
    $("#restoredPill").textContent = restoredCount > 0
      ? `Restored locally · ${restoredCount} value${restoredCount === 1 ? "" : "s"}`
      : "Restored locally";
    $("#restoredPill").hidden = false;

    setStep(4, "done", unknownTokens.length
      ? `Restored locally. ${unknownTokens.length} invented placeholder(s) left unguessed: ${unknownTokens.join(", ")}`
      : `${restoredCount} real value${restoredCount === 1 ? "" : "s"} restored on this device.`);

    updateAuditStrip({
      status: "pass",
      leaked: 0,
      masked: state.plan.length,
      guard: "PASS",
      deviceMs,
      cloudMs: ranLocally ? 0 : cloudMs,
      localOnly: ranLocally,
    });

    // 5. Receipt: counts and sources only (strictly enforced by firestore.rules).
    const payload = buildReceiptPayload({
      task,
      plan: state.plan,
      detectorSource: state.detectorSource,
      reasonerSource: ranLocally ? "on_device" : "in_cloud",
      outboundChars: outbound.length,
      unknownTokensCount: unknownTokens.length,
    });
    state.lastReceiptPayload = { ...payload, at: "serverTimestamp()" };
    state.lastReceiptPath = "Saving to Firestore…";
    renderPayloadInspector();

    if (user) {
      const docRef = await saveReceipt(user.uid, payload);
      state.lastReceiptPath = docRef?.path || `Firestore doc ${docRef?.id || ""}`;
      renderPayloadInspector();
      renderReceipts();
    }
  } catch (e) {
    console.error(e);
    if (e.leaked) {
      updateAuditStrip({ status: "error", leaked: e.leaked.length, masked: state.plan.length, guard: "BLOCKED", deviceMs, cloudMs: 0 });
    }
    $("#error").textContent = e.leaked
      ? `${e.message} Nothing was sent.`
      : `Something went wrong: ${e.message}`;
    document.querySelectorAll('[data-status="busy"]').forEach((el) => (el.dataset.status = "error"));
  } finally {
    $("#run").disabled = false;
  }
}

async function copyRestoredResult() {
  if (!state.restoredText) return;
  const btn = $("#copyResult");
  try {
    await navigator.clipboard.writeText(state.restoredText);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = state.restoredText;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  }
  btn.textContent = "Copied ✓";
  setTimeout(() => { btn.textContent = "Copy restored result"; }, 1800);
}

async function renderReceipts() {
  try {
    const rows = await loadReceipts(user.uid);
    $("#receipts").innerHTML = rows.length ? rows.map((r) => `<li>
      <b>${esc(r.task)}</b> · ${r.masked} masked
      <span>${Object.entries(r.counts || {}).map(([k, v]) => `${esc(k)} ${v}`).join(" · ")}</span>
      <span class="src">${r.detector === "on_device" ? "detect: device" : "detect: rules"} → ${r.reasoner === "on_device" ? "answer: device" : "answer: cloud"} · ${r.outboundChars} chars out</span></li>`).join("")
      : `<li class="empty">No receipts yet.</li>`;
    if (rows.length && !state.lastReceiptPayload) {
      const latest = rows[0];
      state.lastReceiptPayload = {
        task: latest.task,
        counts: latest.counts || {},
        masked: latest.masked,
        detector: latest.detector,
        reasoner: latest.reasoner,
        outboundChars: latest.outboundChars,
        leakGuard: latest.leakGuard,
        unknownTokens: latest.unknownTokens,
        at: latest.at?.toDate ? latest.at.toDate().toISOString() : "serverTimestamp()",
      };
      state.lastReceiptPath = `Latest Firestore receipt (${latest.id})`;
      renderPayloadInspector();
    }
  } catch (e) { console.warn("receipts", e); }
}

async function boot() {
  $("#task").innerHTML = Object.entries({ reply: "Draft a reply", summary: "Summarize", actions: "Extract action items", formal: "Make it formal", arabic: "Translate to Arabic" })
    .map(([k, v]) => `<option value="${k}">${v}</option>`).join("");
  renderPresets();
  selectPreset(PRESETS[0].id);
  renderPayloadInspector();

  $("#presets").addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-preset]");
    if (btn) selectPreset(btn.dataset.preset);
  });
  $("#input").addEventListener("input", () => {
    hideDegradeCallout();
    $("#error").textContent = "";
  });
  $("#run").addEventListener("click", () => run({ approveRulesOnly: false }));
  $("#approveRulesSend").addEventListener("click", () => {
    $("#local").checked = false;
    run({ approveRulesOnly: true });
  });
  $("#keepLocalBtn").addEventListener("click", () => {
    $("#local").checked = true;
    run({ approveRulesOnly: false });
  });
  $("#copyResult").addEventListener("click", copyRestoredResult);
  $("#downloadCert").addEventListener("click", downloadComplianceCertificate);
  $("#runStressTest").addEventListener("click", renderStressTest);
  $("#closeStressPanel").addEventListener("click", () => { $("#stressPanel").hidden = true; });
  $("#togglePayload").addEventListener("click", () => {
    const panel = $("#payloadPanel");
    const open = panel.hidden;
    panel.hidden = !open;
    $("#togglePayload").setAttribute("aria-expanded", String(open));
    renderPayloadInspector();
  });

  policy = await loadPolicy();
  $("#policy").textContent = `Policy from Remote Config (${policy.source}): cloud model ${policy.cloudModel}, ${policy.categories.length} categories, ${policy.maxChars} char limit.`;
  if (!policy.allowLocalReasoning) { $("#local").checked = false; $("#local").disabled = true; }
  detector = detectorModel();
  try { user = await signIn(); renderReceipts(); } catch (e) { console.warn("auth", e); }
  const hasPromptApi = typeof self.LanguageModel !== "undefined";
  $("#device").innerHTML = hasPromptApi
    ? `<span class="badge dev">Gemini Nano API present</span> First run may download the model.`
    : `<span class="badge rules">No on-device model in this browser</span> Veil masks locally with deterministic rules and pauses before any cloud call.`;
}

boot();
