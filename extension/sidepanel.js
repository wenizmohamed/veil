import {
  detectWithRules,
  sanitizeModelSpans,
  buildPlan,
  mask,
  leakCheck,
  unmaskSegments,
  tokenizeMaskedText,
  buildReceiptPayload,
  NANO_DETECT_PROMPT,
  TASKS,
  PRESETS,
  CATEGORIES,
} from "../src/veil-core.js";
import {
  loadPolicy,
  signIn,
  detectorModel,
  reasonerModel,
  saveReceipt,
  InferenceSource,
} from "../src/firebase.js";

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

let policy = { cloudModel: "gemini-3.5-flash-lite", categories: [...CATEGORIES], maxChars: 6000 };
let user = null;
let detector = null;
let lastRestored = "";

function renderMaskedHtml(txt) {
  return tokenizeMaskedText(txt)
    .map((s) => (s.kind === "token" ? `<span class="tok">${esc(s.token)}</span>` : esc(s.value)))
    .join("");
}

function renderRestoredHtml(segs) {
  return segs
    .map((s) => (s.kind === "restored" ? `<span class="rest">${esc(s.value)}</span>` : esc(s.value)))
    .join("");
}

async function detectOnDevice(text) {
  const rules = detectWithRules(text, policy.categories);
  const avail = await self.LanguageModel?.availability?.({ expectedInputs: [{ type: "text", languages: ["en"] }] }).catch(() => "unavailable");
  if ((avail === "available" || avail === "readily") && detector) {
    try {
      await detector.initializeDeviceModel();
      const res = await detector.generateContent(NANO_DETECT_PROMPT(text.slice(0, 900), policy.categories));
      const parsed = JSON.parse(res.response.text());
      return { spans: [...sanitizeModelSpans(text, parsed.entities, policy.categories), ...rules], source: "on_device" };
    } catch {
      return { spans: rules, source: "rules_only" };
    }
  }
  return { spans: rules, source: "rules_only" };
}

async function runExtensionFlow({ approveRulesOnly = false } = {}) {
  const text = $("#extInput").value.trim();
  const task = $("#extTask").value;
  const local = $("#extLocalOnly").checked;
  if (!text) return;

  $("#extApproveCloudBtn").hidden = true;
  $("#extRunBtn").disabled = true;
  $("#extStatus").className = "meta";
  $("#extStatus").textContent = "Step 1/4: Scanning locally...";

  try {
    const { spans, source: detSource } = await detectOnDevice(text);
    const plan = buildPlan(spans);
    const masked = mask(text, plan);
    const outbound = `${TASKS[task]}\n\n${masked}`;

    leakCheck(outbound, plan);
    $("#extCloudSaw").innerHTML = renderMaskedHtml(outbound);

    if (detSource === "rules_only" && !local && !approveRulesOnly) {
      $("#extStatus").className = "meta status-warn";
      $("#extStatus").textContent = `Rules-only masked ${plan.length} item(s) locally. Review above, then click Approve Rules-Only Cloud.`;
      $("#extApproveCloudBtn").hidden = false;
      return;
    }

    $("#extStatus").textContent = local ? "Reasoning 100% locally..." : `Asking ${policy.cloudModel} on placeholders only...`;
    const model = reasonerModel(policy, local);
    const res = await model.generateContent(outbound);
    const draft = res.response.text();
    const resSrc = res.response.inferenceSource || (local ? "on_device" : "in_cloud");
    const { text: restored, segments, unknownTokens, restoredCount } = unmaskSegments(draft, plan);

    lastRestored = restored;
    $("#extOut").innerHTML = renderRestoredHtml(segments);
    $("#extCopyBtn").disabled = !restored.length;
    $("#extBadge").textContent = resSrc === InferenceSource.ON_DEVICE ? "100% Local" : "Hybrid Cloud";
    $("#extStatus").className = "meta status-ok";
    $("#extStatus").textContent = `Verified: ${plan.length} masked · 0 leaked · ${restoredCount} restored locally.`;

    if (user) {
      const receipt = buildReceiptPayload({
        task,
        plan,
        detectorSource: detSource,
        reasonerSource: resSrc === InferenceSource.ON_DEVICE || resSrc === "on_device" ? "on_device" : "in_cloud",
        outboundChars: outbound.length,
        unknownTokensCount: unknownTokens.length,
      });
      await saveReceipt(user.uid, receipt).catch(() => {});
    }
  } catch (err) {
    $("#extStatus").className = "meta";
    $("#extStatus").textContent = `Blocked/Error: ${err?.message || err}`;
  } finally {
    $("#extRunBtn").disabled = false;
  }
}

async function grabPageSelection() {
  if (!chrome?.tabs?.query || !chrome?.scripting?.executeScript) return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => (window.getSelection?.()?.toString() || "").trim(),
    });
    if (result) {
      $("#extInput").value = result;
      $("#extStatus").textContent = `Captured ${result.length} characters locally from active tab.`;
    } else {
      $("#extStatus").textContent = "No highlighted text found on active tab.";
    }
  } catch {
    $("#extStatus").textContent = "Cannot script this chrome:// page; paste text directly.";
  }
}

async function init() {
  $("#extInput").value = PRESETS[0].text;
  $("#grabTabBtn").addEventListener("click", grabPageSelection);
  $("#presetBtn").addEventListener("click", () => { $("#extInput").value = PRESETS[0].text; });
  $("#extRunBtn").addEventListener("click", () => runExtensionFlow({ approveRulesOnly: false }));
  $("#extApproveCloudBtn").addEventListener("click", () => runExtensionFlow({ approveRulesOnly: true }));
  $("#extCopyBtn").addEventListener("click", async () => {
    if (!lastRestored) return;
    await navigator.clipboard.writeText(lastRestored);
    $("#extCopyBtn").textContent = "Copied";
    setTimeout(() => { $("#extCopyBtn").textContent = "Copy"; }, 1400);
  });

  if (typeof chrome !== "undefined" && chrome.storage?.local) {
    const stored = await chrome.storage.local.get("veilPendingText").catch(() => ({}));
    if (stored?.veilPendingText) $("#extInput").value = stored.veilPendingText;
    chrome.storage.onChanged?.addListener((changes) => {
      if (changes.veilPendingText?.newValue) {
        $("#extInput").value = changes.veilPendingText.newValue;
      }
    });
  }

  detector = detectorModel();
  policy = await loadPolicy().catch(() => policy);
  user = await signIn().catch(() => null);
}

init();
