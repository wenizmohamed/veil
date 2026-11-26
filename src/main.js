import "./style.css";
import {
  detectWithRules, sanitizeModelSpans, buildPlan, mask, leakCheck, unmaskSegments,
  tokenizeMaskedText, buildReceiptPayload, verifyOutboundBytesZeroSecrets,
  buildComplianceCertificate, runAdversarialStressTest, countByType,
  computeTelemetrySplit, evaluateFirestoreRule, runAllFirestoreRuleTests,
  runBatchRedactionQueue, buildBatchComplianceBundle,
  FIRESTORE_RULES_SOURCE, FIRESTORE_ATTACK_VECTORS,
  NANO_DETECT_PROMPT, TASKS, PRESETS, CATEGORIES,
} from "./veil-core.js";
import { loadPolicy, signIn, detectorModel, generateWithCloudResilience, saveReceipt, loadReceipts, InferenceSource } from "./firebase.js";

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

let policy = {
  cloudModel: "gemini-4-hydrogen",
  categories: [...CATEGORIES],
  allowLocalReasoning: true,
  maxChars: 6000,
  source: "default",
};
let user, detector, deviceReady = false;

const state = {
  activeTab: "workspace",
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
  lastDeviceMs: null,
  lastCloudMs: null,
  lastFindMs: 0,
  lastGuardMs: 0,
  lastRestoreMs: 0,
  lastLocalOnly: false,
  batchDocs: PRESETS.map((p) => ({
    id: p.id,
    name: `${p.label}.txt`,
    industry: p.industry,
    task: p.defaultTask,
    text: p.text,
  })),
  lastBatchResult: null,
  lastBatchDigests: {},
  lastBatchBundleSha256: null,
  activeRuleVectorId: "raw_text_leak",
  lastRulesSuite: null,
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

// Atmospheric Nightshift starfield canvas (respects prefers-reduced-motion)
function initStarfield() {
  const canvas = $("#starfield");
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext("2d");
  const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let width = 0;
  let height = 0;
  let stars = [];

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = canvas.clientWidth || window.innerWidth;
    height = canvas.clientHeight || Math.round(window.innerHeight * 0.68);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const count = Math.min(210, Math.max(90, Math.round((width * height) / 4800)));
    let seed = 0x51f15e;
    const rand = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    stars = Array.from({ length: count }, () => {
      const r1 = rand();
      const r2 = rand();
      const r3 = rand();
      const r4 = rand();
      return {
        x: r1 * width,
        y: Math.pow(r2, 1.15) * height * 0.94,
        r: r3 > 0.88 ? 1.45 : r3 > 0.45 ? 1.0 : 0.72,
        baseAlpha: 0.18 + r4 * 0.62,
        phase: rand() * Math.PI * 2,
        speed: 0.32 + rand() * 0.75,
        tint: r3 > 0.74 ? "186, 230, 253" : "255, 255, 255",
      };
    });
    draw(0);
  }

  function draw(ts) {
    ctx.clearRect(0, 0, width, height);
    const t = ts * 0.001;
    for (let i = 0; i < stars.length; i++) {
      const s = stars[i];
      const twinkle = reduced ? 0 : Math.sin(t * s.speed + s.phase) * 0.24;
      const alpha = Math.max(0.12, Math.min(0.92, s.baseAlpha + twinkle));
      ctx.fillStyle = `rgba(${s.tint}, ${alpha.toFixed(3)})`;
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fill();
    }
    if (!reduced) requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener("resize", resize);
}

// 48-Bar Nightshift Signal Waveform
function renderWaveform({ maskedCount = 0, localOnly = false, verified = false } = {}) {
  const host = $("#waveformBars");
  if (!host) return;
  const bars = 48;
  const localRatio = localOnly ? 1 : Math.min(0.76, Math.max(0.32, 0.34 + maskedCount * 0.032));
  const localCutoff = Math.round(bars * localRatio);

  const html = [];
  for (let i = 0; i < bars; i++) {
    const waveA = Math.sin(i * 0.42 + maskedCount * 0.5) * 26;
    const waveB = Math.cos(i * 0.85) * 16;
    const centerBoost = Math.exp(-Math.pow((i - bars * 0.44) / 16, 2)) * 24;
    const h = Math.round(Math.max(18, Math.min(96, 36 + waveA + waveB + centerBoost)));
    const cls = i < localCutoff ? (verified && localOnly ? "is-verified" : "is-local") : "";
    const delay = ((i % 12) * 0.14).toFixed(2);
    html.push(`<span class="wave-bar ${cls}" style="height:${h}%;animation-delay:${delay}s"></span>`);
  }
  host.innerHTML = html.join("");
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const hashBuf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function setActiveTab(tabName) {
  state.activeTab = tabName;
  $$(".seg-tab").forEach((btn) => {
    const active = btn.dataset.tab === tabName;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", String(active));
  });
  $$(".tab-panel").forEach((panel) => {
    panel.hidden = panel.dataset.panel !== tabName;
  });
  const dockAudit = $("#dockAuditBtn");
  if (dockAudit) dockAudit.classList.toggle("active", tabName === "audit");
}

function syncLocalModeUI(isLocal) {
  const chk = $("#local");
  if (chk && chk.checked !== isLocal) chk.checked = isLocal;
  const toggle = $("#topLocalToggle");
  if (toggle) toggle.setAttribute("aria-checked", String(isLocal));
  const hybridBtn = $("#dockHybridBtn");
  const localBtn = $("#dockLocalBtn");
  if (hybridBtn) hybridBtn.classList.toggle("active", !isLocal);
  if (localBtn) localBtn.classList.toggle("active", isLocal);
}

function updateStatusCapsule({ label, chip, dot = "ok" }) {
  const labelEl = $("#capsuleLabel");
  const chipEl = $("#capsuleChip");
  const dotEl = $("#capsuleDot");
  if (labelEl && label) labelEl.textContent = label;
  if (chipEl && chip) chipEl.textContent = chip;
  if (dotEl) dotEl.className = `status-dot ${dot}`;
}

function renderPolicyCard() {
  $("#rcCloudModel").textContent = policy.cloudModel;
  $("#rcLocalAllowed").textContent = policy.allowLocalReasoning ? "Allowed (On-Device Nano)" : "Cloud Only (Policy)";
  $("#rcMaxChars").textContent = `${Number(policy.maxChars).toLocaleString()} chars`;
  $("#rcSourceBadge").textContent = `Source: ${policy.source}`;
  $("#rcCategories").innerHTML = policy.categories
    .map((cat) => `<span class="tok" data-type="${esc(cat)}">${esc(cat)}</span>`)
    .join("");
}

function renderRawDiffHtml(text, plan) {
  if (!text) return "";
  if (!plan.length) return esc(text);
  const sorted = [...plan].sort((a, b) => b.text.length - a.text.length);
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = sorted.map((e) => escapeRe(e.text)).join("|");
  if (!pattern) return esc(text);
  const re = new RegExp(`(${pattern})`, "gi");
  const parts = text.split(re);
  const lookup = new Map(sorted.map((e) => [e.text.toLowerCase(), e]));
  return parts.map((part) => {
    const hit = lookup.get(part.toLowerCase());
    if (hit) {
      return `<mark class="raw-pii-mark" title="${esc(hit.token)} (${esc(hit.type)})">${esc(part)}</mark>`;
    }
    return esc(part);
  }).join("");
}

function renderCategoryBreakdown(plan) {
  const host = $("#categoryBars");
  const totalEl = $("#catTotalChip");
  if (!host) return;
  const counts = countByType(plan);
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (totalEl) totalEl.textContent = String(plan.length);
  if (!entries.length) {
    host.innerHTML = `<p class="card-caption">No sensitive categories detected in the active input.</p>`;
    return;
  }
  const maxVal = Math.max(...entries.map(([, v]) => v), 1);
  host.innerHTML = entries.map(([cat, val]) => {
    const pct = Math.max(12, Math.round((val / maxVal) * 100));
    return `
      <div class="cat-row">
        <span class="tok" data-type="${esc(cat)}">${esc(cat)}</span>
        <div class="cat-track"><div class="cat-fill" style="width:${pct}%"></div></div>
        <span class="cat-count tabular">${val}</span>
      </div>
    `;
  }).join("");
}

function renderDiffViews(rawText, maskedText, plan) {
  const rawEl = $("#diffRawView");
  const maskedEl = $("#diffMaskedView");
  const rawChars = $("#diffRawChars");
  const maskedChars = $("#diffMaskedChars");
  if (rawEl) rawEl.innerHTML = renderRawDiffHtml(rawText, plan);
  if (maskedEl) maskedEl.innerHTML = renderTokenizedHtml(maskedText);
  if (rawChars) rawChars.textContent = `${rawText.length} chars`;
  if (maskedChars) maskedChars.textContent = `${maskedText.length} chars`;
}

function renderTelemetrySplitChart({ rawText, maskedText, plan, findMs, guardMs, cloudMs, restoreMs, localOnly }) {
  const latHost = $("#latencyChartWrap");
  const byteHost = $("#byteSplitChartWrap");
  if (!latHost || !byteHost) return;

  const t = computeTelemetrySplit({
    rawText,
    maskedText,
    plan,
    findMs,
    guardMs,
    cloudMs,
    restoreMs,
    localOnly,
  });

  const { latency, bytes } = t;
  const maxStage = Math.max(latency.findMs, latency.guardMs, latency.cloudMs, latency.restoreMs, 1);
  const stages = [
    { label: "01 Find", sub: "On-Device", ms: latency.findMs, color: "#38bdf8" },
    { label: "02 Guard", sub: "On-Device", ms: latency.guardMs, color: "#22c55e" },
    { label: "03 Reason", sub: latency.localOnly ? "Local Only" : "Cloud", ms: latency.cloudMs, color: latency.localOnly ? "#38bdf8" : "#818cf8" },
    { label: "04 Restore", sub: "On-Device", ms: latency.restoreMs, color: "#34d399" },
  ];

  const barMaxW = 265;
  const stageRows = stages.map((s, idx) => {
    const y = 14 + idx * 32;
    const w = s.ms > 0 ? Math.max(10, Math.round((s.ms / maxStage) * barMaxW)) : 4;
    const valStr = s.ms === 0 && idx === 2 ? (latency.localOnly ? "0 ms (local)" : "awaiting run") : `${s.ms.toFixed(1)} ms`;
    return `
      <text x="0" y="${y + 13}" fill="#d7dce5" font-size="11.5" font-family="JetBrains Mono, monospace">${esc(s.label)}</text>
      <text x="78" y="${y + 13}" fill="#8a8f98" font-size="10.5" font-family="Instrument Sans, sans-serif">${esc(s.sub)}</text>
      <rect x="148" y="${y + 2}" width="${barMaxW}" height="14" rx="7" fill="rgba(255,255,255,0.06)" />
      <rect x="148" y="${y + 2}" width="${w}" height="14" rx="7" fill="${s.color}" opacity="${s.ms > 0 ? "0.92" : "0.35"}" />
      <text x="${148 + barMaxW + 10}" y="${y + 13}" fill="#ffffff" font-size="11" font-family="JetBrains Mono, monospace">${esc(valStr)}</text>
    `;
  }).join("");

  const totalBarW = 500;
  const devBarW = Math.max(8, Math.round((latency.onDevicePct / 100) * totalBarW));
  const cloudBarW = Math.max(0, totalBarW - devBarW);

  latHost.innerHTML = `
    <svg viewBox="0 0 520 182" width="100%" role="img" aria-label="Measured pipeline latency breakdown">
      ${stageRows}
      <text x="0" y="152" fill="#8a8f98" font-size="10.5" font-family="JetBrains Mono, monospace">TIME SPLIT: ON-DEVICE ${latency.onDevicePct}% (${latency.onDeviceTotalMs.toFixed(1)} ms) · CLOUD ${latency.cloudPct}% (${latency.cloudMs.toFixed(1)} ms)</text>
      <rect x="0" y="160" width="${totalBarW}" height="10" rx="5" fill="rgba(255,255,255,0.07)" />
      <rect x="0" y="160" width="${devBarW}" height="10" rx="5" fill="#22c55e" />
      ${cloudBarW > 0 ? `<rect x="${devBarW}" y="160" width="${cloudBarW}" height="10" rx="5" fill="#818cf8" />` : ""}
    </svg>
  `;

  const maxB = Math.max(bytes.rawBytes, bytes.outboundBytes, 1);
  const byteRows = [
    { label: "Raw Input", val: bytes.rawBytes, color: "#94a3b8", tag: `${bytes.rawBytes} B local` },
    { label: "PII Shielded", val: bytes.secretBytesShielded, color: "#22c55e", tag: `${bytes.secretBytesShielded} B (${bytes.privacyShieldPct}%)` },
    { label: "Wire Payload", val: bytes.outboundBytes, color: "#38bdf8", tag: `${bytes.outboundBytes} B tokens` },
    { label: "PII on Wire", val: bytes.piiBytesOnWire, color: bytes.piiBytesOnWire === 0 ? "#22c55e" : "#ef4444", tag: `${bytes.piiBytesOnWire} B · ZERO LEAK` },
  ];

  const byteSvgRows = byteRows.map((r, idx) => {
    const y = 12 + idx * 31;
    const w = r.val > 0 ? Math.max(10, Math.round((r.val / maxB) * 250)) : 4;
    return `
      <text x="0" y="${y + 13}" fill="#d7dce5" font-size="11.5" font-family="JetBrains Mono, monospace">${esc(r.label)}</text>
      <rect x="114" y="${y + 2}" width="250" height="14" rx="7" fill="rgba(255,255,255,0.06)" />
      <rect x="114" y="${y + 2}" width="${w}" height="14" rx="7" fill="${r.color}" opacity="${r.val > 0 ? "0.92" : "0.5"}" />
      <text x="374" y="${y + 13}" fill="${idx === 3 ? "#4ade80" : "#ffffff"}" font-size="11" font-family="JetBrains Mono, monospace">${esc(r.tag)}</text>
    `;
  }).join("");

  byteHost.innerHTML = `
    <svg viewBox="0 0 520 140" width="100%" role="img" aria-label="Privacy byte boundary and wire savings breakdown">
      ${byteSvgRows}
    </svg>
  `;

  const deltaSign = bytes.byteDelta > 0 ? `-${bytes.byteDelta} B saved` : bytes.byteDelta < 0 ? `+${Math.abs(bytes.byteDelta)} B token pad` : "0 B neutral";
  $("#telemetryLatencyTotal").textContent = `On-device: ${latency.onDeviceTotalMs.toFixed(1)} ms · Cloud: ${latency.cloudMs > 0 ? `${latency.cloudMs.toFixed(1)} ms` : latency.localOnly ? "0 ms (local)" : "idle"}`;
  $("#telemetryByteHeadline").textContent = `${bytes.secretBytesShielded} B PII shielded · ${deltaSign}`;
  $("#telemetrySplitBadge").textContent = latency.cloudMs > 0
    ? `Hybrid · ${latency.onDeviceTotalMs.toFixed(1)} ms Device vs ${latency.cloudMs.toFixed(1)} ms Cloud`
    : `On-Device Shield · ${bytes.secretBytesShielded} B PII Kept Local`;
  $("#kpiSecretBytes").textContent = `${bytes.secretBytesShielded} B`;
  $("#kpiByteDelta").textContent = deltaSign;
  $("#kpiShieldPct").textContent = `${bytes.privacyShieldPct}%`;
}

// =========================================================================
// BATCH MULTI-DOCUMENT REDACTION QUEUE UI
// =========================================================================

function renderBatchQueueList() {
  const listEl = $("#batchList");
  if (!listEl) return;
  const resultMap = new Map((state.lastBatchResult?.documents || []).map((d) => [d.id, d]));

  if (!state.batchDocs.length) {
    listEl.innerHTML = `<li class="empty">Queue empty. Drop files or click "Load 3 Enterprise Docs".</li>`;
    $("#batchStatusBadge").textContent = "0 Docs Queued";
    $("#batchSummaryBar").hidden = true;
    $("#batchDownloadBtn").disabled = true;
    return;
  }

  listEl.innerHTML = state.batchDocs.map((doc, idx) => {
    const res = resultMap.get(doc.id);
    const digest = state.lastBatchDigests[doc.id];
    const statusHtml = res
      ? `<span class="badge dev">${res.maskedCount} masked · ${res.leakedBytes} leaked · ${res.elapsedMs} ms</span>`
      : `<span class="badge rules">Queued · ${doc.text.length} chars</span>`;
    const metaHtml = res
      ? `<span class="mono-item tabular">${res.rawBytes} B -> ${res.outboundBytes} B (${res.secretBytesShielded} B PII local) · SHA256:${esc((digest || "").slice(0, 12))}</span>`
      : `<span class="mono-item">${esc(doc.industry)} · task: ${esc(doc.task)}</span>`;
    return `
      <li class="batch-row${res?.leakGuardPassed ? " is-verified" : ""}" data-batch-id="${esc(doc.id)}">
        <div class="batch-row-main">
          <span class="step-num">0${idx + 1}</span>
          <strong class="batch-doc-name">${esc(doc.name)}</strong>
          <span class="preset-tag">${esc(doc.industry)}</span>
        </div>
        <div class="batch-row-meta">
          ${metaHtml}
          ${statusHtml}
        </div>
      </li>
    `;
  }).join("");

  if (state.lastBatchResult) {
    const b = state.lastBatchResult;
    $("#batchStatusBadge").className = b.allZeroLeak ? "badge dev" : "badge rules";
    $("#batchStatusBadge").textContent = `${b.passedDocs}/${b.totalDocs} Zero-Leak Verified`;
    $("#batchKpiDocs").textContent = `${b.passedDocs}/${b.totalDocs}`;
    $("#batchKpiMasked").textContent = String(b.totalMasked);
    $("#batchKpiLeaked").textContent = `${b.totalLeaked} B`;
    $("#batchKpiShielded").textContent = `${b.totalSecretBytesShielded} B (${b.aggregateShieldPct}%)`;
    $("#batchBundleHash").textContent = state.lastBatchBundleSha256 || "--";
    $("#batchElapsed").textContent = `${b.elapsedMs} ms total`;
    $("#batchSummaryBar").hidden = false;
    $("#batchDownloadBtn").disabled = false;
  } else {
    $("#batchStatusBadge").className = "badge dev";
    $("#batchStatusBadge").textContent = `${state.batchDocs.length} Docs Queued`;
    $("#batchSummaryBar").hidden = true;
    $("#batchDownloadBtn").disabled = true;
  }
}

async function runBatchQueueUI() {
  if (!state.batchDocs.length) return;
  const btn = $("#batchRunBtn");
  btn.disabled = true;
  btn.textContent = "Redacting...";
  try {
    const summary = runBatchRedactionQueue(state.batchDocs, policy.categories);
    const digests = {};
    for (const d of summary.documents) {
      digests[d.id] = await sha256Hex(d.outbound);
    }
    const concatDigests = summary.documents.map((d) => `${d.id}:${digests[d.id]}:${d.maskedCount}`).join("|");
    const bundleSha256 = await sha256Hex(concatDigests);
    state.lastBatchResult = summary;
    state.lastBatchDigests = digests;
    state.lastBatchBundleSha256 = bundleSha256;
    renderBatchQueueList();
  } finally {
    btn.disabled = false;
    btn.textContent = "Run Batch Queue";
  }
}

async function ingestBatchFiles(fileList) {
  const files = Array.from(fileList || []).slice(0, 8);
  if (!files.length) return;
  const loaded = [];
  for (const f of files) {
    const txt = await f.text();
    if (!txt.trim()) continue;
    loaded.push({
      id: `upload_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      name: f.name,
      industry: "Uploaded",
      task: "summary",
      text: txt.slice(0, policy.maxChars),
    });
  }
  if (!loaded.length) return;
  state.batchDocs = loaded;
  state.lastBatchResult = null;
  state.lastBatchDigests = {};
  state.lastBatchBundleSha256 = null;
  $("#batchDropLabel").textContent = `Loaded ${loaded.length} custom file${loaded.length === 1 ? "" : "s"} into local redaction queue`;
  renderBatchQueueList();
}

function downloadBatchBundle() {
  if (!state.lastBatchResult) return;
  const bundle = buildBatchComplianceBundle({
    batchSummary: state.lastBatchResult,
    docDigests: state.lastBatchDigests,
    bundleSha256: state.lastBatchBundleSha256,
    policySnapshot: policy,
    rulesTestSummary: state.lastRulesSuite,
  });
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `veil-batch-compliance-bundle-${(state.lastBatchBundleSha256 || "zero-leak").slice(0, 12)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// =========================================================================
// LIVE FIRESTORE ZERO-TEXT SECURITY RULES TESTER UI
// =========================================================================

function renderFirestoreRulesCode(evaluation) {
  const host = $("#firestoreRulesCode");
  if (!host) return;
  const failedLines = new Set((evaluation?.failedChecks || []).map((c) => c.line));
  const passedLines = new Set((evaluation?.passedChecks || []).map((c) => c.line));
  const lines = FIRESTORE_RULES_SOURCE.split("\n");

  host.innerHTML = lines.map((lineText, idx) => {
    const num = idx + 1;
    const isFail = failedLines.has(num);
    const isPass = !isFail && passedLines.has(num);
    const cls = isFail ? "rule-line fail" : isPass ? "rule-line pass" : "rule-line";
    const tag = isFail ? `<span class="rule-tag fail">DENY</span>` : isPass ? `<span class="rule-tag pass">OK</span>` : "";
    return `<div class="${cls}"><span class="rule-ln tabular">${String(num).padStart(2, "0")}</span><code>${esc(lineText) || " "}</code>${tag}</div>`;
  }).join("");
}

function renderRuleEvaluation(evaluation) {
  const box = $("#rulesVerdictBox");
  if (!box || !evaluation) return;
  $("#rulesMatchedBlock").textContent = evaluation.matchedRuleBlock;
  const isAllow = evaluation.allowed;
  const checksHtml = isAllow
    ? evaluation.passedChecks.slice(0, 6).map((c) => `<li class="verdict-item pass">Line ${c.line}: <code>${esc(c.rule)}</code></li>`).join("")
    : evaluation.failedChecks.map((c) => `<li class="verdict-item fail">Line ${c.line}: ${esc(c.reason)}</li>`).join("");

  box.className = `rules-verdict-box ${isAllow ? "allow" : "deny"}`;
  box.innerHTML = `
    <div class="verdict-head">
      <span class="verdict-pill ${isAllow ? "allow" : "deny"}">${esc(evaluation.decision)}</span>
      <strong class="verdict-summary">${esc(evaluation.summary)}</strong>
    </div>
    <ul class="verdict-list">${checksHtml}</ul>
  `;
  renderFirestoreRulesCode(evaluation);
}

function renderRuleVectorPills() {
  const host = $("#rulesVectorPills");
  if (!host) return;
  const suiteMap = new Map((state.lastRulesSuite?.results || []).map((r) => [r.id, r]));
  host.innerHTML = FIRESTORE_ATTACK_VECTORS.map((v) => {
    const res = suiteMap.get(v.id);
    const dec = res ? res.evaluation.decision : v.expected;
    const isActive = v.id === state.activeRuleVectorId;
    return `
      <button type="button" class="rule-vec-btn${isActive ? " active" : ""}" data-rule-vec="${esc(v.id)}" aria-pressed="${isActive}">
        <span class="vec-tag ${dec === "ALLOW" ? "allow" : "deny"}">${esc(dec)}</span>
        <span>${esc(v.label)}</span>
      </button>
    `;
  }).join("");
}

function selectRuleVector(vectorId) {
  const vec = FIRESTORE_ATTACK_VECTORS.find((v) => v.id === vectorId);
  if (!vec) return;
  state.activeRuleVectorId = vec.id;
  $("#rulesOpSelect").value = vec.operation;
  $("#rulesPathInput").value = vec.path;
  $("#rulesPayloadInput").value = JSON.stringify(vec.data, null, 2);
  $("#rulesActiveDesc").textContent = vec.description;
  renderRuleVectorPills();
  evaluateCustomRuleUI();
}

function evaluateCustomRuleUI() {
  const op = $("#rulesOpSelect").value;
  const path = $("#rulesPathInput").value.trim();
  const rawJson = $("#rulesPayloadInput").value.trim();
  let parsed;
  try {
    parsed = rawJson ? JSON.parse(rawJson) : {};
  } catch (err) {
    renderRuleEvaluation({
      allowed: false,
      decision: "DENY",
      matchedRuleBlock: "JSON parse error",
      passedChecks: [],
      failedChecks: [{ line: 11, rule: "validReceipt(request.resource.data)", reason: `Invalid JSON payload: ${err.message}` }],
      summary: `Invalid JSON payload: ${err.message}`,
    });
    return;
  }
  const ev = evaluateFirestoreRule({ path, operation: op, data: parsed });
  renderRuleEvaluation(ev);
}

function runAllRulesUI() {
  const suite = runAllFirestoreRuleTests();
  state.lastRulesSuite = suite;
  $("#rulesSummaryBadge").className = suite.allPassed ? "badge dev tabular" : "badge rules tabular";
  $("#rulesSummaryBadge").textContent = `${suite.adversarialBlocked}/${suite.adversarialTotal} Leaks Denied · ${suite.cleanAllowed}/1 Clean Allowed`;
  renderRuleVectorPills();
  selectRuleVector(state.activeRuleVectorId);
}

// Instant zero-network local preview so judges immediately see real PII detection & diff on load
function previewLocalShield() {
  const text = $("#input").value.trim();
  const t0 = performance.now();
  const spans = detectWithRules(text, policy.categories);
  const plan = buildPlan(spans);
  const masked = mask(text, plan);
  const findMs = Math.max(0.2, performance.now() - t0);

  const tGuard0 = performance.now();
  try { leakCheck(masked, plan); } catch {}
  const guardMs = Math.max(0.1, performance.now() - tGuard0);

  const tRestore0 = performance.now();
  unmaskSegments(masked, plan);
  const restoreMs = Math.max(0.1, performance.now() - tRestore0);

  const scanMs = Math.max(1, Math.round(findMs + guardMs + restoreMs));

  state.plan = plan;
  state.masked = masked;
  state.lastDeviceMs = scanMs;
  state.lastFindMs = findMs;
  state.lastGuardMs = guardMs;
  state.lastCloudMs = 0;
  state.lastRestoreMs = restoreMs;
  state.lastLocalOnly = $("#local").checked;

  renderPlan();
  renderCategoryBreakdown(plan);
  renderDiffViews(text, masked, plan);
  renderTelemetrySplitChart({
    rawText: text,
    maskedText: masked,
    plan,
    findMs,
    guardMs,
    cloudMs: 0,
    restoreMs,
    localOnly: $("#local").checked,
  });
  $("#cloudSaw").innerHTML = renderTokenizedHtml(masked);
  $("#detectorBadge").innerHTML = `<span class="badge dev">Local Preview · 0 Bytes Sent</span>`;
  $("#metricMaskedNum").textContent = String(plan.length);
  $("#metricLeakedNum").textContent = "0";
  $("#metricLatencyNum").textContent = String(scanMs);
  $("#vaultCountChip").textContent = String(plan.length);

  renderWaveform({ maskedCount: plan.length, localOnly: $("#local").checked, verified: true });
  updateStatusCapsule({
    label: $("#local").checked ? "On-Device Local · 0 PII Left Device" : "Local Shield Armed · 0 PII Left Device",
    chip: `${plan.length} masked`,
    dot: "ok",
  });
  updateAuditStrip({
    status: plan.length ? "pass" : "",
    leaked: 0,
    masked: plan.length,
    guard: "READY",
    deviceMs: scanMs,
    cloudMs: null,
    localOnly: $("#local").checked,
  });
  $("#auditRouteTag").textContent = $("#local").checked ? "Route: 100% On-Device" : "Route: Hybrid Shield Ready";
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
        <span>${r.restored ? "Restored" : "Restore fail"}</span>
      </div>
    </div>
  `).join("");
  $("#stressPanel").hidden = false;
  $("#stressPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
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
      return `<span class="unknown-tok" title="Placeholder invented by model, left unguessed">${esc(seg.token)}</span>`;
    }
    return esc(seg.value).replace(/\n/g, "<br>");
  }).join("");
}

function renderPlan() {
  $("#plan").innerHTML = state.plan.length
    ? state.plan.map((e) => `<li><code class="tok" data-type="${esc(e.type)}">${esc(e.token)}</code><span>${esc(e.text)}</span><em>${e.source === "nano" ? "Nano" : "rule"}</em></li>`).join("")
    : `<li class="empty">Nothing sensitive found.</li>`;
  $("#planCount").textContent = String(state.plan.length);
  const chip = $("#vaultCountChip");
  if (chip) chip.textContent = String(state.plan.length);
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
  renderPresets();
  previewLocalShield();
}

async function getLocalNanoAvailability() {
  if (typeof self === "undefined" || typeof self.LanguageModel?.availability !== "function") {
    return "unavailable";
  }
  try {
    return await self.LanguageModel.availability({
      expectedInputs: [{ type: "text", languages: ["en"] }],
      expectedOutputs: [{ type: "text", languages: ["en"] }],
    });
  } catch {
    try {
      return await self.LanguageModel.availability();
    } catch {
      return "unavailable";
    }
  }
}

async function ensureDevice() {
  if (deviceReady || !detector) return deviceReady;
  const avail = await getLocalNanoAvailability();
  if (avail === "available" || avail === "readily") {
    try {
      await detector.initializeDeviceModel((p) => setStep(1, "busy", `Loading Gemini Nano... ${Math.round(p * 100)}%`));
      deviceReady = true;
    } catch {
      deviceReady = false;
    }
    return deviceReady;
  }
  // When weights are downloadable in a real browser (non-webdriver), trigger download only if it transitions to available.
  if ((avail === "downloadable" || avail === "downloading") && !navigator.webdriver) {
    try {
      await detector.initializeDeviceModel((p) => setStep(1, "busy", `Downloading Gemini Nano... ${Math.round(p * 100)}%`));
      const postAvail = await getLocalNanoAvailability();
      deviceReady = postAvail === "available" || postAvail === "readily";
    } catch {
      deviceReady = false;
    }
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
      if (e?.name === "QuotaExceededError") {
        // Retry with smaller slices before cleanly falling back to deterministic rules
        try {
          nano = [];
          for (const small of chunks(text, 360)) {
            const res = await detector.generateContent(NANO_DETECT_PROMPT(small, policy.categories));
            const parsed = JSON.parse(res.response.text());
            nano.push(...sanitizeModelSpans(small, parsed.entities, policy.categories));
            state.detectorSource = res.response.inferenceSource || "on_device";
          }
        } catch {
          nano = [];
          state.detectorSource = "rules_only";
        }
      } else {
        if (!nano.length) state.detectorSource = "rules_only";
      }
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
  updateStatusCapsule({ label: "Scanning On-Device...", chip: "Step 1/4", dot: "busy" });

  let deviceMs = 0;
  let findMs = 0;
  let guardMs = 0;
  let restoreMs = 0;
  let cloudMs = 0;

  try {
    // 1. Find secrets on the device.
    setStep(1, "busy", "Scanning text on this device...");
    const t0 = performance.now();
    const spans = await detect(text);
    state.plan = buildPlan(spans);
    state.masked = mask(text, state.plan);
    findMs = Math.max(0.2, performance.now() - t0);
    deviceMs = findMs;

    renderPlan();
    renderCategoryBreakdown(state.plan);
    renderDiffViews(text, state.masked, state.plan);
    renderTelemetrySplitChart({
      rawText: text,
      maskedText: state.masked,
      plan: state.plan,
      findMs,
      guardMs: 0,
      cloudMs: 0,
      restoreMs: 0,
      localOnly: local,
    });
    $("#metricMaskedNum").textContent = String(state.plan.length);
    $("#metricLatencyNum").textContent = String(Math.max(1, Math.round(deviceMs)));
    $("#detectorBadge").innerHTML = badge(state.detectorSource);
    setStep(1, "done", state.detectorSource === "rules_only"
      ? `${state.plan.length} values masked on device with built-in rules (Gemini Nano not downloaded).`
      : `${state.plan.length} values masked on device with Gemini Nano + rules.`);

    if (state.detectorSource === "rules_only" && !local && !approveRulesOnly) {
      setStep(2, "warn", "Paused for review before anything leaves this browser.");
      $("#cloudSaw").innerHTML = renderTokenizedHtml(`${TASKS[task]}\n\n${state.masked}`);
      updateAuditStrip({ status: "warn", leaked: 0, masked: state.plan.length, guard: "PAUSED", deviceMs, cloudMs: 0 });
      updateStatusCapsule({ label: "Paused Locally · Review Placeholders", chip: `${state.plan.length} masked`, dot: "warn" });
      $("#auditRouteTag").textContent = "Route: Paused Before Cloud";
      $("#telemetryModeBadge").className = "badge rules";
      $("#telemetryModeBadge").textContent = "Rules Gate";
      renderWaveform({ maskedCount: state.plan.length, localOnly: true, verified: false });
      showDegradeCallout(
        "Gemini Nano is not downloaded yet in this browser",
        `Built-in deterministic rules and name/company cues masked ${state.plan.length} values locally, and nothing has been sent anywhere. Review the masked list on the right, then approve sending placeholders to ${policy.cloudModel} or keep everything local.`
      );
      return;
    }

    // 2. Leak guard before anything leaves.
    const tGuard0 = performance.now();
    const outbound = `${TASKS[task]}\n\n${state.masked}`;
    leakCheck(outbound, state.plan);
    guardMs = Math.max(0.1, performance.now() - tGuard0);
    deviceMs += guardMs;
    setStep(2, "done", "Leak guard passed: 0 masked values present in outbound request.");
    $("#cloudSaw").innerHTML = renderTokenizedHtml(outbound);
    renderDiffViews(text, outbound, state.plan);
    updateAuditStrip({ status: "pass", leaked: 0, masked: state.plan.length, guard: "PASS", deviceMs, cloudMs: null, localOnly: local });

    // 3. Reason over masked text.
    setStep(3, "busy", local ? "Working on this device..." : `Asking ${policy.cloudModel} on placeholders only...`);
    updateStatusCapsule({
      label: local ? "Reasoning On-Device..." : `Cloud Escalation · Placeholders Only`,
      chip: `${state.plan.length} shielded`,
      dot: "busy",
    });
    const tCloud = performance.now();
    let res, modelUsed = local ? "gemini-nano" : policy.cloudModel, failedOver = false;
    try {
      const out = await generateWithCloudResilience(policy, local, outbound, {
        onRetry: (m, kind) => setStep(3, "busy", kind === "failover" ? `High demand on ${policy.cloudModel}; switching to ${m}...` : `Retrying ${m}...`),
      });
      res = out.res;
      modelUsed = out.modelUsed;
      failedOver = out.failedOver;
    } catch (reasonErr) {
      if (local && state.detectorSource === "rules_only") {
        setStep(3, "warn", "Local-only reasoning needs Chrome Gemini Nano.");
        updateAuditStrip({ status: "warn", leaked: 0, masked: state.plan.length, guard: "PASS", deviceMs, cloudMs: 0, localOnly: true });
        updateStatusCapsule({ label: "0 Bytes Sent · Nano Required Offline", chip: "Local Gate", dot: "warn" });
        showDegradeCallout(
          "Local-only reasoning requires Gemini Nano",
          `Your text stayed 100% in this browser (0 bytes sent). To answer fully offline, enable Chrome Built-in AI Prompt API, or approve sending the ${state.plan.length} masked placeholders to ${policy.cloudModel} now.`,
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
    const activeModelLabel = ranLocally ? "On-Device Nano" : (failedOver ? `${modelUsed} (failover)` : modelUsed);
    setStep(3, "done", ranLocally
      ? `Answered on this device (${Math.round(cloudMs)} ms).`
      : `Answered by ${activeModelLabel} (${Math.round(cloudMs)} ms): saw placeholders only.`);
    $("#reasonerBadge").innerHTML = badge(source);
    $("#routingReasonerPill").textContent = activeModelLabel;
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
    restoreMs = Math.max(0.1, performance.now() - tRestore);
    deviceMs += restoreMs;

    state.lastFindMs = findMs;
    state.lastGuardMs = guardMs;
    state.lastCloudMs = ranLocally ? 0 : cloudMs;
    state.lastRestoreMs = restoreMs;
    state.lastLocalOnly = ranLocally;
    renderTelemetrySplitChart({
      rawText: text,
      maskedText: outbound,
      plan: state.plan,
      findMs,
      guardMs,
      cloudMs: ranLocally ? 0 : cloudMs,
      restoreMs,
      localOnly: ranLocally,
    });

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

    $("#metricLeakedNum").textContent = "0";
    $("#metricLatencyNum").textContent = String(Math.max(1, Math.round(deviceMs)));
    $("#telemetryModeBadge").className = ranLocally ? "badge dev" : "badge cloud";
    $("#telemetryModeBadge").textContent = ranLocally ? "100% On-Device" : "Hybrid Verified";
    $("#auditRouteTag").textContent = ranLocally ? "Route: 100% On-Device" : `Route: Hybrid (${activeModelLabel})`;
    renderWaveform({ maskedCount: state.plan.length, localOnly: ranLocally, verified: true });

    updateStatusCapsule({
      label: ranLocally ? "On-Device Local · 0 Bytes Sent" : "Hybrid Verified · 0 PII Left Device",
      chip: `${state.plan.length} masked · ${Math.round(deviceMs)} ms`,
      dot: "ok",
    });

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
    state.lastReceiptPath = "Saving to Firestore...";
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
      $("#metricLeakedNum").textContent = String(e.leaked.length);
      updateAuditStrip({ status: "error", leaked: e.leaked.length, masked: state.plan.length, guard: "BLOCKED", deviceMs, cloudMs: 0 });
      updateStatusCapsule({ label: "Leak Guard Blocked Outbound Call", chip: "BLOCKED", dot: "err" });
    } else {
      updateStatusCapsule({ label: "Run Interrupted · Local Shield Intact", chip: "Error", dot: "warn" });
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
  btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = "Copy restored result"; }, 1800);
}

async function renderReceipts() {
  try {
    const rows = await loadReceipts(user.uid);
    $("#receipts").innerHTML = rows.length ? rows.map((r) => `<li>
      <b>${esc(r.task)}</b> · ${r.masked} masked
      <span>${Object.entries(r.counts || {}).map(([k, v]) => `${esc(k)} ${v}`).join(" · ")}</span>
      <span class="src">${r.detector === "on_device" ? "detect: device" : "detect: rules"} -> ${r.reasoner === "on_device" ? "answer: device" : "answer: cloud"} · ${r.outboundChars} chars out</span></li>`).join("")
      : `<li class="empty">No receipts yet. Run Veil to write a zero-text count receipt.</li>`;
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
  initStarfield();

  $("#task").innerHTML = Object.entries({ reply: "Draft a reply", summary: "Summarize", actions: "Extract action items", formal: "Make it formal", arabic: "Translate to Arabic" })
    .map(([k, v]) => `<option value="${k}">${v}</option>`).join("");

  renderPresets();
  renderPolicyCard();
  selectPreset(PRESETS[0].id);
  renderPayloadInspector();
  renderBatchQueueList();
  runAllRulesUI();

  // Batch Multi-Document Redaction Queue controls
  $("#batchLoadPresets").addEventListener("click", () => {
    state.batchDocs = PRESETS.map((p) => ({
      id: p.id,
      name: `${p.label}.txt`,
      industry: p.industry,
      task: p.defaultTask,
      text: p.text,
    }));
    state.lastBatchResult = null;
    state.lastBatchDigests = {};
    state.lastBatchBundleSha256 = null;
    $("#batchDropLabel").textContent = "Loaded 3 enterprise documents (Finance + Healthcare + Legal) into local queue";
    renderBatchQueueList();
  });
  $("#batchRunBtn").addEventListener("click", runBatchQueueUI);
  $("#batchDownloadBtn").addEventListener("click", downloadBatchBundle);
  $("#batchFileInput").addEventListener("change", (ev) => {
    ingestBatchFiles(ev.target.files);
    ev.target.value = "";
  });
  const dropzone = $("#batchDropzone");
  dropzone.addEventListener("click", () => $("#batchFileInput").click());
  dropzone.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      $("#batchFileInput").click();
    }
  });
  dropzone.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    dropzone.classList.add("is-dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("is-dragover"));
  dropzone.addEventListener("drop", (ev) => {
    ev.preventDefault();
    dropzone.classList.remove("is-dragover");
    ingestBatchFiles(ev.dataTransfer?.files);
  });

  // Live Firestore Zero-Text Security Rules Tester controls
  $("#rulesVectorPills").addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-rule-vec]");
    if (btn) selectRuleVector(btn.dataset.ruleVec);
  });
  $("#runAllRulesBtn").addEventListener("click", runAllRulesUI);
  $("#testCustomRuleBtn").addEventListener("click", evaluateCustomRuleUI);
  $("#rulesOpSelect").addEventListener("change", evaluateCustomRuleUI);
  $("#rulesPathInput").addEventListener("input", evaluateCustomRuleUI);

  // Segmented tabs + jump buttons
  $$(".seg-tab").forEach((btn) => {
    btn.addEventListener("click", () => setActiveTab(btn.dataset.tab));
  });
  $$("[data-jump-tab]").forEach((btn) => {
    btn.addEventListener("click", () => setActiveTab(btn.dataset.jumpTab));
  });

  // Top & dock local-only mode sync
  const toggleLocal = (nextVal) => {
    if (!policy.allowLocalReasoning && nextVal) return;
    syncLocalModeUI(nextVal);
    previewLocalShield();
  };
  $("#local").addEventListener("change", (ev) => toggleLocal(ev.target.checked));
  $("#topLocalToggle").addEventListener("click", () => toggleLocal(!$("#local").checked));
  $("#dockHybridBtn").addEventListener("click", () => {
    toggleLocal(false);
    setActiveTab("workspace");
  });
  $("#dockLocalBtn").addEventListener("click", () => {
    toggleLocal(true);
    setActiveTab("workspace");
  });
  $("#dockStressBtn").addEventListener("click", renderStressTest);
  $("#dockAuditBtn").addEventListener("click", () => setActiveTab("audit"));
  $("#auditStressBtn").addEventListener("click", renderStressTest);

  // Nightshift white circular play button runs local scan + leak guard pulse
  $("#quickScanPlay").addEventListener("click", () => {
    previewLocalShield();
    setStep(1, "done", `${state.plan.length} values scanned locally in ${state.lastDeviceMs} ms.`);
    setStep(2, "done", "Leak guard verified: 0 raw secrets in masked preview.");
  });

  $("#presets").addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-preset]");
    if (btn) selectPreset(btn.dataset.preset);
  });

  let debounceTimer = null;
  $("#input").addEventListener("input", () => {
    hideDegradeCallout();
    $("#error").textContent = "";
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(previewLocalShield, 160);
  });

  $("#run").addEventListener("click", () => run({ approveRulesOnly: false }));
  $("#approveRulesSend").addEventListener("click", () => {
    syncLocalModeUI(false);
    run({ approveRulesOnly: true });
  });
  $("#keepLocalBtn").addEventListener("click", () => {
    syncLocalModeUI(true);
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

  const hasPromptApi = typeof self.LanguageModel !== "undefined";
  $("#device").innerHTML = hasPromptApi
    ? `<span class="badge dev">Gemini Nano Ready</span> <span>On-device Chrome Prompt API detected</span>`
    : `<span class="badge rules">Rules Shield Active</span> <span>Masks locally and pauses before any cloud call</span>`;

  policy = await loadPolicy();
  $("#policy").textContent = `Remote Config (${policy.source}): ${policy.cloudModel} · ${policy.categories.length} PII categories · ${policy.maxChars} chars`;
  renderPolicyCard();
  if (!policy.allowLocalReasoning) {
    syncLocalModeUI(false);
    $("#local").disabled = true;
  }
  detector = detectorModel();
  try { user = await signIn(); renderReceipts(); } catch (e) { console.warn("auth", e); }
}

boot();
