# Veil

**Use cloud AI on text you can't share.** Gemini Nano finds the private values in your text on your device and swaps them for placeholders. Gemini in the cloud works on the placeholders. Veil puts the real values back locally. The cloud never sees the names, account numbers, amounts or keys.

Built for **#BuildHybridAI 2026** with **Firebase AI Logic hybrid inference** (Web / Chrome).

**Live app:** https://wenizmohamed.github.io/veil/

## The problem

People paste contracts, client emails, invoices and support tickets into AI chatbots every day. The cloud model is the one that writes the good reply, but the text is full of things that shouldn't leave the building: client names, IBANs, Emirates IDs, salaries, API keys. Today the choice is "don't use AI" or "leak it".

On-device models are private but small. Cloud models are capable but remote. Veil splits one task across both so each does the part it's suited for:

| Step | Where it runs | Firebase AI Logic mode | Why |
| --- | --- | --- | --- |
| 1. Find private values | Your browser, Gemini Nano | `InferenceMode.ONLY_ON_DEVICE` | Finding secrets means reading them. That must never be done in the cloud, so this step has **no cloud fallback**. |
| 2. Leak guard | Your browser, plain code | none | Before any request leaves, Veil checks the outgoing text contains none of the masked values, and blocks it if it does. |
| 3. Do the task | Gemini in the cloud | `InferenceMode.ONLY_IN_CLOUD` (or `ONLY_ON_DEVICE` when "Keep everything local" is on) | Drafting a reply or translating to Arabic is where the larger model is worth it. It only ever sees `[PERSON_1]`, `[ACCOUNT_1]`, `[MONEY_1]`. |
| 4. Restore | Your browser, plain code | none | Placeholders are swapped back for the real values. Placeholders the model made up are flagged, never guessed. |

The interesting part is that hybrid inference isn't used as a fallback switch. The **privacy boundary decides the routing**: the step that sees secrets is pinned to the device, and the step that needs capability goes to the cloud with the secrets already removed.

## Features

- **Three one-click industry presets**: `UAE Finance Wire` (IBAN, API key, AED transfer), `Healthcare Clinic Intake` (patient name, Emirates ID, MRN, physician, billing), and `Legal M&A NDA` (counterparties, USD/AED valuation, escrow IBAN, data room token, exclusivity dates).
- **Gemini Nano entity detection** with a JSON `responseConstraint` (people, organizations, emails, phones, addresses, IDs, accounts, amounts, secrets, dates). Spans the model invents or paraphrases are rejected: a value is only masked if it appears verbatim in the text.
- **Deterministic safety net**: built-in rules for emails, phone numbers, IBANs, Luhn-valid card numbers, Emirates ID, US SSN, medical/case IDs, amounts in AED/USD/EUR/GBP/SAR, dates, and API keys (Stripe, AWS, GitHub, JWT). Name cues (greetings, sign-offs, titles like Mr/Dr, labeled fields like Patient/Signatory, company suffixes like LLC, Medical Center, Logistics, Capital Partners) back up the model, because a small on-device model will sometimes miss a name, and masking too much is safer than leaking.
- **Visual privacy boundary proof**: live Privacy Audit Strip (`0 secrets leaked · X values masked · Leak Guard: PASS · On-device / Cloud latency`), color-coded token pills (`[PERSON_1]`, `[ACCOUNT_1]`, `[SECRET_1]`, etc.) across the masked table and cloud panes, subtle green "Restored locally" inline highlights in the final answer, and 1-click **Copy restored result**.
- **Smooth honest degradation**: if Gemini Nano isn't downloaded yet in the browser, Veil masks locally with deterministic rules and pauses with a calm amber callout offering **Approve Rules-Only Mask & Send to Cloud** alongside **Keep everything local**.
- **"What the cloud saw" panel**: the exact outgoing request with color-coded tokens, so you can verify nothing private left.
- **Inference badges** on every step from the SDK's `inferenceSource` (on device vs in cloud).
- **Tasks**: draft a reply, summarize, extract action items, make it formal, translate to Arabic.
- **Privacy receipts & Firestore payload inspector**: per run, counts per category and where each step ran — never text, never values (enforced by `firestore.rules`). Toggle **Verify Firestore zero-text payload** in the UI to inspect the exact JSON document written to Firestore.

## Firebase products used

| Product | How Veil uses it | Code |
| --- | --- | --- |
| **Firebase AI Logic** (Gemini Developer API) | Hybrid inference: `getGenerativeModel` with `ONLY_ON_DEVICE` for detection (Gemini Nano, `onDeviceParams.promptOptions.responseConstraint`) and `ONLY_IN_CLOUD` for the task, `initializeDeviceModel()` with download progress, `inferenceSource` badges | [`src/firebase.js`](src/firebase.js), [`src/main.js`](src/main.js) |
| **App Check** (reCAPTCHA Enterprise / Fraud Defense) | Required by AI Logic; protects the Gemini API from abuse | [`src/firebase.js`](src/firebase.js) |
| **Authentication** (anonymous) | Each browser gets its own receipts, no sign-up | [`src/firebase.js`](src/firebase.js) |
| **Remote Config** | Live policy: cloud model name, which categories to mask, max input size, whether local-only answering is allowed | [`src/firebase.js`](src/firebase.js), [`remoteconfig.template.json`](remoteconfig.template.json) |
| **Cloud Firestore** | Privacy receipts, with rules that reject any field other than counts and sources | [`firestore.rules`](firestore.rules) |

## Run it

Requirements: Node 18+, and Chrome with the built-in Prompt API (Gemini Nano) for the on-device step. See [Chrome's built-in AI docs](https://developer.chrome.com/docs/ai/get-started) for enabling it. Without Nano, Veil still runs in rules-only mode.

```bash
git clone https://github.com/wenizmohamed/veil && cd veil
npm install
npm test          # masking, leak guard and restore tests
npm run dev       # http://localhost:5173
```

On `localhost` the app uses an App Check **debug token**: the browser console prints it on first load; register it under Firebase console > App Check > Apps > Manage debug tokens.

### Use your own Firebase project

1. Create a Firebase project, add a Web app, and open **AI Logic > Get started > Gemini Developer API**.
2. Create a reCAPTCHA Enterprise (Fraud Defense) key for your domain and register it in **App Check** for the web app.
3. Enable **Authentication > Anonymous**, create a **Firestore** database and paste in [`firestore.rules`](firestore.rules).
4. Optional: import [`remoteconfig.template.json`](remoteconfig.template.json) in **Remote Config**.
5. Put your web config and reCAPTCHA site key in [`src/firebase-config.js`](src/firebase-config.js). These identify the project and are not secrets; access is protected by App Check and the security rules.

`npm run build` writes the static site to `docs/`, which GitHub Pages serves.

## Project layout

```
src/veil-core.js      masking plan, mask, leak guard, unmask, Nano prompt + schema (pure, tested)
src/firebase.js       AI Logic hybrid models, App Check, Auth, Remote Config, Firestore
src/main.js           the four-step flow and UI
tests/                vitest suite for the privacy core
firestore.rules       receipts: counts and sources only
docs/                 built site for GitHub Pages
```

## Limits

- Detection quality depends on Gemini Nano. The rules catch structured values; free-text names need the model, which is why Veil pauses instead of sending when the model is missing.
- Masking hides values, not context. "Our CEO's divorce settlement" is still meaningful with names removed. Veil protects identifiers, not topics.
- Placeholders cost the cloud model some fluency (it can't, for example, inflect a name). That's the trade.

## Built during the contest

Everything in this repository was written during the #BuildHybridAI 2026 submission period (started November 17, 2026). It was built with significant help from Claude (Anthropic) as a coding agent. No pre-existing project code is included; third-party code is limited to the Firebase JS SDK, Vite and Vitest.

## License

Apache-2.0
