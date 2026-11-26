const MENU_ID = "veil-mask-selection";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus?.create({
    id: MENU_ID,
    title: "Mask & Ask Veil (On-Device First)",
    contexts: ["selection"],
  });
  chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {});
});

chrome.contextMenus?.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID) return;
  const text = (info.selectionText || "").trim();
  if (text) {
    await chrome.storage.local.set({ veilPendingText: text, veilCapturedAt: Date.now() });
  }
  if (tab?.id && chrome.sidePanel?.open) {
    await chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
  }
});
