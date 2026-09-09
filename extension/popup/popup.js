const LABEL_COLORS = {
  legitimate: "#34d399",
  suspicious: "#fbbf24",
  impersonated: "#fb923c",
  phishing: "#fb923c",
  fraud: "#f87171",
};

const LABEL_TITLES = {
  legitimate: "Legitimate",
  suspicious: "Suspicious",
  impersonated: "Impersonated",
  phishing: "Phishing",
  fraud: "Fraud",
};

const signedOutView = document.getElementById("signedOutView");
const signedInView = document.getElementById("signedInView");
const signInBtn = document.getElementById("signInBtn");
const scanBtn = document.getElementById("scanBtn");
const signOutBtn = document.getElementById("signOutBtn");
const progressEl = document.getElementById("progress");
const progressTextEl = document.getElementById("progressText");
const progressBarEl = document.getElementById("progressBar");
const summaryEl = document.getElementById("summary");
const summaryLineEl = document.getElementById("summaryLine");
const breakdownEl = document.getElementById("breakdown");
const errorLineEl = document.getElementById("errorLine");
const errorBannerEl = document.getElementById("errorBanner");
const recentScansEl = document.getElementById("recentScans");
const recentScansListEl = document.getElementById("recentScansList");

function showSignedIn() {
  signedOutView.classList.add("hidden");
  signedInView.classList.remove("hidden");
}

function showSignedOut() {
  signedInView.classList.add("hidden");
  signedOutView.classList.remove("hidden");
}

function renderProgress(scanProgress) {
  const { done = 0, total = 0 } = scanProgress || {};
  progressEl.classList.remove("hidden");
  progressTextEl.textContent = total > 0 ? `Scanning ${done} / ${total}…` : "Scanning…";
  progressBarEl.style.width = total > 0 ? `${Math.min(100, (done / total) * 100)}%` : "5%";
}

function renderSummary(results) {
  summaryEl.classList.remove("hidden");
  const skippedNote = results.skipped ? `, ${results.skipped} already scanned` : "";
  summaryLineEl.textContent = `Scanned ${results.scanned} new email(s)${skippedNote}.`;

  breakdownEl.innerHTML = "";
  for (const [label, count] of Object.entries(results.byLabel || {})) {
    const row = document.createElement("div");
    row.className = "breakdown-row";

    const dot = document.createElement("span");
    dot.className = "dot";
    dot.style.background = LABEL_COLORS[label] || "#71717a";
    row.appendChild(dot);

    const text = document.createElement("span");
    text.textContent = `${LABEL_TITLES[label] || label}: ${count}`;
    row.appendChild(text);

    breakdownEl.appendChild(row);
  }

  if (results.errors > 0) {
    errorLineEl.textContent = `${results.errors} email(s) failed to analyze — see the extension's service worker console for details.`;
    errorLineEl.classList.remove("hidden");
  } else {
    errorLineEl.classList.add("hidden");
  }
}

function showError(message) {
  errorBannerEl.textContent = message;
  errorBannerEl.classList.remove("hidden");
}

function renderRecentScans(scans) {
  if (!scans || scans.length === 0) {
    recentScansEl.classList.add("hidden");
    return;
  }
  recentScansEl.classList.remove("hidden");
  recentScansListEl.innerHTML = "";

  for (const scan of scans.slice(0, 5)) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "recent-scan-row";
    row.title = scan.subject;
    row.addEventListener("click", () => {
      const url = scan.sourceUrl || `http://localhost:5173/cases/${scan.caseId}`;
      chrome.tabs.create({ url });
    });

    const subject = document.createElement("span");
    subject.className = "recent-scan-subject";
    subject.textContent = scan.subject;
    row.appendChild(subject);

    const score = document.createElement("span");
    score.className = "recent-scan-score";
    const color = LABEL_COLORS[scan.classificationLabel] || "#71717a";
    score.style.color = color;
    score.style.background = `${color}1a`;
    score.textContent = scan.fraudScore !== null ? `${scan.fraudScore}` : "—";
    row.appendChild(score);

    recentScansListEl.appendChild(row);
  }
}

async function loadLastScan() {
  const stored = await chrome.storage.local.get([
    "lastScanResults",
    "scanInProgress",
    "scanProgress",
    "recentScans",
  ]);
  if (stored.scanInProgress) {
    scanBtn.disabled = true;
    summaryEl.classList.add("hidden");
    renderProgress(stored.scanProgress);
  } else if (stored.lastScanResults) {
    renderSummary(stored.lastScanResults);
  }
  renderRecentScans(stored.recentScans);
}

function checkSignInState() {
  chrome.identity.getAuthToken({ interactive: false }, (token) => {
    if (chrome.runtime.lastError || !token) {
      showSignedOut();
    } else {
      showSignedIn();
      loadLastScan();
    }
  });
}

// Live progress while this popup is open, and correct state if it's reopened
// mid-scan — the background service worker is the source of truth in storage.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.scanProgress && !signedInView.classList.contains("hidden")) {
    renderProgress(changes.scanProgress.newValue);
  }
  if (changes.scanInProgress && changes.scanInProgress.newValue === false) {
    progressEl.classList.add("hidden");
    scanBtn.disabled = false;
  }
});

signInBtn.addEventListener("click", () => {
  signInBtn.disabled = true;
  signInBtn.textContent = "Signing in…";
  chrome.identity.getAuthToken({ interactive: true }, (token) => {
    signInBtn.disabled = false;
    signInBtn.textContent = "Sign in with Google";
    if (chrome.runtime.lastError || !token) {
      showError(chrome.runtime.lastError?.message || "Sign-in failed.");
      return;
    }
    showSignedIn();
  });
});

scanBtn.addEventListener("click", () => {
  scanBtn.disabled = true;
  summaryEl.classList.add("hidden");
  errorBannerEl.classList.add("hidden");
  renderProgress({ done: 0, total: 0 });

  chrome.runtime.sendMessage({ type: "SCAN_INBOX" }, (response) => {
    progressEl.classList.add("hidden");
    scanBtn.disabled = false;

    if (!response) {
      showError("No response from the background worker — try again.");
      return;
    }
    if (!response.ok) {
      showError(response.error || "Scan failed. Is the backend running at localhost:8000?");
      return;
    }
    renderSummary(response.results);
    chrome.storage.local.get("recentScans", (stored) => renderRecentScans(stored.recentScans));
  });
});

signOutBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "SIGN_OUT" }, () => {
    showSignedOut();
  });
});

// Intercept any anchor clicks inside the popup (both "Open Dashboard" links
// included) and open them via chrome.tabs.create instead of a plain
// target="_blank" navigation, which silently no-ops from an MV3 popup.
document.addEventListener("click", (e) => {
  const anchor = e.target.closest("a");
  if (anchor && anchor.href && (anchor.href.startsWith("http://") || anchor.href.startsWith("https://"))) {
    e.preventDefault();
    chrome.tabs.create({ url: anchor.href });
  }
});

checkSignInState();

