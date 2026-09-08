// Service worker (MV3). Orchestrates: Google OAuth -> paginate through the whole
// inbox via the Gmail API -> upload each raw message to the existing backend
// pipeline (POST /api/cases/upload, unchanged except for one new optional
// source_url field) -> read back the classification -> apply a matching colored
// Gmail label. On-demand only (triggered from the popup), no background polling/
// push — see extension/README.md for why.
//
// Progress is written to chrome.storage.local after every message (not just at the
// end) for two reasons: the popup can show live "scanned X/Y" while open or after
// being reopened mid-scan, and — since a 200-message scan can run for several
// minutes and Chrome can terminate an idle MV3 service worker — a scan that gets
// cut off resumes cleanly next click: already-scanned IDs are skipped, nothing is
// lost, nothing is double-counted.

const BACKEND_BASE_URL = "http://localhost:8000";
// Safety cap, not a Gmail API limit — a genuinely unbounded scan risks a very long
// run against Gmail's rate limits and a full backend pipeline call (WHOIS/DNS/
// ip-api/AI) per message. 200 covers a full inbox for most accounts; raise it here
// if you need more.
const MAX_MESSAGES_PER_SCAN = 200;
const PAGE_SIZE = 50;
const SCANNED_IDS_KEY = "scannedMessageIds";
const LABEL_IDS_KEY = "labelIds";
const SCAN_PROGRESS_KEY = "scanProgress";
const RECENT_SCANS_KEY = "recentScans";
const RECENT_SCANS_LIMIT = 30; // popup shows the first 5; kept longer in storage in case that changes

// Hex values confirmed against the Gmail API's actual allowed label-color palette.
const LABEL_DEFINITIONS = {
  legitimate: { name: "Shield: Legitimate", backgroundColor: "#16a766", textColor: "#ffffff" },
  suspicious: { name: "Shield: Suspicious", backgroundColor: "#fad165", textColor: "#000000" },
  impersonated: { name: "Shield: Impersonated", backgroundColor: "#ffad47", textColor: "#000000" },
  phishing: { name: "Shield: Phishing", backgroundColor: "#ff7537", textColor: "#ffffff" },
  fraud: { name: "Shield: Fraud", backgroundColor: "#cc3a21", textColor: "#ffffff" },
};

// ---------- OAuth ----------

function getAuthToken(interactive) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(new Error(chrome.runtime.lastError?.message || "No token returned"));
        return;
      }
      resolve(token);
    });
  });
}

async function revokeAuthToken() {
  const token = await getAuthToken(false).catch(() => null);
  if (!token) return;
  await fetch(`https://accounts.google.com/o/oauth2/revoke?token=${token}`).catch(() => {});
  await new Promise((resolve) => chrome.identity.removeCachedAuthToken({ token }, resolve));
}

// ---------- Gmail API ----------

async function gmailFetch(path, token, options = {}) {
  const response = await fetch(`https://www.googleapis.com/gmail/v1/users/me${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, ...(options.headers || {}) },
  });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`Gmail API ${path} failed: ${response.status} ${body}`);
  }
  return response.json();
}

async function listAllInboxMessageIds(token, maxTotal) {
  const ids = [];
  let pageToken;
  do {
    const query = new URLSearchParams({ labelIds: "INBOX", maxResults: String(PAGE_SIZE) });
    if (pageToken) query.set("pageToken", pageToken);
    const data = await gmailFetch(`/messages?${query.toString()}`, token);
    ids.push(...(data.messages || []).map((m) => m.id));
    pageToken = data.nextPageToken;
  } while (pageToken && ids.length < maxTotal);
  return ids.slice(0, maxTotal);
}

async function getRawMessage(messageId, token) {
  const data = await gmailFetch(`/messages/${messageId}?format=raw`, token);
  return data.raw; // base64url-encoded full RFC822 message
}

function base64UrlToBytes(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function gmailMessageUrl(messageId) {
  return `https://mail.google.com/mail/u/0/#inbox/${messageId}`;
}

// ---------- Label management ----------

async function ensureLabels(token) {
  const stored = await chrome.storage.local.get(LABEL_IDS_KEY);
  const labelIds = { ...(stored[LABEL_IDS_KEY] || {}) };

  const existing = await gmailFetch("/labels", token);
  const byName = new Map((existing.labels || []).map((l) => [l.name, l.id]));

  for (const [key, def] of Object.entries(LABEL_DEFINITIONS)) {
    if (byName.has(def.name)) {
      labelIds[key] = byName.get(def.name);
      continue;
    }
    try {
      const created = await gmailFetch("/labels", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: def.name,
          labelListVisibility: "labelShow",
          messageListVisibility: "show",
          color: { backgroundColor: def.backgroundColor, textColor: def.textColor },
        }),
      });
      labelIds[key] = created.id;
    } catch (err) {
      // Defensive fallback: if a color pairing gets rejected for this account,
      // retry uncolored so labeling still works rather than failing the whole scan.
      console.warn("Label color rejected, retrying uncolored:", err);
      const created = await gmailFetch("/labels", token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: def.name, labelListVisibility: "labelShow", messageListVisibility: "show" }),
      });
      labelIds[key] = created.id;
    }
  }

  await chrome.storage.local.set({ [LABEL_IDS_KEY]: labelIds });
  return labelIds;
}

async function applyLabel(messageId, labelId, token) {
  await gmailFetch(`/messages/${messageId}/modify`, token, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ addLabelIds: [labelId] }),
  });
}

// ---------- Backend (existing pipeline, unmodified aside from source_url) ----------

async function uploadToBackend(messageId, rawBytes, sourceUrl) {
  const blob = new Blob([rawBytes], { type: "message/rfc822" });
  const formData = new FormData();
  formData.append("file", blob, `gmail_${messageId}.eml`);
  formData.append("source_url", sourceUrl);

  const response = await fetch(`${BACKEND_BASE_URL}/api/cases/upload`, { method: "POST", body: formData });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`Backend upload failed: ${response.status} ${body}`);
  }
  return response.json(); // { case_id, email_analysis_id, status }
}

async function getCaseDetail(caseId) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/cases/${caseId}`);
  if (!response.ok) throw new Error(`Backend case fetch failed: ${response.status}`);
  return response.json();
}

// ---------- Orchestration ----------

async function scanInbox() {
  const token = await getAuthToken(true);
  const labelIds = await ensureLabels(token);

  const stored = await chrome.storage.local.get(SCANNED_IDS_KEY);
  const scannedIds = new Set(stored[SCANNED_IDS_KEY] || []);

  const messageIds = await listAllInboxMessageIds(token, MAX_MESSAGES_PER_SCAN);
  const toScan = messageIds.filter((id) => !scannedIds.has(id));

  const results = { scanned: 0, skipped: messageIds.length - toScan.length, byLabel: {}, errors: 0 };
  await chrome.storage.local.set({ scanInProgress: true, [SCAN_PROGRESS_KEY]: { done: 0, total: toScan.length } });

  const recentStored = await chrome.storage.local.get(RECENT_SCANS_KEY);
  let recentScans = recentStored[RECENT_SCANS_KEY] || [];

  for (const [index, messageId] of toScan.entries()) {
    try {
      const raw = await getRawMessage(messageId, token);
      const rawBytes = base64UrlToBytes(raw);
      const sourceUrl = gmailMessageUrl(messageId);
      const upload = await uploadToBackend(messageId, rawBytes, sourceUrl);
      const caseDetail = await getCaseDetail(upload.case_id);
      const email = caseDetail.email_analyses[0];
      const detection = email?.detection_result;
      const label = detection?.classification_label || "suspicious";

      if (labelIds[label]) {
        await applyLabel(messageId, labelIds[label], token);
      }

      scannedIds.add(messageId);
      results.scanned += 1;
      results.byLabel[label] = (results.byLabel[label] || 0) + 1;

      recentScans = [
        {
          caseId: upload.case_id,
          subject: email?.subject || "(no subject)",
          fromAddress: email?.from_address || "",
          classificationLabel: label,
          fraudScore: detection?.fraud_score ?? null,
          sourceUrl,
          scannedAt: new Date().toISOString(),
        },
        ...recentScans,
      ].slice(0, RECENT_SCANS_LIMIT);
    } catch (err) {
      console.error(`Failed to scan message ${messageId}:`, err);
      results.errors += 1;
    }

    // Persisted every iteration (not batched) so a reopened popup or an
    // interrupted scan reflects real progress, not stale/zero state.
    await chrome.storage.local.set({
      [SCANNED_IDS_KEY]: Array.from(scannedIds),
      [SCAN_PROGRESS_KEY]: { done: index + 1, total: toScan.length },
      [RECENT_SCANS_KEY]: recentScans,
    });
  }

  await chrome.storage.local.set({
    scanInProgress: false,
    lastScanAt: new Date().toISOString(),
    lastScanResults: results,
  });

  return results;
}

// ---------- Popup <-> background messaging ----------

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "SCAN_INBOX") {
    scanInbox()
      .then((results) => sendResponse({ ok: true, results }))
      .catch(async (err) => {
        await chrome.storage.local.set({ scanInProgress: false });
        sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
      });
    return true; // keep the message channel open for the async response
  }
  if (message.type === "SIGN_OUT") {
    revokeAuthToken()
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }
});
