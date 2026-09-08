# Email Threat Shield — Gmail inbox scanner

A Chrome extension that scans your Gmail inbox and labels risky emails by threat
level, using the exact same detection pipeline as the web dashboard — it just
fetches each email via the Gmail API instead of you uploading a `.eml` file by
hand, and shows the result as a colored Gmail label instead of a case-detail page.

**Nothing new runs on the backend.** Each scanned email is POSTed to the existing
`POST /api/cases/upload` endpoint exactly like a manual upload — so every scanned
email also shows up on the web dashboard (`localhost:5173`) as its own case, with
the full signal breakdown, intelligence, and PDF report available for it.

## What this needs from you (I can't do this part — it's your Google account)

Do these once, in order:

### 1. Load the extension and get its ID

1. Open `chrome://extensions` in Chrome.
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked**, and select this `extension/` folder.
4. It'll appear as "Email Threat Shield — SIH26106." Copy the **ID** shown under
   its name (a long string of lowercase letters, e.g. `abcdefghijklmnop...`).

This ID is stable across reloads as long as you don't move this folder — you're
getting it now so you can create matching OAuth credentials next.

### 2. Create a Google Cloud OAuth client

1. Go to [console.cloud.google.com](https://console.cloud.google.com) and create a
   new project (any name, e.g. "SIH26106 Email Shield").
2. **APIs & Services → Library** → search **Gmail API** → **Enable**.
3. **APIs & Services → OAuth consent screen**:
   - User type: **External**
   - App name / support email: anything reasonable
   - Scopes: add `https://www.googleapis.com/auth/gmail.modify`
   - **Test users**: add your own Gmail address (and your teammates', if they'll
     run this too) — this keeps the app in **Testing** mode, which skips Google's
     full app-verification review entirely. Fine for a hackathon demo; you'd only
     need verification to publish this for the general public.
4. **APIs & Services → Credentials → Create Credentials → OAuth client ID**:
   - Application type: **Chrome Extension**
   - Item ID: paste the extension ID from step 1
5. Copy the generated **Client ID** (ends in `.apps.googleusercontent.com`).

### 3. Wire the client ID in and reload

1. Open `extension/manifest.json`, replace `PASTE_YOUR_OAUTH_CLIENT_ID_HERE...`
   in the `oauth2.client_id` field with the client ID from step 2.
2. Back on `chrome://extensions`, click the **reload** icon on the extension card.

### 4. Allow the extension to talk to your backend

Add the extension's origin to `backend/.env`'s `CORS_ORIGINS`, comma-separated:

```
CORS_ORIGINS=http://localhost:5173,chrome-extension://<your-extension-id>
```

Restart the backend (`uvicorn --reload` picks this up automatically on save).

### 5. Run it

1. Make sure the backend (`localhost:8000`) is running — the extension calls it
   directly, so it must be up for scanning to work.
2. Click the extension icon → **Sign in with Google** → approve the consent screen
   (it'll show an "unverified app" warning since this is in Testing mode — click
   **Advanced → Go to \[app name\] (unsafe)**, this is expected for a dev/test OAuth
   client, not a red flag).
3. Click **Scan Inbox**. It checks your 15 most recent inbox emails, skips any it's
   already scanned, and applies a colored `Shield: ...` label to each.
4. Check your actual Gmail inbox — labels should appear next to the scanned rows.
5. Cross-check one on the dashboard (`localhost:5173`) — the case list will show it
   with the same classification.

## How it works

```
popup "Scan Inbox" click
  -> background.js gets a Google OAuth token (chrome.identity)
  -> paginates through your inbox, up to 200 messages (Gmail API, nextPageToken)
  -> for each one not already scanned:
       - fetches the full raw RFC822 message (Gmail API, format=raw)
       - POSTs it to POST /api/cases/upload along with a source_url pointing back
         at the real Gmail message — the *same* backend endpoint the web
         dashboard's upload page uses, plus that one new optional field
       - reads back the classification from GET /api/cases/{id}
       - applies a matching colored Gmail label (creating the 5 labels once,
         first run)
  -> writes progress to chrome.storage.local after every message — the popup
     shows it live, and a scan that gets interrupted resumes cleanly (already-
     scanned IDs are skipped, nothing is lost or double-counted)
```

The web dashboard's **Critical Threats** section lists every scanned email that
came back ≥90% risk; clicking one opens the real Gmail message directly via that
stored `source_url`.

## Scope of this pass

- **Gmail only** — not Outlook/other providers.
- **On-demand, capped at 200 messages per scan** — a genuine full-inbox scan for
  most accounts, but not literally unbounded: each message triggers the full
  backend pipeline (WHOIS/DNS/ip-api/AI), so a truly unlimited scan risks a very
  long run against Gmail's own rate limits. Change `MAX_MESSAGES_PER_SCAN` at the
  top of `background.js` if you want more; click "Scan Inbox" again afterward to
  pick up where the cap left off, since already-scanned messages are skipped.
- **Not real-time** — nothing runs automatically in the background or on a
  schedule. Real-time scanning-as-mail-arrives would need a Google Cloud Pub/Sub
  push subscription with a publicly reachable webhook — meaningfully more
  infrastructure, out of scope here.
- **Local backend only** — the extension is hardcoded to `http://localhost:8000`.
  If you deploy the backend somewhere public, update `BACKEND_BASE_URL` at the top
  of `background.js`.
