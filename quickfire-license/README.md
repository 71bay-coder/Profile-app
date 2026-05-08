# Quickfire License Server

A lightweight Node.js server that manages license keys for the Quickfire app.
SQLite database — no external dependencies, runs anywhere Node runs.

---

## Quick start (local testing)

```bash
cd server
npm install
node index.js
```

Server runs at `http://localhost:3000`
Admin dashboard at `http://localhost:3000/admin-ui`

---

## Environment variables

| Variable        | Default                          | Description                          |
|-----------------|----------------------------------|--------------------------------------|
| `PORT`          | `3000`                           | Port to listen on                    |
| `ADMIN_SECRET`  | `CHANGE_THIS_SECRET_BEFORE_DEPLOY` | Password for all admin API routes  |
| `DB_PATH`       | `./licenses.db`                  | Path to SQLite database file         |

**Set ADMIN_SECRET before deploying.** This is your personal password for the admin dashboard and API.

---

## Free deployment (Railway)

Railway gives you a free persistent Node.js server — perfect for this.

1. Create a free account at [railway.app](https://railway.app)
2. New Project → Deploy from GitHub repo (push this folder to a private GitHub repo first)
   OR use the Railway CLI:
   ```bash
   npm install -g @railway/cli
   railway login
   railway init
   railway up
   ```
3. In Railway dashboard → Variables → add:
   - `ADMIN_SECRET` = your secret password (make it long and random)
   - `PORT` = `3000`
4. Railway gives you a public URL like `https://quickfire-license-production.up.railway.app`
5. **Update the Quickfire app**: in `src/engine/licenseClient.js` change `SERVER_URL` to your Railway URL

---

## Free deployment (Render)

1. Create account at [render.com](https://render.com)
2. New → Web Service → connect your GitHub repo
3. Build command: `npm install`
4. Start command: `node index.js`
5. Add environment variables: `ADMIN_SECRET`, `PORT=10000`
6. Note: Render free tier spins down after inactivity — Railway is better for always-on

---

## Admin dashboard

Open `http://your-server-url/admin-ui` in your browser.

Enter your `ADMIN_SECRET` in the field at the top right and click **Load**.

### Generating keys
- Set count (1-100 at a time)
- Optional label (e.g. "Discord giveaway batch 1")
- Optional internal note
- Click Generate — keys appear instantly, click copy icon to copy each one

### Managing keys
- **Revoke** — user loses access immediately on next app launch (or next online check)
- **Restore** — re-enables a revoked key
- **Delete** — permanently removes key and all its events
- **Export CSV** — download all keys as a spreadsheet

### Events log
Every activation, validation, revocation, and failed attempt is logged with timestamp, key, device ID, and IP address.

---

## How the license system works

```
App launch
    │
    ▼
Read stored key + offline token from disk
    │
    ├─── Try online validation (5s timeout)
    │         │
    │         ├── Server OK + valid  → refresh offline token → allow
    │         ├── Server OK + revoked → clear offline token → block
    │         └── Server unreachable ──┐
    │                                  │
    └─────────────────────────── Offline fallback
                                       │
                                       ├── Offline token exists + valid → allow (offline mode)
                                       └── No token or invalid → block
```

**Key binding**: When a key is first activated, the device's hardware ID (SHA-256 hash of CPU model + hostname + MAC address) is stored on the server. That key can never be activated on a different device.

**Offline fallback**: After a successful online validation, an HMAC-SHA256 token is stored locally. If the server is unreachable, this token proves the device was previously authorized. Revoking a key clears the server record — the next time the app goes online, the revocation takes effect.

---

## API reference

All admin routes require the header `X-Admin-Secret: <your secret>`.

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/activate` | Activate a key on a device |
| `POST` | `/validate` | Validate a key+hwid combo |
| `POST` | `/admin/generate` | Generate new keys |
| `POST` | `/admin/revoke` | Revoke a key |
| `POST` | `/admin/unrevoke` | Restore a revoked key |
| `POST` | `/admin/delete` | Permanently delete a key |
| `GET`  | `/admin/keys` | List all keys + events |
| `GET`  | `/health` | Server health check |
