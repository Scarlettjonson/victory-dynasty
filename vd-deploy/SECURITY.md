# Victory Dynasty — Free Security Guide

**Honest first:** no website is 100% hack-proof. This package removes the common, easy attacks using only free/open-source tools.
I wrote and syntax-checked the code and tested the database queries on real SQLite, but I could NOT run the backend with its npm packages or scan the live site here. Do the tests in section 5 yourself.

## 1. What I audited (your site code) — results
| Check | Result |
|---|---|
| API keys / passwords / secrets in frontend | None found. Secrets live only in the server `.env` |
| Inline `onclick=`, `eval`, `document.write`, `javascript:` links | None found (so a strict CSP is possible) |
| External scripts / fonts / trackers | None. Only your Facebook link (opens with `noopener noreferrer`) |
| Intro iframe | Already `sandbox="allow-scripts"`; the parent only accepts messages from that iframe |
| XSS risk | `innerHTML` was used for events text. **Fixed:** all text is now escaped (`esc()`). Chat uses `textContent` only |
| Fake "verified" badge + "private sample" wording | **Removed** (it could mislead visitors). Easy to undo if you disagree |
| Missing legal pages | **Added** Privacy / Terms / Responsible Play pop-ups (templates — see section 4) |
| 3.9 MB music inside the HTML | **Moved** to `assets/music.mp3` in `vd-deploy` (page loads faster) |
| Missing security headers | **Fixed:** ready-made `_headers` (CSP with script hashes, HSTS, nosniff, frame-ancestors none, etc.) |
| Referrer leak | **Fixed:** `referrer` policy added |

## 2. What I built
- **Chat frontend** (`vd-chat/`): validates backend URL (https only), honeypot bot-trap, no cookies, uses a server-signed guest token.
- **Backend** (`vd-backend/`, Node + SQLite, all free):
  - SQL injection: every query uses `?` placeholders. Strict length/format checks, control characters stripped, 4 KB body limit.
  - Guests get a **signed token**; knowing a Guest ID alone cannot read or write a chat.
  - Rate limits: new guest IDs 20/hour/IP, messages 30/10 min, admin login **5 tries/15 min**.
  - CORS: only your site can call the guest API.
  - **Photo/video uploads** (📎): real file-type check by content (not the file name), SVG/HTML/executables rejected, photos ≤ 8 MB / videos ≤ 30 MB, max 20 files per guest, random names, stored outside the website folder, only a logged-in admin can open them, deleted with the chat after the retention period. Photos from phones are shrunk before upload.
  - **Admin page** at `https://api.YOURDOMAIN.com/admin/` (reply to customers). Strict CSP, no inline code.
  - Admin: argon2id password hash, `HttpOnly + Secure + SameSite=Strict` cookie, **CSRF token + Origin check**, 2-hour sessions, logout.
  - Safe errors (no stack traces). Server listens on `127.0.0.1` only. Old chats auto-deleted after 150 days.
- **Site** (`vd-deploy/`): `index.html`, `assets/music.mp3`, `_headers`, `robots.txt`, `.well-known/security.txt`.

## 3. Setup, step by step (simple)
**A. Website (free): Cloudflare Pages or Netlify**
1. Make a free account. Create a new site and upload the folder `vd-deploy` (it contains `index.html` and `_headers`).
2. Connect your domain. Turn HTTPS on (automatic) and switch on "Always use HTTPS".
3. Open `_headers`, change `https://api.YOURDOMAIN.com` to your real API address.
4. Put your real email inside `.well-known/security.txt`. Fill every [BRACKET] in the Privacy/Terms/Responsible Play pop-ups (search `[LEGAL BUSINESS NAME]` in `index.html`).

**B. Backend (needs a small always-on computer)**
1. Install Node 20+. In `vd-backend`: `npm install`.
2. `cp .env.example .env`. Fill: `SITE_ORIGIN` (your website), `ADMIN_ORIGIN` (your API address, e.g. https://api.yourdomain.com), `SERVER_SECRET` (command is inside the file).
3. Make the admin password hash: `npm run hash -- "a long password phrase"` and paste the result into `.env` inside single quotes.
4. `npm start`. It listens only on this machine. Put nginx in front (`deploy/nginx.conf.example`) and get a free certificate: `sudo certbot --nginx`.
5. In the website, set `window.VD_CHAT_CONFIG.apiBase` to your API address (in `index.html`, search `apiBase:""`). Then redo step A3.
6. Firewall (free): `sudo ufw allow 22,80,443/tcp && sudo ufw enable`. SSH: keys only, no password login.

**C. Protect the admin account:** use a long unique password, store it in a free password manager (Bitwarden), and never reuse it.

## 4. What CANNOT be fully done for free (be aware)
- **A server to run the backend:** most free tiers sleep, have limits, or may change. Oracle Always Free works but needs a card for sign-up and can be reclaimed. A cheap VPS is the reliable choice.
- **Big DDoS attacks:** Cloudflare free helps with basic floods, but there is no guarantee.
- **Advanced bot/WAF rules, 24/7 monitoring, professional penetration test, backups with guarantees:** these are paid in practice. Free substitutes below are weaker.
- **A domain name** costs money.
- **Admin page is basic** (list, read, reply). No push notifications; it refreshes every 5 seconds. Extra free lock: allow only your own IP in nginx (example inside `nginx.conf.example`).
- **Legal/compliance:** my Privacy/Terms/Responsible Play texts are *templates with [BRACKETS]*, not legal advice. Rules for sweepstakes-style games and for payment processors differ by state and company — ask a lawyer. Also confirm you really accept each payment method shown (Stripe, PayPal, Apple Pay often forbid this kind of business).
- **Hosted on GitHub Pages?** It cannot set headers; the CSP and clickjacking protection would be weaker.

- **Uploads are NOT virus-scanned** (a free scanner like ClamAV can be added on the server). Video can use a lot of disk space: watch your disk, and lower `MAX_VID` if needed. Only open customer files on a device with an up-to-date antivirus.

## 5. Free tools to test (run these yourself)
Mozilla Observatory · securityheaders.com · SSL Labs · OWASP ZAP (scan your site and API) · `npm audit` · Semgrep (free) · Gitleaks (find leaked secrets) · Lighthouse in Chrome. Aim for A-grade headers and zero high-severity ZAP alerts.

## 6. Checklist
- [ ] HTTPS everywhere, HTTP redirects to HTTPS
- [ ] `_headers` uploaded; `YOURDOMAIN` replaced; Observatory shows A
- [ ] `.env` never in Git or on the website; `.gitignore` kept
- [ ] Strong admin password + `ADMIN_PASSWORD_HASH` set; 2FA on hosting, domain, email and GitHub accounts
- [ ] Backend only reachable through nginx; ports closed except 22/80/443; SSH keys only
- [ ] `npm audit` and updates monthly; OS updates automatic (`unattended-upgrades`)
- [ ] Back up `data/chat.db` weekly to a second place (encrypted)
- [ ] Legal pop-ups filled in and lawyer-checked; retention days set; payment logos match what you really accept
- [ ] ZAP scan done; rate limits tested (try 6 wrong admin logins → blocked)
- [ ] Never paste secrets into the website files or into chat tools

## 7. What I could not test here
No browser or npm network was available, so I could not open the pages, run the server with its packages, or scan the live site. I checked all script syntax, tested the database queries and the token logic with real code, and re-read the code for bugs (found and fixed: admin rate-limit counter reset, same-millisecond message skip, bad-JSON error code, and chat creating guest records for every visitor).

## 8. Free Cloudflare backend (new)
`vd-cloud/` replaces the Node server for testing: Worker + D1, no card. Guide: `vd-cloud/SETUP-FREE.md`. Keeps: signed guest tokens, rate limits, CORS allow-list, HttpOnly/Secure/SameSite=Strict admin cookie, CSRF token, forced password change, photo type check by content, strict CSP on the admin page. The Node server in `vd-backend/` is kept as the option for a full server later (it supports videos).
