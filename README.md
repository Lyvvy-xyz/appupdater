# AppUpdater

![Version](https://img.shields.io/badge/version-50.9.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-informational?logo=windows)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Intune](https://img.shields.io/badge/Microsoft-Intune-0078d4?logo=microsoft&logoColor=white)
![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)
![License](https://img.shields.io/badge/license-Private-red)

> **WPF-based PowerShell tool for generating Microsoft Intune Win32 packages** — with an optional Cloudflare Worker backend for centralized manifest hosting, authentication, device telemetry, and a live status dashboard.

---

## ✨ Features

- 🖥️ **Dark-theme WPF GUI** — keyboard-navigable interface with styled dialogs, pickers, and wizards
- 📦 **Auto-generated artifacts** — produces `.intunewin` packages, registry-based detection scripts, and deploy scripts per app
- ☁️ **Cloudflare Worker backend** — optional cloud mode with manifest hosting, web dashboard, and device telemetry
- 🔐 **TOTP MFA** — time-based one-time password enrollment with QR-code flow
- 🔑 **Windows Credential Manager** — bearer tokens stored via DPAPI, never on disk in plaintext
- 🔒 **HMAC-signed sessions** — tamper-resistant cookies with 24 h TTL and rate-limited login
- 🛡️ **Authenticode binary verification** — downloaded executables checked for valid Microsoft signatures before use
- 📡 **Per-app event telemetry** — device-side events sent to Worker with HMAC secrets and rate limiting
- 🔄 **Offline mode** — full package generation without any cloud dependency
- 🧙 **First-run wizard** — guided Cloudflare setup or offline fallback on first launch

---

## 🔀 Operating Modes

|  | ☁️ Cloudflare-Connected | 💾 Offline |
|---|---|---|
| **Manifest hosting** | Cloudflare KV (`APP_MANIFEST` namespace) | Local `appVersions.xml` |
| **Authentication** | TOTP + PBKDF2-SHA256 session | N/A |
| **Device telemetry** | Per-device event log via `/event` | None |
| **Web dashboard** | `/status` page on Worker subdomain | None |
| **Token storage** | Windows Credential Manager (machine scope) | N/A |
| **Setup required** | Cloudflare API token + account | None |
| **Launch flag** | *(default)* | `-Offline` switch |

---

## 🖥️ Requirements

| Requirement | Detail |
|---|---|
| **OS** | Windows 10 / Windows 11 |
| **PowerShell** | 5.1 or later |
| **IntuneWinAppUtil.exe** | Place in the same directory as the script, or add to `$env:PATH`. [Download ↗](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool) |
| **Cloudflare account** | Optional — required for cloud-connected mode only |
| **Admin rights** | Required for ACL enforcement and Credential Manager access |

---

## 🚀 Quick Start

```powershell
# Cloud-connected mode (default)
.\AppUpdaterV509.ps1

# Offline mode — no Cloudflare required
.\AppUpdaterV509.ps1 -Offline
```

On first launch a setup wizard runs automatically:

1. **Choose mode** — Cloudflare-connected or Offline
2. **If Cloudflare:** Enter your API token and organization name → the script deploys the Worker and configures KV
3. **Set dashboard password** (≥ 12 chars, ≥ 1 letter + ≥ 1 digit)
4. **Optionally enroll TOTP** for two-factor login to the web dashboard

---

## 🗂️ GUI Overview

The main menu is keyboard-driven. Press the number key or click a button:

| Key | Button | Action |
|---|---|---|
| `1` / `D1` | 🟢 **Build app package** | Downloads installer → inspects it → generates `.intunewin` + detect/deploy scripts |
| `2` / `D2` | **Open Output folder** | Opens `C:\ProgramData\AppUpdater\_output\` in Explorer |
| `3` / `D3` | **Open status page** *or* **Connect to Cloudflare** | Opens the Worker dashboard in browser, or launches the Cloudflare setup wizard |
| `4` / `D4` | **Worker / app options** | Manage apps, reset dashboard password, rotate bearer token *(disabled in offline mode)* |
| `5` / `D5` | **Full reset** | Wipes all local configuration and credentials |
| `6` / `D6` | **Manage local manifest** | Opens the manifest editor *(disabled if no local XML found)* |
| `Esc` | **Exit** | Close the application |

---

## 📦 Generated Artifacts

<details>
<summary><strong>Build output per app</strong> — click to expand</summary>

Each app build writes to `C:\ProgramData\AppUpdater\_output\{AppID}\`:

| File | Purpose |
|---|---|
| `{AppID}.intunewin` | Intune Win32 package — upload directly to the Intune portal |
| `Detect-{AppID}.ps1` | Detection script — registry key check, runs in SYSTEM context |
| `Deploy-{AppID}.ps1` | Deploy script — downloads and installs silently, runs as admin |

**Runtime paths installed on enrolled devices:**

| Path | Purpose |
|---|---|
| `C:\ProgramData\AppUpdater\{AppID}\{AppID}.ps1` | Persistent update script, kept for re-run |
| `C:\ProgramData\AppUpdater\{AppID}\logs\` | Per-app structured log directory |
| `C:\Users\Public\Desktop\Update {DisplayName}.lnk` | Desktop shortcut for manual update trigger |

</details>

---

## 📋 App Manifest Format

<details>
<summary><strong>appVersions.xml schema</strong> — click to expand</summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<AppManifest>
  <App>
    <ID>7Zip</ID>                          <!-- Unique identifier, alphanumeric -->
    <DisplayName>7-Zip</DisplayName>       <!-- Shown in desktop shortcut & popups -->
    <Version></Version>                    <!-- Auto-populated after build -->
    <DownloadURL>https://...</DownloadURL> <!-- Direct link to installer (HTTPS only) -->
    <FallbackURL></FallbackURL>            <!-- Optional secondary download URL -->
    <SilentArgs>/S</SilentArgs>            <!-- Silent install flags (EXE) or auto for MSI -->
    <RegistryDisplayName>7-Zip</RegistryDisplayName> <!-- Matches Add/Remove Programs entry -->
    <ProcessesToKill></ProcessesToKill>    <!-- Comma-separated processes to close before install -->
    <LaunchExe></LaunchExe>               <!-- Optional: exe to launch after install -->
  </App>
  <!-- Add more <App> blocks for additional applications -->
</AppManifest>
```

**Notes:**
- `ID` must be alphanumeric only (`A-Z`, `a-z`, `0-9`) — used as folder and filename
- `DownloadURL` must be HTTPS; the downloaded binary is Authenticode-verified before use
- MSI packages have silent args auto-detected (`/qn /norestart`)
- Multiple `<App>` entries are supported in one manifest file

</details>

---

## ☁️ Cloudflare Worker API

<details>
<summary><strong>All endpoints</strong> — click to expand</summary>

The embedded Worker is deployed to your Cloudflare account at `https://app-updater.{subdomain}.workers.dev`.

**Auth types:**
- 🔒 **Session** — HMAC-SHA256 signed cookie (browser / dashboard flows)
- 🗝️ **Bearer** — `X-Auth-Token` header (PowerShell machine-to-Worker calls)

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | None | Liveness check — returns `200 OK` |
| `GET` | `/login` | None | Render login page |
| `POST` | `/login` | None | Submit password (+ TOTP if enrolled) |
| `POST` | `/logout` | 🔒 Session | Invalidate current session |
| `POST` | `/logout-all` | 🔒 Session | Invalidate all active sessions |
| `GET` | `/set-password` | None | First-run password setup page |
| `POST` | `/set-password` | None | Save initial dashboard password |
| `GET` | `/change-password` | 🔒 Session | Change password page |
| `POST` | `/change-password` | 🔒 Session | Update password |
| `GET` | `/totp-setup` | 🔒 Session | TOTP enrollment page (QR code) |
| `POST` | `/totp-setup` | 🔒 Session | Confirm TOTP enrollment |
| `POST` | `/totp-disable` | 🔒 Session | Remove TOTP requirement |
| `GET` | `/status` | 🔒 Session | Main dashboard — app list + device telemetry |
| `GET` | `/app/{id}` | 🔒 Session | Per-app detail view + event log |
| `POST` | `/manifest` | 🗝️ Bearer | Upload/replace app manifest |
| `DELETE` | `/app/{id}` | 🗝️ Bearer | Remove an app and all its telemetry |
| `GET` | `/deploy/{id}` | None | Download deploy script for an app |
| `POST` | `/deploy-store/{id}` | 🗝️ Bearer | Push deploy script from build machine to Worker |
| `POST` | `/event` | App secret | Ingest telemetry event from enrolled device |
| `GET` | `/evtsec-export` | 🗝️ Bearer | Export event HMAC secret (for script embedding) |

</details>

---

## 🔐 Security Model

| Component | Mechanism |
|---|---|
| **Bearer token** | Windows Credential Manager, target `AppUpdater-ManifestToken` (LocalMachine scope, DPAPI-encrypted) |
| **Dashboard password** | PBKDF2-SHA256, 100 000 iterations, stored only in Cloudflare KV (`auth_password`) |
| **Session cookie** | HMAC-SHA256 signed, `HttpOnly`, `Secure`, `SameSite=Strict`, 24 h `Max-Age` |
| **Login rate limit** | 5 failures / IP / 15 minutes, then locked |
| **TOTP** | RFC 6238 (time-based OTP), secret stored in KV as `totp_secret` |
| **Event telemetry secret** | 32-byte random base64, per-app, auto-rotates on every Worker re-deploy |
| **Binary integrity** | Microsoft Authenticode signature verified before any downloaded `.exe` is executed |
| **Generated scripts** | NTFS ACL–enforced (not Authenticode-signed); deployment share permissions applied via `icacls` |
| **Script Block Logging** | Enabled at runtime for audit trail |

> **Trust boundary:** Local Administrators can read the Credential Manager token. Limit machine access accordingly.

---

## 🔧 Cloudflare Setup

> Skip this section if using **Offline mode**.

### 1 — Create an API Token

Go to [Cloudflare → Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens) and create a token with:

| Permission | Level |
|---|---|
| Workers Scripts | Edit |
| Workers KV Storage | Edit |
| Account Settings | Read |

### 2 — Run the Wizard

Launch the script and choose **Cloudflare-connected** on first run. When prompted:

```
Cloudflare API Token : <paste token>
Organization name    : <your org name — shown in update popups>
```

The wizard will:
1. Validate your token and resolve your Account ID
2. Create the `APP_MANIFEST` KV namespace
3. Compile and deploy the embedded Worker
4. Store the bearer token securely in Windows Credential Manager
5. Open the dashboard URL in your browser for password setup

### 3 — Set Dashboard Password

On first open, set a password (≥ 12 chars, ≥ 1 letter + ≥ 1 digit) and optionally enroll TOTP.

---

## 📝 Logging

AppUpdater uses a **three-tier logging system** with restricted ACLs per file:

| Tier | Purpose | Location |
|---|---|---|
| **Detail** | Full verbose trace of all operations | `AppUpdater.log` (working directory) |
| **Task-run** | Per-build summary with timestamps | `C:\ProgramData\AppUpdater\{AppID}\logs\` |
| **Status** | Short success/failure outcome per app | `C:\ProgramData\AppUpdater\{AppID}\logs\` |

Console output uses styled prefixes: `[OK]` `[WARN]` `[FAIL]` `[INFO]` `[STEP]` with matching colours.

---

## ⚠️ Known Limitations

- 📄 **Log rotation not implemented** — logs append indefinitely; prune manually if needed
- 🔒 **Single-instance mutex** — uses global namespace; may conflict if another instance is already running
- 🪟 **Windows-only** — depends on WPF, NTFS ACLs, DPAPI, and Windows Credential Manager
- 🌐 **Cloud features require internet** — offline mode is available but telemetry and dashboard are unavailable
- ✍️ **Generated scripts are not Authenticode-signed** — NTFS ACL protection is the only code integrity control

---

## 📁 Key Files

| File | Description |
|---|---|
| `AppUpdaterV509.ps1` | Main script — 10 500+ lines, embeds the full Cloudflare Worker JS source |
| `appVersions.xml` | Local app manifest (offline mode or initial seeding) |
| `IntuneWinAppUtil.exe` | Microsoft Win32 Content Prep Tool — required for `.intunewin` generation |

---

## 🏷️ Version History

| Version | Notes |
|---|---|
| **50.9.0** | Current — Cloudflare Worker backend, TOTP MFA, Credential Manager token storage |
| 50.7.0 | Session auth, event telemetry, PBKDF2 passwords |
| 50.6.0 | Initial WPF GUI, offline mode |
