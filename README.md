# AppUpdater

A WPF-based PowerShell tool for generating Microsoft Intune Win32 packages. Supports both offline and Cloudflare-connected deployment modes with TOTP MFA, signed sessions, and Windows Credential Manager integration.

---

## Features

- **WPF GUI** — intuitive interface for building and managing Intune Win32 packages
- **Auto-generated artifacts** — produces `.intunewin` packages, detection scripts (`Detect-{AppID}.ps1`), and deployment scripts (`Deploy-{AppID}.ps1`) per app
- **Two operating modes:**
  - **Cloudflare-connected** — Worker hosts the app manifest, dashboard, authentication, and health endpoint
  - **Offline** — packages built locally; manifest remains on disk
- **TOTP MFA** — time-based one-time password authentication
- **Windows Credential Manager** — bearer tokens stored securely via the Credential Manager API
- **Signed sessions** — HMAC-signed session tokens for tamper resistance
- **Binary verification** — downloaded binaries checked for valid Microsoft Authenticode signatures

---

## Requirements

- Windows 10 / 11
- PowerShell 5.1 or later
- [`IntuneWinAppUtil.exe`](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool) — place in the same directory as the script or in your PATH
- *(Optional)* A deployed Cloudflare Worker for cloud-connected features

---

## Usage

```powershell
.\AppUpdaterV509.ps1
```

The WPF GUI will launch. From there you can:

1. Load or configure your app manifest
2. Set download URLs, silent install arguments, and registry detection keys
3. Build `.intunewin` packages ready for Intune upload
4. Configure the Cloudflare backend (optional)

---

## Security Model

| Component | Mechanism |
|-----------|-----------|
| Bearer token storage | Windows Credential Manager (DPAPI-backed) |
| Dashboard password | PBKDF2-SHA256, 100k iterations, stored in Cloudflare KV |
| Session integrity | HMAC-signed tokens |
| Binary integrity | Microsoft Authenticode signature verification |
| Script Block Logging | Enabled for audit trail |

> **Note:** Generated deploy scripts rely on NTFS ACLs rather than Authenticode signing. Ensure appropriate filesystem permissions on the deployment share.

---

## Version

**v5.09**
