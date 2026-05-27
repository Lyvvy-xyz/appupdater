<#
.SYNOPSIS
  AppUpdater v50 — Intune Win32 package generator with optional Cloudflare-Worker
  manifest backend, signed sessions, TOTP MFA, and Windows Credential Manager protection.

.DESCRIPTION
  All UI is WPF. Two operating modes:
    * Cloudflare-connected — Worker hosts manifest, dashboard, auth, health.
    * Offline              — packages built locally; manifest stays on disk.

  Generated artefacts (per app):
    C:\ProgramData\AppUpdater\_output\{AppID}\{AppID}.intunewin   ← Intune Win32 package
    C:\ProgramData\AppUpdater\_output\{AppID}\Detect-{AppID}.ps1  ← Intune detection script
    C:\ProgramData\AppUpdater\_output\{AppID}\Deploy-{AppID}.ps1  ← Deploy script (run as admin)
  Runtime artefacts created on target devices by the deploy script:
    C:\ProgramData\AppUpdater\{AppID}\{AppID}.ps1
    C:\ProgramData\AppUpdater\{AppID}\logs\…
    C:\Users\Public\Desktop\Update {DisplayName}.lnk

.PARAMETER InstallerPath
  Optional path to a .exe / .msi to seed the package builder (drag-drop entry).

.PARAMETER Offline
  Skip Cloudflare connectivity at startup.

.NOTES
  SECURITY MODEL (read before deploying):
  ----------------------------------------
  Trust boundary: any account that can run admin PowerShell on the build machine
  is fully trusted — they can retrieve the Cloudflare bearer token from Windows
  Credential Manager (Target = AppUpdater-ManifestToken, scoped to LocalMachine).

  What this means in practice:
  * Bearer token (AUTH_TOKEN): stored in Windows Credential Manager, accessible to
    local Administrators. Protects the Worker API — rotate via Worker Options > Reset.
  * Dashboard password: set by the admin during first-run setup; hashed with
    PBKDF2-SHA256 (100 k iterations) and stored only in Cloudflare KV.
  * Event-telemetry secret (EVTSEC): embedded in every generated deploy script
    (by design — rotates automatically on each re-deploy).
  * Generated deploy scripts are NOT Authenticode-signed. Rely on NTFS ACLs on the
    deployment share; sign them yourself if your environment requires it.
  * Downloaded binaries (IntuneWinAppUtil.exe) are verified for a valid Authenticode
    signature issued by Microsoft Corporation before execution.
#>
[CmdletBinding()]
param(
  [string] $InstallerPath = '',
  [switch] $Offline
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# -----------------------------------------------------------------------------
# Console hide — UI is WPF only. Retry loop because the window handle is not
# always available immediately after a UAC re-launch with -WindowStyle Hidden.
# -----------------------------------------------------------------------------
Add-Type -Name Win32 -Namespace Native -MemberDefinition `
  '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);'
$consoleHandle = [System.IntPtr]::Zero
for ($i = 0; $i -lt 10 -and $consoleHandle -eq [System.IntPtr]::Zero; $i++) {
  $consoleHandle = ([System.Diagnostics.Process]::GetCurrentProcess()).MainWindowHandle
  if ($consoleHandle -eq [System.IntPtr]::Zero) { Start-Sleep -Milliseconds 50 }
}
if ($consoleHandle -ne [System.IntPtr]::Zero) {
  [Native.Win32]::ShowWindow($consoleHandle, 0) | Out-Null
} else {
  Add-Type -Name Win32Console -Namespace Native -ErrorAction SilentlyContinue `
    -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool FreeConsole();'
  [Native.Win32Console]::FreeConsole() | Out-Null
}

# -----------------------------------------------------------------------------
# Resolve script path robustly. $MyInvocation.MyCommand.Path is empty when
# launched via Start-Process with -WindowStyle Hidden.
# -----------------------------------------------------------------------------
$ScriptPath = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path }
              elseif ($PSCommandPath)           { $PSCommandPath }
              else { [System.IO.Path]::GetFullPath($MyInvocation.InvocationName) }
$ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)
$ScriptDir  = Split-Path $ScriptPath -Parent

# -----------------------------------------------------------------------------
# Drag-and-drop hand-off. The .cmd launcher writes the dragged path here BEFORE
# elevation; we consume it now so it survives the UAC re-launch.
# Path is validated on consumption, not on read, so the temp file can never
# coerce code execution — only carry a string.
# -----------------------------------------------------------------------------
$DropTempFile = Join-Path $env:TEMP 'appupdater_drop.txt'
if (-not $InstallerPath -and (Test-Path -LiteralPath $DropTempFile -PathType Leaf)) {
  try {
    $raw = Get-Content -LiteralPath $DropTempFile -Raw -ErrorAction Stop
    $InstallerPath = $raw.Trim().Trim('"').Trim("'")
  } catch { $InstallerPath = '' }
  Remove-Item -LiteralPath $DropTempFile -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
# Self-elevation. UAC is triggered once, then InstallerPath / Offline are
# forwarded. Argument quoting is hardened against embedded quotes.
# -----------------------------------------------------------------------------
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $argList = @(
    '-Sta','-ExecutionPolicy','Bypass','-WindowStyle','Hidden',
    '-File', ('"{0}"' -f $ScriptPath)
  )
  if ($InstallerPath) {
    # Sanitise: kill embedded double-quotes that would close our quoted arg.
    $safe = $InstallerPath -replace '"',''
    $argList += @('-InstallerPath', ('"{0}"' -f $safe))
  }
  if ($Offline) { $argList += '-Offline' }
  Start-Process (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList ($argList -join ' ')
  exit 0
}

# =============================================================================
# SINGLE-INSTANCE GUARD — reject a second launch while one is already running.
# The OS releases the mutex automatically when the process exits.
# =============================================================================
$script:_mutex = [System.Threading.Mutex]::new($false, 'Global\AppUpdater_v50_SingleInstance')
$_mutexAcquired = $false
try { $_mutexAcquired = $script:_mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $_mutexAcquired = $true }
if (-not $_mutexAcquired) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show(
        'AppUpdater is already running.',
        'AppUpdater', 'OK', 'Information') | Out-Null
    exit 0
}

# =============================================================================
# ENVIRONMENT CHECK — warn if OS build or PS version is below minimum.
# =============================================================================
$_envWarnings = @()
if ([System.Environment]::OSVersion.Version.Build -lt 17763) {
  $_envWarnings += "Windows build $([System.Environment]::OSVersion.Version.Build) is below the minimum supported build 17763 (Windows 10 1809)."
}
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
  $_envWarnings += "PowerShell $($PSVersionTable.PSVersion) is below the minimum required version 5.1."
}
if ($_envWarnings) {
  Add-Type -AssemblyName PresentationFramework
  [System.Windows.MessageBox]::Show(
    "AppUpdater may not work correctly on this system:`n`n$($_envWarnings -join "`n`n")`n`nYou can continue, but some features may not work as expected.",
    'Compatibility Warning', 'OK', 'Warning') | Out-Null
}

# =============================================================================
# CONSTANTS — all paths are absolute and rooted at $ScriptDir.
# =============================================================================
$ConfigFile        = Join-Path $ScriptDir '.appupdater-config'
$ManifestTokenFile = Join-Path $ScriptDir '.manifest-token'
$XmlFile           = Join-Path $ScriptDir 'appVersions.xml'
$IntuneWinUtilURL  = 'https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe'
$IntuneWinUtilPath = Join-Path $ScriptDir 'IntuneWinAppUtil.exe'
$PSADTCacheDir     = Join-Path $ScriptDir 'PSAppDeployToolkit'
$PSADTv3URL        = 'https://github.com/PSAppDeployToolkit/PSAppDeployToolkit/releases/latest/download/PSAppDeployToolkit.zip'
$TempBase          = Join-Path $ScriptDir 'Temp'
$OutputBase        = 'C:\ProgramData\AppUpdater\_output'
$script:LogFile    = Join-Path $ScriptDir 'AppUpdater.log'
$script:IsAdmin    = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$CF_API            = 'https://api.cloudflare.com/client/v4'
$WorkerName        = 'app-updater'
$KVNamespace       = 'APP_MANIFEST'
$script:Version    = '50.9.0'

# =============================================================================
# EMBEDDED WORKER SOURCE  (self-contained — no separate worker.js needed)
# =============================================================================
$WorkerSource = @'
// =============================================================================
// AUTH MODEL
// -----------------------------------------------------------------------------
// Two parallel auth paths coexist on this worker:
//  1. Bearer token (X-Auth-Token header == env.AUTH_TOKEN)
//     Used by AppUpdater.ps1 machine pushes to POST /manifest, DELETE /app/{id},
//     POST /deploy-store/{id}. Token lives only in the PS1 runbox; never in KV.
//  2. Password + HMAC session cookie (browser UX for /status)
//     Password stored in KV 'auth_password' as PBKDF2-SHA256(100000 iters,
//     16B salt, 32B key) JSON. Session secret in KV 'auth_session_secret'
//     (32B random, base64). Cookie is HMAC-SHA256({exp,iat,nonce}) signed
//     with that secret. Cookie is HttpOnly, Secure, SameSite=Strict,
//     Max-Age=86400 (24h). Rate-limit 5 fails / IP / 15 min via KV TTL.
// First-run: if 'auth_password' missing, any GET /status shows a set-password
// page; password must be >=12 chars with >=1 letter + >=1 digit.
// All crypto uses Web Crypto (crypto.subtle). Compare with constant-time XOR.
// Bearer path is untouched by session middleware — PS1 clients keep working.
// =============================================================================
const KV_XML='appVersions.xml',KV_HEALTH='healthResults';
const KV_PWD='auth_password',KV_SEC='auth_session_secret',KV_RL='rl:',KV_TOTP='totp_secret',KV_TOTP_PEND='totp_pending';
// Per-app event telemetry. Keys:
//   evtsec               - master HMAC secret (32B b64). Rotated on every Re-deploy.
//   evtlog:{appId}       - rolling JSON array of last EVT_LOG_MAX events
//   evthost:{appId}:{id} - latest single event from a (machineGuid|hostname)
//   evtrl:app:{appId}    - per-app rate-limit counter
const KV_EVT_SEC='evtsec',KV_EVT_LOG='evtlog:',KV_EVT_HOST='evthost:',KV_EVT_RL='evtrl:app:';
const EVT_TS_SKEW=300,EVT_LOG_MAX=200,EVT_RL_WINDOW=300,EVT_RL_MAX=60;
const EVT_STATUSES=['running','current','installed','error'];
const SESSION_TTL=86400;
const RL_WINDOW=900,RL_MAX=15;
export default{
  async fetch(r,e){
  const u=new URL(r.url);
  if(u.pathname==='/health')return new Response(JSON.stringify({status:'ok',ts:new Date().toISOString()}),{headers:{'Content-Type':'application/json'}});
  if(u.pathname==='/appVersions.xml'){
  const x=await e.APP_MANIFEST.get(KV_XML);
  if(!x)return new Response('<?xml version="1.0"?><error>Manifest not loaded</error>',{status:404,headers:{'Content-Type':'application/xml'}});
  return new Response(x,{headers:{'Content-Type':'application/xml','Cache-Control':'no-cache'}});
  }
  if(u.pathname==='/login'&&r.method==='GET'){const te=!!(await e.APP_MANIFEST.get(KV_TOTP));return htmlResponse(loginPage('',te));}
  if(u.pathname==='/login'&&r.method==='POST')return handleLogin(r,e);
  if(u.pathname==='/logout')return handleLogout();
  if(u.pathname==='/logout-all'&&r.method==='POST')return handleLogoutAll(r,e);
  if(u.pathname==='/set-password'&&r.method==='GET')return secureRedirect(new URL('/status',r.url).toString());
  if(u.pathname==='/set-password'&&r.method==='POST')return handleSetPassword(r,e);
  if(u.pathname==='/change-password'&&r.method==='GET')return handleChangePasswordGet(r,e);
  if(u.pathname==='/change-password'&&r.method==='POST')return handleChangePasswordPost(r,e);
  if(u.pathname==='/totp-setup'&&r.method==='GET')return handleTOTPSetupGet(r,e);
  if(u.pathname==='/totp-setup'&&r.method==='POST')return handleTOTPSetupPost(r,e);
  if(u.pathname==='/totp-disable'&&r.method==='POST')return handleTOTPDisable(r,e);
  if(u.pathname==='/status')return handleStatus(r,e);
  if(u.pathname==='/manifest'&&r.method==='POST')return handleUpdate(r,e);
  // GET /evtsec-export — returns the event HMAC secret for PS1 package builds (bearer auth only)
  if(u.pathname==='/evtsec-export'&&r.method==='GET'){
    const t=r.headers.get('X-Auth-Token');
    if(!t||!ctEqualStr(t,e.AUTH_TOKEN))return new Response('Unauthorized',{status:401});
    return new Response(e.EVTSEC||await e.APP_MANIFEST.get(KV_EVT_SEC)||'',{status:200,headers:{'Content-Type':'text/plain'}});
  }
  // DELETE /app/{id} — remove an app from the manifest
  if(u.pathname.startsWith('/app/')&&r.method==='DELETE')return handleDeleteApp(r,e,u.pathname.slice(5));
  // GET /deploy/{id} — download the deploy script for an app
  if(u.pathname.startsWith('/deploy/')&&r.method==='GET')return handleDownloadDeploy(r,e,u.pathname.slice(8));
  // POST /deploy-store/{id} — store a deploy script (auth required)
  if(u.pathname.startsWith('/deploy-store/')&&r.method==='POST')return handleStoreDeploy(r,e,u.pathname.slice(14));
  // Per-app drill-down + device-event telemetry
  if(u.pathname==='/event'&&r.method==='POST')return handleEvent(r,e);
  if(u.pathname.startsWith('/app/')&&r.method==='GET')return handleAppDetail(r,e,u.pathname.slice(5));
  // Root and any other path -> landing page
  const manifest=await e.APP_MANIFEST.get(KV_XML);
  const health=await e.APP_MANIFEST.get(KV_HEALTH);
  const appCount=manifest?[...manifest.matchAll(/<App>/g)].length:0;
  return htmlResponse(landingPage(u.hostname,!!manifest,appCount,!!health));
  },
  async scheduled(_,e,ctx){ctx.waitUntil(runChecks(e));}
};

// -----------------------------------------------------------------------------
// b64 / b64url helpers. Workers have atob/btoa but not Buffer.
// -----------------------------------------------------------------------------
function b64e(buf){const b=new Uint8Array(buf);let s='';for(let i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}
function b64d(s){const bin=atob(s);const b=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)b[i]=bin.charCodeAt(i);return b;}
function b64urlE(buf){return b64e(buf).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function b64urlD(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return b64d(s);}

// -----------------------------------------------------------------------------
// constantTimeEqual — XOR-accumulate, returns true only when all bytes match.
// Accepts Uint8Array. Length mismatch short-circuits but still drains.
// -----------------------------------------------------------------------------
function constantTimeEqual(a,b){
  if(a.length!==b.length)return false;
  let d=0;for(let i=0;i<a.length;i++)d|=a[i]^b[i];
  return d===0;
}
// String wrapper — constant-time compare for bearer token checks.
function ctEqualStr(a,b){const e=new TextEncoder();return constantTimeEqual(e.encode(String(a||'')),e.encode(String(b||'')));}

// -----------------------------------------------------------------------------
// pbkdf2Verify — reconstruct hash from provided password + stored salt/iters,
// compare constant-time to stored hash. Returns boolean.
// -----------------------------------------------------------------------------
async function pbkdf2Verify(password,stored){
  try{
  const rec=JSON.parse(stored);
  if(rec.algo!=='PBKDF2-SHA256')return false;
  const salt=b64d(rec.salt),expected=b64d(rec.hash);
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:rec.iterations,hash:'SHA-256'},key,expected.length*8);
  return constantTimeEqual(new Uint8Array(bits),expected);
  }catch(_){return false;}
}

// -----------------------------------------------------------------------------
// hmacSign / hmacVerify — HMAC-SHA256 over the base64url(JSON(payload)).
// Cookie format: <b64url(payload)>.<b64url(sig)>.
// -----------------------------------------------------------------------------
async function hmacKey(secretB64){
  const raw=b64d(secretB64);
  return crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
async function hmacSign(payload,secretB64){
  const k=await hmacKey(secretB64);
  const body=b64urlE(new TextEncoder().encode(JSON.stringify(payload)));
  const sig=await crypto.subtle.sign('HMAC',k,new TextEncoder().encode(body));
  return body+'.'+b64urlE(sig);
}
async function hmacVerify(token,secretB64){
  try{
  const [body,sig]=token.split('.');
  if(!body||!sig)return null;
  const k=await hmacKey(secretB64);
  const ok=await crypto.subtle.verify('HMAC',k,b64urlD(sig),new TextEncoder().encode(body));
  if(!ok)return null;
  const payload=JSON.parse(new TextDecoder().decode(b64urlD(body)));
  if(!payload.exp||payload.exp<Math.floor(Date.now()/1000))return null;
  return payload;
  }catch(_){return null;}
}

// -----------------------------------------------------------------------------
// parseCookie / setSessionCookie — minimal cookie plumbing.
// -----------------------------------------------------------------------------
function parseCookie(header,name){
  if(!header)return null;
  const parts=header.split(/;\s*/);
  for(const p of parts){const i=p.indexOf('=');if(i>0&&p.slice(0,i)===name)return decodeURIComponent(p.slice(i+1));}
  return null;
}
function setSessionCookie(value,maxAge){
  return `__Host-au_session=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
function clearSessionCookie(){
  return '__Host-au_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';
}

// -----------------------------------------------------------------------------
// Security headers — applied to every HTML/redirect response.
// CSP blocks framing (frame-ancestors 'none' also beats X-Frame-Options in
// modern browsers), limits fetch targets to same-origin, and allows only
// inline styles/scripts (no external resources loaded by these pages).
// -----------------------------------------------------------------------------
const SEC={
  'X-Content-Type-Options':'nosniff',
  'X-Frame-Options':'DENY',
  'Referrer-Policy':'strict-origin-when-cross-origin',
  'Content-Security-Policy':"default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()'
};
// Wrap an HTML body with security headers.
function htmlResponse(body,status=200){
  return new Response(body,{status,headers:{...SEC,'Content-Type':'text/html;charset=utf-8'}});
}
// Redirect with security headers. Pass a Set-Cookie string as the third arg when needed.
function secureRedirect(url,status=302,cookie=null){
  const h={...SEC,'Location':url};
  if(cookie)h['Set-Cookie']=cookie;
  return new Response(null,{status,headers:h});
}

// -----------------------------------------------------------------------------
// rateLimit — KV TTL counter per IP. Returns true when exceeded.
// -----------------------------------------------------------------------------
async function rateLimit(e,ip){
  const key=KV_RL+ip;
  const cur=await e.APP_MANIFEST.get(key);
  const n=cur?parseInt(cur,10)+1:1;
  await e.APP_MANIFEST.put(key,String(n),{expirationTtl:RL_WINDOW});
  return n>RL_MAX;
}

// -----------------------------------------------------------------------------
// getOrCreateSessionSecret — ensures a 32-byte secret exists in KV.
// -----------------------------------------------------------------------------
async function getOrCreateSessionSecret(e){
  let s=await e.APP_MANIFEST.get(KV_SEC);
  if(s)return s;
  const buf=crypto.getRandomValues(new Uint8Array(32));
  s=b64e(buf);
  await e.APP_MANIFEST.put(KV_SEC,s);
  return s;
}

// -----------------------------------------------------------------------------
// verifySession — returns payload when the request carries a valid cookie.
// -----------------------------------------------------------------------------
async function verifySession(r,e){
  const tok=parseCookie(r.headers.get('Cookie'),'__Host-au_session');
  if(!tok)return null;
  const sec=await e.APP_MANIFEST.get(KV_SEC);
  if(!sec)return null;
  return hmacVerify(tok,sec);
}

// -----------------------------------------------------------------------------
// handleLogin — POST form, check rate limit, verify password, issue cookie.
// -----------------------------------------------------------------------------
async function handleLogin(r,e){
  const stored=await e.APP_MANIFEST.get(KV_PWD);
  if(!stored)return secureRedirect(new URL('/status',r.url).toString());
  const ip=r.headers.get('CF-Connecting-IP');
  if(!ip)return new Response('',{status:403}); // must route through Cloudflare
  if(await rateLimit(e,ip))return htmlResponse(loginPage('Too many login attempts — please wait 15 minutes before trying again.'),429);
  const form=await r.formData();
  const pwd=form.get('password')||'';
  if(!await pbkdf2Verify(pwd,stored))return htmlResponse(loginPage('Incorrect password — please try again.'),401);
  // TOTP check (only if a secret is configured)
  const totpSec=await e.APP_MANIFEST.get(KV_TOTP);
  if(totpSec){
    const otp=String(form.get('otp')||'').replace(/[\s\-]/g,'');
    if(!otp||!await verifyTOTP(totpSec,otp,e))return htmlResponse(loginPage('Invalid authenticator code — please try again.',true),401);
  }
  const sec=await getOrCreateSessionSecret(e);
  const now=Math.floor(Date.now()/1000);
  const nonceBuf=crypto.getRandomValues(new Uint8Array(12));
  const token=await hmacSign({iat:now,exp:now+SESSION_TTL,nonce:b64urlE(nonceBuf)},sec);
  return secureRedirect('/status',302,setSessionCookie(token,SESSION_TTL));
}

// -----------------------------------------------------------------------------
// handleLogout — clear the cookie and redirect to /login.
// -----------------------------------------------------------------------------
function handleLogout(){
  return secureRedirect('/login',302,clearSessionCookie());
}
// -----------------------------------------------------------------------------
// handleLogoutAll — rotate session secret so ALL existing tokens are invalid.
// Requires an active session (prevents CSRF from unauthenticated pages).
// -----------------------------------------------------------------------------
async function handleLogoutAll(r,e){
  const sess=await verifySession(r,e);
  if(!sess)return secureRedirect('/login',302,clearSessionCookie());
  const buf=crypto.getRandomValues(new Uint8Array(32));
  await e.APP_MANIFEST.put(KV_SEC,b64e(buf));
  return secureRedirect('/login',302,clearSessionCookie());
}

// -----------------------------------------------------------------------------
// handleSetPassword — only accepted when no password is set yet (first run).
// Validates policy, writes PBKDF2 record, issues session cookie.
// -----------------------------------------------------------------------------
async function handleSetPassword(r,e){
  const existing=await e.APP_MANIFEST.get(KV_PWD);
  if(existing)return htmlResponse('<p style="font-family:sans-serif;color:#c00;padding:2rem">Password already set. Use AppUpdater to reset it from the <em>Worker Options</em> menu.</p>',403);
  const form=await r.formData();
  const pwd=String(form.get('password')||'');
  const conf=String(form.get('confirm')||'');
  if(pwd!==conf)return htmlResponse(setPasswordPage('Passwords do not match.'),400);
  if(pwd.length<12||!/[A-Za-z]/.test(pwd)||!/[0-9]/.test(pwd))return htmlResponse(setPasswordPage('Password must be at least 12 characters and include a letter and a digit.'),400);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iters=100000;
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(pwd),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:iters,hash:'SHA-256'},key,256);
  const rec={algo:'PBKDF2-SHA256',iterations:iters,salt:b64e(salt),hash:b64e(bits)};
  await e.APP_MANIFEST.put(KV_PWD,JSON.stringify(rec));
  const sec=await getOrCreateSessionSecret(e);
  const now=Math.floor(Date.now()/1000);
  const nonceBuf=crypto.getRandomValues(new Uint8Array(12));
  const token=await hmacSign({iat:now,exp:now+SESSION_TTL,nonce:b64urlE(nonceBuf)},sec);
  return secureRedirect('/status',302,setSessionCookie(token,SESSION_TTL));
}

// -----------------------------------------------------------------------------
// handleChangePasswordGet / handleChangePasswordPost
// Authenticated (session required). Allows a logged-in admin to change their
// dashboard password without going through the full reset-via-PS1 flow.
// -----------------------------------------------------------------------------
async function handleChangePasswordGet(r,e){
  const sess=await verifySession(r,e);
  if(!sess)return secureRedirect('/login',302,clearSessionCookie());
  return htmlResponse(changePasswordPage(''));
}
async function handleChangePasswordPost(r,e){
  const sess=await verifySession(r,e);
  if(!sess)return secureRedirect('/login',302,clearSessionCookie());
  const stored=await e.APP_MANIFEST.get(KV_PWD);
  if(!stored)return htmlResponse(changePasswordPage('No password is set. Use the set-password page.'),400);
  const form=await r.formData();
  const current=String(form.get('current')||'');
  const newPwd=String(form.get('password')||'');
  const conf=String(form.get('confirm')||'');
  if(!await pbkdf2Verify(current,stored))return htmlResponse(changePasswordPage('Current password is incorrect.'),401);
  if(newPwd!==conf)return htmlResponse(changePasswordPage('New passwords do not match.'),400);
  if(newPwd.length<12||!/[A-Za-z]/.test(newPwd)||!/[0-9]/.test(newPwd))return htmlResponse(changePasswordPage('New password must be at least 12 characters and include a letter and a digit.'),400);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iters=100000;
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(newPwd),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:iters,hash:'SHA-256'},key,256);
  const rec={algo:'PBKDF2-SHA256',iterations:iters,salt:b64e(salt),hash:b64e(bits)};
  await e.APP_MANIFEST.put(KV_PWD,JSON.stringify(rec));
  return secureRedirect('/status',302);
}
function changePasswordPage(err){
  return CSS+`
<title>AppUpdater &mdash; Change password</title>
</head><body>
<div class="bar" style="background:#0a0a0a;border-bottom-color:var(--c)">
  <div class="dot" style="background:var(--c);box-shadow:0 0 8px var(--c)"></div>
  <h1 style="color:var(--c)">AppUpdater</h1>
  <div class="meta">Change dashboard password</div>
</div>
<div class="hero"><div class="logo">Security</div><h1>Change password</h1></div>
<div class="wrap" style="max-width:460px">
  <form method="POST" action="/change-password" style="background:var(--s);border:1px solid var(--b);border-radius:8px;padding:22px">
  ${err?`<div style="background:#3f0a0a;border:1px solid #7f1d1d;color:#fca5a5;padding:8px 12px;border-radius:4px;margin-bottom:14px;font-size:12px">${err}</div>`:''}
  <div class="mf"><label>Current password</label><input type="password" name="current" autofocus required/></div>
  <div class="mf"><label>New password <span style="color:#555;font-size:10px;text-transform:none">(min 12 chars, letters + digits)</span></label><input type="password" name="password" required minlength="12"/></div>
  <div class="mf"><label>Confirm new password</label><input type="password" name="confirm" required minlength="12"/></div>
  <div class="modal-btns" style="margin-top:8px">
    <a href="/status" style="color:var(--dim);font-size:12px;text-decoration:none;margin-right:16px">&#8592; Cancel</a>
    <button class="btn-save" type="submit" style="padding:10px 24px">Change password</button>
  </div>
  </form>
</div></body></html>`;}

async function handleUpdate(r,e){
  const ip=r.headers.get('CF-Connecting-IP');
  if(!ip)return new Response('',{status:403}); // must route through Cloudflare
  if(await rateLimit(e,ip))return new Response('Too many requests',{status:429});
  // Bearer token path preserved for PS1 pushes.
  const t=r.headers.get('X-Auth-Token');
  if(t&&ctEqualStr(t,e.AUTH_TOKEN)){/* ok */}
  else{
  const sess=await verifySession(r,e);
  if(!sess)return new Response('Unauthorized',{status:401});
  }
  const b=await r.text();
  if(!b||!b.includes('<AppManifest>')||!b.includes('</AppManifest>'))return new Response('Invalid XML',{status:400});
  const open=b.indexOf('<AppManifest>'),close=b.lastIndexOf('</AppManifest>');
  if(open<0||close<0||open>close)return new Response('Invalid XML: malformed structure',{status:400});
  const bLow=b.toLowerCase();
  const BANNED=['<script','javascript:','vbscript:','onload=','onerror=','onclick=','<!entity','<!doctype','<![cdata','<?xml-stylesheet'];
  for(const term of BANNED){if(bLow.includes(term))return new Response('Invalid XML: disallowed content',{status:400});}
  if(b.length>524288)return new Response('Manifest too large',{status:413});
  await e.APP_MANIFEST.put(KV_XML,b);
  return new Response('Manifest updated successfully',{status:200});
}
async function handleDeleteApp(r,e,appId){
  const t=r.headers.get('X-Auth-Token');
  if(t&&ctEqualStr(t,e.AUTH_TOKEN)){/* ok */}
  else{
  const sess=await verifySession(r,e);
  if(!sess)return new Response('Unauthorized',{status:401});
  }
  if(!appId)return new Response('App ID required',{status:400});
  const uninstall=new URL(r.url).searchParams.get('uninstall')==='true';
  let xml=await e.APP_MANIFEST.get(KV_XML);
  if(!xml)return new Response('No manifest',{status:404});
  const sid=appId.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const cleaned=xml.replace(new RegExp('\\s*<App>[\\s\\S]*?<ID>'+sid+'<\/ID>[\\s\\S]*?<\/App>','g'),'');
  if(cleaned===xml)return new Response('App not found',{status:404});
  let final=cleaned;
  if(uninstall){
  const ts=new Date().toISOString();
  const entry='  <App id="'+appId+'" removedAt="'+ts+'"/>';
  if(final.includes('<RemovedApps>')){
  if(!final.includes('id="'+appId+'"'))final=final.replace('</RemovedApps>',entry+'\n</RemovedApps>');
  } else {
  final=final.replace('</AppManifest>','\n  <RemovedApps>\n'+entry+'\n  </RemovedApps>\n</AppManifest>');
  }
  }
  await e.APP_MANIFEST.put(KV_XML,final);
  return new Response(uninstall?'Removed and flagged for uninstall':'Removed',{status:200});
}
async function handleStoreDeploy(r,e,appId){
  const t=r.headers.get('X-Auth-Token');
  if(t&&ctEqualStr(t,e.AUTH_TOKEN)){/* ok */}
  else{
  const sess=await verifySession(r,e);
  if(!sess)return new Response('Unauthorized',{status:401});
  }
  if(!appId)return new Response('App ID required',{status:400});
  const body=await r.text();
  await e.APP_MANIFEST.put('deploy:'+appId,body);
  return new Response('Stored',{status:200});
}
async function handleDownloadDeploy(r,e,appId){
  // Requires bearer token (PS1 machine pushes) or an active session (browser dashboard).
  const t=r.headers.get('X-Auth-Token');
  if(!(t&&ctEqualStr(t,e.AUTH_TOKEN))){
    const sess=await verifySession(r,e);
    if(!sess)return new Response('Unauthorized',{status:401,headers:{'Content-Type':'text/plain'}});
  }
  const script=await e.APP_MANIFEST.get('deploy:'+appId);
  if(!script)return new Response('Deploy script not found. Build this app with AppUpdater.ps1 first.',{status:404,headers:{'Content-Type':'text/plain'}});
  return new Response(script,{headers:{'Content-Type':'text/plain;charset=utf-8','Content-Disposition':`attachment; filename="Deploy-${appId}.ps1"`}});
}
async function runChecks(e){
  const x=await e.APP_MANIFEST.get(KV_XML);if(!x)return;
  const urls=[...new Set([...x.matchAll(/<(?:DownloadURL|FallbackURL)>([^<]+)</g)].map(m=>m[1].trim()).filter(Boolean))];
  const res={};
  await Promise.all(urls.map(async u=>{
  try{const r=await fetch(u,{method:'HEAD',signal:AbortSignal.timeout(12000)});res[u]={ok:r.ok,code:r.status,ts:new Date().toISOString()};}
  catch(err){res[u]={ok:false,code:0,err:err.message,ts:new Date().toISOString()};}
  }));
  await e.APP_MANIFEST.put(KV_HEALTH,JSON.stringify(res));
}
async function handleStatus(r,e){
  // First run: no password set -> force set-password page.
  const stored=await e.APP_MANIFEST.get(KV_PWD);
  if(!stored)return htmlResponse(setPasswordPage(''));
  // Otherwise require a valid session cookie.
  const sess=await verifySession(r,e);
  if(!sess)return secureRedirect(new URL('/login',r.url).toString());
  const x=await e.APP_MANIFEST.get(KV_XML);
  const hr=await e.APP_MANIFEST.get(KV_HEALTH);
  const h=hr?JSON.parse(hr):{};
  if(!x)return htmlResponse(setupPage(true));
  const apps=[...x.matchAll(/<App>([\s\S]*?)<\/App>/g)].map(m=>{
  const b=m[1],g=t=>{const r=b.match(new RegExp('<'+t+'>([^<]*)</'+t+'>'));return r?r[1].trim():'';};
  return{id:g('ID'),name:g('DisplayName'),ver:g('Version'),dl:g('DownloadURL'),fb:g('FallbackURL')};
  });
  const dead=Object.values(h).filter(v=>!v.ok).length;
  const live=Object.values(h).filter(v=>v.ok).length;
  const pend=apps.reduce((n,a)=>{if(a.dl&&!h[a.dl])n++;if(a.fb&&!h[a.fb])n++;return n;},0);
  const lastTs=Object.values(h).sort((a,b)=>b.ts>a.ts?1:-1)[0]?.ts;
  const lastStr=lastTs?new Date(lastTs).toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}):'Never — cron runs hourly';
  const allOK=dead===0&&Object.keys(h).length>0;
  const allPend=dead===0&&Object.keys(h).length===0&&apps.length>0;
  const badge=u=>{
  if(!u)return'<span class="b na">N/A</span>';
  const hh=h[u];
  if(!hh)return'<span class="b pend">Pending</span>';
  return hh.ok?'<span class="b live">&#10003; Live</span>':`<span class="b dead">&#10007; Dead${hh.code?' ('+hh.code+')':''}</span>`;
  };
  const rows=apps.map(a=>`<tr>
  <td><a href="/app/${encodeURIComponent(a.id)}" style="color:#e5e7eb;text-decoration:none" title="View per-device status"><b>${htmlEscape(a.name||a.id)}</b><br><small style="color:var(--dim)">${htmlEscape(a.id)} &nbsp;&middot;&nbsp; <span style="color:var(--c)">view devices &rsaquo;</span></small></a></td>
  <td><small>${htmlEscape(a.ver)||'<span class="dim">auto</span>'}</small></td>
  <td class="uc">${a.dl?`<a href="${htmlEscape(a.dl)}" target="_blank" title="${htmlEscape(a.dl)}">${htmlEscape(a.dl)}</a>`:'<span class="dim">&mdash;</span>'}</td>
  <td>${badge(a.dl)}</td>
  <td class="uc">${a.fb?`<a href="${htmlEscape(a.fb)}" target="_blank" title="${htmlEscape(a.fb)}">${htmlEscape(a.fb)}</a>`:'<span class="dim">&mdash;</span>'}</td>
  <td>${badge(a.fb)}</td>
  <td class="actions"><div class="actions-inner">
  <a href="/deploy/${encodeURIComponent(a.id)}" class="btn-dl" title="Download Deploy-${htmlEscape(a.id)}.ps1">&#8595; Deploy</a>
  <button class="edit-btn" onclick="editApp('${a.id}','${jsEsc(a.name||a.id)}','${jsEsc(a.ver||'')}')">&#9998;</button><button class="btn-del" onclick="delApp('${a.id}','${jsEsc(a.name||a.id)}')" title="Remove">&#10005;</button>
  </div></td>
  </tr>`).join('');
  return htmlResponse(CSS+`
<title>AppUpdater ${apps.length===0?'&#9711; No apps yet':allPend?'&#9711; Pending':dead>0?'&#9888; '+dead+' Issue'+(dead>1?'s':''):'&#10003; All OK'}</title>
</head><body>
<div class="bar" style="background:${apps.length===0||allPend?'#1a1200':allOK?'#052e16':'#3f0a0a'};border-bottom-color:${apps.length===0||allPend?'var(--y)':allOK?'var(--g)':'var(--r)'}">
  <div class="bar-in">
  <div class="dot" style="background:${apps.length===0||allPend?'var(--y)':allOK?'var(--g)':'var(--r)'};box-shadow:0 0 8px ${apps.length===0||allPend?'var(--y)':allOK?'var(--g)':'var(--r)'}"></div>
  <h1 style="color:${apps.length===0||allPend?'var(--y)':allOK?'var(--g)':'var(--r)'}">${apps.length===0?'NO APPS YET — SET ONE UP IN APPUPDATER':allPend?'PENDING — AWAITING FIRST HEALTH CHECK (RUNS HOURLY)':allOK?'ALL SYSTEMS OK':dead+' URL'+(dead>1?'s':'')+' UNREACHABLE'}</h1>
  <div class="meta">Last check: ${lastStr}<br>Auto-refreshes every 60s &middot; Health checks run hourly<br><span style="display:inline-flex;gap:6px;margin-top:4px"><button onclick="location.reload()" style="background:#1a1a1a;border:1px solid #333;color:#22d3ee;padding:3px 10px;border-radius:3px;font-family:inherit;font-size:11px;cursor:pointer">&#8635; Refresh</button><a href="/change-password" style="background:#1a1a1a;border:1px solid #333;color:#888;padding:3px 10px;border-radius:3px;font-size:11px;cursor:pointer;text-decoration:none">&#128274; Change password</a><a href="/logout" style="background:#1a1a1a;border:1px solid #333;color:#888;padding:3px 10px;border-radius:3px;font-size:11px;cursor:pointer;text-decoration:none">Sign out</a><button onclick="if(confirm('Sign out of ALL devices and sessions?')){fetch('/logout-all',{method:'POST'}).then(()=>location.href='/login')}" style="background:#1a0a0a;border:1px solid #3f1010;color:#ef4444;padding:3px 10px;border-radius:3px;font-family:inherit;font-size:11px;cursor:pointer">Sign out all</button></span></div>
  </div>
</div>
<div class="wrap">
  <div class="cards">
  <div class="card apps"><div class="n">${apps.length}</div><div class="l">Apps</div></div>
  <div class="card lv"><div class="n">${live}</div><div class="l">Live URLs</div></div>
  <div class="card dd" style="${dead>0?'border-color:#7f1d1d':''}"><div class="n" style="color:${dead>0?'var(--r)':'var(--dim)'}">${dead}</div><div class="l">Dead URLs</div></div>
  <div class="card pd"><div class="n" style="color:${pend>0?'var(--y)':'var(--dim)'}">${pend}</div><div class="l">Pending</div></div>
  </div>
  <div class="sh"><span>App Manifest</span><small>${Object.keys(h).length===0?'No health data yet — cron runs hourly':'Checks run hourly &middot; Dead URLs pulse red'}</small></div>
  <table>
  <thead><tr><th style="width:20%">App</th><th style="width:58px">Version</th><th>Primary URL</th><th style="width:82px">Status</th><th style="width:17%">Fallback URL</th><th style="width:82px">Status</th><th style="width:154px">Actions</th></tr></thead>
  <tbody>${rows||'<tr><td colspan="7" style="text-align:center;color:var(--dim);padding:24px">No apps in manifest yet</td></tr>'}</tbody>
  </table>
  <p style="margin:6px 0 0;font-size:11px;color:var(--dim)">&#9432; PSADT export is done from within the AppUpdater app &mdash; use the PSADT button in the app list after building.</p>
  <div id="toast" style="display:none;position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#1e1e1e;border:1px solid var(--b);padding:10px 20px;border-radius:6px;font-size:13px;color:var(--t);z-index:999"></div>
</div>
<script>
let _delId=null,_delName=null;

/* ── Toast ───────────────────────────────────────────────────────────────── */
function toast(msg,ok){
  const el=document.getElementById('toast');
  el.textContent=msg;el.style.display='block';
  el.style.borderColor=ok?'var(--g)':'var(--r)';el.style.color=ok?'var(--g)':'var(--r)';
  setTimeout(()=>{el.style.display='none';},3500);
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if(document.getElementById('editModal').style.display==='flex')closeEdit();
    if(document.getElementById('delModal').style.display==='flex')closeDelModal();
  }
});

/* ── Delete modal (replaces confirm()) ───────────────────────────────────── */
function delApp(id,name){
  _delId=id;_delName=name;
  document.getElementById('del_app_name').textContent='"'+name+'"';
  document.getElementById('delModal').style.display='flex';
}
function closeDelModal(){document.getElementById('delModal').style.display='none';}
async function confirmDel(uninstall){
  closeDelModal();
  const id=_delId,name=_delName;
  const url='/app/'+id+(uninstall?'?uninstall=true':'');
  try{
    const r=await fetch(url,{method:'DELETE'});
    if(r.ok){toast(uninstall?name+' flagged for uninstall on all devices.':name+' removed from manifest.',true);setTimeout(()=>location.reload(),2500);}
    else if(r.status===401){location.href='/login';}
    else{toast('Error: '+(await r.text()),false);}
  }catch(err){toast('Request failed: '+err.message,false);}
}

/* ── Edit modal ──────────────────────────────────────────────────────────── */
function closeEdit(){document.getElementById('editModal').style.display='none';}
function showEditModal(id,xml){
  const sid=id.replace(/[.*+?^{}()|[\]\\$]/g,'\\$&');
  const appBlock=xml.match(new RegExp('<App>[\\s\\S]*?<ID>'+sid+'<\\/ID>[\\s\\S]*?<\\/App>'));
  if(!appBlock){toast('App not found in manifest',false);return;}
  const fld=t=>{const r=appBlock[0].match(new RegExp('<'+t+'>([^<]*)<\\/'+t+'>'));return r?r[1].trim():'';};
  const m=document.getElementById('editModal');
  m.querySelector('#ef_id').value=id;
  m.querySelector('#ef_xml').value=xml;
  m.querySelector('#ef_name').value=fld('DisplayName');
  m.querySelector('#ef_ver').value=fld('Version');
  m.querySelector('#ef_dl').value=fld('DownloadURL');
  m.querySelector('#ef_fb').value=fld('FallbackURL');
  m.querySelector('#ef_args').value=fld('SilentArgs');
  m.querySelector('#ef_reg').value=fld('RegistryDisplayName');
  m.querySelector('#ef_kill').value=fld('ProcessesToKill');
  m.querySelector('#ef_launch').value=fld('LaunchExe');
  m.style.display='flex';
}
function editApp(id,name,ver){
  fetch('/appVersions.xml')
    .then(rx=>{if(!rx.ok)throw new Error('Could not fetch manifest');return rx.text();})
    .then(xml=>showEditModal(id,xml))
    .catch(err=>toast(err.message,false));
}
async function submitEdit(){
  const m=document.getElementById('editModal');
  const id=m.querySelector('#ef_id').value;
  const origXml=m.querySelector('#ef_xml').value;
  const sid=id.replace(/[.*+?^{}()|[\]\\$]/g,'\\$&');
  const appBlock=origXml.match(new RegExp('<App>[\\s\\S]*?<ID>'+sid+'<\\/ID>[\\s\\S]*?<\\/App>'));
  if(!appBlock){toast('App block not found',false);return;}
  const get=n=>m.querySelector('#ef_'+n).value;
  let block=appBlock[0];
  [['DisplayName',get('name')],['Version',get('ver')],['DownloadURL',get('dl')],
   ['FallbackURL',get('fb')],['SilentArgs',get('args')],['RegistryDisplayName',get('reg')],
   ['ProcessesToKill',get('kill')],['LaunchExe',get('launch')]].forEach(([tag,val])=>{
    block=block.replace(new RegExp('(<'+tag+'>)[^<]*(<\\/'+tag+'>)'),(_,o,c)=>o+val+c);
  });
  const newXml=origXml.split(appBlock[0]).join(block);
  try{
    const rp=await fetch('/manifest',{method:'POST',headers:{'Content-Type':'application/xml'},body:newXml});
    if(rp.ok){closeEdit();toast('Saved. Refreshing...',true);setTimeout(()=>location.reload(),1500);}
    else if(rp.status===401){location.href='/login';}
    else{toast('Error: '+(await rp.text()),false);}
  }catch(err){toast('Request failed: '+err.message,false);}
}
</script>

<!-- Delete modal -->
<div class="modal" id="delModal" onclick="if(event.target===this)closeDelModal()">
<div class="modal-box" style="width:460px">
<div style="font-size:14px;font-weight:700;color:#ef4444;margin-bottom:8px">&#10005; Remove App</div>
<div style="font-size:13px;color:#e5e7eb;margin-bottom:16px">What would you like to do with <span id="del_app_name" style="color:#f5c842"></span>?</div>
<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:18px">
<button onclick="confirmDel(false)" style="background:#101820;border:1px solid #1e3a5f;color:#e8e8f4;padding:12px 16px;border-radius:6px;cursor:pointer;text-align:left;font-family:inherit;font-size:12px"><b style="display:block;margin-bottom:3px">Remove from manifest only</b><span style="color:#55577a">Devices keep the app — only removed from monitoring.</span></button>
<button onclick="confirmDel(true)" style="background:#1a0505;border:1px solid #3f0a0a;color:#e8e8f4;padding:12px 16px;border-radius:6px;cursor:pointer;text-align:left;font-family:inherit;font-size:12px"><b style="display:block;margin-bottom:3px;color:#ef4444">Remove + Uninstall from all devices</b><span style="color:#55577a">Each device will silently uninstall on its next scheduled task run. Cannot be undone.</span></button>
</div>
<div class="modal-btns" style="margin-top:0">
<button class="btn-cancel-m" onclick="closeDelModal()">Cancel</button>
</div>
</div></div>

<!-- Edit modal -->
<div class="modal" id="editModal" onclick="if(event.target===this)closeEdit()">
<div class="modal-box">
<div style="font-size:14px;font-weight:700;color:#e5e7eb;margin-bottom:16px">&#9998; Edit App</div>
<input type="hidden" id="ef_id"/><input type="hidden" id="ef_xml"/>
<div class="mf"><label>Display Name</label><input id="ef_name"/></div>
<div class="mf"><label>Version <span style="color:#555;font-size:10px;text-transform:none">(blank = auto-detect from installer)</span></label><input id="ef_ver" placeholder="e.g. 124.0.0.0"/></div>
<div class="mf"><label>Download URL</label><input id="ef_dl"/></div>
<div class="mf"><label>Fallback URL</label><input id="ef_fb"/></div>
<div class="mf"><label>Silent Args</label><input id="ef_args"/></div>
<div class="mf"><label>Registry Display Name</label><input id="ef_reg"/></div>
<div class="mf"><label>Processes to Kill <span style="color:#555;font-size:10px;text-transform:none">(comma-separated)</span></label><input id="ef_kill"/></div>
<div class="mf"><label>Launch Exe <span style="color:#555;font-size:10px;text-transform:none">(optional)</span></label><input id="ef_launch"/></div>
<div class="modal-btns">
<button class="btn-cancel-m" onclick="closeEdit()">Cancel</button>
<button class="btn-save" onclick="submitEdit()">Save changes</button>
</div>
</div></div>
</body></html>`);
}
const CSS=`<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<style>
:root{--bg:#080808;--s:#111;--b:#1e1e1e;--t:#d4d4d4;--dim:#555;--g:#22c55e;--r:#ef4444;--y:#f59e0b;--c:#22d3ee;--p:#a78bfa}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:ui-monospace,Consolas,monospace;font-size:14px;min-height:100vh}
.bar{border-bottom:2px solid;padding:0}
.bar-in{max-width:1100px;margin:0 auto;padding:14px 24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.dot{width:12px;height:12px;flex-shrink:0;border-radius:50%}
@keyframes p{0%,100%{opacity:1}50%{opacity:.2}}
.bar h1{font-size:15px;letter-spacing:.06em}
.meta{margin-left:auto;color:var(--dim);font-size:12px;text-align:right;line-height:1.6}
.wrap{max-width:1100px;margin:0 auto;padding:20px 24px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}
.card{background:var(--s);border:1px solid var(--b);border-radius:6px;padding:12px 16px}
.card .n{font-size:28px;font-weight:700;line-height:1}
.card .l{font-size:11px;color:var(--dim);margin-top:4px;text-transform:uppercase;letter-spacing:.06em}
.apps .n{color:var(--c)}.lv .n{color:var(--g)}
.sh{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.sh span{font-size:11px;color:var(--c);text-transform:uppercase;letter-spacing:.08em}
.sh small{font-size:11px;color:var(--dim)}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th{background:#0c0c0c;color:var(--c);padding:8px 12px;text-align:left;border-bottom:1px solid var(--b);font-weight:400;font-size:11px;text-transform:uppercase;letter-spacing:.06em;overflow:hidden}
td{padding:9px 12px;border-bottom:1px solid #161616;vertical-align:middle;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#0e0e0e}
td b,td small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
b{color:#e5e7eb}small{color:var(--dim);font-size:11px}.dim{color:var(--dim)}
.uc{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.uc a{color:#60a5fa;text-decoration:none;font-size:12px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.uc a:hover{text-decoration:underline}
.b{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:.04em}
.b.live{background:#052e16;color:var(--g);border:1px solid #166534}
.b.dead{background:#3f0a0a;color:var(--r);border:1px solid #7f1d1d;animation:p 1.4s infinite}
.b.pend{background:#1c1505;color:var(--y);border:1px solid #713f12}
.b.na{background:#111;color:var(--dim);border:1px solid var(--b)}
.edit-btn{background:transparent;border:1px solid #1e3a5f;color:#60a5fa;padding:2px 8px;border-radius:3px;font-family:inherit;font-size:12px;cursor:pointer}
.edit-btn:hover{background:#0c1a2e}
.del-btn{background:transparent;border:1px solid #3f1010;color:#ef4444;padding:2px 8px;border-radius:3px;font-family:inherit;font-size:11px;cursor:pointer;letter-spacing:.03em}
.del-btn:hover{background:#3f0a0a;border-color:#7f1d1d}
.actions{white-space:nowrap;text-align:right}
.actions-inner{display:flex;gap:6px;align-items:center;justify-content:flex-end}
.btn-dl{display:inline-block;padding:3px 8px;border-radius:3px;font-size:11px;color:var(--c);border:1px solid #1e3a4a;background:#0a1929;text-decoration:none;cursor:pointer}
.btn-dl:hover{background:#0e2236;border-color:var(--c)}
.btn-del{padding:3px 8px;border-radius:3px;font-size:11px;color:var(--r);border:1px solid #3f0a0a;background:#1a0505;cursor:pointer}
.btn-del:hover{background:#2a0808;border-color:var(--r)}
/* landing / setup page extras */
.hero{padding:48px 24px 32px;text-align:center}
.logo{font-size:13px;color:var(--c);letter-spacing:.2em;text-transform:uppercase;margin-bottom:8px}
.hero h1{font-size:28px;font-weight:700;color:#e5e7eb;letter-spacing:-.01em;margin-bottom:8px}
.hero p{color:var(--dim);font-size:13px;max-width:440px;margin:0 auto}
.steps{max-width:560px;margin:0 auto 40px;display:flex;flex-direction:column;gap:0}
.step{display:flex;gap:14px;padding:14px 16px;border-left:2px solid var(--b);position:relative}
.step:last-child{border-left-color:transparent}
.step.done{border-left-color:var(--g)}
.step.active{border-left-color:var(--c)}
.step.todo{border-left-color:var(--b)}
.step-icon{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0;margin-top:1px}
.step.done .step-icon{background:#052e16;color:var(--g);border:1px solid #166534}
.step.active .step-icon{background:#0c1a2e;color:var(--c);border:1px solid #1e40af;animation:p 2s infinite}
.step.todo .step-icon{background:#111;color:var(--dim);border:1px solid var(--b)}
.step-body{}
.step-title{font-size:13px;font-weight:700;color:#e5e7eb;margin-bottom:2px}
.step.todo .step-title{color:var(--dim)}
.step-desc{font-size:12px;color:var(--dim);line-height:1.5}
.step.active .step-desc{color:#94a3b8}
.endpoints{max-width:560px;margin:0 auto 32px;background:var(--s);border:1px solid var(--b);border-radius:8px;overflow:hidden}
.endpoints .hdr{padding:10px 16px;font-size:11px;color:var(--c);text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--b);background:#0c0c0c}
.ep{display:flex;align-items:center;padding:10px 16px;border-bottom:1px solid #161616;gap:10px}
.ep:last-child{border-bottom:none}
.ep-method{font-size:10px;font-weight:700;color:var(--dim);width:32px;flex-shrink:0}
.ep-path{font-size:12px;color:#60a5fa;flex:1}
.ep-desc{font-size:11px;color:var(--dim);text-align:right}
.ep-status{font-size:11px;flex-shrink:0}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;align-items:center;justify-content:center}
.modal-box{background:#111;border:1px solid #2a2a2a;border-radius:8px;padding:24px;width:520px;max-width:95vw;max-height:90vh;overflow-y:auto}
.mf{margin-bottom:12px}.mf label{display:block;font-size:11px;color:var(--dim);margin-bottom:4px;letter-spacing:.06em;text-transform:uppercase}
.mf input{width:100%;background:#0a0a0a;border:1px solid #1e1e1e;border-radius:4px;color:var(--t);padding:7px 10px;font-size:12px;font-family:inherit}
.mf input:focus{outline:none;border-color:var(--c)}
.modal-btns{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}
.btn-save{background:var(--c);color:#000;border:none;padding:8px 20px;border-radius:4px;cursor:pointer;font-weight:700;font-size:12px;font-family:inherit}
.btn-cancel-m{background:transparent;color:var(--dim);border:1px solid #2a2a2a;padding:8px 20px;border-radius:4px;cursor:pointer;font-size:12px;font-family:inherit}
</style>`;
function landingPage(host,hasManifest,appCount,hasHealth){
  const s=(cls,icon,title,desc)=>`<div class="step ${cls}"><div class="step-icon">${icon}</div><div class="step-body"><div class="step-title">${title}</div><div class="step-desc">${desc}</div></div></div>`;
  const step3cls=hasManifest?'done':'active';
  const step3icon=hasManifest?'&#10003;':'3';
  const step3desc=hasManifest?`Manifest loaded with <b>${appCount}</b> app${appCount!==1?'s':''} &mdash; <a href="/status" style="color:var(--c)">view status dashboard</a>.`:'Run <b>AppUpdater.ps1</b>, add your first app, and the manifest will be pushed automatically.';
  const step4cls=hasManifest?(hasHealth?'done':'active'):'todo';
  const step4icon=hasManifest&&hasHealth?'&#10003;':'4';
  const step4desc=hasManifest&&hasHealth?'Health checks have run &mdash; URL status visible on the dashboard.':'Run <b>AppUpdater.ps1</b> — paste your installer path when prompted to build a package.';
  const step5cls=hasManifest&&hasHealth?'active':'todo';
  const manifestBadge=hasManifest?'<span class="b live">&#10003; '+appCount+' app'+(appCount!==1?'s':'')+'</span>':'<span class="b pend">No manifest yet</span>';
  const healthBadge=hasHealth?'<span class="b live">&#10003; Live</span>':'<span class="b pend">Pending (hourly)</span>';
  return CSS+`
<title>AppUpdater${hasManifest?' &mdash; '+appCount+' app'+(appCount!==1?'s':'')+' loaded':''}</title>
</head><body>
<div class="bar" style="background:#0a0a0a;border-bottom-color:var(--c)">
  <div class="dot" style="background:var(--c);box-shadow:0 0 8px var(--c)"></div>
  <h1 style="color:var(--c)">AppUpdater Worker</h1>
  <div class="meta">${host}<br>Cloudflare Worker</div>
</div>
<div class="hero">
  <div class="logo">AppUpdater</div>
  <h1>${hasManifest?appCount+' app'+(appCount!==1?'s':'')+' loaded.':'Your Worker is live.'}</h1>
  <p>${hasManifest?'Manifest is active. Update scripts on enrolled devices will fetch from this worker automatically.':'This Cloudflare Worker serves your app manifest and monitors download link health. Run <b>AppUpdater.ps1</b> to finish setup.'}</p>
</div>
<div class="wrap">
  <div class="sh" style="max-width:560px;margin:0 auto 12px"><span>Endpoints</span></div>
  <div class="endpoints">
  <div class="hdr">Available routes</div>
  <div class="ep"><span class="ep-method">GET</span><span class="ep-path">/health</span><span class="ep-desc">Liveness check (JSON)</span><span class="ep-status"><span class="b live">&#10003; Live</span></span></div>
  <div class="ep"><span class="ep-method">GET</span><span class="ep-path">/status</span><span class="ep-desc">App manifest &amp; URL health dashboard</span><span class="ep-status">${manifestBadge}</span></div>
  <div class="ep"><span class="ep-method">GET</span><span class="ep-path">/appVersions.xml</span><span class="ep-desc">Manifest XML served to update scripts</span><span class="ep-status">${manifestBadge}</span></div>
  <div class="ep"><span class="ep-method">GET</span><span class="ep-path">/deploy/{id}</span><span class="ep-desc">Download deploy script for an app</span><span class="ep-status"><span class="b live">&#10003; Ready</span></span></div>
  <div class="ep"><span class="ep-method">POST</span><span class="ep-path">/manifest</span><span class="ep-desc">Upload / replace manifest (auth required)</span><span class="ep-status"><span class="b live">&#10003; Ready</span></span></div>
  <div class="ep"><span class="ep-method">DELETE</span><span class="ep-path">/app/{id}</span><span class="ep-desc">Remove app from manifest (auth required)</span><span class="ep-status"><span class="b live">&#10003; Ready</span></span></div>
  </div>
  <div class="sh" style="max-width:560px;margin:24px auto 12px"><span>Setup progress</span></div>
  <div class="steps">
  ${s('done','&#10003;','Worker deployed','Cloudflare Worker is running and handling requests.')}
  ${s('done','&#10003;','KV storage ready','Key-value store bound &mdash; manifest and health data stored here.')}
  ${s(step3cls,step3icon,'App manifest',step3desc)}
  ${s(step4cls,step4icon,'Build Intune packages',step4desc)}
  ${s(step5cls,'5','Monitor from /status','The <a href="/status" style="color:var(--c)">status dashboard</a> shows all apps, versions, and URL health checks running hourly.')}
  </div>
</div></body></html>`;}
function setupPage(noManifest){
  const msg=noManifest?'Manifest not uploaded yet':'No apps in manifest yet';
  const sub=noManifest?'Run AppUpdater.ps1 and build your first app &mdash; it will be pushed automatically.':'Build your first app with AppUpdater.ps1 and it will appear here.';
  return CSS+`
<title>AppUpdater Status &mdash; Getting Started</title>
</head><body>
<div class="bar" style="background:#0c1a0a;border-bottom-color:var(--y)">
  <div class="dot" style="background:var(--y);box-shadow:0 0 8px var(--y);animation:p 2s infinite"></div>
  <h1 style="color:var(--y)">Waiting for apps</h1>
  <div class="meta">Auto-refreshes every 60s</div>
</div>
<div class="hero">
  <div class="logo">AppUpdater Status</div>
  <h1>${msg}</h1>
  <p>${sub}</p>
</div>
<div class="wrap">
  <div class="cards" style="max-width:560px;margin:0 auto 32px;grid-template-columns:repeat(3,1fr)">
  <div class="card apps"><div class="n" style="color:var(--dim)">0</div><div class="l">Apps</div></div>
  <div class="card"><div class="n" style="color:var(--dim)">0</div><div class="l">Live URLs</div></div>
  <div class="card"><div class="n" style="color:var(--dim)">0</div><div class="l">Dead URLs</div></div>
  </div>
  <div class="sh" style="max-width:560px;margin:0 auto 12px"><span>What to do next</span></div>
  <div class="steps" style="max-width:560px">
  <div class="step done"><div class="step-icon">&#10003;</div><div class="step-body"><div class="step-title">Worker is live</div><div class="step-desc">Cloudflare Worker is running and ready.</div></div></div>
  <div class="step active"><div class="step-icon">2</div><div class="step-body"><div class="step-title">Build your first app package</div><div class="step-desc">Run <b>AppUpdater.ps1</b>, paste your installer path when prompted. Manifest is pushed automatically.</div></div></div>
  <div class="step todo"><div class="step-icon">3</div><div class="step-body"><div class="step-title">This page updates automatically</div><div class="step-desc">Once your first app is built and the manifest pushed, all apps appear here with live URL health status.</div></div></div>
  </div>
</div></body></html>`;}
// -----------------------------------------------------------------------------
// loginPage — shown to anonymous users hitting /status once a password is set.
// -----------------------------------------------------------------------------
function loginPage(err,totpEnabled=false){
  return CSS+`
<title>AppUpdater &mdash; Sign in</title>
</head><body>
<div class="bar" style="background:#0a0a0a;border-bottom-color:var(--c)">
  <div class="dot" style="background:var(--c);box-shadow:0 0 8px var(--c)"></div>
  <h1 style="color:var(--c)">AppUpdater</h1>
  <div class="meta">Sign in to view /status</div>
</div>
<div class="hero">
  <div class="logo">Sign in</div>
  <h1>Enter password</h1>
  <p>This dashboard is password-protected. Sessions last 24 hours.${totpEnabled?' An authenticator code is also required.':''}</p>
</div>
<div class="wrap" style="max-width:420px">
  <form method="POST" action="/login" style="background:var(--s);border:1px solid var(--b);border-radius:8px;padding:22px">
  ${err?`<div style="background:#3f0a0a;border:1px solid #7f1d1d;color:#fca5a5;padding:8px 12px;border-radius:4px;margin-bottom:14px;font-size:12px">${err}</div>`:''}
  <div class="mf"><label>Password</label><input type="password" name="password" autofocus required/></div>
  ${totpEnabled?`<div class="mf"><label>Authenticator code <span style="color:#555;font-size:10px;text-transform:none">(6 digits from your app)</span></label><input type="text" name="otp" inputmode="numeric" maxlength="7" autocomplete="one-time-code" required/></div>`:''}
  <div class="modal-btns" style="margin-top:8px"><button class="btn-save" type="submit" style="padding:10px 24px">Sign in</button></div>
  </form>
</div></body></html>`;}
// -----------------------------------------------------------------------------
// setPasswordPage — first-run flow when no auth_password exists yet.
// -----------------------------------------------------------------------------
function setPasswordPage(err){
  return CSS+`
<title>AppUpdater &mdash; Set password</title>
</head><body>
<div class="bar" style="background:#0c1a0a;border-bottom-color:var(--y)">
  <div class="dot" style="background:var(--y);box-shadow:0 0 8px var(--y);animation:p 2s infinite"></div>
  <h1 style="color:var(--y)">First-run setup</h1>
  <div class="meta">Choose a password to protect /status</div>
</div>
<div class="hero">
  <div class="logo">First-run</div>
  <h1>Set a password</h1>
  <p>This password gates the /status dashboard. Machine pushes from AppUpdater.ps1 keep using the bearer token separately.</p>
</div>
<div class="wrap" style="max-width:460px">
  <form method="POST" action="/set-password" style="background:var(--s);border:1px solid var(--b);border-radius:8px;padding:22px">
  ${err?`<div style="background:#3f0a0a;border:1px solid #7f1d1d;color:#fca5a5;padding:8px 12px;border-radius:4px;margin-bottom:14px;font-size:12px">${err}</div>`:''}
  <div class="mf"><label>New password <span style="color:#555;font-size:10px;text-transform:none">(min 12 chars, letters + digits)</span></label><input type="password" name="password" autofocus required minlength="12"/></div>
  <div class="mf"><label>Confirm password</label><input type="password" name="confirm" required minlength="12"/></div>
  <div class="modal-btns" style="margin-top:8px"><button class="btn-save" type="submit" style="padding:10px 24px">Set password</button></div>
  </form>
</div></body></html>`;}
// =============================================================================
// TOTP MFA — RFC 6238 / HOTP RFC 4226 implemented entirely in Web Crypto.
// Compatible with Google Authenticator, Authy, Microsoft Authenticator,
// YubiKey Authenticator, and any TOTP-compatible app.
// =============================================================================
function b32decode(s){
  const B='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s=s.toUpperCase().replace(/[^A-Z2-7]/g,'');
  let bits='';
  for(const c of s){const i=B.indexOf(c);if(i>=0)bits+=i.toString(2).padStart(5,'0');}
  const out=new Uint8Array(Math.floor(bits.length/8));
  for(let i=0;i<out.length;i++)out[i]=parseInt(bits.slice(i*8,(i+1)*8),2);
  return out;
}
function b32encode(bytes){
  const B='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let r='',buf=0,bits=0;
  for(const b of bytes){buf=(buf<<8)|b;bits+=8;while(bits>=5){r+=B[(buf>>(bits-5))&31];bits-=5;}}
  if(bits>0)r+=B[(buf<<(5-bits))&31];
  return r;
}
function generateTOTPSecret(){return b32encode(crypto.getRandomValues(new Uint8Array(20)));}
// e is optional — when provided, used-code KV tracking closes the 90-second replay window.
// Omit e during initial setup confirmation where replay tracking is not needed.
async function verifyTOTP(secret,code,e){
  try{
    const bytes=b32decode(secret);
    const key=await crypto.subtle.importKey('raw',bytes,{name:'HMAC',hash:'SHA-1'},false,['sign']);
    const now=Math.floor(Date.now()/1000);
    const codeStr=String(code).replace(/\s/g,'').padStart(6,'0');
    for(let d=-1;d<=1;d++){
      const t=Math.floor(now/30)+d;
      const tb=new ArrayBuffer(8);
      new DataView(tb).setUint32(4,t>>>0,false);
      const hmac=new Uint8Array(await crypto.subtle.sign('HMAC',key,tb));
      const off=hmac[19]&0xf;
      const otp=((hmac[off]&0x7f)<<24|hmac[off+1]<<16|hmac[off+2]<<8|hmac[off+3])%1000000;
      if(otp.toString().padStart(6,'0')===codeStr){
        if(e){
          const rk='totp_used:'+codeStr+':'+t;
          try{
            const used=await e.APP_MANIFEST.get(rk);
            if(used)return false;  // replay detected — same code already consumed
            await e.APP_MANIFEST.put(rk,'1',{expirationTtl:90});
          }catch{ /* KV write failed — degrade gracefully, accept login */ }
        }
        return true;
      }
    }
    return false;
  }catch{return false;}
}
// GET /totp-setup — shows current TOTP status or setup flow (auth required)
async function handleTOTPSetupGet(r,e){
  const sess=await verifySession(r,e);
  if(!sess)return secureRedirect('/login',302,clearSessionCookie());
  const active=await e.APP_MANIFEST.get(KV_TOTP);
  if(active)return htmlResponse(totpStatusPage(r.url,false));
  const secret=generateTOTPSecret();
  await e.APP_MANIFEST.put(KV_TOTP_PEND,secret,{expirationTtl:600});
  const oa=`otpauth://totp/AppUpdater?secret=${secret}&issuer=AppUpdater&algorithm=SHA1&digits=6&period=30`;
  return htmlResponse(totpSetupPage(secret,oa,''));
}
// POST /totp-setup — verify a code, then activate the pending secret
async function handleTOTPSetupPost(r,e){
  const sess=await verifySession(r,e);
  if(!sess)return secureRedirect('/login',302,clearSessionCookie());
  const form=await r.formData();
  const code=String(form.get('code')||'').replace(/[\s\-]/g,'');
  const secret=await e.APP_MANIFEST.get(KV_TOTP_PEND);
  if(!secret){const oa=`otpauth://totp/AppUpdater?secret=EXPIRED&issuer=AppUpdater&algorithm=SHA1&digits=6&period=30`;return htmlResponse(totpSetupPage('',oa,'Session expired. <a href="/totp-setup" style="color:var(--c)">Start again.</a>'));}
  const ok=await verifyTOTP(secret,code);
  if(!ok){
    const oa=`otpauth://totp/AppUpdater?secret=${secret}&issuer=AppUpdater&algorithm=SHA1&digits=6&period=30`;
    return htmlResponse(totpSetupPage(secret,oa,'Incorrect code — please try again. Make sure your phone clock is accurate.'),401);
  }
  await e.APP_MANIFEST.put(KV_TOTP,secret);
  await e.APP_MANIFEST.delete(KV_TOTP_PEND);
  return htmlResponse(totpStatusPage(r.url,true));
}
// POST /totp-disable — remove TOTP (auth required)
async function handleTOTPDisable(r,e){
  const sess=await verifySession(r,e);
  if(!sess)return secureRedirect('/login',302,clearSessionCookie());
  await e.APP_MANIFEST.delete(KV_TOTP);
  return secureRedirect('/totp-setup',302);
}
// TOTP setup page — shown when TOTP is not yet configured
// QR code is NOT fetched from any external service. The otpauth:// link opens
// the authenticator app directly on mobile; the manual key is shown for desktop.
function totpSetupPage(secret,otpauth,err){
  return CSS+`
<title>AppUpdater &mdash; Set up MFA</title>
</head><body>
<div class="bar" style="background:#0a0a0a;border-bottom-color:var(--p)">
  <div class="dot" style="background:var(--p);box-shadow:0 0 8px var(--p)"></div>
  <h1 style="color:var(--p)">AppUpdater</h1>
  <div class="meta">Two-factor authentication</div>
</div>
<div class="hero">
  <div class="logo" style="color:var(--p)">Security</div>
  <h1>Set up TOTP MFA</h1>
  <p>Add the key below to Google Authenticator, Authy, Microsoft Authenticator, or any TOTP app, then enter the 6-digit code to verify and activate.</p>
</div>
<div class="wrap" style="max-width:480px">
  ${err?`<div style="background:#3f0a0a;border:1px solid #7f1d1d;color:#fca5a5;padding:10px 14px;border-radius:4px;margin-bottom:16px;font-size:12px">${err}</div>`:''}
  <div style="background:var(--s);border:1px solid var(--b);border-radius:8px;padding:24px;margin-bottom:16px;text-align:center">
    <div style="margin-bottom:14px">
      <a href="${otpauth}" style="display:inline-block;background:#0c1a2e;border:1px solid #1e40af;color:#60a5fa;padding:10px 20px;border-radius:6px;font-size:13px;text-decoration:none">&#128272; Open in authenticator app &rarr;</a>
      <p style="font-size:11px;color:var(--dim);margin-top:8px">On mobile, tap the link above. On desktop, use the key below.</p>
    </div>
    <div style="font-size:11px;color:var(--dim);margin-bottom:6px;text-transform:uppercase;letter-spacing:.08em">Manual entry key</div>
    <div style="font-family:monospace;font-size:15px;color:var(--p);letter-spacing:.18em;word-break:break-all;margin-bottom:8px">${secret}</div>
    <div style="font-size:10px;color:var(--dim)">SHA-1 &nbsp;&middot;&nbsp; 6 digits &nbsp;&middot;&nbsp; 30 s period</div>
  </div>
  <form method="POST" action="/totp-setup" style="background:var(--s);border:1px solid var(--b);border-radius:8px;padding:22px">
    <div class="mf">
      <label>Verification code <span style="color:#555;font-size:10px;text-transform:none">(enter the current 6-digit code from your app)</span></label>
      <input type="text" name="code" inputmode="numeric" maxlength="7" autocomplete="one-time-code" autofocus required
        style="letter-spacing:.3em;font-size:20px;text-align:center;padding:10px"/>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
      <a href="/status" style="color:var(--dim);font-size:12px;text-decoration:none">&#8592; Back to dashboard</a>
      <button class="btn-save" type="submit" style="padding:10px 28px;background:var(--p)">Enable MFA</button>
    </div>
  </form>
</div></body></html>`;}
// TOTP status page — shown when TOTP is already configured
function totpStatusPage(reqUrl,justEnabled){
  return CSS+`
<title>AppUpdater &mdash; MFA</title>
</head><body>
<div class="bar" style="background:#0a0a0a;border-bottom-color:var(--p)">
  <div class="dot" style="background:var(--p);box-shadow:0 0 8px var(--p)"></div>
  <h1 style="color:var(--p)">AppUpdater</h1>
  <div class="meta">Two-factor authentication</div>
</div>
<div class="hero">
  <div class="logo" style="color:var(--p)">Security</div>
  <h1>${justEnabled?'MFA enabled!':'TOTP MFA is active'}</h1>
  <p>${justEnabled?'Your /status dashboard now requires a password <em>and</em> an authenticator code.':'The /status login requires your password plus a 6-digit code from your authenticator app.'}</p>
</div>
<div class="wrap" style="max-width:480px">
  <div style="background:var(--s);border:1px solid #166534;border-radius:8px;padding:22px;margin-bottom:16px;display:flex;gap:14px;align-items:flex-start">
    <div style="font-size:28px;line-height:1;flex-shrink:0">&#x1f512;</div>
    <div>
      <div style="color:var(--g);font-weight:700;margin-bottom:4px">TOTP MFA active</div>
      <div style="font-size:12px;color:var(--dim);line-height:1.5">Compatible with Google Authenticator, Authy, Microsoft Authenticator, and hardware tokens via YubiKey Authenticator.</div>
    </div>
  </div>
  <div style="background:var(--s);border:1px solid var(--b);border-radius:8px;padding:22px">
    <div style="font-size:13px;font-weight:700;color:#e5e7eb;margin-bottom:6px">Disable MFA</div>
    <div style="font-size:12px;color:var(--dim);margin-bottom:14px">Removes the authenticator requirement. Password-only login will resume immediately. Make sure you still know your password before disabling.</div>
    <form method="POST" action="/totp-disable">
      <button type="submit" class="btn-cancel-m" style="border-color:#3f0a0a;color:#ef4444">&#x26a0; Remove TOTP MFA</button>
    </form>
  </div>
  <div style="margin-top:14px;text-align:center">
    <a href="/status" style="color:var(--dim);font-size:12px;text-decoration:none">&#8592; Back to dashboard</a>
  </div>
</div></body></html>`;}

// =============================================================================
// PER-APP EVENT TELEMETRY
// Devices POST to /event after each update run. Auth is HMAC-SHA256 over a
// canonical string; the master secret is in KV (rotated on every Re-deploy).
// Strict input validation, replay window, per-IP + per-app rate limits.
// =============================================================================

// XML-escape every untrusted field before splicing into the drill-down page.
function htmlEscape(s){
  return String(s==null?'':s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
// JS string escape — used for values embedded inside JS string literals in HTML
// onclick attributes. Escapes backslash, single-quote, and double-quote.
function jsEsc(s){return String(s==null?'':s).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"');}
// Canonicalize fields server-side. Kills control chars; caps length.
function evtClean(s,max){
  if(s==null)return '';
  return String(s).replace(/[\x00-\x1f\x7f]/g,'').slice(0,max);
}
// Strip absolute Windows paths from error text before storage (no leaking
// of C:\Users\<name>\… style data into the dashboard or KV).
function evtScrub(s){
  return evtClean(s,200).replace(/[A-Za-z]:\\[^\s'"<>]+/g,'<path>');
}
// Constant-time hex compare so a timing oracle can't recover the HMAC.
function ctEqualHex(a,b){
  if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;
  let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);
  return d===0;
}
async function evtHmacHex(secretB64,msg){
  const key=await crypto.subtle.importKey('raw',b64d(secretB64),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(msg)));
  let hex='';for(let i=0;i<sig.length;i++)hex+=sig[i].toString(16).padStart(2,'0');
  return hex;
}
async function getEventSecret(e){
  // Prefer EVTSEC Worker Secret (set via Secrets API during setup/re-deploy).
  // Fall back to KV for deployments that have not yet been updated.
  return e.EVTSEC||await e.APP_MANIFEST.get(KV_EVT_SEC);
}
async function evtRateLimit(e,appId){
  const k=KV_EVT_RL+appId;
  const cur=parseInt(await e.APP_MANIFEST.get(k)||'0',10);
  if(cur>=EVT_RL_MAX)return true;
  // expirationTtl resets the counter window every EVT_RL_WINDOW seconds
  await e.APP_MANIFEST.put(k,String(cur+1),{expirationTtl:EVT_RL_WINDOW});
  return false;
}
// Per-device rate limit — prevents a single bad device from flooding the rolling log.
async function evtDeviceRateLimit(e,deviceId){
  const k='evtrl:dev:'+deviceId.slice(0,64);
  const cur=parseInt(await e.APP_MANIFEST.get(k)||'0',10);
  if(cur>=EVT_RL_MAX)return true;
  await e.APP_MANIFEST.put(k,String(cur+1),{expirationTtl:EVT_RL_WINDOW});
  return false;
}

// POST /event — body is JSON; auth via X-Event-Timestamp + X-Event-Sig headers.
// Returns 204 on success; never returns information that could aid an oracle.
async function handleEvent(r,e){
  const ip=r.headers.get('CF-Connecting-IP');
  if(!ip)return new Response('',{status:403}); // must route through Cloudflare
  if(await rateLimit(e,ip))return new Response('',{status:429});
  const secret=await getEventSecret(e);
  if(!secret)return new Response('',{status:503});

  const ts=parseInt(r.headers.get('X-Event-Timestamp')||'0',10);
  const sig=r.headers.get('X-Event-Sig')||'';
  const now=Math.floor(Date.now()/1000);
  if(!ts||Math.abs(now-ts)>EVT_TS_SKEW)return new Response('',{status:401});

  const bodyText=await r.text();
  if(bodyText.length>4096)return new Response('',{status:413});

  let body;
  try{body=JSON.parse(bodyText)}catch{return new Response('',{status:400});}

  const appId=evtClean(body.appId,64);
  if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(appId))return new Response('',{status:400});
  const hostname=evtClean(body.hostname,64).replace(/[^A-Za-z0-9._-]/g,'');
  const machineGuid=evtClean(body.machineGuid,40).replace(/[^A-Fa-f0-9-]/g,'');
  const status=evtClean(body.status,16);
  if(!EVT_STATUSES.includes(status))return new Response('',{status:400});
  const version=evtClean(body.version,32).replace(/[^A-Za-z0-9._+-]/g,'');
  const error=body.error?evtScrub(body.error):'';
  const durationMs=Math.max(0,Math.min(86400000,parseInt(body.durationMs||'0',10)||0));

  // Verify HMAC. Canonical string is fixed-order, fixed-separator.
  const canon=ts+'|'+appId+'|'+(machineGuid||hostname)+'|'+bodyText;
  const expected=await evtHmacHex(secret,canon);
  if(!ctEqualHex(sig.toLowerCase(),expected))return new Response('',{status:401});

  // Per-app rate limit (in addition to per-IP).
  if(await evtRateLimit(e,appId))return new Response('',{status:429});

  // Per-device rate limit — prevents a single device from displacing all other entries.
  const deviceKey=(machineGuid||hostname||ip).slice(0,64);
  if(await evtDeviceRateLimit(e,deviceKey))return new Response('',{status:429});

  const evt={ts:now,hostname,version,status,error,durationMs};
  const slot=(machineGuid||hostname||'unknown').slice(0,64);

  // Latest-per-host slot (last-write-wins from this device).
  await e.APP_MANIFEST.put(KV_EVT_HOST+appId+':'+slot,JSON.stringify(evt));

  // Append to rolling per-app log (last EVT_LOG_MAX entries).
  const logKey=KV_EVT_LOG+appId;
  let log=[];
  try{const raw=await e.APP_MANIFEST.get(logKey);if(raw)log=JSON.parse(raw);}catch{log=[];}
  log.push(evt);
  if(log.length>EVT_LOG_MAX)log=log.slice(-EVT_LOG_MAX);
  await e.APP_MANIFEST.put(logKey,JSON.stringify(log));

  return new Response('',{status:204});
}

// GET /app/{id} — authenticated drill-down. No JS; everything escaped.
async function handleAppDetail(r,e,appId){
  const sess=await verifySession(r,e);
  if(!sess){
    const t=r.headers.get('X-Auth-Token');
    if(!t||!ctEqualStr(t,e.AUTH_TOKEN))return secureRedirect('/login',302);
  }
  const id=evtClean(appId,64);
  if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id))return new Response('Invalid app id',{status:400});

  // Pull manifest entry (for display name + advertised version).
  let appName=id,advertised='';
  try{
    const xml=await e.APP_MANIFEST.get(KV_XML)||'';
    const re=new RegExp('<App>[\\s\\S]*?<ID>'+id.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&')+'</ID>[\\s\\S]*?</App>');
    const m=xml.match(re);
    if(m){
      const dn=m[0].match(/<DisplayName>([^<]*)<\/DisplayName>/);if(dn)appName=dn[1];
      const v =m[0].match(/<Version>([^<]*)<\/Version>/);       if(v) advertised=v[1];
    }
  }catch{}

  // Latest-per-host slots.
  const hostList=await e.APP_MANIFEST.list({prefix:KV_EVT_HOST+id+':'});
  const hosts=[];
  for(const k of hostList.keys){
    try{
      const raw=await e.APP_MANIFEST.get(k.name);
      if(raw){const o=JSON.parse(raw);o._slot=k.name.slice((KV_EVT_HOST+id+':').length);hosts.push(o);}
    }catch{}
  }
  hosts.sort((a,b)=>(b.ts||0)-(a.ts||0));

  // Rolling timeline.
  let timeline=[];
  try{const raw=await e.APP_MANIFEST.get(KV_EVT_LOG+id);if(raw)timeline=JSON.parse(raw).reverse();}catch{}

  const fmtTs=t=>t?new Date(t*1000).toISOString().replace('T',' ').slice(0,19)+' UTC':'';
  const statusBadge=s=>{
    const cls={running:'pend',current:'live',installed:'live',error:'dead'}[s]||'na';
    return `<span class="b ${cls}">${htmlEscape(s||'?')}</span>`;
  };

  const hostsRows=hosts.length?hosts.map(h=>`<tr>
    <td><b>${htmlEscape(h.hostname||h._slot||'unknown')}</b></td>
    <td>${statusBadge(h.status)}</td>
    <td>${htmlEscape(h.version||'')}</td>
    <td><small>${fmtTs(h.ts)}</small></td>
    <td>${h.durationMs?htmlEscape(Math.round(h.durationMs/1000)+'s'):''}</td>
    <td><small>${htmlEscape(h.error||'')}</small></td>
  </tr>`).join(''):`<tr><td colspan="6" class="dim" style="text-align:center;padding:24px">No devices have reported yet.</td></tr>`;

  const tlRows=timeline.length?timeline.slice(0,100).map(h=>`<tr>
    <td><small>${fmtTs(h.ts)}</small></td>
    <td>${htmlEscape(h.hostname||'')}</td>
    <td>${statusBadge(h.status)}</td>
    <td>${htmlEscape(h.version||'')}</td>
    <td><small>${htmlEscape(h.error||'')}</small></td>
  </tr>`).join(''):'';

  return htmlResponse(CSS+`
<title>AppUpdater — ${htmlEscape(appName)}</title>
</head><body>
<div class="bar" style="background:#0a0a0a;border-bottom-color:var(--c)">
  <div class="bar-in">
  <div class="dot" style="background:var(--c);box-shadow:0 0 8px var(--c)"></div>
  <h1 style="color:var(--c)">${htmlEscape(appName)}</h1>
  <div class="meta">App ID: ${htmlEscape(id)}${advertised?'<br>Manifest version: '+htmlEscape(advertised):''}</div>
  </div>
</div>
<div class="wrap">
  <div style="margin-bottom:14px"><a href="/status" style="color:var(--c);font-size:12px;text-decoration:none">&#8592; Back to dashboard</a></div>

  <div class="sh"><span>Devices &mdash; latest status</span><small>${hosts.length} reporting</small></div>
  <table>
    <colgroup><col style="width:24%"><col style="width:11%"><col style="width:14%"><col style="width:18%"><col style="width:8%"><col style="width:25%"></colgroup>
    <thead><tr><th>Hostname</th><th>Status</th><th>Version</th><th>Last seen</th><th>Run</th><th>Last error</th></tr></thead>
    <tbody>${hostsRows}</tbody>
  </table>

  <div class="sh" style="margin-top:24px"><span>Timeline (last ${Math.min(timeline.length,100)} events)</span><small>${timeline.length} total</small></div>
  ${timeline.length?`<table>
    <colgroup><col style="width:18%"><col style="width:22%"><col style="width:11%"><col style="width:14%"><col style="width:35%"></colgroup>
    <thead><tr><th>When</th><th>Host</th><th>Status</th><th>Version</th><th>Error</th></tr></thead>
    <tbody>${tlRows}</tbody>
  </table>`:'<div class="dim" style="text-align:center;padding:24px">No timeline yet.</div>'}
</div></body></html>`);
}
'@

# =============================================================================
# STRUCTURED LOGGER — Write-AppLog drives a persistent on-disk audit log;
# Write-* helpers preserve the legacy call sites used throughout the script.
# In hidden-console (WPF-only) mode they no-op visually; in runspaces they
# are re-stubbed to enqueue progress lines for the WPF progress windows.
# =============================================================================
function Write-AppLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG')][string] $Level = 'INFO'
  )
  try {
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = '{0} [{1}] {2}' -f $ts, $Level, $Message
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
  } catch { }   # never let logging fail the caller
}

function Write-OK   { param([string]$m) try { Write-Host "  [OK]  $m" -ForegroundColor Green  } catch {}; Write-AppLog $m INFO }
function Write-Warn { param([string]$m) try { Write-Host "  [!!]  $m" -ForegroundColor Yellow } catch {}; Write-AppLog $m WARN }
function Write-Fail { param([string]$m) try { Write-Host "  [XX]  $m" -ForegroundColor Red    } catch {}; Write-AppLog $m ERROR }
function Write-Info { param([string]$m) try { Write-Host "  [--]  $m" -ForegroundColor Cyan   } catch {}; Write-AppLog $m INFO }
function Write-Step { param([string]$n,[string]$m) try { Write-Host "  [$n] $m" -ForegroundColor White } catch {}; Write-AppLog "[$n] $m" INFO }
function Write-Rule    { try { Write-Host ('  ' + ('-' * 68)) -ForegroundColor DarkGray } catch {} }
function Write-BoxTop  { param($C=[ConsoleColor]::DarkGray) try { Write-Host ('  +' + ('-' * 68) + '+') -ForegroundColor $C } catch {} }
function Write-BoxBot  { param($C=[ConsoleColor]::DarkGray) try { Write-Host ('  +' + ('-' * 68) + '+') -ForegroundColor $C } catch {} }
function Write-BoxLine { param([string]$m,$C=[ConsoleColor]::Gray) try { Write-Host "  | $m" -ForegroundColor $C } catch {} }

# =============================================================================
# INPUT VALIDATION — applied at every external-input boundary.
# =============================================================================
function Test-SafeAppId {
  # AppID becomes a folder name, scheduled-task name, registry path component
  # and shortcut filename. Restrict to a conservative ASCII set.
  param([string]$Value)
  return ($Value -and $Value -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
}
function Test-SafeFileName {
  param([string]$Value)
  if (-not $Value) { return $false }
  if ($Value -match '[\\/:*?"<>|]')   { return $false }
  if ($Value -match '^(\.|\.\.)$')    { return $false }
  return $true
}
function Test-SafeHttpsUrl {
  # Allow only https:// URLs with a non-empty host. http:// is rejected to
  # prevent downgrade attacks on installer downloads.
  param([string]$Value)
  if (-not $Value) { return $false }
  $u = $null
  if (-not [Uri]::TryCreate($Value,[UriKind]::Absolute,[ref]$u)) { return $false }
  return ($u.Scheme -eq 'https' -and $u.Host)
}
function Test-SafeSubdomainLabel {
  # DNS label per RFC 1035 + commonly-used hyphens.
  param([string]$Value)
  return ($Value -cmatch '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
}
function ConvertTo-SafeFsName {
  # Aggressive sanitiser for paths derived from app metadata.
  param([string]$Value, [string]$Default = 'app')
  if (-not $Value) { return $Default }
  $clean = ($Value -replace '[^A-Za-z0-9._-]','_').Trim('_','.')
  if (-not $clean) { return $Default }
  if ($clean.Length -gt 64) { $clean = $clean.Substring(0,64) }
  return $clean
}
function Resolve-SafeChildPath {
  # Joins a parent and child path, then refuses results that escape the
  # parent (defence in depth for paths derived from manifest content).
  param(
    [Parameter(Mandatory)][string] $Parent,
    [Parameter(Mandatory)][string] $Child
  )
  $combined   = [System.IO.Path]::GetFullPath((Join-Path $Parent $Child))
  $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\','/')
  $parentRoot = $parentFull + [System.IO.Path]::DirectorySeparatorChar
  $isInside = $combined.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
              $combined.StartsWith($parentRoot, [StringComparison]::OrdinalIgnoreCase)
  if (-not $isInside) {
    throw "Path traversal blocked: '$Child' escapes '$Parent'."
  }
  return $combined
}

# =============================================================================
# DOWNLOAD INTEGRITY HELPERS
# Verify Authenticode signatures and SHA-256 hashes for all downloaded binaries
# before they are executed. Files that fail verification are deleted immediately.
# =============================================================================
function Test-DownloadAuthenticode {
  param(
    [Parameter(Mandatory)][string] $FilePath,
    [string] $ExpectedPublisher = ''
  )
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
  } catch {
    Remove-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    throw "Could not check Authenticode signature for '$(Split-Path $FilePath -Leaf)': $($_.Exception.Message). File removed."
  }
  if ($sig.Status -ne 'Valid') {
    Remove-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    throw "Authenticode verification FAILED for '$(Split-Path $FilePath -Leaf)'. Status: $($sig.Status). File removed."
  }
  if ($ExpectedPublisher) {
    $subj = $sig.SignerCertificate.Subject
    if ($subj -notmatch [regex]::Escape($ExpectedPublisher)) {
      Remove-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
      throw "Unexpected publisher for '$(Split-Path $FilePath -Leaf)': '$subj'. Expected '$ExpectedPublisher'. File removed."
    }
  }
  Write-AppLog "Authenticode OK: $(Split-Path $FilePath -Leaf) (Publisher: $($sig.SignerCertificate.Subject))" INFO
}

function Test-DownloadHash {
  param(
    [Parameter(Mandatory)][string] $FilePath,
    [Parameter(Mandatory)][string] $ExpectedSha256
  )
  $actual = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
  if ($actual -ne $ExpectedSha256.ToUpper()) {
    Remove-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    throw "SHA-256 mismatch for '$(Split-Path $FilePath -Leaf)'.`nExpected: $($ExpectedSha256.ToUpper())`nActual:   $actual`nFile removed."
  }
  Write-AppLog "SHA-256 OK: $(Split-Path $FilePath -Leaf)" INFO
}

# =============================================================================
# WPF UI LAYER
# =============================================================================
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# Explicit Application object required: prevents WPF auto-exit during the
# zero-open-windows gap between menu close and next window open.
# OnExplicitShutdown: never auto-exit; only exit when we call Shutdown().
if (-not [System.Windows.Application]::Current) {
  $script:_WpfApp = [System.Windows.Application]::new()
  $script:_WpfApp.ShutdownMode = [System.Windows.ShutdownMode]::OnExplicitShutdown
} else {
  [System.Windows.Application]::Current.ShutdownMode = [System.Windows.ShutdownMode]::OnExplicitShutdown
}

# =============================================================================
# CREDENTIAL MANAGER HELPERS — the bearer token is stored in Windows Credential
# Manager (Target = 'AppUpdater-ManifestToken', Type = Generic, Persist =
# LocalMachine).  Any local Administrator can read the entry; standard users
# cannot.  This replaces the earlier DPAPI + .manifest-token file approach.
#
# Migration: if an old DPAPI-protected .manifest-token file or config entry is
# found at startup, Invoke-TokenFileMigration re-saves it to Credential Manager
# automatically and deletes the legacy file.
# =============================================================================
$script:_DpapiPrefix  = 'DPAPI:'   # kept for migration detection
$script:_CredMgrSentinel = 'CREDMGR'  # stored in config to indicate Cred Mgr use

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WinCredManager {
    [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredWrite([In] ref CREDENTIAL cred, [In] uint flags);

    [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredRead(string target, uint type, uint flags, out IntPtr credPtr);

    [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern void CredFree([In] IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public const uint CRED_TYPE_GENERIC        = 1;
    public const uint CRED_PERSIST_LOCAL_MACHINE = 2;

    public static bool Write(string target, string username, string secret) {
        byte[] blob = Encoding.Unicode.GetBytes(secret);
        var c = new CREDENTIAL {
            Type             = CRED_TYPE_GENERIC,
            TargetName       = target,
            CredentialBlobSize = (uint)blob.Length,
            CredentialBlob   = Marshal.AllocHGlobal(blob.Length),
            Persist          = CRED_PERSIST_LOCAL_MACHINE,
            UserName         = username
        };
        try {
            Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length);
            return CredWrite(ref c, 0);
        } finally { Marshal.FreeHGlobal(c.CredentialBlob); }
    }

    public static string Read(string target) {
        IntPtr ptr;
        if (!CredRead(target, CRED_TYPE_GENERIC, 0, out ptr)) return null;
        try {
            var c = Marshal.PtrToStructure<CREDENTIAL>(ptr);
            if (c.CredentialBlobSize == 0) return null;
            byte[] blob = new byte[c.CredentialBlobSize];
            Marshal.Copy(c.CredentialBlob, blob, 0, blob.Length);
            return Encoding.Unicode.GetString(blob);
        } finally { CredFree(ptr); }
    }

    public static bool Delete(string target) {
        return CredDelete(target, CRED_TYPE_GENERIC, 0);
    }
}
'@ -ErrorAction SilentlyContinue

function Protect-ManifestToken {
  # Writes token to Windows Credential Manager; returns the sentinel 'CREDMGR'
  # to be persisted in the config JSON (no sensitive data in the config file).
  # Falls back to DPAPI if Credential Manager is unavailable.
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string] $Token)
  if ([string]::IsNullOrEmpty($Token)) { return $Token }
  try {
    $ok = [WinCredManager]::Write('AppUpdater-ManifestToken', 'AppUpdater', $Token)
    if (-not $ok) { throw "CredWrite returned false (Win32Error=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
    return $script:_CredMgrSentinel
  } catch {
    Write-AppLog "Credential Manager write failed — falling back to DPAPI: $($_.Exception.Message)" WARN
    try {
      Add-Type -AssemblyName System.Security -ErrorAction Stop
      $cipher = [System.Security.Cryptography.ProtectedData]::Protect(
        [System.Text.Encoding]::UTF8.GetBytes($Token), $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
      return $script:_DpapiPrefix + [Convert]::ToBase64String($cipher)
    } catch {
      Write-AppLog "DPAPI fallback also failed: $($_.Exception.Message)" ERROR
      return $Token
    }
  }
}

function Unprotect-ManifestToken {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string] $Stored)
  if ([string]::IsNullOrEmpty($Stored)) { return '' }
  # New path: Credential Manager sentinel
  if ($Stored -eq $script:_CredMgrSentinel) {
    try {
      $val = [WinCredManager]::Read('AppUpdater-ManifestToken')
      if ($val) { return $val }
      Write-AppLog "Credential Manager entry 'AppUpdater-ManifestToken' not found." ERROR
    } catch { Write-AppLog "Credential Manager read failed: $($_.Exception.Message)" ERROR }
    return ''
  }
  # Migration path: DPAPI blob from older installs
  if ($Stored.StartsWith($script:_DpapiPrefix)) {
    try {
      Add-Type -AssemblyName System.Security -ErrorAction Stop
      $b64   = $Stored.Substring($script:_DpapiPrefix.Length)
      $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        [Convert]::FromBase64String($b64), $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
      return [System.Text.Encoding]::UTF8.GetString($plain)
    } catch {
      Write-AppLog "DPAPI Unprotect failed: $($_.Exception.Message)" ERROR
      return ''
    }
  }
  # Legacy plaintext — pass through so migration can re-protect it
  return $Stored
}

function Get-StoredManifestToken {
  # Returns '' (never $null) so callers can use the value directly.
  # Checks Credential Manager first, then config file (handles migration).
  [CmdletBinding()] param()
  try {
    $val = [WinCredManager]::Read('AppUpdater-ManifestToken')
    if ($val) { return $val }
  } catch { Write-AppLog "Credential Manager read in Get-StoredManifestToken failed: $($_.Exception.Message)" WARN }
  # Fallback: read via config ManifestToken field (covers DPAPI migration path)
  if (Test-Path -LiteralPath $script:ConfigFile -PathType Leaf) {
    try {
      $cfg = Get-Content -LiteralPath $script:ConfigFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction SilentlyContinue
      if ($cfg -and $cfg.ManifestToken -and $cfg.ManifestToken -ne $script:_CredMgrSentinel) {
        return Unprotect-ManifestToken ([string]$cfg.ManifestToken)
      }
    } catch { Write-AppLog "Config read in Get-StoredManifestToken failed: $($_.Exception.Message)" WARN }
  }
  # Legacy: .manifest-token file
  if (Test-Path -LiteralPath $script:ManifestTokenFile -PathType Leaf) {
    try {
      $raw = (Get-Content -LiteralPath $script:ManifestTokenFile -Raw -ErrorAction Stop).Trim()
      return Unprotect-ManifestToken $raw
    } catch { Write-AppLog "Read manifest token file failed: $($_.Exception.Message)" ERROR }
  }
  return ''
}

function Invoke-TokenFileMigration {
  # One-time startup migration:
  #   1. Migrate any DPAPI-protected or plaintext token from the legacy
  #      .manifest-token file or config JSON into Windows Credential Manager.
  #   2. Apply SYSTEM+Admins-only ACL to the config file.
  #   3. Delete the legacy .manifest-token file once migrated.
  # Runs silently — failures are logged but never surfaced to the user.
  [CmdletBinding()] param()

  # Harden ACL on config file
  if (Test-Path -LiteralPath $script:ConfigFile -PathType Leaf) {
    try {
      $acl = icacls $script:ConfigFile 2>$null | Out-String
      if ($acl -notmatch 'NT AUTHORITY\\SYSTEM') {
        icacls $script:ConfigFile /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(F)" /grant:r "BUILTIN\Administrators:(F)" 2>&1 | Out-Null
        Write-AppLog "ACL hardened: $script:ConfigFile" INFO
      }
    } catch { Write-AppLog "ACL migration failed for config: $($_.Exception.Message)" WARN }
  }

  # Migrate legacy .manifest-token file → Credential Manager
  if (Test-Path -LiteralPath $script:ManifestTokenFile -PathType Leaf) {
    try {
      $raw = (Get-Content -LiteralPath $script:ManifestTokenFile -Raw -ErrorAction Stop).Trim()
      if ($raw) {
        $plain = Unprotect-ManifestToken $raw   # handles both DPAPI: and plaintext
        if ($plain) {
          $ok = [WinCredManager]::Write('AppUpdater-ManifestToken', 'AppUpdater', $plain)
          if ($ok) {
            Write-AppLog "Token migrated from .manifest-token file to Windows Credential Manager." INFO
            Remove-Item -LiteralPath $script:ManifestTokenFile -Force -ErrorAction SilentlyContinue
          } else {
            Write-AppLog "Credential Manager write failed during migration — legacy file retained." WARN
          }
        }
      }
    } catch { Write-AppLog "Token file migration failed: $($_.Exception.Message)" WARN }
  }

  # Migrate config file: if ManifestToken is a DPAPI blob, re-write as CREDMGR sentinel
  if (Test-Path -LiteralPath $script:ConfigFile -PathType Leaf) {
    try {
      $cfg = Get-Content -LiteralPath $script:ConfigFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction SilentlyContinue
      if ($cfg -and $cfg.ManifestToken -and $cfg.ManifestToken -ne $script:_CredMgrSentinel) {
        $plain = Unprotect-ManifestToken ([string]$cfg.ManifestToken)
        if ($plain) {
          $ok = [WinCredManager]::Write('AppUpdater-ManifestToken', 'AppUpdater', $plain)
          if ($ok) {
            $cfg.ManifestToken = $script:_CredMgrSentinel
            $cfg | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ConfigFile -Encoding UTF8 -Force
            Write-AppLog "Config ManifestToken migrated to Credential Manager sentinel." INFO
          }
        }
      }
    } catch { Write-AppLog "Config token migration failed: $($_.Exception.Message)" WARN }
  }
}

function New-WpfWin {
  <#
    Loads a XAML string into a WPF Window. Must be called from an STA thread
    (WPF requirement). On parse failure, walks the inner-exception chain to
    surface the root cause, logs it, and shows an error dialog.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Xaml)

  if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Write-AppLog 'New-WpfWin called from non-STA thread — refusing.' WARN
    return $null
  }
  try {
    $clean = $Xaml.TrimStart([char]0xFEFF).Replace("`r`n","`n").Trim()
    $doc = [xml]$clean
    return [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $doc))
  } catch {
    $msgs = @(); $ex = $_.Exception
    while ($ex) { $msgs += $ex.Message; $ex = $ex.InnerException }
    $root = if ($msgs) { $msgs[-1] } else { 'Unknown XAML error.' }
    Write-AppLog "XAML load failed: $root" ERROR
    Show-WpfMsg -Title 'Interface Error' -Message "Could not load window.`n`nRoot cause: $root" -Type 'error'
    return $null
  }
}

function Get-El {
  <#
    Resolves a list of x:Name'd controls on a window into a hashtable.
    Returns @{} for a $null window so callers don't need a null guard.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory,Position=0)] $Window,
    [Parameter(Mandatory,Position=1)][string[]] $Names
  )
  $map = @{}
  if (-not $Window) { return $map }
  foreach ($n in $Names) { $map[$n] = $Window.FindName($n) }
  return $map
}

# ---------------------------------------------------------------------------
# Shared XAML styles — injected into every window
# ---------------------------------------------------------------------------
$S = @'
  <Window.Resources>

  <!-- Standard button -->
  <Style x:Key="Btn" TargetType="Button">
  <Setter Property="Background"  Value="#1c1c2e"/>
  <Setter Property="Foreground"  Value="#9999bb"/>
  <Setter Property="BorderBrush"  Value="#2e2e45"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding"  Value="16,10"/>
  <Setter Property="FontSize"  Value="13"/>
  <Setter Property="FontFamily"  Value="Segoe UI"/>
  <Setter Property="Cursor"  Value="Hand"/>
  <Setter Property="Template"><Setter.Value>
  <ControlTemplate TargetType="Button">
  <Border x:Name="bd" Background="{TemplateBinding Background}"
  BorderBrush="{TemplateBinding BorderBrush}"
  BorderThickness="{TemplateBinding BorderThickness}"
  CornerRadius="7" Padding="{TemplateBinding Padding}">
  <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
  VerticalAlignment="Center"/>
  </Border>
  <ControlTemplate.Triggers>
  <Trigger Property="IsMouseOver" Value="True">
  <Setter TargetName="bd" Property="Background" Value="#26263e"/>
  <Setter TargetName="bd" Property="BorderBrush" Value="#3e3e5e"/>
  </Trigger>
  <Trigger Property="IsPressed" Value="True">
  <Setter TargetName="bd" Property="Background" Value="#101018"/>
  </Trigger>
  <Trigger Property="IsEnabled" Value="False">
  <Setter Property="Opacity" Value="0.3"/>
  </Trigger>
  </ControlTemplate.Triggers>
  </ControlTemplate>
  </Setter.Value></Setter>
  </Style>

  <!-- Blue accent button -->
  <Style x:Key="BtnPrimary" TargetType="Button" BasedOn="{StaticResource Btn}">
  <Setter Property="Background"  Value="#1a2a3a"/>
  <Setter Property="Foreground"  Value="#6baadf"/>
  <Setter Property="BorderBrush" Value="#2a4a6a"/>
  </Style>

  <!-- Green accent button -->
  <Style x:Key="BtnSuccess" TargetType="Button" BasedOn="{StaticResource Btn}">
  <Setter Property="Background"  Value="#1a3a1a"/>
  <Setter Property="Foreground"  Value="#4ec94e"/>
  <Setter Property="BorderBrush" Value="#2a5a2a"/>
  </Style>


  <!-- Text field -->
  <Style x:Key="Field" TargetType="TextBox">
  <Setter Property="Background"  Value="#0c0c18"/>
  <Setter Property="Foreground"  Value="#ddddee"/>
  <Setter Property="CaretBrush"  Value="#6baadf"/>
  <Setter Property="BorderBrush"  Value="#2e2e45"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding"  Value="10,0"/>
  <Setter Property="FontSize"  Value="13"/>
  <Setter Property="FontFamily"  Value="Segoe UI"/>
  <Setter Property="Template"><Setter.Value>
  <ControlTemplate TargetType="TextBox">
  <Border Background="{TemplateBinding Background}"
  BorderBrush="{TemplateBinding BorderBrush}"
  BorderThickness="{TemplateBinding BorderThickness}"
  CornerRadius="6">
  <ScrollViewer x:Name="PART_ContentHost"
  Margin="{TemplateBinding Padding}"
  VerticalAlignment="Center"/>
  </Border>
  <ControlTemplate.Triggers>
  <Trigger Property="IsFocused" Value="True">
  <Setter Property="BorderBrush" Value="#4a6a9a"/>
  </Trigger>
  </ControlTemplate.Triggers>
  </ControlTemplate>
  </Setter.Value></Setter>
  </Style>

  <!-- Password field -->
  <Style x:Key="PwField" TargetType="PasswordBox">
  <Setter Property="Background"  Value="#0c0c18"/>
  <Setter Property="Foreground"  Value="#ddddee"/>
  <Setter Property="CaretBrush"  Value="#6baadf"/>
  <Setter Property="BorderBrush"  Value="#2e2e45"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding"  Value="10,0"/>
  <Setter Property="FontSize"  Value="13"/>
  </Style>

  <!-- Field label -->
  <Style TargetType="Label">
  <Setter Property="Foreground"  Value="#55557a"/>
  <Setter Property="FontSize"  Value="11"/>
  <Setter Property="FontFamily"  Value="Segoe UI"/>
  <Setter Property="Padding"  Value="2,0,0,5"/>
  </Style>

  <!-- Danger (destructive) button -->
  <Style x:Key="BtnDanger" TargetType="Button">
    <Setter Property="Background" Value="#3a1a1a"/>
    <Setter Property="Foreground" Value="#ff6060"/>
    <Setter Property="BorderBrush" Value="#5a2a2a"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="12,6"/>
    <Setter Property="FontSize" Value="12"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Button">
          <Border x:Name="bdDgr" Background="{TemplateBinding Background}"
                  BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}"
                  CornerRadius="6" Padding="{TemplateBinding Padding}">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="bdDgr" Property="Background" Value="#5a1a1a"/>
              <Setter TargetName="bdDgr" Property="BorderBrush" Value="#aa3333"/>
              <Setter Property="Foreground" Value="#ff9090"/>
            </Trigger>
            <Trigger Property="IsPressed" Value="True">
              <Setter TargetName="bdDgr" Property="Background" Value="#7a1a1a"/>
            </Trigger>
            <Trigger Property="IsEnabled" Value="False">
              <Setter TargetName="bdDgr" Property="Background" Value="#1a1a1a"/>
              <Setter Property="Foreground" Value="#444"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <!-- Card-style button (info / blue accent) — used by modal "choose one" dialogs -->
  <Style x:Key="BtnCardInfo" TargetType="Button">
    <Setter Property="Background" Value="#101820"/>
    <Setter Property="BorderBrush" Value="#1e3a5f"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="16,12"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
    <Setter Property="VerticalContentAlignment" Value="Center"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Button">
          <Border x:Name="bdCi" Background="{TemplateBinding Background}"
                  BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}"
                  CornerRadius="7" Padding="{TemplateBinding Padding}">
            <ContentPresenter HorizontalAlignment="Stretch" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="bdCi" Property="Background" Value="#16243a"/>
              <Setter TargetName="bdCi" Property="BorderBrush" Value="#2a5080"/>
            </Trigger>
            <Trigger Property="IsPressed" Value="True">
              <Setter TargetName="bdCi" Property="Background" Value="#0a1018"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <!-- Card-style button (danger / red accent) — used by modal "choose one" dialogs -->
  <Style x:Key="BtnCardDanger" TargetType="Button">
    <Setter Property="Background" Value="#1a0a0a"/>
    <Setter Property="BorderBrush" Value="#4a1a1a"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="16,12"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
    <Setter Property="VerticalContentAlignment" Value="Center"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Button">
          <Border x:Name="bdCd" Background="{TemplateBinding Background}"
                  BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}"
                  CornerRadius="7" Padding="{TemplateBinding Padding}">
            <ContentPresenter HorizontalAlignment="Stretch" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="bdCd" Property="Background" Value="#2a0e0e"/>
              <Setter TargetName="bdCd" Property="BorderBrush" Value="#7a2a2a"/>
            </Trigger>
            <Trigger Property="IsPressed" Value="True">
              <Setter TargetName="bdCd" Property="Background" Value="#3a0a0a"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  </Window.Resources>
'@

# ---------------------------------------------------------------------------
# Get-HeaderXaml — consistent title bar for all windows
# $showBack  : include ‹ back button
# $showClose : include ✕ close button
# $showBadge : include gradient U badge (first-run / main menu)
# ---------------------------------------------------------------------------
function Get-HeaderXaml {
  param(
  [string]$title,
  [string]$sub  = '',
  [bool]  $showBack  = $false,
  [bool]  $showClose = $true,
  [bool]  $showBadge = $false,
  [bool]  $showMinimize = $false
  )
  $badge = if ($showBadge) { @'
  <Border Width="42" Height="42" CornerRadius="9" Margin="0,0,13,0" VerticalAlignment="Center">
  <Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
  <GradientStop Color="#00b4d8" Offset="0"/>
  <GradientStop Color="#7c3aed" Offset="1"/>
  </LinearGradientBrush></Border.Background>
  <TextBlock Text="U" FontSize="21" FontWeight="Bold" Foreground="White"
  HorizontalAlignment="Center" VerticalAlignment="Center"/>
  </Border>
'@ } else { '' }

  $subLine = if ($sub) { "<TextBlock x:Name=`"WinSub`" Text=`"$sub`" FontSize=`"11`" Foreground=`"#44445a`" Margin=`"0,3,0,0`"/>" } else { '' }

  $backBtn = if ($showBack) { @'
  <Button x:Name="BtnBack" Width="34" Height="34" Cursor="Hand" ToolTip="Back"
    Margin="0,0,2,0" Padding="0" Background="Transparent"
    BorderBrush="Transparent" BorderThickness="0"
    Foreground="#6666aa" FontSize="19" FontWeight="Light">
    <Button.Template><ControlTemplate TargetType="Button">
      <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6"
              Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd" Property="Background" Value="#2a2a44"/>
          <Setter Property="Foreground" Value="#ccccee"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate></Button.Template>
    <TextBlock Text="&#8249;" FontSize="20" FontWeight="Light"
               HorizontalAlignment="Center" VerticalAlignment="Center"/>
  </Button>
'@ } else { '' }

  $closeBtn = if ($showClose) { @'
  <Button x:Name="BtnClose" Width="34" Height="34" Cursor="Hand" ToolTip="Close"
    Padding="0" Background="Transparent"
    BorderBrush="Transparent" BorderThickness="0"
    Foreground="#6666aa">
    <Button.Template><ControlTemplate TargetType="Button">
      <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6"
              Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd" Property="Background" Value="#5a1a1a"/>
          <Setter Property="Foreground" Value="#ff6060"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate></Button.Template>
    <TextBlock Text="&#10005;" FontSize="11"
               HorizontalAlignment="Center" VerticalAlignment="Center"/>
  </Button>
'@ } else { '' }


  $minimizeBtn = if ($showMinimize) { @'
  <Button x:Name="BtnMinimize" Width="34" Height="34" Cursor="Hand" ToolTip="Minimise"
    Padding="0" Background="Transparent"
    BorderBrush="Transparent" BorderThickness="0"
    Foreground="#6666aa">
    <Button.Template><ControlTemplate TargetType="Button">
      <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6"
              Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd" Property="Background" Value="#2a2a44"/>
          <Setter Property="Foreground" Value="#ccccee"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate></Button.Template>
    <TextBlock Text="&#8722;" FontSize="14"
               HorizontalAlignment="Center" VerticalAlignment="Center"/>
  </Button>
'@ } else { '' }
  return @"
  <Border x:Name="TitleBar" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74">
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="Auto"/>
  </Grid.ColumnDefinitions>

  <!-- Left: badge + title -->
  <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="20,0">
  $badge
  <StackPanel VerticalAlignment="Center">
  <TextBlock Text="$title" FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4"/>
  $subLine
  </StackPanel>
  </StackPanel>

  <!-- Right: back + close -->
  <StackPanel Grid.Column="1" Orientation="Horizontal"
  VerticalAlignment="Center" Margin="0,0,12,0">
  $backBtn
  $minimizeBtn
  $closeBtn
  </StackPanel>

  </Grid>
  </Border>
"@
}

# ---------------------------------------------------------------------------
# Set-WinBehavior — wires the standard chrome controls (drag from titlebar,
# close, back, minimise). Called once per window after instantiation.
# ---------------------------------------------------------------------------
function Set-WinBehavior {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] $Window,
    [scriptblock] $OnClose = $null,
    [scriptblock] $OnBack  = $null
  )
  if (-not $Window) { return }
  $titleBar = $Window.FindName('TitleBar')
  if ($titleBar) {
    $titleBar.Add_MouseLeftButtonDown({
      $cur = $_.OriginalSource
      $isBtn = $false
      while ($null -ne $cur -and $cur -ne $titleBar) {
        if ($cur -is [System.Windows.Controls.Button]) { $isBtn = $true; break }
        try { $cur = [System.Windows.Media.VisualTreeHelper]::GetParent($cur) } catch { break }
      }
      if (-not $isBtn) { try { $Window.DragMove() } catch {} }
    }.GetNewClosure())
  }

  $closeBtn = $Window.FindName('BtnClose')
  if ($closeBtn) {
    $handler = if ($OnClose) { $OnClose } else { { $Window.Close() }.GetNewClosure() }
    $closeBtn.Add_Click($handler)
  }
  $backBtn = $Window.FindName('BtnBack')
  if ($backBtn) {
    $handler = if ($OnBack) { $OnBack } else { { $Window.Close() }.GetNewClosure() }
    $backBtn.Add_Click($handler)
  }
  $minBtn = $Window.FindName('BtnMinimize')
  if ($minBtn) {
    $minBtn.Add_Click({ $Window.WindowState = [System.Windows.WindowState]::Minimized }.GetNewClosure())
  }
}

# =============================================================================
# Show-WpfMsg — themed modal dialog. Returns $true when the primary button is
# pressed; $false on cancel / close. Use -Confirm to render a Cancel button.
# All caller-supplied strings are XML-escaped before splicing into the XAML
# template so titles or messages can never inject markup.
# =============================================================================
function Show-WpfMsg {
  [CmdletBinding()]
  param(
    [string] $Title    = 'AppUpdater',
    [string] $Message  = '',
    [string] $Detail   = '',
    [ValidateSet('info','success','warn','error')][string] $Type = 'info',
    [string] $YesLabel = 'OK',
    [string] $NoLabel  = 'Cancel',
    [switch] $Confirm,
    [object] $Owner    = $null
  )

  $palette = @{
    info    = @('#1a2a3a','#2a4a6a','#6baadf')
    success = @('#1a3a1a','#2a5a2a','#4ec94e')
    warn    = @('#2a2a18','#4a4a28','#f5c842')
    error   = @('#3a1a1a','#6a2a2a','#ff6060')
  }
  $colours = $palette[$Type]
  $esc = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }

  $confirmBlock = if ($Confirm) {
    '<Button x:Name="BtnNo" Content="{0}" Style="{{StaticResource Btn}}" MinWidth="100" Padding="14,0" Margin="0,0,8,0"/>' -f (& $esc $NoLabel)
  } else { '' }

  $detailBlock = if ($Detail) {
    '<TextBlock Text="{0}" FontSize="11" Foreground="#9999bb" Margin="20,4,20,0" TextWrapping="Wrap"/>' -f (& $esc $Detail)
  } else { '' }

  $template = @'
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  ResizeMode="NoResize" SizeToContent="WidthAndHeight" MinWidth="380" MaxWidth="520"
  WindowStartupLocation="CenterScreen" Background="#0f0f1a" FontFamily="Segoe UI">
__STYLES__
  <StackPanel>
    <Border x:Name="TitleBar" Background="__BG__" BorderBrush="__BR__" BorderThickness="0,0,0,1" Padding="20,0">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock Text="__TITLE__" FontSize="14" FontWeight="SemiBold" Foreground="__FG__"
                   TextWrapping="Wrap" VerticalAlignment="Center" Margin="0,14"/>
        <Button x:Name="BtnClose" Grid.Column="1" Width="34" Height="34" Cursor="Hand" ToolTip="Close"
          Background="Transparent" BorderBrush="Transparent" BorderThickness="0" Foreground="__FG__"
          VerticalAlignment="Center" Margin="0,0,6,0">
          <TextBlock Text="&#10005;" FontSize="11" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Button>
      </Grid>
    </Border>
    <TextBlock Text="__BODY__" FontSize="13" Foreground="#bbbbcc" Margin="20,16,20,0" TextWrapping="Wrap"/>
    __DETAIL__
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="20,16,20,16">
      __CONFIRM__
      <Button x:Name="BtnOk" Content="__OK__" Style="{StaticResource BtnPrimary}" MinWidth="100" Padding="14,0"/>
    </StackPanel>
  </StackPanel>
</Window>
'@

  $bodySafe = (& $esc $Message) -replace "`r`n|`n|`r",'&#10;'
  $xaml = $template.
    Replace('__STYLES__', $script:S).
    Replace('__BG__',     $colours[0]).
    Replace('__BR__',     $colours[1]).
    Replace('__FG__',     $colours[2]).
    Replace('__TITLE__',  (& $esc $Title)).
    Replace('__BODY__',   $bodySafe).
    Replace('__DETAIL__', $detailBlock).
    Replace('__CONFIRM__',$confirmBlock).
    Replace('__OK__',     (& $esc $YesLabel))

  $win = New-WpfWin $xaml
  if (-not $win) { return $false }
  if ($Owner) { try { $win.Owner = $Owner } catch {} }
  Set-WinBehavior $win -OnClose { $script:_mr = $false; $win.Close() }.GetNewClosure()

  $script:_mr = $false
  $win.FindName('BtnOk').Add_Click({ $script:_mr = $true;  $win.Close() }.GetNewClosure())
  if ($Confirm) {
    $no = $win.FindName('BtnNo')
    if ($no) { $no.Add_Click({ $script:_mr = $false; $win.Close() }.GetNewClosure()) }
  }
  $win.ShowDialog() | Out-Null
  return $script:_mr
}


# =============================================================================
# Show-WpfPackageReadyDialog — structured completion dialog; each actionable
# item is a button. Shared by Show-WpfSimpleIntuneResult and
# Show-WpfSimplePSADTResult.
# =============================================================================
function Show-WpfPackageReadyDialog {
  [CmdletBinding()]
  param(
    [string] $Title        = 'Package Ready',
    [string] $IntuneWinFile = '',
    [string] $OutputDir    = '',
    [string] $InstallCmd   = '',
    [string] $UninstallCmd = '',
    [string] $RegistryName    = '',
    [string] $PSADTVer        = '',
    [string] $DeployScriptPath = ''
  )

  $esc           = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
  $eTitle        = & $esc $Title
  $eFile         = & $esc $IntuneWinFile
  $eOutputDir    = & $esc $OutputDir
  $eInstall      = & $esc $InstallCmd
  $eUninstall    = & $esc $UninstallCmd
  $eRegistryName = & $esc $RegistryName
  $detectPath    = Join-Path $OutputDir 'detect.ps1'

  $psadtChipXaml = if ($PSADTVer) {
    $ePSADTVer = & $esc $PSADTVer
    "      <Border Background=`"#0d1a2a`" BorderBrush=`"#1e3a5f`" BorderThickness=`"1`" CornerRadius=`"4`" Padding=`"8,3`" Margin=`"0,0,6,0`"><TextBlock Text=`"PSADT $ePSADTVer`" FontSize=`"10`" FontWeight=`"SemiBold`" Foreground=`"#6baadf`"/></Border>"
  } else { '' }

  $runPreviewBtnXaml = if ($DeployScriptPath) {
    '      <Button x:Name="BtnRunPreview" Content="Run preview" Style="{StaticResource Btn}" MinWidth="110" Padding="14,0" Margin="0,0,8,0"/>'
  } else { '' }

  $xaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  ResizeMode="NoResize" SizeToContent="WidthAndHeight" MinWidth="480" MaxWidth="560"
  WindowStartupLocation="CenterScreen" Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <StackPanel>
    <Border x:Name="TitleBar" Background="#1a3a1a" BorderBrush="#2a5a2a" BorderThickness="0,0,0,1" Padding="20,0">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="0,14">
          <TextBlock Text="&#10003;" FontSize="18" FontWeight="Bold" Foreground="#4ec94e"
                     VerticalAlignment="Center" Margin="0,0,10,0"/>
          <TextBlock Text="$eTitle" FontSize="14" FontWeight="SemiBold" Foreground="#4ec94e"
                     VerticalAlignment="Center" TextWrapping="Wrap"/>
        </StackPanel>
        <Button x:Name="BtnClose" Grid.Column="1" Width="34" Height="34" Cursor="Hand" ToolTip="Close"
          Background="Transparent" BorderBrush="Transparent" BorderThickness="0" Foreground="#4ec94e"
          VerticalAlignment="Center" Margin="0,0,6,0">
          <TextBlock Text="&#10005;" FontSize="11" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Button>
      </Grid>
    </Border>
    <TextBlock Text="$eFile created successfully." FontSize="13" Foreground="#bbbbcc"
               Margin="20,14,20,0" TextWrapping="Wrap"/>
    <Border Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1"
            CornerRadius="6" Padding="14,10" Margin="20,10,20,0">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center" Margin="0,0,10,0">
          <TextBlock Text="Output folder" FontSize="10" Foreground="#444466" Margin="0,0,0,2"/>
          <TextBlock Text="$eOutputDir" FontSize="11" FontFamily="Consolas" Foreground="#7777aa"
                     TextWrapping="Wrap"/>
        </StackPanel>
        <Button x:Name="BtnOpenFolder" Grid.Column="1" Content="Open &#x203a;"
                Style="{StaticResource Btn}" Height="28" Padding="10,0" FontSize="11"
                VerticalAlignment="Center"/>
      </Grid>
    </Border>
    <Border Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1"
            CornerRadius="6" Padding="14,10" Margin="20,6,20,0">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center" Margin="0,0,10,0">
          <TextBlock Text="Install command" FontSize="10" Foreground="#444466" Margin="0,0,0,2"/>
          <TextBlock Text="$eInstall" FontSize="11" FontFamily="Consolas" Foreground="#7777aa"
                     TextWrapping="Wrap"/>
        </StackPanel>
        <Button x:Name="BtnCopyInstall" Grid.Column="1" Content="Copy"
                Style="{StaticResource Btn}" Height="28" Padding="10,0" FontSize="11"
                VerticalAlignment="Center"/>
      </Grid>
    </Border>
    <Border Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1"
            CornerRadius="6" Padding="14,10" Margin="20,6,20,0">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center" Margin="0,0,10,0">
          <TextBlock Text="Uninstall command" FontSize="10" Foreground="#444466" Margin="0,0,0,2"/>
          <TextBlock Text="$eUninstall" FontSize="11" FontFamily="Consolas" Foreground="#7777aa"
                     TextWrapping="Wrap"/>
        </StackPanel>
        <Button x:Name="BtnCopyUninstall" Grid.Column="1" Content="Copy"
                Style="{StaticResource Btn}" Height="28" Padding="10,0" FontSize="11"
                VerticalAlignment="Center"/>
      </Grid>
    </Border>
    <Button x:Name="BtnDetection" Style="{StaticResource BtnCardInfo}"
            Margin="20,6,20,0" Padding="14,10">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center">
          <TextBlock Text="Detection script" FontSize="10" Foreground="#444466" Margin="0,0,0,2"/>
          <TextBlock Text="detect.ps1  &#xB7;  Custom Script" FontSize="11" Foreground="#aaaacc"/>
        </StackPanel>
        <TextBlock Grid.Column="1" Text="Open &#x203a;" FontSize="11" Foreground="#6baadf"
                   VerticalAlignment="Center" Margin="14,0,0,0"/>
      </Grid>
    </Button>
    <StackPanel Orientation="Horizontal" Margin="20,10,20,0">
      <Border Background="#0d1a0d" BorderBrush="#1a3a1a" BorderThickness="1"
              CornerRadius="4" Padding="8,3" Margin="0,0,6,0">
        <TextBlock Text="SYSTEM  &#xB7;  64-bit" FontSize="10" Foreground="#4ec94e"/>
      </Border>
$psadtChipXaml
      <Border Background="#1a1a2e" BorderBrush="#2e2e45" BorderThickness="1"
              CornerRadius="4" Padding="8,3">
        <TextBlock Text="Detects: $eRegistryName" FontSize="10" Foreground="#7777aa"/>
      </Border>
    </StackPanel>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="20,16,20,16">
$runPreviewBtnXaml
      <Button x:Name="BtnDone" Content="Done" Style="{StaticResource BtnSuccess}"
              MinWidth="100" Padding="14,0"/>
    </StackPanel>
  </StackPanel>
</Window>
"@

  $win = New-WpfWin $xaml
  if (-not $win) { return }
  Set-WinBehavior $win

  $el = Get-El $win @('BtnOpenFolder','BtnCopyInstall','BtnCopyUninstall','BtnDetection','BtnDone','BtnRunPreview','BtnClose')

  $captureOutputDir    = $OutputDir
  $captureInstall      = $InstallCmd
  $captureUninstall    = $UninstallCmd
  $captureDetectPath   = $detectPath
  $captureDeployScript = $DeployScriptPath

  $el['BtnOpenFolder'].Add_Click({
    try { Start-Process explorer.exe $captureOutputDir } catch {}
  }.GetNewClosure())

  $el['BtnCopyInstall'].Add_Click({
    try { [System.Windows.Clipboard]::SetText($captureInstall) } catch {}
  }.GetNewClosure())

  $el['BtnCopyUninstall'].Add_Click({
    try { [System.Windows.Clipboard]::SetText($captureUninstall) } catch {}
  }.GetNewClosure())

  $el['BtnDetection'].Add_Click({
    try { Start-Process explorer.exe "/select,`"$captureDetectPath`"" } catch {}
  }.GetNewClosure())

  if ($DeployScriptPath -and $el['BtnRunPreview']) {
    $el['BtnRunPreview'].Add_Click({
      try {
        $dir = Split-Path $captureDeployScript -Parent
        Start-Process (Join-Path $PSHOME 'powershell.exe') `
          -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$captureDeployScript`" -DeploymentType Install -DeployMode Interactive" `
          -WorkingDirectory $dir -ErrorAction Stop
      } catch {
        [System.Windows.MessageBox]::Show("Could not launch preview:`n$($_.Exception.Message)", 'Preview Failed')
      }
    }.GetNewClosure())
  }

  $el['BtnDone'].Add_Click({ $win.Close() }.GetNewClosure())

  $win.ShowDialog() | Out-Null
}


# =============================================================================
# Show-WpfFirstRun
# =============================================================================
function Show-WpfFirstRun {
  param([string]$DefaultOrg = 'IT Services')
  $hdr = Get-HeaderXaml 'Welcome to AppUpdater' 'Choose how you want to work' `
  -showBack:$false -showClose:$true -showBadge:$true

  $x = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="540" Height="490"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="*"/>
  </Grid.RowDefinitions>

  $hdr

  <StackPanel Grid.Row="1" Margin="24,18,24,24">
  <Border x:Name="CardCloud"
  Background="#101820" BorderBrush="#1e3a5f" BorderThickness="1"
  CornerRadius="9" Padding="20,16" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
  <StackPanel Orientation="Horizontal" Margin="0,0,0,7">
  <TextBlock Text="Connect to Cloudflare" FontSize="14" FontWeight="SemiBold" Foreground="#e8e8f4"/>
  <Border Background="#0d2a0d" BorderBrush="#1a5c1a" BorderThickness="1" CornerRadius="3" Padding="6,1" Margin="10,2,0,0">
    <TextBlock Text="RECOMMENDED" FontSize="9" FontWeight="Bold" Foreground="#4ec94e"/>
  </Border>
  </StackPanel>
  <TextBlock FontSize="12" Foreground="#5577aa" TextWrapping="Wrap" Margin="0,0,0,8">
  Set up once in about 2 minutes. Your devices check for updates automatically, and you get a live dashboard showing which apps are deployed and whether download links are healthy.
  </TextBlock>
  <TextBlock FontSize="11" Foreground="#335566" TextWrapping="Wrap">
  &#128274;&#160; The dashboard is protected behind a password — only you can see your app data. You set the password during setup.
  </TextBlock>
  </StackPanel>
  </Border>

  <Border x:Name="CardOffline"
  Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
  CornerRadius="9" Padding="20,16" Margin="0,0,0,22" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Build packages only" FontSize="14" FontWeight="SemiBold" Foreground="#c8c8e0" Margin="0,0,0,6" TextWrapping="Wrap" />
  <TextBlock FontSize="12" Foreground="#55557a" TextWrapping="Wrap">
  No cloud setup needed — packages work completely standalone. You can connect to Cloudflare any time from the main menu.
  </TextBlock>
  </StackPanel>
  </Border>

  <TextBlock Text="Your organisation name" FontSize="11" Foreground="#55557a" Margin="2,0,0,4"/>
 <TextBlock Text="Shown in the update notification that appears on users&#x2019; machines — e.g. &#x22;Acme IT&#x22; or &#x22;IT Services&#x22;" FontSize="10" Foreground="#333355" Margin="2,0,0,6" TextWrapping="Wrap" />
  <TextBox x:Name="OrgName" Style="{StaticResource Field}" Height="42"/>
  </StackPanel>
  </Grid>
</Window>
"@
  $w = New-WpfWin $x
  if (-not $w) { return @{ mode = 'offline'; orgName = $DefaultOrg } }
  $el = Get-El $w @('CardCloud', 'CardOffline', 'OrgName')
  $el['OrgName'].Text = $DefaultOrg
  Set-WinBehavior $w

  $script:_frm = 'offline'
  $hlCloud  = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x2a,0x7a,0xd5))
  $loCloud  = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x1e,0x3a,0x5f))
  $hlOffline= [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x5b,0x9b,0xd5))
  $loOffline= [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x2a,0x2a,0x3a))

  $el['CardCloud'].Add_MouseLeftButtonUp({
  $script:_frm = 'cloudflare'
  $el['CardCloud'].BorderBrush  = $hlCloud
  $el['CardOffline'].BorderBrush = $loOffline
  $w.Close()
  })
  $el['CardOffline'].Add_MouseLeftButtonUp({
  $script:_frm = 'offline'
  $el['CardOffline'].BorderBrush = $hlOffline
  $el['CardCloud'].BorderBrush  = $loCloud
  $w.Close()
  })

  $w.ShowDialog() | Out-Null
  $org = $el['OrgName'].Text.Trim()
  if (-not $org) { $org = $DefaultOrg }
  return @{ mode = $script:_frm; orgName = $org }
}

# =============================================================================
# Get-LocalManifest
# Shared by "Manage local manifest" (main menu B6) and Show-WpfManifestManager.
# Ensures appVersions.xml exists, is readable, and has at least one <App> with
# an ID — the pre-check before opening the manager (amend / export / import /
# delete) or before B6 can call Show-WpfManifestManager with a single question:
# did we get valid data, or not?
#
# Returns @{ Ok=$true;  Apps=<XmlElement[]> }  — guaranteed Count >= 1
#      or @{ Ok=$false; Reason='<user-facing message>' }
#
# ROOT-CAUSE FIX:  [xml].AppManifest.App returns $null (not an empty array)
# when no <App> elements are present.  @($null).Count equals 1, not 0, so
# the old   "if ($apps.Count -eq 0)"   guard was never triggered for an
# empty-but-valid XML file.  Piping through Where-Object strips the $null
# before the count is evaluated, so Count is genuinely 0.
# =============================================================================
function Get-LocalManifest {
  param(
  [Parameter(Mandatory)][string] $XmlFile
  )

  # Security: path must already be an absolute, .xml path (caller passes the
  # script-level $XmlFile constant — never a user-typed string).
  if (-not [System.IO.Path]::IsPathRooted($XmlFile) -or
      $XmlFile -notmatch '\.xml$') {
    return @{ Ok = $false; Reason = 'Invalid manifest path.' }
  }

  # File-missing
  if (-not (Test-Path $XmlFile -PathType Leaf)) {
    return @{ Ok = $false; Reason = "appVersions.xml not found.`n`nBuild your first package using option 1 on the main menu." }
  }

  # Read
  $raw = $null
  try {
    $raw = Get-Content $XmlFile -Raw -Encoding UTF8 -ErrorAction Stop
  } catch {
    return @{ Ok = $false; Reason = "Could not read manifest:`n$($_.Exception.Message)" }
  }

  if ([string]::IsNullOrWhiteSpace($raw)) {
    return @{ Ok = $false; Reason = "appVersions.xml is empty.`n`nBuild your first package using option 1 on the main menu." }
  }

  # Parse — [xml] cast throws on malformed XML
  # Repair bare '&' in URL text content written before XML-escaping was added.
  # Replaces '&' only when it is not already the start of a named or numeric
  # entity reference (&amp; &lt; &#39; &#x2F; etc.), leaving valid XML intact.
  $raw = $raw -replace '&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[\da-fA-F]+;)', '&amp;'

  [xml] $manifest = $null
  try {
    $manifest = [xml] $raw
  } catch {
    $errDetail = $_.Exception.Message -replace "(?s)^Cannot convert value .* to type 'System\.Xml\.XmlDocument'\. Error: ", ''
    return @{ Ok = $false; Reason = "Manifest XML is invalid:`n$errDetail" }
  }

  # Extract apps.
  # FIX: pipe through Where-Object to strip $null *before* wrapping in @().
  # Without this, @($null).Count = 1 and the Count -eq 0 guard below never fires.
  $apps = @(
    $manifest.AppManifest.App |
    Where-Object { $_ -ne $null -and $_.ID }
  )

  if ($apps.Count -eq 0) {
    return @{
      Ok     = $false
      Reason = "No app entries found in appVersions.xml.`n`nBuild your first package using option 1 on the main menu."
    }
  }

  return @{ Ok = $true; Apps = $apps }
}

# =============================================================================
# Show-WpfManifestManager
# Lists apps in appVersions.xml. Per row: Amend (pre-filled builder), Delete.
# Footer: Export All (copy whole file), Import (replace file + optional batch build).
# XAML note: window XML is single-quoted (@'...'@) to avoid $ expansion;
#  $S styles and $itemsXaml are injected via .Replace() after build.
#
# All validation is delegated to Get-LocalManifest.  If Ok=$false, Show-WpfMsg
# then return (main menu B6 pre-validates so this path is rare from B6).
# =============================================================================
# =============================================================================
# Show-WpfDeleteChoice — three-option modal dialog for the manifest manager.
# Returns 'manifest' | 'everything' | 'cancel'.
# =============================================================================
function Show-WpfDeleteChoice {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $AppName,
    [Parameter(Mandatory)][string] $AppID
  )
  $esc = [System.Security.SecurityElement]::Escape($AppName)
  $idEsc = [System.Security.SecurityElement]::Escape($AppID)
  $hdr = Get-HeaderXaml 'Delete app' "How much should be removed?" -showBack:$false -showClose:$true

  $xaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="540" SizeToContent="Height" WindowStartupLocation="CenterScreen"
  Topmost="True" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="Auto"/><RowDefinition Height="60"/></Grid.RowDefinitions>
    $hdr
    <StackPanel Grid.Row="1" Margin="22,16,22,8">
      <TextBlock FontSize="13" Foreground="#cccccc" TextWrapping="Wrap" Margin="0,0,0,12">
        <Run FontWeight="SemiBold" Foreground="#e8e8f4">$esc</Run>
        <Run Foreground="#55557a"> ($idEsc)</Run>
      </TextBlock>

      <Button x:Name="DcManifest" Style="{StaticResource BtnCardInfo}" Margin="0,0,0,10">
        <StackPanel>
          <TextBlock Text="Manifest only" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,3"/>
          <TextBlock FontSize="11" Foreground="#5577aa" TextWrapping="Wrap">Removes the XML entry from appVersions.xml. The deployed scripts, scheduled task, ProgramData folder, and desktop shortcut on this machine are left alone. Devices keep working until they are uninstalled separately.</TextBlock>
        </StackPanel>
      </Button>

      <Button x:Name="DcEverything" Style="{StaticResource BtnCardDanger}" Margin="0,0,0,10">
        <StackPanel>
          <TextBlock Text="Manifest + everything on this machine" FontSize="13" FontWeight="SemiBold" Foreground="#ff8888" Margin="0,0,0,3"/>
          <TextBlock FontSize="11" Foreground="#aa6666" TextWrapping="Wrap">Removes the XML entry, then on THIS machine deletes:</TextBlock>
          <TextBlock FontSize="11" Foreground="#aa6666" TextWrapping="Wrap" Margin="0,4,0,0">  - Scheduled tasks (AppUpdater_$idEsc, AppUpdaterLaunch_$idEsc)</TextBlock>
          <TextBlock FontSize="11" Foreground="#aa6666" TextWrapping="Wrap">  - Desktop shortcut "Update $esc.lnk"</TextBlock>
          <TextBlock FontSize="11" Foreground="#aa6666" TextWrapping="Wrap">  - C:\ProgramData\AppUpdater\$idEsc</TextBlock>
          <TextBlock FontSize="11" Foreground="#aa6666" TextWrapping="Wrap">  - Output\$idEsc (build output)</TextBlock>
          <TextBlock FontSize="10" Foreground="#664444" TextWrapping="Wrap" Margin="0,6,0,0">Other devices already running the deployed package are NOT affected.</TextBlock>
        </StackPanel>
      </Button>
    </StackPanel>
    <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0" Padding="22,12">
      <Button x:Name="DcCancel" Content="Cancel" Height="32" MinWidth="100" Padding="14,0"
        HorizontalAlignment="Right" Style="{StaticResource Btn}"/>
    </Border>
  </Grid>
</Window>
"@
  $w = New-WpfWin $xaml
  if (-not $w) { return 'cancel' }
  $w.Tag = 'cancel'
  Set-WinBehavior $w -OnClose { $w.Tag = 'cancel'; $w.Close() }.GetNewClosure()
  $el = Get-El $w @('DcManifest','DcEverything','DcCancel')
  $el['DcCancel'].Add_Click({     $w.Tag = 'cancel';     $w.Close() }.GetNewClosure())
  $el['DcManifest'].Add_Click({   $w.Tag = 'manifest';   $w.Close() }.GetNewClosure())
  $el['DcEverything'].Add_Click({ $w.Tag = 'everything'; $w.Close() }.GetNewClosure())
  $w.Add_ContentRendered({ $w.Activate() | Out-Null })
  $w.ShowDialog() | Out-Null
  Write-AppLog "Show-WpfDeleteChoice returning '$([string]$w.Tag)' for $AppID"
  return [string]$w.Tag
}

# =============================================================================
# Remove-AppLocalArtifacts — wipe everything the deploy script created on
# THIS machine for a single app. Scheduled tasks, ProgramData folder, desktop
# shortcuts (Public + per-user fallbacks), and the local build-output folder.
# Returns @{ Lines = [string[]]; HadErrors = [bool] } — the caller renders the
# lines into a Show-WpfMsg so the user sees exactly what happened.
# =============================================================================
function Remove-AppLocalArtifacts {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $AppID,
    [Parameter(Mandatory)][string] $DisplayName
  )
  $lines = @()
  $hadErrors = $false

  # 1. Scheduled tasks. Both the deploy-script task and the launch wrapper if present.
  foreach ($taskName in @("AppUpdater_$AppID", "AppUpdaterLaunch_$AppID")) {
    try {
      $existing = schtasks /query /tn $taskName 2>$null
      if ($LASTEXITCODE -eq 0 -and $existing) {
        schtasks /delete /tn $taskName /f 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
          $lines += "  [OK] Scheduled task '$taskName' deleted"
          Write-AppLog "Removed scheduled task: $taskName" INFO
        } else {
          $lines += "  [!!] Could not delete scheduled task '$taskName' (exit $LASTEXITCODE)"
          $hadErrors = $true
        }
      } else {
        $lines += "  [-] Scheduled task '$taskName' not present"
      }
    } catch {
      $lines += "  [!!] Scheduled task '$taskName' check failed: $($_.Exception.Message)"
      $hadErrors = $true
    }
  }

  # 2. Desktop shortcut — try Public Desktop first, then every user profile's Desktop.
  $shortcutName = "Update $DisplayName.lnk"
  $shortcutPaths = @("C:\Users\Public\Desktop\$shortcutName")
  try {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notin @('Public','Default','Default User','All Users','desktop.ini') } |
      ForEach-Object { $shortcutPaths += Join-Path $_.FullName "Desktop\$shortcutName" }
  } catch { }
  foreach ($sc in $shortcutPaths) {
    if (Test-Path -LiteralPath $sc) {
      try {
        Remove-Item -LiteralPath $sc -Force -ErrorAction Stop
        $lines += "  [OK] Removed shortcut: $sc"
        Write-AppLog "Removed shortcut: $sc" INFO
      } catch {
        $lines += "  [!!] Could not remove shortcut '$sc': $($_.Exception.Message)"
        $hadErrors = $true
      }
    }
  }

  # 3. ProgramData folder — the runtime working directory created by the deploy script.
  $programDataDir = Join-Path 'C:\ProgramData\AppUpdater' $AppID
  if (Test-Path -LiteralPath $programDataDir) {
    try {
      Remove-Item -LiteralPath $programDataDir -Recurse -Force -ErrorAction Stop
      $lines += "  [OK] Removed $programDataDir"
      Write-AppLog "Removed ProgramData folder: $programDataDir" INFO
    } catch {
      $lines += "  [!!] Could not remove '$programDataDir': $($_.Exception.Message)"
      $hadErrors = $true
    }
  } else {
    $lines += "  [-] $programDataDir not present"
  }

  # 4. Build-output folder in ProgramData\AppUpdater\_output (artefacts shipped to Intune).
  if ($script:OutputBase) {
    $outDir = Join-Path $script:OutputBase $AppID
    if (Test-Path -LiteralPath $outDir) {
      try {
        Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction Stop
        $lines += "  [OK] Removed $outDir"
        Write-AppLog "Removed Output folder: $outDir" INFO
      } catch {
        $lines += "  [!!] Could not remove '$outDir': $($_.Exception.Message)"
        $hadErrors = $true
      }
    }
  }

  return @{ Lines = $lines; HadErrors = $hadErrors }
}

function Show-WpfManifestManager {
  param(
    [string]    $XmlFile,
    [hashtable] $Config,
    $Owner = $null
  )

  $loaded = Get-LocalManifest -XmlFile $XmlFile
  if (-not $loaded.Ok) {
    Show-WpfMsg -Title 'Manifest' -Message $loaded.Reason -Type 'info'
    return
  }
  $apps = $loaded.Apps
  Write-AppLog "ManifestManager opened: $($apps.Count) app(s)"

  # Build per-app row XAML (Amend + Delete; PSADT export offered after successful Amend)
  $itemsXaml = ($apps | ForEach-Object {
    $id  = $_.ID
    $ver = if ($_.Version)     { $_.Version }     else { '' }
    $nm  = if ($_.DisplayName) { $_.DisplayName } else { $id }
    # XML + XAML safe: escape &, <, " and curly braces.
    # { at the start of a XAML attribute value triggers markup-extension parsing;
    # &#x7B; / &#x7D; are the XML character entities for { and } and are always safe.
    $nm  = $nm  -replace '&','&amp;' -replace '<','&lt;' -replace '"',"'" `
                -replace '\{','&#x7B;' -replace '\}','&#x7D;'
    $ver = $ver -replace '&','&amp;' -replace '\{','&#x7B;' -replace '\}','&#x7D;'
    $id2 = $id  -replace '[^A-Za-z0-9_]','_'
    (
      ('  <Border x:Name="ROW_{0}" Background="#101820" BorderBrush="#1e3a5f" BorderThickness="1"' -f $id2) + "`n" +
      '  CornerRadius="6" Padding="14,10" Margin="0,0,0,6">' + "`n" +
      '  <Grid>' + "`n" +
      '  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>' + "`n" +
      '  <StackPanel>' + "`n" +
 (' <TextBlock x:Name="NM_{2}" Text="{0}" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />' -f $nm,$ver,$id2) + "`n" +
 (' <TextBlock x:Name="VV_{2}" Text="{0} v{1}" FontSize="11" Foreground="#55577a" Margin="0,2,0,0" TextWrapping="Wrap" />' -f $id,$ver,$id2) + "`n" +
      '  </StackPanel>' + "`n" +
      '  <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">' + "`n" +
      ('  <Button x:Name="AMD_{0}" Content="Amend"   Height="28" Padding="10,0" Style="{{StaticResource BtnPrimary}}" Margin="0,0,6,0"/>' -f $id2) + "`n" +
      ('  <Button x:Name="DEL_{0}" Content="Delete"  Height="28" Padding="10,0" Style="{{StaticResource BtnDanger}}"/>' -f $id2) + "`n" +
      '  </StackPanel>' + "`n" +
      '  </Grid>' + "`n" +
      '  </Border>'
    )
  }) -join "`n"

  $hdr  = Get-HeaderXaml 'Local manifest' "appVersions.xml  --  $($apps.Count) app(s)" `
          -showBack:$true -showClose:$true
  $winH = [Math]::Min(74 + 60 + ($apps.Count * 65) + 58, 620)

  $rawXaml = @'
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="560" Height="WINHEIGHT"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
STYLESBLOCK
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="*"/>
  <RowDefinition Height="58"/>
  </Grid.RowDefinitions>
HEADERBLOCK
  <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="20,14,20,0">
  <StackPanel>
ITEMSBLOCK
  <TextBlock x:Name="EmptyMsg" Visibility="Collapsed" FontSize="12"
    Foreground="#44445a" TextWrapping="Wrap" TextAlignment="Center"
    Margin="20,30,20,0"
    Text="No apps remain.&#xA;Use the main menu to package a new app."/>
  </StackPanel>
  </ScrollViewer>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
  <Button x:Name="BtnExportAll" Content="Export All" Height="30" Padding="12,0"
    Style="{StaticResource Btn}" Margin="0,0,8,0"/>
  <Button x:Name="BtnImport" Content="Import" Height="30" Padding="12,0"
    Style="{StaticResource BtnPrimary}" Margin="0,0,8,0"/>
  <Button x:Name="BtnPushWorker" Content="Push to Worker" Height="30" Padding="12,0"
    Style="{StaticResource Btn}" Visibility="Collapsed"/>
  </StackPanel>
  </Border>
  </Grid>
</Window>
'@
  $x = $rawXaml.Replace('WINHEIGHT',  [string]$winH)
  $x = $x.Replace('STYLESBLOCK', $script:S)
  $x = $x.Replace('HEADERBLOCK', $hdr)
  $x = $x.Replace('ITEMSBLOCK',  $itemsXaml)

  $w = New-WpfWin $x
  if (-not $w) { return }
  Set-WinBehavior $w -OnBack { $w.Close() }
  if ($Owner) { try { $w.Owner = $Owner } catch {} }

  $cap_xmlFile = $XmlFile
  $cap_config  = $Config
  $cap_w       = $w

  # Per-app Amend + Delete
  foreach ($app in $apps) {
    $rawId  = $app.ID
    $safeId = $rawId -replace '[^A-Za-z0-9_]','_'
    $amdBtn = $w.FindName("AMD_$safeId")
    $delBtn = $w.FindName("DEL_$safeId")
    $rowEl  = $w.FindName("ROW_$safeId")
    $nmEl   = $w.FindName("NM_$safeId")
    $vvEl   = $w.FindName("VV_$safeId")
    $cap_app = $app; $cap_id = $rawId
    $cap_nm  = if ($app.DisplayName) { $app.DisplayName } else { $rawId }
    $cap_S   = $script:S

    if ($amdBtn) {
      $amdBtn.Add_Click({
        $defaults = @{
          AppID           = $cap_app.ID
          DisplayName     = $cap_app.DisplayName
          DownloadURL     = $cap_app.DownloadURL
          FallbackURL     = $cap_app.FallbackURL
          SilentArgs      = $cap_app.SilentArgs
          RegistryName    = $cap_app.RegistryDisplayName
          ProcessesToKill = $cap_app.ProcessesToKill
          LaunchExe       = $cap_app.LaunchExe
        }
        Write-AppLog "Amend requested for $($cap_app.ID)"
        # Open App Form while the manifest manager's ShowDialog frame is still
        # alive — calling ShowDialog after Close() silently fails on some PS builds.
        # -AmendMode locks the App ID, retitles the dialog, and skips the
        # installer-picker requirement (URLs are already in $defaults).
        $hasW = ($cap_config -and $cap_config.WorkerURL -and $cap_config.WorkerURL -ne '')
        $fd = Show-WpfAppForm -Defaults $defaults -HasWorker ([bool]$hasW) -AmendMode
        if ($fd -is [hashtable]) {
          # App Form completed. Still inside the manifest manager's dispatcher
          # frame, so Show-WpfOutputChoice and the build-progress ShowDialog()
          # will both work here.
          $outChoice2 = Show-WpfOutputChoice -AppID $fd.AppID
          if (-not $outChoice2) { return }   # user closed the dialog without choosing — stay on manifest manager
          $bq2 = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
          $bd2 = [System.Collections.Generic.List[string]]::new()
          $brs2 = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
          $brs2.ApartmentState = 'MTA'; $brs2.ThreadOptions = 'ReuseThread'; $brs2.Open()
          $brs2.SessionStateProxy.SetVariable('_bq',$bq2)
          $brs2.SessionStateProxy.SetVariable('_bd',$bd2)
          $brs2.SessionStateProxy.SetVariable('_cfg',$cap_config)
          $brs2.SessionStateProxy.SetVariable('_fd',$fd)
          $brs2.SessionStateProxy.SetVariable('_oc',$outChoice2)
          foreach ($vn2 in @('ScriptPath','ScriptDir','XmlFile','ConfigFile','ManifestTokenFile',
            'IntuneWinUtilURL','IntuneWinUtilPath','TempBase','OutputBase','CF_API','WorkerName','KVNamespace')) {
            $brs2.SessionStateProxy.SetVariable($vn2,(Get-Variable $vn2 -ValueOnly -EA SilentlyContinue))
          }
          $_fns2 = (@('Invoke-PackageBuilder','Invoke-InstallerInspector','Get-InstalledVersion',
            'Read-MsiProperties','Get-InstallerType','Get-SilentArgs',
            'Protect-ManifestToken','Unprotect-ManifestToken','Get-StoredManifestToken',
            'Test-SafeAppId','Test-SafeFileName','Test-SafeHttpsUrl','Test-SafeSubdomainLabel',
            'ConvertTo-SafeFsName','Resolve-SafeChildPath',
            'Set-PhaseActive','Set-PhaseDone','Set-Pill',
            'Write-AppLog','Write-OK','Write-Warn','Write-Fail','Write-Step','Write-Info',
            'Write-Rule','Write-BoxTop','Write-BoxBot','Write-BoxLine') | ForEach-Object {
              $fn=Get-Item "Function:\$_" -EA SilentlyContinue; if($fn){"function $_ {`n$($fn.ScriptBlock)`n}"}
          }) -join "`n"
          $brs2.SessionStateProxy.SetVariable('_fnSrc',$_fns2)
          $bps2=[System.Management.Automation.PowerShell]::Create(); $bps2.Runspace=$brs2
          $bps2.AddScript({
            function New-WpfWin{param([string]$x)return $null}; function Get-El{param($w,[string[]]$n)return @{}}
            function Get-HeaderXaml{param([string]$t,[string]$s='',[bool]$b=$false,[bool]$c=$true,[bool]$bg=$false)return ''}
            function Set-WinBehavior{param($w,[scriptblock]$OC=$null,[scriptblock]$OB=$null)}
            function Show-WpfMsg{param([string]$T='',[string]$M='',[string]$Ty='info',[switch]$Confirm)$_bq.Enqueue("info|[$T] $M");return $true}
            function Show-WpfOutputChoice{param([string]$AppID='')return $_oc}
            function Show-WpfFirstRun{return @{mode='offline';orgName='IT Services'}}
            function Show-WpfMainMenu{param([hashtable]$Config)return 6}
            function Show-WpfAppForm{param([hashtable]$D=@{},[bool]$H=$false,[bool]$AE=$true)return $null}
            function Show-WpfCloudflareWizard{param([string]$OrgName='')return $null}
            function Show-WpfPSADTExport{param([string]$AppID='',[string]$DisplayName='',[string]$ProcessesToKill='',[string]$ExpectedPub='',[string]$OrgName='')$_bq.Enqueue("info|Build complete. Use the PSADT button in the app list to export as a PSADT package.")}
            function Export-PSADTPackage{param([string]$AppID='',[string]$DisplayName='',[string]$ProcessesToKill='',[string]$ExpectedPub='',[string]$PSADTVersion='v3',[string]$PSADTToolkitPath='',[string]$OrgName='')}
            function Get-PSADTToolkit{param([string]$ManualPath='')return $null}
            function Invoke-SimpleBuildCore{param([hashtable]$Config=@{},[hashtable]$FormData=@{})}
            function Show-WpfSimpleIntuneResult{param([string]$AppID='',[string]$DisplayName='',[string]$OutputDir='',[string]$RegistryName='')}
            function Show-WpfSimplePSADTResult{param([string]$AppID='',[string]$DisplayName='',[string]$OutputDir='',[string]$PSADTVer='v3',[string]$RegistryName='')}
            function Show-WpfPackageReadyDialog{param([string]$Title='',[string]$IntuneWinFile='',[string]$OutputDir='',[string]$InstallCmd='',[string]$UninstallCmd='',[string]$RegistryName='',[string]$PSADTVer='',[string]$DeployScriptPath='')}
            function Show-WpfSimplePSADTToolkit{param([string]$InitialError='')return $null}
            function Write-AppLog{param([string]$Message,[string]$Level='INFO')}
            function Write-Host{param([object]$O,[string]$FC='Gray',[switch]$NL)
              $c=switch($FC){'Green'{'ok'}'Cyan'{'info'}'Yellow'{'warn'}'Red'{'err'}'DarkGray'{'dim'}'White'{'white'}default{'gray'}}
              $_bq.Enqueue("$c|$O")}
            function Write-OK{param([string]$M)Write-Host "  OK  $M" -FC Green}
            function Write-Warn{param([string]$M)Write-Host "  !!  $M" -FC Yellow}
            function Write-Fail{param([string]$M)Write-Host "  XX  $M" -FC Red}
            function Write-Step{param([string]$n,[string]$M)Write-Host "  [$n] $M" -FC Cyan}
            function Write-Info{param([string]$M)Write-Host "       $M" -FC DarkGray}
            function Write-Rule{}; function Write-BoxTop{param($C)}; function Write-BoxBot{param($C)}
            function Write-BoxLine{param([string]$m,$C)Write-Host "  $m" -FC $C}
            try{Invoke-Expression $_fnSrc}catch{$_bq.Enqueue("err|Load failed: $($_.Exception.Message)");$_bd.Add('error');return}
            try{Invoke-PackageBuilder -Config $_cfg -FormData $_fd;$_bd.Add('ok')}
            catch{$_bq.Enqueue("err|ERROR: $($_.Exception.Message)");$_bd.Add('error')}
          }) | Out-Null
          $bh2 = $bps2.BeginInvoke()
          $bp2 = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="560" Height="460" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$cap_S
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/><RowDefinition Height="60"/></Grid.RowDefinitions>
  <Border x:Name="TB2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74" Margin="20,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
  <StackPanel VerticalAlignment="Center">
 <TextBlock x:Name="BT2" Text="Building $($fd.AppID)..." FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />
  <TextBlock x:Name="BS2" Text="Please wait" FontSize="11" Foreground="#44445a" Margin="0,3,0,0"/>
  </StackPanel></Grid></Border>
  <RichTextBox x:Name="BL2" Grid.Row="1" Background="#07070f" Foreground="#666688"
    BorderThickness="0" Padding="16" IsReadOnly="True" FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Button x:Name="BC2" Content="Building..." Style="{StaticResource Btn}" Width="120" HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
  </Border>
  </Grid>
</Window>
"@)
          if ($bp2) {
            $bp2El=Get-El $bp2 @('BT2','BS2','BL2','BC2','TB2')
            $bp2Doc=$bp2El['BL2'].Document; $bp2Doc.Blocks.Clear()
            $bp2Para=[Windows.Documents.Paragraph]::new(); $bp2Doc.Blocks.Add($bp2Para)
            $bp2El['TB2'].Add_MouseLeftButtonDown({$bp2.DragMove()})
            $bpCm2=@{ok='#4ec94e';info='#6baadf';warn='#f5c842';err='#ff6060';dim='#444460';white='#e8e8f4';gray='#666688'}
            $bpTmr2=[System.Windows.Threading.DispatcherTimer]::new()
            $bpTmr2.Interval=[TimeSpan]::FromMilliseconds(200)
            $bpTmr2.Add_Tick({
              $mi2=''
              while($bq2.TryDequeue([ref]$mi2)){
                $pi2=$mi2 -split '\|',2; $ci2=$bpCm2[$pi2[0]]; if(-not$ci2){$ci2='#888'}
                $ti2=if($pi2.Count-gt 1){$pi2[1]}else{$mi2}
                $ri2=[Windows.Documents.Run]::new("$ti2`n")
                $rb2=[Convert]::ToByte($ci2.Substring(1,2),16);$gb2=[Convert]::ToByte($ci2.Substring(3,2),16);$bb2=[Convert]::ToByte($ci2.Substring(5,2),16)
                $ri2.Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($rb2,$gb2,$bb2))
                $bp2Para.Inlines.Add($ri2); $bp2El['BL2'].ScrollToEnd()
              }
              if($bd2.Count-gt 0){
                $bpTmr2.Stop(); $ok2b=$bd2[0]-eq'ok'
                $bp2El['BT2'].Text=if($ok2b){'Build complete'}else{'Build finished with errors'}
                $bp2El['BC2'].IsEnabled=$true
                $bp2El['BC2'].Content=if($ok2b){'Done  ✓'}else{'Close'}
                $bp2El['BC2'].Style=$bp2.Resources[$(if($ok2b){'BtnSuccess'}else{'Btn'})]
                $bps2.EndInvoke($bh2)|Out-Null; $brs2.Close()
                if($ok2b){
                  $script:_bp2Secs=5
                  $bp2El['BS2'].Text='Continuing in 5 seconds…'
                  $bp2El['BC2'].Content='Done  ✓  (5)'
                  $script:_bp2CdTmr=[System.Windows.Threading.DispatcherTimer]::new()
                  $script:_bp2CdTmr.Interval=[TimeSpan]::FromSeconds(1)
                  $script:_bp2CdTmr.Add_Tick({
                    $script:_bp2Secs--
                    if($script:_bp2Secs-le 0){$script:_bp2CdTmr.Stop();$bp2.Close();return}
                    $bp2El['BC2'].Content="Done  ✓  ($script:_bp2Secs)"
                    $bp2El['BS2'].Text="Continuing in $script:_bp2Secs second$(if($script:_bp2Secs-ne 1){'s'})…"
                  })
                  $script:_bp2CdTmr.Start()
                } else {
                  $bp2El['BS2'].Text='Check output above'
                }
              }
            })
            $bp2El['BC2'].Add_Click({if($script:_bp2CdTmr){$script:_bp2CdTmr.Stop()};$bp2.Close()})
            $bp2.Add_ContentRendered({$bpTmr2.Start()})
            $bp2.Add_Closing({if($bpTmr2.IsEnabled){$bpTmr2.Stop()};if($script:_bp2CdTmr){$script:_bp2CdTmr.Stop()}})
            $bp2.ShowDialog() | Out-Null
          } else {
            $bps2.EndInvoke($bh2)|Out-Null; $brs2.Close()
          }
          try {
            [xml]$freshMx = Get-Content $cap_xmlFile -Raw -Encoding UTF8 -ErrorAction Stop
            $freshNode = @($freshMx.AppManifest.App | Where-Object { $_.ID -eq $fd.AppID }) | Select-Object -First 1
            if ($freshNode) {
              $newName = if ($freshNode.DisplayName) { [string]$freshNode.DisplayName } else { [string]$fd.AppID }
              $newVer  = if ($freshNode.Version)     { [string]$freshNode.Version }     else { '' }
              if ($nmEl) { $nmEl.Text = $newName }
              if ($vvEl) { $vvEl.Text = "$($fd.AppID) v$newVer" }
            }
          } catch {
            Write-AppLog "Amend refresh warning for $($fd.AppID): $($_.Exception.Message)" WARN
          }
          $cap_doPSADT = Show-WpfMsg `
            -Title   'Amend complete' `
            -Message "$($fd.AppID) has been rebuilt." `
            -Detail  'Also export as a PSADT-wrapped Intune package now?' `
            -Type    'success' -Confirm -YesLabel 'Export PSADT' -NoLabel 'Done'
          if ($cap_doPSADT) {
            $_psaProcs   = if ($fd.ProcessesToKill)                       { $fd.ProcessesToKill }
                           elseif ($cap_app -and $cap_app.ProcessesToKill) { $cap_app.ProcessesToKill }
                           else                                            { '' }
            $_psaOrgName = if ($cap_config -and $cap_config.OrgName) { $cap_config.OrgName } else { 'IT Services' }
            Show-WpfPSADTExport `
              -AppID           $fd.AppID `
              -DisplayName     (if ($fd.DisplayName) { $fd.DisplayName } else { $fd.AppID }) `
              -ProcessesToKill $_psaProcs `
              -ExpectedPub     '' `
              -OrgName         $_psaOrgName
          }
        }
        # If user cancelled App Form or output choice, stay on the manifest manager.
      }.GetNewClosure())
    }

    if ($delBtn) {
      $delBtn.Add_Click({
        try {
        $delChoice = Show-WpfDeleteChoice -AppName $cap_nm -AppID $cap_id
        if (-not $delChoice -or $delChoice -eq 'cancel') { return }

        $localReport = $null
        if ($delChoice -eq 'everything') {
          $localReport = Remove-AppLocalArtifacts -AppID $cap_id -DisplayName $cap_nm
        }

        try {
          [xml]$mx = Get-Content $cap_xmlFile -Raw -Encoding UTF8 -ErrorAction Stop
          $nodes = @($mx.AppManifest.App | Where-Object { $_.ID -eq $cap_id })
          if ($nodes.Count -eq 0) { throw "App ID '$cap_id' was not found in appVersions.xml." }
          foreach ($node in $nodes) { $mx.AppManifest.RemoveChild($node) | Out-Null }
          $mx.Save($cap_xmlFile)
          Write-AppLog "Manifest entry removed for $cap_id (count=$($nodes.Count))"

          # Check remaining apps before building the success message.
          # If this was the last app: delete the XML file so B6 greys out on
          # main menu reload, and include guidance in the success dialog.
          $isLastApp = $false
          try {
            [xml]$chk = Get-Content $cap_xmlFile -Raw -Encoding UTF8 -ErrorAction Stop
            $remaining = @($chk.AppManifest.App | Where-Object { $_ -ne $null -and $_.ID })
            if ($remaining.Count -eq 0) {
              $isLastApp = $true
              Remove-Item $cap_xmlFile -Force -ErrorAction SilentlyContinue
            }
          } catch {}

          $msg = "$cap_nm removed from manifest."
          if ($isLastApp) {
            $msg += "`n`nNo apps remain in the manifest.`nTo package a new app, close this window and use the main menu."
          }
          if ($localReport) {
            $msg += "`n`nMachine cleanup:`n" + ($localReport.Lines -join "`n")
          }
          $msgType = if ($localReport -and $localReport.HadErrors) { 'warn' } else { 'success' }
          Show-WpfMsg -Title 'Deleted' -Message $msg -Type $msgType
          if ($rowEl) { $rowEl.Visibility = [System.Windows.Visibility]::Collapsed }
          if ($isLastApp) {
            $emptyEl = $cap_w.FindName('EmptyMsg')
            if ($emptyEl) { $emptyEl.Visibility = [System.Windows.Visibility]::Visible }
            $subEl = $cap_w.FindName('WinSub')
            if ($subEl) { $subEl.Text = 'No apps remain — use the main menu to add one' }
          }
        } catch {
          Write-AppLog "Delete failed for $cap_id : $($_.Exception.Message)" -Level ERROR
          Show-WpfMsg -Title 'Delete failed' -Message $_.Exception.Message -Type 'error'
        }
        } catch { Write-AppLog "Delete handler exception for $cap_id : $($_.Exception.Message)" ERROR }
      }.GetNewClosure())
    }
  }

  # Export All
  $btnExportAll = $w.FindName('BtnExportAll')
  if ($btnExportAll) {
    $btnExportAll.Add_Click({
      $dlg = New-Object Microsoft.Win32.SaveFileDialog
      $dlg.FileName = 'appVersions-export'; $dlg.DefaultExt = '.xml'
      $dlg.Filter   = 'XML files|*.xml|All files|*.*'
      if ($dlg.ShowDialog()) {
        try {
          Copy-Item $cap_xmlFile $dlg.FileName -Force
          Write-AppLog "Export All saved to: $($dlg.FileName)"
          Show-WpfMsg -Title 'Exported' -Message "All apps saved to:`n$($dlg.FileName)" -Type 'info'
        } catch {
          Write-AppLog "Export All failed: $($_.Exception.Message)" -Level ERROR
          Show-WpfMsg -Title 'Export failed' -Message $_.Exception.Message -Type 'error'
        }
      }
    }.GetNewClosure())
  }

  # Import -- validates XML, replaces appVersions.xml, then offers deploy choice
  $btnImport = $w.FindName('BtnImport')
  if ($btnImport) {
    $btnImport.Add_Click({
      $dlg = New-Object Microsoft.Win32.OpenFileDialog
      $dlg.Filter = 'XML files|*.xml|All files|*.*'; $dlg.Title = 'Select appVersions.xml to import'
      if (-not $dlg.ShowDialog()) { return }
      try {
        $rawXml2 = Get-Content $dlg.FileName -Raw -Encoding UTF8 -ErrorAction Stop
        if (-not $rawXml2 -or -not $rawXml2.Contains('<AppManifest>')) {
          Show-WpfMsg -Title 'Invalid file' -Message "The file does not contain a valid <AppManifest> root element." -Type 'error'; return
        }
        [xml]$importedDoc = $rawXml2
        $importedApps = @($importedDoc.AppManifest.App | Where-Object { $_ -ne $null -and $_.ID })
        if ($importedApps.Count -eq 0) {
          Show-WpfMsg -Title 'Empty manifest' -Message "No app entries found in the selected file." -Type 'warn'; return
        }
        Copy-Item $dlg.FileName $cap_xmlFile -Force
        Write-AppLog "Imported $($importedApps.Count) app(s) from $($dlg.FileName)"
        $script:_importBuildList = $null
        $deployChoice = Show-WpfImportDeployChoice -Apps $importedApps -Config $cap_config
        if ($deployChoice -eq 'all') {
          $buildList = @()
          foreach ($ia in $importedApps) {
            $buildList += @{
              AppID           = $ia.ID
              DisplayName     = if ($ia.DisplayName) { $ia.DisplayName } else { $ia.ID }
              DownloadURL     = if ($ia.DownloadURL) { $ia.DownloadURL } else { '' }
              FallbackURL     = if ($ia.FallbackURL) { $ia.FallbackURL } else { '' }
              SilentArgs      = if ($ia.SilentArgs)  { $ia.SilentArgs }  else { '/silent' }
              RegistryName    = if ($ia.RegistryDisplayName) { $ia.RegistryDisplayName } else { $ia.DisplayName }
              ProcessesToKill = if ($ia.ProcessesToKill) { $ia.ProcessesToKill } else { '' }
              LaunchExe       = if ($ia.LaunchExe) { $ia.LaunchExe } else { '' }
              Mode            = 'online'
            }
          }
          $script:_importBuildList = $buildList
          Write-AppLog "Import: Deploy All for $($buildList.Count) apps"
          $cap_w.Close()
        } elseif ($deployChoice -eq 'pick' -and $script:_importPickedList -and $script:_importPickedList.Count -gt 0) {
          $script:_importBuildList = $script:_importPickedList
          Write-AppLog "Import: Pick & Choose - $($script:_importBuildList.Count) app(s)"
          $cap_w.Close()
        } else {
          Write-AppLog "Import: no build requested"
          Show-WpfMsg -Title 'Imported' `
            -Message "$($importedApps.Count) app(s) imported.`nThe manifest will be served to enrolled devices from your Worker." `
            -Type 'info'
          $cap_w.Close()
        }
      } catch {
        Write-AppLog "Import failed: $($_.Exception.Message)" -Level ERROR
        Show-WpfMsg -Title 'Import failed' -Message $_.Exception.Message -Type 'error'
      }
    }.GetNewClosure())
  }

  # Push to Worker — only shown when a Worker URL + manifest token exist
  $btnPushWorker = $w.FindName('BtnPushWorker')
  if ($btnPushWorker) {
    $hasWorkerURL = ($Config -and $Config.WorkerURL -and $Config.WorkerURL -ne '')
    $pushToken    = Get-StoredManifestToken
    if ($hasWorkerURL -and $pushToken) {
      $btnPushWorker.Visibility = 'Visible'
      $cap_pushToken = $pushToken
      $btnPushWorker.Add_Click({
        $btnPushWorker.IsEnabled = $false
        $btnPushWorker.Content   = 'Pushing...'
        try {
          $xml  = Get-Content $cap_xmlFile -Raw -Encoding UTF8 -ErrorAction Stop
          $urls = @($cap_config.WorkerURL, $cap_config.WorkerDevURL) |
                  Where-Object { $_ -and $_ -ne '' } | Select-Object -Unique
          $pushed = $false
          foreach ($url in $urls) {
            try {
              $r = Invoke-RestMethod -Uri "$url/manifest" -Method POST `
                -Headers @{ 'X-Auth-Token' = $cap_pushToken; 'Content-Type' = 'application/xml' } `
                -Body $xml -TimeoutSec 15 -ErrorAction Stop
              if ($r -match 'success') { $pushed = $true; break }
            } catch {}
          }
          if ($pushed) {
            $btnPushWorker.Content = 'Pushed ✓'
            Show-WpfMsg -Title 'Manifest pushed' `
              -Message "appVersions.xml has been uploaded to your Worker.`nEnrolled devices will pick up the changes on their next check." `
              -Type 'success'
          } else {
            $btnPushWorker.Content = 'Push to Worker'
            $btnPushWorker.IsEnabled = $true
            Show-WpfMsg -Title 'Push failed' `
              -Message "Could not reach the Worker. Check your internet connection and try again, or use Re-deploy / update Worker from the main menu." `
              -Type 'error'
          }
        } catch {
          $btnPushWorker.Content   = 'Push to Worker'
          $btnPushWorker.IsEnabled = $true
          Show-WpfMsg -Title 'Push failed' -Message $_.Exception.Message -Type 'error'
        }
      }.GetNewClosure())
    }
  }

  $w.ShowDialog() | Out-Null
}

# =============================================================================
# Show-WpfImportDeployChoice
# Called after a successful manifest import.  Returns: 'all' | 'pick' | 'none'
# =============================================================================
function Show-WpfImportDeployChoice {
  param([object[]]$Apps, [hashtable]$Config)
  $script:_importPickedList = $null
  $appCount = $Apps.Count
  $hdr = Get-HeaderXaml 'Import complete' "$appCount app(s) imported" -showBack:$true -showClose:$true
  $appCountText = "$appCount app" + $(if($appCount -ne 1){'s'}else{''})

  $rawXaml = @'
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="520" Height="390" WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
STYLESBLOCK
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="*"/>
  <RowDefinition Height="60"/>
  </Grid.RowDefinitions>
HEADERBLOCK
  <StackPanel Grid.Row="1" Margin="24,16,24,0">
  <TextBlock FontSize="12" Foreground="#6666aa" Margin="0,0,0,16"
    Text="Would you like to build packages for the imported apps?" TextWrapping="Wrap"/>
  <Border x:Name="CardAll" Background="#101820" BorderBrush="#1e3a5f" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Build All" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
  <TextBlock x:Name="CardAllSub" FontSize="12" Foreground="#5577aa" TextWrapping="Wrap"
    Text="APPCOUNT_TEXT -- build packages for all apps. You will be asked for output type once."/>
  </StackPanel>
  </Border>
  <Border x:Name="CardPick" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Pick &amp; Choose" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
 <TextBlock Text="Select which apps to build from a checklist." FontSize="12" Foreground="#55557a" TextWrapping="Wrap" />
  </StackPanel>
  </Border>
  <Border x:Name="CardNone" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Just import" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
 <TextBlock Text="Replace the local manifest only. Build packages later." FontSize="12" Foreground="#55557a" TextWrapping="Wrap" />
  </StackPanel>
  </Border>
  </StackPanel>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Button x:Name="BtnCancel" Content="Cancel" Style="{StaticResource Btn}"
    Width="90" HorizontalAlignment="Right" Margin="0,0,20,0"/>
  </Border>
  </Grid>
</Window>
'@
  $x = $rawXaml.Replace('STYLESBLOCK', $script:S)
  $x = $x.Replace('HEADERBLOCK', $hdr)
  $x = $x.Replace('APPCOUNT_TEXT', $appCountText)
  $w = New-WpfWin $x
  if (-not $w) { return 'none' }
  Set-WinBehavior $w `
    -OnClose { $script:_idc = 'none'; $w.Close() }.GetNewClosure() `
    -OnBack  { $script:_idc = 'none'; $w.Close() }.GetNewClosure()
  $el = Get-El $w @('CardAll','CardPick','CardNone','BtnCancel')
  $script:_idc = 'none'
  $cap_apps2   = $Apps
  $cap_config2 = $Config
  $el['BtnCancel'].Add_Click({ $script:_idc = 'none'; $w.Close() }.GetNewClosure())
  $el['CardAll' ].Add_MouseLeftButtonDown({ $script:_idc = 'all';  $w.Close() }.GetNewClosure())
  $el['CardNone'].Add_MouseLeftButtonDown({ $script:_idc = 'none'; $w.Close() }.GetNewClosure())
  $el['CardPick'].Add_MouseLeftButtonDown({
    $w.Close()
    $script:_importPickedList = Show-WpfImportPicklist -Apps $cap_apps2 -Config $cap_config2
    $script:_idc = if ($script:_importPickedList -and $script:_importPickedList.Count -gt 0) { 'pick' } else { 'none' }
  }.GetNewClosure())
  $w.ShowDialog() | Out-Null
  return $script:_idc
}

# =============================================================================
# Show-WpfImportPicklist
# Checkbox list -- select which apps to build after import.
# Returns array of FormData hashtables for selected apps.
# =============================================================================
function Show-WpfImportPicklist {
  param([object[]]$Apps, [hashtable]$Config)
  $cbXaml = ($Apps | ForEach-Object {
    $id2 = $_.ID -replace '[^A-Za-z0-9_]','_'
    $nm2 = if ($_.DisplayName) { $_.DisplayName } else { $_.ID }
    $nm2 = $nm2 -replace '"',"'" -replace '&','&amp;' -replace '<','&lt;'
    ('  <CheckBox x:Name="CB_{0}" Content="{1}" IsChecked="True"' -f $id2,$nm2) +
    '  Foreground="#e8e8f4" FontSize="13" Margin="0,0,0,10"/>'
  }) -join "`n"
  $hdr = Get-HeaderXaml 'Pick apps to build' 'Select which packages to create' -showBack:$true -showClose:$true
  $pickH = [Math]::Min(74 + ($Apps.Count * 44) + 60, 560)

  $rawXaml = @'
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="480" Height="PICKH" WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
STYLESBLOCK
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="*"/>
  <RowDefinition Height="60"/>
  </Grid.RowDefinitions>
HEADERBLOCK
  <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="24,16,24,0">
  <StackPanel>
CBBLOCK
  </StackPanel>
  </ScrollViewer>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,20,0">
  <Button x:Name="BtnCancel" Content="Cancel" Style="{StaticResource Btn}" MinWidth="90" Padding="14,0" Margin="0,0,10,0"/>
  <Button x:Name="BtnBuild" Content="Build Selected" Style="{StaticResource BtnPrimary}" MinWidth="130" Padding="14,0"/>
  </StackPanel>
  </Border>
  </Grid>
</Window>
'@
  $x = $rawXaml.Replace('PICKH',       [string]$pickH)
  $x = $x.Replace('STYLESBLOCK', $script:S)
  $x = $x.Replace('HEADERBLOCK', $hdr)
  $x = $x.Replace('CBBLOCK',     $cbXaml)
  $w = New-WpfWin $x
  if (-not $w) { return @() }
  Set-WinBehavior $w -OnBack { $script:_pickResult = @(); $w.Close() }
  $el = Get-El $w @('BtnCancel','BtnBuild')
  $script:_pickResult = @()
  $el['BtnCancel'].Add_Click({ $script:_pickResult = @(); $w.Close() })
  $cap_apps3   = $Apps
  $cap_w3      = $w
  $el['BtnBuild'].Add_Click({
    $picked3 = @()
    foreach ($a3 in $cap_apps3) {
      $sid3 = $a3.ID -replace '[^A-Za-z0-9_]','_'
      $cb3  = $cap_w3.FindName("CB_$sid3")
      if ($cb3 -and $cb3.IsChecked) {
        $picked3 += @{
          AppID           = $a3.ID
          DisplayName     = if ($a3.DisplayName) { $a3.DisplayName } else { $a3.ID }
          DownloadURL     = if ($a3.DownloadURL) { $a3.DownloadURL } else { '' }
          FallbackURL     = if ($a3.FallbackURL) { $a3.FallbackURL } else { '' }
          SilentArgs      = if ($a3.SilentArgs)  { $a3.SilentArgs }  else { '/silent' }
          RegistryName    = if ($a3.RegistryDisplayName) { $a3.RegistryDisplayName } else { $a3.DisplayName }
          ProcessesToKill = if ($a3.ProcessesToKill) { $a3.ProcessesToKill } else { '' }
          LaunchExe       = if ($a3.LaunchExe) { $a3.LaunchExe } else { '' }
          Mode            = 'online'
        }
      }
    }
    $script:_pickResult = $picked3
    $cap_w3.Close()
  }.GetNewClosure())
  $w.ShowDialog() | Out-Null
  return $script:_pickResult
}

# Show-WpfMainMenu
# =============================================================================
function Show-WpfMainMenu {
  param([hashtable]$Config)
  # Reset before every call — prevents stale value if window fails to open
  $script:_mc = 0
  $wURL = if ($Config -and $Config.WorkerURL) { $Config.WorkerURL } else { '' }
  $hasW = [bool]$wURL
  $hdr  = Get-HeaderXaml 'AppUpdater Builder' 'Intune Win32 Package Generator' `
  -showBack:$false -showClose:$true -showBadge:$true -showMinimize:$true

  $x = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="CanMinimize"
  Width="500" Height="615"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="*"/>
  <RowDefinition Height="50"/>
  </Grid.RowDefinitions>

  $hdr

  <StackPanel Grid.Row="1" Margin="20,14,20,0">
  <!-- Worker status pill -->
  <Border x:Name="PillBox" Margin="0,0,0,6" CornerRadius="8"
  Padding="12,8" BorderThickness="1">
  <StackPanel Orientation="Horizontal">
  <Ellipse x:Name="PillDot" Width="8" Height="8"
  VerticalAlignment="Center" Margin="0,0,8,0"/>
  <TextBlock x:Name="PillText" FontSize="12"
  VerticalAlignment="Center" FontFamily="Consolas"/>
  </StackPanel>
  </Border>

  <Button x:Name="B1" Height="54" HorizontalContentAlignment="Left"
  Margin="0,0,0,8" Style="{StaticResource BtnSuccess}">
  <TextBlock Text="  Build app package"
  FontSize="14" FontWeight="SemiBold" VerticalAlignment="Center"/>
  </Button>
  <Button x:Name="B2" Height="46" HorizontalContentAlignment="Left"
  Margin="0,0,0,6" Style="{StaticResource Btn}">
  <TextBlock Text="  Open Output folder"
  FontSize="13" VerticalAlignment="Center"/>
  </Button>
  <Button x:Name="B3" Height="46" HorizontalContentAlignment="Left"
  Margin="0,0,0,6" Style="{StaticResource Btn}">
  <TextBlock x:Name="B3Lbl" Text="  Open status page"
  FontSize="13" VerticalAlignment="Center"/>
  </Button>
  <Button x:Name="B4" Height="46" HorizontalContentAlignment="Left"
  Margin="0,0,0,6" Style="{StaticResource Btn}">
  <TextBlock x:Name="B4Lbl" Text="  Worker / app options"
  FontSize="13" VerticalAlignment="Center"/>
  </Button>
  <Button x:Name="B5" Height="46" HorizontalContentAlignment="Left"
  Margin="0,0,0,6" Style="{StaticResource Btn}">
  <TextBlock Text="  Full reset"
  FontSize="13" Foreground="#666688" VerticalAlignment="Center"/>
  </Button>
  <Button x:Name="B6" Height="46" HorizontalContentAlignment="Left"
  Margin="0,0,0,0" Style="{StaticResource Btn}">
  <TextBlock x:Name="B6Lbl" Text="  Manage local manifest"
  FontSize="13" VerticalAlignment="Center"/>
  </Button>
  </StackPanel>

  <Border Grid.Row="2" Background="#09090f"
  BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <TextBlock x:Name="FooterText"
  FontSize="10" Foreground="#1e1e32" FontFamily="Consolas"
  VerticalAlignment="Center" Margin="20,0"/>
  </Border>
  </Grid>
</Window>
"@
  $w = New-WpfWin $x
  if (-not $w) { return 6 }
  $el = Get-El $w @('PillBox','PillDot','PillText','FooterText','B1','B2','B3','B3Lbl','B4','B4Lbl','B5','B6','B6Lbl')
  Set-WinBehavior $w -OnClose { $script:_mc = 7; $w.Close() }

  if ($hasW) {
  $el['PillBox'].Background  = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x0a,0x18,0x0a))
  $el['PillBox'].BorderBrush = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x18,0x38,0x18))
  $el['PillDot'].Fill  = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))
  $el['PillText'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))
  $el['PillText'].Text  = $wURL
  } else {
  $el['PillBox'].Background  = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x12,0x12,0x1e))
  $el['PillBox'].BorderBrush = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x22,0x22,0x35))
  $el['PillDot'].Fill  = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x40,0x40,0x60))
  $el['PillText'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x40,0x40,0x60))
  $el['PillText'].Text  = 'Not connected  —  click Connect to Cloudflare to set up'
  $el['B3Lbl'].Text  = '  Connect to Cloudflare'
  $el['B4Lbl'].Text  = '  Worker / app options'
  $el['B4'].IsEnabled  = $false
  }
  $orgName = if ($Config -and $Config.OrgName) { $Config.OrgName } else { 'IT Services' }
  $el['FooterText'].Text = "AppUpdater v$($script:Version)  ·  $orgName"
  $xmlExists = Test-Path $script:XmlFile
  $el['B6'].IsEnabled = $xmlExists
  if (-not $xmlExists) { $el['B6Lbl'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x40,0x40,0x60)) }

  $script:_mc = 7
  $el['B1'].Add_Click({ $script:_mc = 1; $w.Close() })
  $el['B2'].Add_Click({ $script:_mc = 2; $w.Close() })
  $el['B3'].Add_Click({ $script:_mc = 3; $w.Close() })
  $el['B4'].Add_Click({ $script:_mc = 4; $w.Close() })
  $el['B5'].Add_Click({ $script:_mc = 5; $w.Close() })
  $el['B6'].Add_Click({ $script:_mc = 6; $w.Close() })
  $w.Add_KeyDown({
  $k = $_.Key.ToString()
  if ($k -match '^D([1-7])$') {
    $num = [int]$Matches[1]
    $btn = $w.FindName("B$num")
    if ($btn -and -not $btn.IsEnabled) { return }
    $script:_mc = $num; $w.Close()
  }
  if ($k -eq 'Escape')  { $script:_mc = 7; $w.Close() }
  })
  $w.ShowDialog() | Out-Null
  return $script:_mc
}

# =============================================================================
# Show-WpfOutputChoice
# =============================================================================
function Show-WpfOutputChoice {
  param([string]$AppID = '')
  $hdr = Get-HeaderXaml 'Package built' 'What would you like to do with it?' `
  -showBack:$true -showClose:$true

  # Build C2 block conditionally based on admin status
  $isAdminNow = $script:IsAdmin
  $c2Block = if ($isAdminNow) {
    @'
  <Border x:Name="C2" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
  CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
  <TextBlock Text="Run on this machine" FontSize="13" FontWeight="SemiBold"
  Foreground="#e8e8f4" Margin="0,0,0,4"/>
  <TextBlock Text="Installs the scheduled task, scripts and Public Desktop shortcut on this PC now. Output shown in this window." FontSize="12" Foreground="#55557a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
'@
  } else {
    @'
  <Border x:Name="C2" Background="#0e0e16" BorderBrush="#22223a" BorderThickness="1"
  CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Opacity="0.5">
  <StackPanel>
  <TextBlock Text="Run on this machine  (requires admin)" FontSize="13" FontWeight="SemiBold"
  Foreground="#55557a" Margin="0,0,0,4"/>
  <TextBlock Text="Not available — AppUpdater is not running as administrator." FontSize="12" Foreground="#44445a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  <Border Background="#1a1400" BorderBrush="#4a3a00" BorderThickness="1" CornerRadius="6" Padding="12,8" Margin="0,-4,0,10">
  <TextBlock FontSize="11" Foreground="#d4b840" TextWrapping="Wrap">
  &#9888;  To deploy to this machine: choose <Bold>Save scripts only</Bold>, then right-click Deploy-AppID.ps1 in C:\ProgramData\AppUpdater\_output and choose <Italic>Run as administrator</Italic>.
  </TextBlock>
  </Border>
'@
  }

  $x = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="520" Height="520"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="*"/>
  </Grid.RowDefinitions>

  $hdr

  <StackPanel Grid.Row="1" Margin="24,18,24,24">
  <Border x:Name="C1" Background="#101820" BorderBrush="#1e3a5f" BorderThickness="1"
  CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
  <TextBlock Text="Create .intunewin" FontSize="13" FontWeight="SemiBold"
  Foreground="#e8e8f4" Margin="0,0,0,4"/>
  <TextBlock Text="Package for Intune Win32 app upload."
  FontSize="12" Foreground="#5577aa"/>
  </StackPanel>
  </Border>
$c2Block
  <Border x:Name="C3" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
  CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
  <TextBlock Text="Save scripts only" FontSize="13" FontWeight="SemiBold"
  Foreground="#e8e8f4" Margin="0,0,0,4"/>
  <TextBlock Text="Copy generated scripts to C:\ProgramData\AppUpdater\_output. Run Deploy-AppID.ps1 as admin on each machine to set up." FontSize="12" Foreground="#55557a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  <Border x:Name="C4" Background="#0e1a12" BorderBrush="#1e4a2a" BorderThickness="1"
  CornerRadius="8" Padding="18,14" Cursor="Hand">
  <StackPanel>
  <TextBlock Text="Export as PSADT package" FontSize="13" FontWeight="SemiBold"
  Foreground="#e8e8f4" Margin="0,0,0,4"/>
  <TextBlock Text="Save scripts and wrap with PowerShell App Deployment Toolkit for enterprise close-apps prompts." FontSize="12" Foreground="#3a7a55" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  </StackPanel>
  </Grid>
</Window>
"@
  $w = New-WpfWin $x
  if (-not $w) { return 'scripts' }
  $el = Get-El $w @('C1','C2','C3','C4')
  Set-WinBehavior $w -OnBack { $script:_oc = $null; $w.Close() }
  $script:_oc = $null   # null = cancelled (X button); only set non-null when an option is clicked
  $el['C1'].Add_MouseLeftButtonUp({ $script:_oc = 'intunewin'; $w.Close() })
  if ($isAdminNow) {
    $el['C2'].Add_MouseLeftButtonUp({ $script:_oc = 'local'; $w.Close() })
  }
  $el['C3'].Add_MouseLeftButtonUp({ $script:_oc = 'scripts'; $w.Close() })
  $el['C4'].Add_MouseLeftButtonUp({ $script:_oc = 'psadt';   $w.Close() })
  $w.ShowDialog() | Out-Null
  return $script:_oc
}

# =============================================================================
# Show-WpfAppForm
# Fields are HIDDEN until a file is picked with Browse (or Defaults provided)
# =============================================================================
function Show-WpfAppForm {
  param(
    [hashtable]$Defaults = @{},
    [bool]$HasWorker = $false,
    [switch]$AmendMode    # Editing an existing manifest entry — locks App ID, retitles dialog
  )

  $modeRow = if ($HasWorker) { @'
  <TextBlock Text="Package mode" FontSize="11" Foreground="#55557a" Margin="0,0,0,6"/>
  <StackPanel Orientation="Horizontal" Margin="0,0,0,16">
  <Button x:Name="BtnOnline"  Content="Online (Worker)"  Style="{StaticResource BtnPrimary}"
  Height="36" Padding="14,0" Margin="0,0,8,0"/>
  <Button x:Name="BtnOffline" Content="Offline (direct)" Style="{StaticResource Btn}"
  Height="36" Padding="14,0"/>
  </StackPanel>
'@ } else { '' }

  if ($AmendMode) {
    $editingName = if ($Defaults.DisplayName) { $Defaults.DisplayName } elseif ($Defaults.AppID) { $Defaults.AppID } else { 'app' }
    $hdrTitle    = "Edit: $editingName"
    $hdrSub      = 'Modify any field, then save. App ID is locked to keep package paths consistent.'
  } else {
    $hdrTitle    = 'App package details'
    $hdrSub      = 'Browse to an installer, or fill in fields manually'
  }
  $hdr = Get-HeaderXaml $hdrTitle $hdrSub -showBack:$true -showClose:$true -showMinimize:$true

  # Fields start Collapsed for new builds; Visible when amending or pre-filling
  $startVis = if ($Defaults.Count -gt 0 -or $AmendMode) { 'Visible' } else { 'Collapsed' }
  $buildBtnText = if ($AmendMode) { 'Save changes  &#187;' } else { 'Build package  &#8250;' }

  # Package-type toggle row — hidden in amend mode (runtime packages cannot be changed to simple)
  $pkgTypeRowVis = if ($AmendMode) { 'Collapsed' } else { 'Visible' }
  $pkgTypeRow = @"
  <!-- ── Package type toggle (Simple / Runtime) ── -->
  <StackPanel x:Name="PkgTypeRow" Visibility="$pkgTypeRowVis" Margin="0,0,0,10">
  <Border CornerRadius="7" Background="#0d0d1c" BorderBrush="#22224a" BorderThickness="1" Padding="14,12">
  <StackPanel>
  <TextBlock Text="PACKAGE TYPE" FontSize="9" FontWeight="SemiBold"
  Foreground="#2e2e4e" Margin="0,0,0,8"/>
  <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
  <Button x:Name="BtnRuntime" Content="AppUpdater Runtime" Style="{StaticResource BtnPrimary}"
  Height="32" Padding="12,0" Margin="0,0,8,0" FontSize="12"/>
  <Button x:Name="BtnSimple"  Content="Simple Package"     Style="{StaticResource Btn}"
  Height="32" Padding="12,0" FontSize="12"/>
  </StackPanel>
  <TextBlock x:Name="PkgTypeDesc"
  Text="Runtime: installs auto-update task, scripts and desktop shortcut on every device."
  FontSize="11" Foreground="#33334a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  </StackPanel>
"@

  $x = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="CanMinimize"
  Width="600" SizeToContent="Height" MinHeight="220" MaxHeight="860"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="Auto"/>
  <RowDefinition Height="*"/>
  <RowDefinition Height="64"/>
  </Grid.RowDefinitions>

  $hdr

  <!-- Installer picker (always visible) -->
  <Border Grid.Row="1" Margin="24,12,24,0" Background="#0c0c18"
  BorderBrush="#2e2e45" BorderThickness="1" CornerRadius="7" Padding="14,11">
  <Grid>
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="Auto"/>
  </Grid.ColumnDefinitions>
  <StackPanel VerticalAlignment="Center">
  <TextBlock Text="Installer file" FontSize="11" Foreground="#55557a" Margin="0,0,0,3"/>
  <TextBlock x:Name="InspLabel"
  Text="No file selected — click Browse to auto-detect fields"
  FontSize="11" Foreground="#33334a"
  FontFamily="Consolas" TextTrimming="CharacterEllipsis"/>
  </StackPanel>
  <Button x:Name="BtnBrowse" Grid.Column="1"
  Content="Browse..." Style="{StaticResource BtnPrimary}"
  Height="34" Padding="14,0" Margin="12,0,0,0"
  FontSize="12" VerticalAlignment="Center"/>
  </Grid>
  </Border>

  <!-- Fields — hidden until file selected (or Defaults pre-filled) -->
  <ScrollViewer Grid.Row="2" x:Name="FieldScroll"
  Visibility="$startVis"
  VerticalScrollBarVisibility="Auto" Margin="0,10,0,0">
  <StackPanel Margin="20,8,20,12">
  $modeRow
  $pkgTypeRow
  <!-- ── CARD: Identity ── -->
  <Border Margin="0,0,0,8" CornerRadius="7"
  Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1">
  <StackPanel Margin="14,12,14,14">
  <TextBlock Text="IDENTITY" FontSize="9" FontWeight="SemiBold"
  Foreground="#2e2e4e" Margin="0,0,0,10"/>
  <Grid Margin="0,0,0,10">
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="12"/>
  <ColumnDefinition Width="*"/>
  </Grid.ColumnDefinitions>
  <StackPanel Grid.Column="0">
  <Label Content="App ID (no spaces)"/>
  <TextBox x:Name="FID" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="12"/>
  </StackPanel>
  <StackPanel Grid.Column="2">
  <Label Content="Display Name"/>
  <TextBox x:Name="FDN" Style="{StaticResource Field}" Height="34"/>
  </StackPanel>
  </Grid>
  </StackPanel>
  </Border>
  <!-- ── CARD: Download ── -->
  <Border x:Name="DownloadCard" Margin="0,0,0,8" CornerRadius="7"
  Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1">
  <StackPanel Margin="14,12,14,14">
  <TextBlock Text="DOWNLOAD" FontSize="9" FontWeight="SemiBold"
  Foreground="#2e2e4e" Margin="0,0,0,10"/>
  <Grid Margin="0,0,0,10">
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="12"/>
  <ColumnDefinition Width="*"/>
  </Grid.ColumnDefinitions>
  <StackPanel Grid.Column="0">
  <Label Content="Primary URL"/>
  <TextBox x:Name="FDL" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="11"/>
  </StackPanel>
  <StackPanel Grid.Column="2">
  <Label Content="Fallback URL (optional)"/>
  <TextBox x:Name="FFB" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="11"/>
  </StackPanel>
  </Grid>
  </StackPanel>
  </Border>
  <!-- ── CARD: Install ── -->
  <Border Margin="0,0,0,8" CornerRadius="7"
  Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1">
  <StackPanel Margin="14,12,14,14">
  <TextBlock Text="INSTALL" FontSize="9" FontWeight="SemiBold"
  Foreground="#2e2e4e" Margin="0,0,0,10"/>
  <Grid>
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="12"/>
  <ColumnDefinition Width="*"/>
  </Grid.ColumnDefinitions>
  <StackPanel Grid.Column="0">
  <Label Content="Silent install arguments"/>
  <TextBox x:Name="FAR" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="12"/>
  </StackPanel>
  <StackPanel Grid.Column="2">
  <Label Content="Registry Display Name"/>
  <TextBox x:Name="FRG" Style="{StaticResource Field}" Height="34" FontSize="12"/>
  <TextBlock x:Name="ArpHint" Visibility="Collapsed" FontSize="10" Foreground="#d4b840"
  TextWrapping="Wrap" Margin="0,4,0,0">
  &#9888; Must match the exact name in Add/Remove Programs — used for detection and uninstall.
  </TextBlock>
  </StackPanel>
  </Grid>
  </StackPanel>
  </Border>
  <!-- ── Simple package target + banner (visible only in Simple mode) ── -->
  <StackPanel x:Name="SimplePkgTargetRow" Visibility="Collapsed" Margin="0,0,0,8">
  <Border CornerRadius="7" Background="#0a0a16" BorderBrush="#1a1a30" BorderThickness="1" Padding="14,12">
  <StackPanel>
  <TextBlock Text="PACKAGE AS" FontSize="9" FontWeight="SemiBold"
  Foreground="#2e2e4e" Margin="0,0,0,8"/>
  <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
  <Button x:Name="BtnTgtIntune"   Content="Intune .intunewin" Style="{StaticResource BtnPrimary}"
  Height="30" Padding="10,0" Margin="0,0,6,0" FontSize="11"/>
  <Button x:Name="BtnTgtPsadtV3" Content="PSADT v3"          Style="{StaticResource Btn}"
  Height="30" Padding="10,0" Margin="0,0,6,0" FontSize="11"/>
  <Button x:Name="BtnTgtPsadtV4" Content="PSADT v4"          Style="{StaticResource Btn}"
  Height="30" Padding="10,0" FontSize="11"/>
  </StackPanel>
  <TextBlock x:Name="SimpleTgtDesc" FontSize="11" Foreground="#33334a" TextWrapping="Wrap" Margin="0,4,0,0">
  Bundles the installer directly in a .intunewin package. No runtime installed on devices.
  </TextBlock>
  </StackPanel>
  </Border>
  </StackPanel>
  <!-- ── Banner browse (visible only when PSADT target selected) ── -->
  <Border x:Name="BannerRow" Visibility="Collapsed" Margin="0,0,0,8" CornerRadius="7"
  Background="#0a0a14" BorderBrush="#1a1a2e" BorderThickness="1">
  <StackPanel Margin="14,12,14,12">
  <TextBlock Text="PSADT BANNER (OPTIONAL)" FontSize="9" FontWeight="SemiBold"
  Foreground="#2e2e4e" Margin="0,0,0,8"/>
  <Grid>
  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
  <TextBlock x:Name="BannerLabel" Text="No banner — using PSADT default" FontSize="11"
  Foreground="#33334a" FontFamily="Consolas" TextTrimming="CharacterEllipsis"
  VerticalAlignment="Center"/>
  <Button x:Name="BtnBrowseBanner" Grid.Column="1" Content="Browse PNG..."
  Style="{StaticResource Btn}" Height="30" Padding="10,0" Margin="8,0,0,0"
  FontSize="11" VerticalAlignment="Center"/>
  </Grid>
  </StackPanel>
  </Border>
  <!-- ── Advanced expander ── -->
  <Border x:Name="AdvancedExpander" CornerRadius="7"
  Background="#0a0a16" BorderBrush="#1a1a2e" BorderThickness="1">
  <StackPanel>
  <Button x:Name="BtnAdvanced" Background="Transparent" BorderThickness="0"
  Cursor="Hand" Padding="14,9" HorizontalContentAlignment="Left">
  <StackPanel Orientation="Horizontal">
  <TextBlock x:Name="AdvArrow" Text="&#x25B6;" FontSize="9"
  Foreground="#2e2e4e" VerticalAlignment="Center" Margin="0,0,8,0"/>
  <TextBlock Text="Advanced options" FontSize="11"
  Foreground="#2e2e4e" VerticalAlignment="Center"/>
  <TextBlock Text="  auto-detected at install time · override only"
  FontSize="10" Foreground="#1e1e34" VerticalAlignment="Center"/>
  </StackPanel>
  </Button>
  <StackPanel x:Name="AdvancedPanel" Visibility="Collapsed" Margin="14,0,14,14">
  <Grid>
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="12"/>
  <ColumnDefinition Width="*"/>
  </Grid.ColumnDefinitions>
  <StackPanel Grid.Column="0">
  <Label Content="Processes to kill (no .exe)"/>
  <TextBox x:Name="FKL" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="11"/>
  </StackPanel>
  <StackPanel x:Name="LaunchExeRow" Grid.Column="2">
  <Label Content="Launch exe after install"/>
  <TextBox x:Name="FLX" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="11"/>
  </StackPanel>
  </Grid>
  <Grid Margin="0,8,0,0">
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="12"/>
  <ColumnDefinition Width="*"/>
  </Grid.ColumnDefinitions>
  <StackPanel Grid.Column="0">
  <Label Content="Expected publisher (optional)"/>
  <TextBox x:Name="FPB" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="11"
    ToolTip="Authenticode signer CN — leave blank to skip publisher check"/>
  </StackPanel>
  <StackPanel Grid.Column="2">
  <Label Content="SHA-256 hash (optional, offline only)"/>
  <Grid>
  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
  <TextBox x:Name="FSHA" Grid.Column="0" Style="{StaticResource Field}" Height="34" FontFamily="Consolas" FontSize="11"
    ToolTip="64-character hex SHA-256 of the installer — leave blank to skip"/>
  <Button x:Name="BtnFetchHash" Grid.Column="1" Content="Fetch" Height="34" Padding="8,0" Margin="4,0,0,0"
    Style="{StaticResource Btn}" FontSize="11" IsEnabled="False"
    ToolTip="Download the installer and compute its SHA-256 hash"/>
  </Grid>
  <TextBlock x:Name="HashStatus" FontSize="10" Foreground="#55557a" Margin="0,3,0,0"/>
  </StackPanel>
  </Grid>
  </StackPanel>
  </StackPanel>
  </Border>
  </StackPanel>
  </ScrollViewer>

  <!-- Placeholder shown when fields are hidden -->
  <Border Grid.Row="2" x:Name="FieldPlaceholder"
  Visibility="$(if ($startVis -eq 'Visible') {'Collapsed'} else {'Visible'})"
  Margin="24,20,24,0">
  <TextBlock FontSize="13" Foreground="#33334a" TextWrapping="Wrap">
  Browse to an installer above to auto-detect app details,
  or type an App ID and Download URL manually.
  </TextBlock>
  </Border>

  <!-- Footer -->
  <Border Grid.Row="3" Background="#09090f"
  BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
  VerticalAlignment="Center" Margin="0,0,24,0">
  <Button x:Name="BtnCancel" Content="Cancel"
  Style="{StaticResource Btn}" Width="100" Margin="0,0,10,0"/>
  <Button x:Name="BtnBuild"  Content="$buildBtnText"
  Style="{StaticResource BtnPrimary}" Width="165"
  FontWeight="SemiBold" FontSize="13"/>
  </StackPanel>
  </Border>
  </Grid>
</Window>
"@
  $w = New-WpfWin $x
  if (-not $w) { return $null }

  $named = @('BtnBrowse','InspLabel','FieldScroll','FieldPlaceholder',
  'FID','FDN','FDL','FFB','FAR','FRG','FKL','FLX','FPB','FSHA','BtnCancel','BtnBuild',
  'BtnAdvanced','AdvancedPanel','AdvArrow','BtnFetchHash','HashStatus',
  'DownloadCard','ArpHint','LaunchExeRow','PkgTypeDesc',
  'BtnRuntime','BtnSimple',
  'SimplePkgTargetRow','SimpleTgtDesc','BtnTgtIntune','BtnTgtPsadtV3','BtnTgtPsadtV4',
  'BannerRow','BannerLabel','BtnBrowseBanner')
  if ($HasWorker) { $named += @('BtnOnline','BtnOffline') }
  # Simple-mode state variables (script-scope so delegates can mutate them)
  $script:_pkgType    = 'runtime'  # 'runtime' | 'simple'
  $script:_simpleTgt  = 'intunewin' # 'intunewin' | 'psadt-v3' | 'psadt-v4'
  $script:_bannerPath = ''
  $script:_installerPath = if ($Defaults.ContainsKey('InstallerPath') -and $Defaults.InstallerPath) { $Defaults.InstallerPath } else { '' }
  $el = Get-El $w $named
  $script:_fr = 'back'
  Set-WinBehavior $w `
    -OnClose { $script:_fr = 'back'; $w.Close() }.GetNewClosure() `
    -OnBack  { $script:_fr = 'back'; $w.Close() }.GetNewClosure()

  # Pre-fill any supplied defaults
  $fldMap = @{
  AppID='FID'; DisplayName='FDN'; DownloadURL='FDL'; FallbackURL='FFB'
  SilentArgs='FAR'; RegistryName='FRG'; ProcessesToKill='FKL'; LaunchExe='FLX'
  ExpectedPublisher='FPB'; InstallerSHA256='FSHA'
  }
  foreach ($k in $fldMap.Keys) {
  if ($Defaults.ContainsKey($k) -and $Defaults[$k]) {
  $el[$fldMap[$k]].Text = $Defaults[$k]
  }
  }

  # Amend mode: lock App ID (changing it would orphan the deployed scripts and
  # task on every device), hide the installer-picker row (we already have URLs),
  # and visibly reveal the fields right away.
  if ($AmendMode) {
    $el['FID'].IsReadOnly = $true
    $el['FID'].Background = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x06,0x06,0x10))
    $el['FID'].ToolTip   = 'App ID is locked when editing — it identifies the deployed package on every device.'
    $el['InspLabel'].Text = "Editing $($Defaults.DisplayName) — installer browse not required"
    $el['BtnBrowse'].IsEnabled = $false
    $el['FieldScroll'].Visibility       = [Windows.Visibility]::Visible
    $el['FieldPlaceholder'].Visibility  = [Windows.Visibility]::Collapsed
  }

  # Mode toggle
  $script:_pm = if ($HasWorker) { 'online' } else { 'offline' }
  if ($HasWorker) {
  $el['BtnOnline'].Add_Click({
  $script:_pm = 'online'
  $script:_el['BtnOnline'].Style  = $w.Resources['BtnPrimary']
  $script:_el['BtnOffline'].Style = $w.Resources['Btn']
  })
  $el['BtnOffline'].Add_Click({
  $script:_pm = 'offline'
  $script:_el['BtnOffline'].Style = $w.Resources['BtnPrimary']
  $script:_el['BtnOnline'].Style  = $w.Resources['Btn']
  })
  }

  # Browse — open file dialog, auto-fill, THEN reveal fields.
  # $script:_el pins the element hashtable into script scope so the Add_Click
  # delegate (which runs in a child scope) can reach it reliably.
  # Pin el into script scope before any delegates are wired
  $script:_el = $el

  # ── Simple / Runtime package-type toggle ──────────────────────────────────
  # Helper: set UI to runtime or simple mode
  $script:_applyPkgMode = {
    param([string]$mode)
    $script:_pkgType = $mode
    if ($mode -eq 'simple') {
      $script:_el['BtnRuntime'].Style = $w.Resources['Btn']
      $script:_el['BtnSimple'].Style  = $w.Resources['BtnPrimary']
      $script:_el['PkgTypeDesc'].Text = 'Simple: bundles the installer directly. No auto-update, no task, no shortcuts.'
      $script:_el['DownloadCard'].Visibility       = [Windows.Visibility]::Collapsed
      $script:_el['LaunchExeRow'].Visibility       = [Windows.Visibility]::Collapsed
      $script:_el['ArpHint'].Visibility            = [Windows.Visibility]::Visible
      $script:_el['SimplePkgTargetRow'].Visibility = [Windows.Visibility]::Visible
    } else {
      $script:_el['BtnRuntime'].Style = $w.Resources['BtnPrimary']
      $script:_el['BtnSimple'].Style  = $w.Resources['Btn']
      $script:_el['PkgTypeDesc'].Text = 'Runtime: installs auto-update task, scripts and desktop shortcut on every device.'
      $script:_el['DownloadCard'].Visibility       = [Windows.Visibility]::Visible
      $script:_el['LaunchExeRow'].Visibility       = [Windows.Visibility]::Visible
      $script:_el['ArpHint'].Visibility            = [Windows.Visibility]::Collapsed
      $script:_el['SimplePkgTargetRow'].Visibility = [Windows.Visibility]::Collapsed
      $script:_el['BannerRow'].Visibility          = [Windows.Visibility]::Collapsed
    }
  }

  $el['BtnRuntime'].Add_Click({ & $script:_applyPkgMode 'runtime' })
  $el['BtnSimple'].Add_Click({  & $script:_applyPkgMode 'simple'  })

  # ── Simple package target (Intune / PSADT v3 / PSADT v4) ─────────────────
  $script:_applySimpleTgt = {
    param([string]$tgt)
    $script:_simpleTgt = $tgt
    foreach ($btn in @('BtnTgtIntune','BtnTgtPsadtV3','BtnTgtPsadtV4')) {
      $script:_el[$btn].Style = $w.Resources['Btn']
    }
    $activeBtn = switch ($tgt) {
      'intunewin' { 'BtnTgtIntune' }
      'psadt-v3'  { 'BtnTgtPsadtV3' }
      'psadt-v4'  { 'BtnTgtPsadtV4' }
    }
    $script:_el[$activeBtn].Style = $w.Resources['BtnPrimary']
    $desc = switch ($tgt) {
      'intunewin' { 'Bundles the installer directly in a .intunewin package. No runtime installed on devices.' }
      'psadt-v3'  { 'PSADT v3 wrap — shows close-apps dialog and progress bar. Preview runs before wrapping.' }
      'psadt-v4'  { 'PSADT v4 wrap — module-based API. Preview runs on this machine before wrapping into .intunewin.' }
    }
    $script:_el['SimpleTgtDesc'].Text = $desc
    $isPsadt = ($tgt -ne 'intunewin')
    $script:_el['BannerRow'].Visibility = if ($isPsadt) { [Windows.Visibility]::Visible } else { [Windows.Visibility]::Collapsed }
  }

  $el['BtnTgtIntune'].Add_Click({   & $script:_applySimpleTgt 'intunewin' })
  $el['BtnTgtPsadtV3'].Add_Click({  & $script:_applySimpleTgt 'psadt-v3'  })
  $el['BtnTgtPsadtV4'].Add_Click({  & $script:_applySimpleTgt 'psadt-v4'  })

  # ── Banner PNG browse ─────────────────────────────────────────────────────
  $el['BtnBrowseBanner'].Add_Click({
    $dlg = [System.Windows.Forms.OpenFileDialog]::new()
    $dlg.Title  = 'Select PSADT banner image'
    $dlg.Filter = 'PNG image (*.png)|*.png|All files (*.*)|*.*'
    $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
    if ($dlg.ShowDialog() -eq 'OK') {
      $script:_bannerPath = $dlg.FileName
      $script:_el['BannerLabel'].Text       = $dlg.FileName
      $script:_el['BannerLabel'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x6b,0xaa,0xdf))
    }
  })

  # Pre-apply simple mode if Defaults indicate it (e.g. re-edit after preview rejection)
  if ($Defaults.ContainsKey('Mode') -and $Defaults.Mode -eq 'simple') {
    & $script:_applyPkgMode 'simple'
    if ($Defaults.ContainsKey('SimplePkgTarget') -and $Defaults.SimplePkgTarget) {
      & $script:_applySimpleTgt $Defaults.SimplePkgTarget
    }
    if ($Defaults.ContainsKey('BannerImagePath') -and $Defaults.BannerImagePath) {
      $script:_bannerPath = $Defaults.BannerImagePath
      $script:_el['BannerLabel'].Text       = $Defaults.BannerImagePath
      $script:_el['BannerLabel'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x6b,0xaa,0xdf))
    }
  }

  # FEAT-O: Enable BtnFetchHash only when FDL contains a valid HTTPS URL
  $el['FDL'].Add_TextChanged({
    $script:_el['BtnFetchHash'].IsEnabled = ($script:_el['FDL'].Text.Trim() -match '^https://')
  })

  # FEAT-O: Download installer and compute SHA-256 in a background runspace
  $el['BtnFetchHash'].Add_Click({
    $url = $script:_el['FDL'].Text.Trim()
    if ($url -notmatch '^https://') { return }
    $script:_el['BtnFetchHash'].IsEnabled = $false
    $script:_el['HashStatus'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x55,0x55,0x7a))
    $script:_el['HashStatus'].Text = 'Downloading...'

    $script:_fhQ    = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $script:_fhDone = [System.Collections.Generic.List[string]]::new()

    $fhRs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $fhRs.ApartmentState = 'MTA'; $fhRs.ThreadOptions = 'ReuseThread'; $fhRs.Open()
    $fhRs.SessionStateProxy.SetVariable('_fhQ',   $script:_fhQ)
    $fhRs.SessionStateProxy.SetVariable('_fhDone',$script:_fhDone)
    $fhRs.SessionStateProxy.SetVariable('_fhUrl', $url)
    $script:_fhRs = $fhRs

    $fhPs = [System.Management.Automation.PowerShell]::Create()
    $fhPs.Runspace = $fhRs
    $fhPs.AddScript({
      $tmp = [System.IO.Path]::GetTempFileName()
      try {
        $wc = [System.Net.WebClient]::new()
        $wc.DownloadFile($_fhUrl, $tmp)
        $wc.Dispose()
        $_fhQ.Enqueue('status|Hashing...')
        $sha    = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($tmp)
        $hash   = [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLower()
        $stream.Close(); $sha.Dispose()
        $_fhDone.Add("ok|$hash")
      } catch {
        $_fhDone.Add("err|$($_.Exception.Message)")
      } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
      }
    }) | Out-Null
    $script:_fhHandle = $fhPs.BeginInvoke()
    $script:_fhPs = $fhPs

    $script:_fhTmr = [System.Windows.Threading.DispatcherTimer]::new()
    $script:_fhTmr.Interval = [TimeSpan]::FromMilliseconds(300)
    $script:_fhTmr.Add_Tick({
      $msg = ''
      while ($script:_fhQ.TryDequeue([ref]$msg)) {
        $parts = $msg -split '\|',2
        if ($parts[0] -eq 'status') { $script:_el['HashStatus'].Text = $parts[1] }
      }
      if ($script:_fhDone.Count -gt 0) {
        $script:_fhTmr.Stop()
        $res = $script:_fhDone[0] -split '\|',2
        if ($res[0] -eq 'ok') {
          $script:_el['FSHA'].Text      = $res[1]
          $script:_el['HashStatus'].Text = "Done  $($res[1].Substring(0,8))..."
          $script:_el['HashStatus'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4c,0xaf,0x50))
        } else {
          $script:_el['HashStatus'].Text = "Error: $($res[1])"
          $script:_el['HashStatus'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xcf,0x6b,0x79))
        }
        $script:_el['BtnFetchHash'].IsEnabled = $true
        $script:_fhPs.EndInvoke($script:_fhHandle) | Out-Null
        $script:_fhRs.Close()
      }
    })
    $script:_fhTmr.Start()
  })

  # Advanced expander toggle
  $el['BtnAdvanced'].Add_Click({
  $panel = $script:_el['AdvancedPanel']
  $arrow = $script:_el['AdvArrow']
  if ($panel.Visibility -eq [Windows.Visibility]::Collapsed) {
  $panel.Visibility = [Windows.Visibility]::Visible
  $arrow.Text = [char]0x25BC
  } else {
  $panel.Visibility = [Windows.Visibility]::Collapsed
  $arrow.Text = [char]0x25B6
  }
  })

  $el['BtnBrowse'].Add_Click({
  $dlg = [System.Windows.Forms.OpenFileDialog]::new()
  $dlg.Title  = 'Select installer'
  $dlg.Filter = 'Installer files (*.exe;*.msi)|*.exe;*.msi|All files (*.*)|*.*'
  $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
  if ($dlg.ShowDialog() -eq 'OK') {
  $path = $dlg.FileName
  $script:_installerPath = $path  # track for simple mode bundling
  $script:_el['InspLabel'].Text = $path
  $script:_el['InspLabel'].Foreground = [Windows.Media.SolidColorBrush]::new(
  [Windows.Media.Color]::FromRgb(0x6b,0xaa,0xdf))
  # Reveal fields and let the window grow to fit
  $script:_el['FieldScroll'].Visibility  = [Windows.Visibility]::Visible
  $script:_el['FieldPlaceholder'].Visibility = [Windows.Visibility]::Collapsed
  # Auto-detect — redirect stream 6 so Write-Host inside inspector
  # does not throw when there is no console host (WPF-only mode)
  try {
  $d = Invoke-InstallerInspector -InstallerPath $path 6>$null
  if ($d -and $d.AppID)       { $script:_el['FID'].Text = $d.AppID }
  if ($d -and $d.DisplayName) { $script:_el['FDN'].Text = $d.DisplayName }
  if ($d -and $d.SilentArgs)  { $script:_el['FAR'].Text = $d.SilentArgs }
  if ($d -and $d.RegistryName){ $script:_el['FRG'].Text = $d.RegistryName }
  if ($d -and $d.Publisher)   { $script:_el['FPB'].Text = $d.Publisher }
  } catch {}
  }
  })

  # Also show fields if user clicks Build without browsing (so they can type)
  $showFieldsOnType = {
  $script:_el['FieldScroll'].Visibility  = [Windows.Visibility]::Visible
  $script:_el['FieldPlaceholder'].Visibility = [Windows.Visibility]::Collapsed
  }
  $el['FieldPlaceholder'].Add_MouseLeftButtonDown($showFieldsOnType)

  $script:_fr = $null
  $el['BtnCancel'].Add_Click({ $script:_fr = 'back'; $w.Close() }.GetNewClosure())
  $el['BtnBuild'].Add_Click({
  # Show fields first if still hidden
  $script:_el['FieldScroll'].Visibility  = [Windows.Visibility]::Visible
  $script:_el['FieldPlaceholder'].Visibility = [Windows.Visibility]::Collapsed

  $id = $script:_el['FID'].Text.Trim()
  if (-not $id)  { Show-WpfMsg -Title 'Required' -Message 'App ID is required.' -Type 'warn'; return }
  if (-not (Test-SafeAppId $id)) { Show-WpfMsg -Title 'Invalid App ID' -Message "App ID must start with a letter or number and contain only letters, numbers, dots, hyphens, and underscores (max 64 characters). Spaces are not allowed." -Type 'warn'; return }
  if (-not $script:_el['FDN'].Text.Trim()) { Show-WpfMsg -Title 'Required' -Message 'Display Name is required.' -Type 'warn'; return }

  if ($script:_pkgType -eq 'simple') {
    # Simple mode: installer on disk is required (it gets bundled)
    if (-not $script:_installerPath -or -not (Test-Path -LiteralPath $script:_installerPath -PathType Leaf)) {
      Show-WpfMsg -Title 'Installer Required' -Message 'Simple Package mode bundles the installer file.`nBrowse to the installer (.exe or .msi) first.' -Type 'warn'
      return
    }
    # Registry name warning (non-fatal — they may know it already)
    if (-not $script:_el['FRG'].Text.Trim()) {
      $cont = Show-WpfMsg -Title 'Registry Name Recommended' `
        -Message 'Registry Display Name is empty.' `
        -Detail  'ARP-based detection and uninstall will not work without a Registry Display Name matching Add/Remove Programs.' `
        -Type 'warn' -Confirm -YesLabel 'Continue anyway' -NoLabel 'Go back'
      if (-not $cont) { return }
    }
  } else {
    # Runtime mode: original validation
    if ($script:_pm -ne 'offline' -and -not $script:_el['FDL'].Text.Trim()) { Show-WpfMsg -Title 'Required' -Message 'Download URL is required.' -Type 'warn'; return }
    if (-not $script:_el['FAR'].Text.Trim()) { Show-WpfMsg -Title 'Required' -Message 'Silent install arguments are required.' -Type 'warn'; return }
    if (-not $script:_el['FRG'].Text.Trim()) { Show-WpfMsg -Title 'Required' -Message 'Registry Name is required.' -Type 'warn'; return }
  }

  $script:_fr = @{
  AppID             = $id
  DisplayName       = $script:_el['FDN'].Text.Trim()
  DownloadURL       = $script:_el['FDL'].Text.Trim()
  FallbackURL       = $script:_el['FFB'].Text.Trim()
  SilentArgs        = $script:_el['FAR'].Text.Trim()
  RegistryName      = $script:_el['FRG'].Text.Trim()
  ProcessesToKill   = $script:_el['FKL'].Text.Trim()
  LaunchExe         = $script:_el['FLX'].Text.Trim()
  ExpectedPublisher = $script:_el['FPB'].Text.Trim()
  InstallerSHA256   = $script:_el['FSHA'].Text.Trim()
  InstallerPath     = $script:_installerPath
  Mode              = if ($script:_pkgType -eq 'simple') { 'simple' } else { $script:_pm }
  SimplePkgTarget   = $script:_simpleTgt
  BannerImagePath   = $script:_bannerPath
  }
  $w.Close()
  })

  # Stop the hash-fetch timer and abandon the runspace if the window closes
  # while a fetch is still in progress — prevents EndInvoke() blocking the
  # WPF dispatcher on the next tick after the form has already gone away.
  $w.Add_Closing({
    if ($script:_fhTmr -and $script:_fhTmr.IsEnabled) { $script:_fhTmr.Stop() }
    if ($script:_fhPs)  { try { $script:_fhPs.Stop()  } catch {} }
    if ($script:_fhRs)  { try { $script:_fhRs.Close() } catch {} }
    $script:_fhTmr = $null; $script:_fhPs = $null; $script:_fhRs = $null
  })

  $w.ShowDialog() | Out-Null
  # Return: hashtable = user built, 'back' = back button, $null = X (exit signal)
  return $script:_fr
}

# Overrides the earlier stub: adds 2 MB rollover, thread-ID, and $env:TEMP fallback.
function Write-AppLog {
  param(
    [string]$Message,
    [string]$Level = 'INFO'   # INFO | WARN | ERROR | DEBUG
  )
  try {
    $lf = if ($script:LogFile) { $script:LogFile } else { "$env:TEMP\AppUpdater.log" }
    # Roll over if > 2 MB
    if ((Test-Path $lf) -and (Get-Item $lf).Length -gt 2MB) {
      Rename-Item $lf "$lf.bak" -Force -ErrorAction SilentlyContinue
    }
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $tid   = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $apt   = [System.Threading.Thread]::CurrentThread.ApartmentState
    "$stamp [$Level] [T$tid/$apt] $Message" | Out-File $lf -Append -Encoding UTF8 -ErrorAction SilentlyContinue
  } catch {}
}

# =============================================================================
# Show-WpfCloudflareWizard
# =============================================================================
# =============================================================================
# Show-WpfPSADTExport
# Dark-themed dialog that gathers PSADT export options, then calls Export-PSADTPackage.
# =============================================================================
function Show-WpfPSADTExport {
  param(
    [Parameter(Mandatory)][string]$AppID,
    [Parameter(Mandatory)][string]$DisplayName,
    [string]$ProcessesToKill = '',
    [string]$ExpectedPub     = '',
    [string]$OrgName         = 'IT Services',
    [string]$InitialError    = ''
  )

  $hdr = Get-HeaderXaml "Wrap as PSADT — $DisplayName" `
    'PSADT handles close-apps prompts when Intune first deploys this app. AppUpdater runtime is set up identically.' `
    -showBack:$true -showClose:$true

  # Determine toolkit status text
  $markerFile    = Join-Path $PSADTCacheDir 'AppDeployToolkit\AppDeployToolkitMain.ps1'
  $toolkitCached = Test-Path $markerFile
  $toolkitStatus = if ($InitialError) { $InitialError }
                   elseif ($toolkitCached) { "Cached: $PSADTCacheDir" }
                   else { 'Will download ~5 MB on export' }

  $x = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="520" SizeToContent="Height" MinHeight="200"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="Auto"/>
  <RowDefinition Height="64"/>
  </Grid.RowDefinitions>
  $hdr
  <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
  <StackPanel Margin="24,14,24,10">
  <!-- PSADT version card -->
  <Border Margin="0,0,0,10" CornerRadius="7" Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1">
  <StackPanel Margin="14,12,14,14">
  <TextBlock Text="PSADT VERSION" FontSize="9" FontWeight="SemiBold" Foreground="#2e2e4e" Margin="0,0,0,10"/>
  <StackPanel Orientation="Horizontal">
  <RadioButton x:Name="RV3" Content="v3.x  (≤3.10, most widely deployed)" GroupName="PSADTVER" IsChecked="True"
    Foreground="#e8e8f0" FontSize="12" Margin="0,0,18,0"/>
  </StackPanel>
  <StackPanel Orientation="Horizontal" Margin="0,6,0,0">
  <RadioButton x:Name="RV4" Content="v4.x  (≥4.0, module-based API)" GroupName="PSADTVER"
    Foreground="#e8e8f0" FontSize="12" Margin="0,0,18,0"/>
  </StackPanel>
  <StackPanel Orientation="Horizontal" Margin="0,6,0,0">
  <RadioButton x:Name="RVBOTH" Content="Both  (generates v3 and v4 folders)" GroupName="PSADTVER"
    Foreground="#e8e8f0" FontSize="12"/>
  </StackPanel>
  </StackPanel>
  </Border>
  <!-- Toolkit source card -->
  <Border Margin="0,0,0,10" CornerRadius="7" Background="#0c0c1a" BorderBrush="#1e1e32" BorderThickness="1">
  <StackPanel Margin="14,12,14,14">
  <TextBlock Text="PSADT FRAMEWORK" FontSize="9" FontWeight="SemiBold" Foreground="#2e2e4e" Margin="0,0,0,8"/>
  <TextBlock x:Name="ToolkitStatus" Text="$toolkitStatus" FontSize="11" Foreground="#55557a" FontFamily="Consolas" Margin="0,0,0,8"/>
  <StackPanel Orientation="Horizontal">
  <TextBlock Text="Or use existing folder: " FontSize="11" Foreground="#55557a" VerticalAlignment="Center"/>
  <TextBox x:Name="ManualPath" Style="{StaticResource Field}" Width="200" Height="28" FontFamily="Consolas" FontSize="10" Margin="8,0,8,0"/>
  <Button x:Name="BtnBrowse" Content="Browse..." Style="{StaticResource Btn}" Height="28" Padding="8,0" FontSize="11"/>
  </StackPanel>
  </StackPanel>
  </Border>
  </StackPanel>
  </ScrollViewer>
  <!-- Footer -->
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,24,0">
  <Button x:Name="BtnCancel" Content="Cancel"  Style="{StaticResource Btn}"     Height="34" Padding="18,0" Margin="0,0,8,0" FontSize="12"/>
  <Button x:Name="BtnExport" Content="Export  ›" Style="{StaticResource BtnPrimary}" Height="34" Padding="18,0" FontSize="12"/>
  </StackPanel>
  </Border>
  </Grid>
</Window>
"@

  $w  = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new([xml]$x))
  $el = Get-El $w @('RV3','RV4','RVBOTH','ToolkitStatus','ManualPath','BtnBrowse','BtnCancel','BtnExport')
  Set-WinBehavior $w -OnBack { $w.Close() }.GetNewClosure()
  $el['BtnCancel'].Add_Click({ $w.Close() }.GetNewClosure())
  if ($InitialError) {
    $el['ToolkitStatus'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x88,0x44))
  }

  $el['BtnBrowse'].Add_Click({
    $dlg = [System.Windows.Forms.FolderBrowserDialog]::new()
    $dlg.Description = 'Select PSADT root — must contain an AppDeployToolkit subfolder (for v4 packages, navigate into PSAppDeployToolkit\Frontend\v3)'
    if ($dlg.ShowDialog() -eq 'OK') {
      $script:_el['ManualPath'].Text = $dlg.SelectedPath
    }
  })

  $script:_psadtResult = $null
  $el['BtnExport'].Add_Click({
    $ver = if ($script:_el['RV4'].IsChecked)    { 'v4'   }
           elseif ($script:_el['RVBOTH'].IsChecked) { 'both' }
           else                                     { 'v3'   }
    $manPath = $script:_el['ManualPath'].Text.Trim()
    $script:_psadtResult = @{ Version=$ver; ManualPath=$manPath }
    $w.Close()
  })

  $script:_el = $el
  $w.ShowDialog() | Out-Null

  if (-not $script:_psadtResult) { return }

  Export-PSADTPackage `
    -AppID            $AppID `
    -DisplayName      $DisplayName `
    -ProcessesToKill  $ProcessesToKill `
    -ExpectedPub      $ExpectedPub `
    -PSADTVersion     $script:_psadtResult.Version `
    -PSADTToolkitPath $script:_psadtResult.ManualPath `
    -OrgName          $OrgName
}

function Show-WpfCloudflareWizard {
  param([string]$OrgName = 'IT Services')
  $hdr = Get-HeaderXaml 'Connect to Cloudflare' 'Takes about 2 minutes — everything is set up automatically' `
  -showBack:$true -showClose:$true

  $x = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="540" Height="760"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="*"/>
  <RowDefinition Height="64"/>
  </Grid.RowDefinitions>

  $hdr

  <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
  <StackPanel Margin="24,16,24,0">

    <!-- API Token -->
    <Grid Margin="0,0,0,4">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
 <TextBlock Text="Cloudflare API Token" Foreground="#8888aa" FontSize="12" VerticalAlignment="Center" TextWrapping="Wrap" />
      <TextBlock Grid.Column="1" FontSize="11" Foreground="#3d5a7a" VerticalAlignment="Center">
        <Hyperlink x:Name="LinkTokenPage" Foreground="#3d6a9a" TextDecorations="Underline">Create token &#8599;</Hyperlink>
      </TextBlock>
    </Grid>
    <PasswordBox x:Name="Token" Style="{StaticResource PwField}" Height="40" Margin="0,0,0,6"/>
    <!-- Token creation guide -->
    <Border Background="#07111a" BorderBrush="#1a2a3a" BorderThickness="1" CornerRadius="5" Padding="12,10" Margin="0,0,0,14">
      <StackPanel>
        <TextBlock FontSize="11" FontWeight="SemiBold" Foreground="#6baadf" Margin="0,0,0,6">How to create the token:</TextBlock>
        <TextBlock FontSize="11" Foreground="#7799bb" Margin="0,0,0,3">1.  Click "Create token" above  &#8599;</TextBlock>
        <TextBlock FontSize="11" Foreground="#7799bb" Margin="0,0,0,3">2.  Click <Run FontWeight="SemiBold" Foreground="#aaccee">Use template</Run> next to "Edit Cloudflare Workers"</TextBlock>
        <TextBlock FontSize="11" Foreground="#7799bb" Margin="0,0,0,6">3.  The template covers Workers + KV + Account. You must also add these two Access rows:</TextBlock>
        <Border Background="#0a1c2a" BorderBrush="#1e3a50" BorderThickness="1" CornerRadius="4" Padding="10,7" Margin="0,0,0,6">
          <StackPanel>
            <TextBlock FontSize="11" Foreground="#55aa88" Margin="0,0,0,2">&#10003;  Account &#8250; Workers Scripts &#8250; Edit              (from template)</TextBlock>
            <TextBlock FontSize="11" Foreground="#55aa88" Margin="0,0,0,2">&#10003;  Account &#8250; Workers KV Storage &#8250; Edit         (from template)</TextBlock>
            <TextBlock FontSize="11" Foreground="#55aa88" Margin="0,0,0,2">&#10003;  Account &#8250; Account Settings &#8250; Read            (from template)</TextBlock>
          </StackPanel>
        </Border>
        <TextBlock FontSize="10" Foreground="#666688" Margin="0,4,0,0" TextWrapping="Wrap">Custom domain setup is done after deploy via <Run FontWeight="SemiBold" Foreground="#88aacc">Worker / app options &#8250; Set up custom domain</Run> — that flow uses a separate token and walks you through it.</TextBlock>
        <TextBlock FontSize="11" Foreground="#7799bb" Margin="0,0,0,0">4.  Click <Run FontWeight="SemiBold" Foreground="#aaccee">Continue to summary</Run> and save the token.</TextBlock>
      </StackPanel>
    </Border>

    <!-- Org name -->
    <StackPanel Orientation="Horizontal" Margin="0,0,0,3">
 <TextBlock Text="Organisation name" Foreground="#8888aa" FontSize="12" VerticalAlignment="Center" TextWrapping="Wrap" />
      <TextBlock x:Name="HlpOrg" Text=" ?" FontSize="10" Foreground="#3a3a5c" Cursor="Help"
        VerticalAlignment="Center" Margin="2,0,0,0">
        <TextBlock.ToolTip>
          <ToolTip Background="#111128" BorderBrush="#2a2a44" Foreground="#9999cc"
            FontSize="11" MaxWidth="280" HasDropShadow="True" Padding="9,7">
            <TextBlock TextWrapping="Wrap">Just your team or company name — something like <Span Foreground="#ccccff">Acme IT</Span> or <Span Foreground="#ccccff">IT Services</Span>. It appears in the update popup that users see when their apps are being upgraded.</TextBlock>
          </ToolTip>
        </TextBlock.ToolTip>
      </TextBlock>
    </StackPanel>
    <TextBox x:Name="Org" Style="{StaticResource Field}" Height="40" Margin="0,0,0,12"/>

    <!-- Status page is password-protected at first run; password is set after deploy. -->
    <TextBlock FontSize="11" Foreground="#6a6a88" TextWrapping="Wrap" Margin="0,4,0,0">
      After deploy you&#x2019;ll be asked to set a password that gates the /status dashboard. Machine pushes keep using the bearer token separately.
    </TextBlock>
    <TextBlock x:Name="WizError" Foreground="#ff6666" FontSize="11" TextWrapping="Wrap"
      Margin="0,10,0,0" Visibility="Collapsed"/>

  </StackPanel>
  </ScrollViewer>

  <Border Grid.Row="2" Background="#09090f"
  BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
  VerticalAlignment="Center" Margin="0,0,24,0">
  <Button x:Name="BtnCancel" Content="Cancel"
  Style="{StaticResource Btn}" Width="100" Margin="0,0,10,0"/>
  <Button x:Name="BtnGo" Content="Deploy Worker  &#8250;"
  Style="{StaticResource BtnPrimary}" Width="165"
  FontWeight="SemiBold" FontSize="13" IsDefault="True" IsEnabled="False"/>
  </StackPanel>
  </Border>
  </Grid>
</Window>
"@
  $w = New-WpfWin $x
  if (-not $w) { return $null }
  $el = Get-El $w @('Token','Org',
                    'BtnCancel','BtnGo','LinkTokenPage','HlpOrg','WizError')
  $el['Org'].Text = $OrgName
  Set-WinBehavior $w -OnBack { $w.Close() }

  # Wire up hyperlinks and ? icons
  $el['LinkTokenPage'].Add_Click({
    try { Start-Process 'https://dash.cloudflare.com/profile/api-tokens' } catch {}
    $_.Handled = $true })

  # Use a .NET List as result container — captured by reference in the closure,
  # so mutations inside the event handler are visible outside it.
  # ($script: variables written inside GetNewClosure() handlers are NOT visible
  # outside the closure due to a PowerShell scoping quirk.)
  $cfWizResult = [System.Collections.Generic.List[hashtable]]::new()
  Write-AppLog "Wizard: window opened — Token=$($null -ne $el['Token']) BtnGo=$($null -ne $el['BtnGo'])"
  # Enable Deploy button only when a token has been typed (checklist §6: "enter token → Next enabled")
  $cap_goBtn  = $el['BtnGo']
  $cap_tokPwd = $el['Token']
  $el['Token'].Add_PasswordChanged({
    $cap_goBtn.IsEnabled = ($cap_tokPwd.Password.Length -gt 0)
  }.GetNewClosure())
  $el['BtnCancel'].Add_Click({ $w.Close() }.GetNewClosure())
  $btnGo = $el['BtnGo']
  if (-not $btnGo) { $btnGo = $w.FindName('BtnGo') }
  if (-not $btnGo) {
    Write-AppLog 'Wizard: BtnGo element not found — cannot wire handler' -Level ERROR
    [System.Windows.MessageBox]::Show(
      'Internal error: Deploy button not found. Please restart AppUpdater.',
      'AppUpdater', 'OK', 'Error') | Out-Null
    return $null
  }
  # Capture direct element references AND the log file path so the closure
  # does not call script-level functions (Write-AppLog etc.) that are out of
  # scope when WPF invokes the handler via the dispatcher.
  $cap_btnGo    = $btnGo
  $cap_tokBox   = $el['Token']
  $cap_orgBox   = $el['Org']
  $cap_errBlock = $el['WizError']
  $cap_win      = $w
  $cap_result   = $cfWizResult
  $cap_log      = $script:LogFile
  $btnGo.Add_Click({
    try {
      $ts  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
      $tid = [System.Threading.Thread]::CurrentThread.ManagedThreadId
      $apt = [System.Threading.Thread]::CurrentThread.ApartmentState
      try { Add-Content -LiteralPath $cap_log -Value "$ts [INFO] [T$tid/$apt] Wizard: BtnGo clicked" -Encoding UTF8 -ErrorAction Stop } catch {}
      $cap_btnGo.IsEnabled = $false
      $cap_btnGo.Content   = 'Validating...'
      if ($cap_errBlock) { $cap_errBlock.Visibility = [System.Windows.Visibility]::Collapsed }
      $tok = if ($cap_tokBox) { $cap_tokBox.Password } else { '' }
      $org = if ($cap_orgBox) { $cap_orgBox.Text.Trim() } else { '' }
      try { Add-Content -LiteralPath $cap_log -Value "$ts [INFO] [T$tid/$apt] Wizard: tok_empty=$(-not $tok) org='$org'" -Encoding UTF8 -ErrorAction Stop } catch {}
      if (-not $tok) {
        if ($cap_errBlock) { $cap_errBlock.Text = 'API token is required.'; $cap_errBlock.Visibility = [System.Windows.Visibility]::Visible }
        $cap_btnGo.IsEnabled = $true; $cap_btnGo.Content = 'Deploy Worker  ›'; return
      }
      # Validate token against Cloudflare API inline so the user sees the error
      # without the wizard closing. Brief UI freeze is acceptable here.
      try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        $wc = [System.Net.WebClient]::new()
        $wc.Headers['Authorization'] = "Bearer $tok"
        $wc.Headers['Content-Type']  = 'application/json'
        $raw    = $wc.DownloadString('https://api.cloudflare.com/client/v4/user/tokens/verify')
        $wc.Dispose()
        $parsed = $raw | ConvertFrom-Json
        if ($parsed.result.status -ne 'active') { throw "Token status is '$($parsed.result.status)' — expected 'active'." }
        try { Add-Content -LiteralPath $cap_log -Value "$ts [INFO] [T$tid/$apt] Wizard: token validated OK" -Encoding UTF8 -ErrorAction Stop } catch {}
      } catch {
        $errMsg = $_.Exception.Message
        if ($cap_errBlock) { $cap_errBlock.Text = "Invalid token: $errMsg"; $cap_errBlock.Visibility = [System.Windows.Visibility]::Visible }
        try { Add-Content -LiteralPath $cap_log -Value "$ts [WARN] [T$tid/$apt] Wizard: inline token validation failed: $errMsg" -Encoding UTF8 -ErrorAction Stop } catch {}
        $cap_btnGo.IsEnabled = $true; $cap_btnGo.Content = 'Deploy Worker  ›'; return
      }
      $cap_result.Add(@{ Token=$tok; OrgName=$org })
      try { Add-Content -LiteralPath $cap_log -Value "$ts [INFO] [T$tid/$apt] Wizard: result saved (count=$($cap_result.Count)), closing" -Encoding UTF8 -ErrorAction Stop } catch {}
      $cap_win.Close()
    } catch {
      $cap_btnGo.IsEnabled = $true; $cap_btnGo.Content = 'Deploy Worker  ›'
      $errMsg = $_.Exception.Message
      try { Add-Content -LiteralPath $cap_log -Value "$ts [ERROR] [T$tid/$apt] Wizard: BtnGo EXCEPTION: $errMsg" -Encoding UTF8 -ErrorAction Stop } catch {}
      if ($cap_errBlock) { $cap_errBlock.Text = "Unexpected error: $errMsg"; $cap_errBlock.Visibility = [System.Windows.Visibility]::Visible }
    }
  }.GetNewClosure())
  $w.Add_ContentRendered({
    $w.Activate() | Out-Null
    $el['Token'].Focus() | Out-Null
  }.GetNewClosure())
  $w.ShowDialog() | Out-Null
  Write-AppLog "Wizard: ShowDialog returned — result count=$($cfWizResult.Count)"
  if ($cfWizResult.Count -eq 0) { Write-AppLog "Wizard: cancelled (no data)" -Level WARN; return $null }
  $cfWizData = $cfWizResult[0]

  Write-AppLog "Wizard: starting Phase 1 (token validation)"
  # ──────────────────────────────────────────────────────────────────────────
  # PHASE 1 (STA thread): validate token + resolve account/zone with pickers.
  # These steps need WPF (Show-WpfPicker) so they run here before the runspace.
  # ──────────────────────────────────────────────────────────────────────────
  $script:ApiToken = $cfWizData.Token

  # Token validation
  try {
    Write-AppLog "Wizard: calling Invoke-CF token/verify"
    $v = Invoke-CF -Method GET -Path "/user/tokens/verify"
    if ($v.result.status -ne "active") { throw "Token status: $($v.result.status)" }
  } catch {
    Write-AppLog "Wizard: token validation failed: $($_.Exception.Message)" -Level ERROR
    Show-WpfMsg -Title 'Invalid API Token' `
      -Message "Could not validate your Cloudflare token. Check that it has the correct permissions and try again.`n`nDetail: $($_.Exception.Message)" `
      -Type 'error'
    return $null
  }

  # Account discovery
  $preAccountID = ''; $preAccountName = ''
  try {
    $accts = (Invoke-CF -Method GET -Path "/accounts?per_page=20").result
    if (-not $accts -or $accts.Count -eq 0) { throw "No accounts found on this token" }
    if ($accts.Count -eq 1) {
      $preAccountID = $accts[0].id; $preAccountName = $accts[0].name
    } else {
      $pickedAcct = Show-WpfPicker -Title 'Select Cloudflare Account' `
        -Items ($accts | ForEach-Object { $_.name })
      if ($null -eq $pickedAcct) { $pickedAcct = 0 }
      $preAccountID = $accts[$pickedAcct].id; $preAccountName = $accts[$pickedAcct].name
    }
    Write-AppLog "Wizard: account resolved: $preAccountName ($preAccountID)"
  } catch {
    Write-AppLog "Wizard: account discovery failed: $($_.Exception.Message)" -Level ERROR
    Show-WpfMsg -Title 'Account Error' `
      -Message "Could not list Cloudflare accounts.`n`n$($_.Exception.Message)" `
      -Type 'error'
    return $null
  }

  # Always deploy to workers.dev — custom domain is added post-deploy via Worker Options.
  $preZoneName = ''; $preCustomDomain = ''
  Write-AppLog "Wizard: deploying to workers.dev — custom domain can be added via Worker Options after setup"

  # Collect dashboard password from user on the STA thread (never auto-generated, never logged).
  $dashPwd = ''
  for ($__attempt = 0; $__attempt -lt 5; $__attempt++) {
    $p1 = Show-WpfInput -Title 'Set Dashboard Password' `
      -Label "Set a password for the /status dashboard.`nMin 12 characters, at least one letter and one digit." `
      -Secret
    if ($null -eq $p1) { Write-AppLog "Wizard: password setup cancelled by user." -Level WARN; return $null }
    $p2 = Show-WpfInput -Title 'Confirm Dashboard Password' `
      -Label 'Confirm your password:' -Secret
    if ($null -eq $p2) { Write-AppLog "Wizard: password confirm cancelled by user." -Level WARN; return $null }
    if ($p1 -ne $p2) {
      Show-WpfMsg -Title 'Password Mismatch' -Message 'Passwords do not match. Please try again.' -Type 'warn'
      continue
    }
    if ($p1.Length -lt 12 -or $p1 -notmatch '[A-Za-z]' -or $p1 -notmatch '\d') {
      Show-WpfMsg -Title 'Weak Password' `
        -Message "Password must be at least 12 characters and include at least one letter and one digit." `
        -Type 'warn'
      continue
    }
    $dashPwd = $p1; $p1 = $null; $p2 = $null
    break
  }
  if (-not $dashPwd) {
    Show-WpfMsg -Title 'Setup Cancelled' -Message 'Dashboard password was not set. Setup cancelled.' -Type 'warn'
    return $null
  }
  Write-AppLog "Wizard: dashboard password collected (not logged)."

  # ──────────────────────────────────────────────────────────────────────────
  # PHASE 2 (MTA runspace) — deploy Worker, KV, secrets, manifest.
  # Pre-resolved data is passed in; no WPF calls are permitted in the runspace
  # (it is MTA, WPF is STA-only). Console / log calls are stubbed inside the
  # script block so output flows to the progress-window queue instead.
  # ──────────────────────────────────────────────────────────────────────────
  $cfQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
  $cfDone  = [System.Collections.Generic.List[object]]::new()
  $cfRs    = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
  $cfRs.ApartmentState = 'MTA'
  $cfRs.ThreadOptions  = 'ReuseThread'
  $cfRs.Open()

  # Hand-in: progress queue + completion sentinel + all pre-resolved wizard data.
  # Variables are passed by-name; nothing is interpolated into a script block.
  $runspaceVars = @{
    _cq               = $cfQueue
    _cd               = $cfDone
    _token            = $cfWizData.Token
    _acctID           = $preAccountID
    _acctName         = $preAccountName
    _zoneName         = $preZoneName
    _customDomain     = $preCustomDomain
    _orgName          = $cfWizData.OrgName
    _dashPwd          = $dashPwd   # user-set dashboard password — cleared from $dashPwd after this
    CF_API            = $CF_API
    WorkerSource      = $WorkerSource
    WorkerName        = $WorkerName
    KVNamespace       = $KVNamespace
    XmlFile           = $XmlFile
    ConfigFile        = $ConfigFile
    ManifestTokenFile = $ManifestTokenFile
    ScriptDir         = $ScriptDir
  }
  $dashPwd = $null   # remove from outer scope now it's handed to the runspace
  foreach ($k in $runspaceVars.Keys) { $cfRs.SessionStateProxy.SetVariable($k, $runspaceVars[$k]) }

  # Capture core deployment functions verbatim into the new runspace. Write-*
  # helpers and Write-AppLog are re-stubbed inside the script block so progress
  # is queued back to the WPF progress window — don't include them here.
  $deploymentFnNames = @(
    'Invoke-CloudflareSetup',
    'Invoke-CF',
    'New-MultipartBody',
    'Protect-ManifestToken',
    'Unprotect-ManifestToken'
  )
  $deploymentFnSrc = ($deploymentFnNames | ForEach-Object {
    $fn = Get-Item "Function:\$_" -ErrorAction SilentlyContinue
    if ($fn) { "function $_ {`n$($fn.ScriptBlock)`n}" }
  }) -join "`n"
  $cfRs.SessionStateProxy.SetVariable('_fnSrc', $deploymentFnSrc)

  $cfPs = [System.Management.Automation.PowerShell]::Create()
  $cfPs.Runspace = $cfRs
  $cfPs.AddScript({
    # ── Stub every WPF / interactive call — runspace is MTA, no UI allowed ──
    function New-WpfWin      { param([string]$xaml) return $null }
    function Get-El          { param($w,[string[]]$names) return @{} }
    function Set-WinBehavior { param($w,[scriptblock]$OnClose=$null,[scriptblock]$OnBack=$null) }
    function Get-HeaderXaml  { param([string]$t='',[string]$s='',[bool]$showBack=$false,[bool]$showClose=$true,[bool]$showBadge=$false) return '' }
    function Show-WpfMsg     { param([string]$Title='',[string]$Message='',[string]$Detail='',[string]$Type='info',[string]$YesLabel='OK',[string]$NoLabel='Cancel',[switch]$Confirm,[object]$Owner=$null)
      $_cq.Enqueue("info|[$Title] $Message"); return $true }
    function Show-WpfPicker  { param([string]$Title='',[string]$Subtitle='',[string[]]$Items=@()) return 0 }
    function Show-WpfInput   { param([string]$Title='',[string]$Label='',[string]$Default='',[switch]$Secret,[string]$Placeholder='') return $Default }
    function Read-YesNo      { param([string]$Label,[bool]$Default=$true) return $true }
    function Read-Prompt     { param([string]$Prompt='',[string]$Default='',[switch]$Secret,[switch]$Required) return $Default }
    function Write-Host      { param([object]$Object='',[string]$ForegroundColor='Gray',[switch]$NoNewline)
      $col = switch ($ForegroundColor) {
        'Green'    { 'ok'   } 'Cyan'     { 'info' } 'Yellow'   { 'warn' }
        'Red'      { 'err'  } 'DarkGray' { 'dim'  } 'White'    { 'white' }
        default    { 'gray' }
      }
      $_cq.Enqueue("$col|$Object") }
    function Write-OK   { param([string]$M) $_cq.Enqueue("ok|  ✓  $M") }
    function Write-Warn { param([string]$M) $_cq.Enqueue("warn|  !!  $M") }
    function Write-Fail { param([string]$M) $_cq.Enqueue("err|  ✗  $M") }
    function Write-Step { param([string]$n,[string]$M) $_cq.Enqueue("info|  [$n] $M") }
    function Write-Info { param([string]$M) $_cq.Enqueue("dim|       $M") }
    function Write-Rule { }
    function Write-BoxTop  { param($C) }
    function Write-BoxBot  { param($C) }
    function Write-BoxLine { param([string]$m,$C) $_cq.Enqueue("ok|  $m") }
    function Write-AppLog  { param([string]$Message,[string]$Level='INFO') $_cq.Enqueue("dim|[LOG:$Level] $Message") }

    # Load deployment functions from captured source
    # Define script-scoped sentinel values used by Protect/Unprotect-ManifestToken
    $script:_DpapiPrefix     = 'DPAPI:'
    $script:_CredMgrSentinel = 'CREDMGR'

    $_cq.Enqueue("info|Loading deployment functions...")
    try { Invoke-Expression $_fnSrc } catch {
      $_cq.Enqueue("err|Failed to load functions: $($_.Exception.Message)")
      $_cd.Add(@{ Error = "Function load failed: $($_.Exception.Message)" })
      return
    }

    $_cq.Enqueue("info|Starting Cloudflare deployment...")
    try {
      $result = Invoke-CloudflareSetup `
        -ApiToken           $_token `
        -OrgNameOverride    $_orgName `
        -PreAccountID       $_acctID `
        -PreAccountName     $_acctName `
        -PreZoneName        $_zoneName `
        -PreCustomDomain    $_customDomain `
        -DashboardPassword  (ConvertTo-SecureString -String $_dashPwd -AsPlainText -Force)
      $script:_dashPwd = $null   # clear plain string from runspace scope after conversion
      $_cd.Add($result)
    } catch {
      $_cq.Enqueue("err|Deployment failed: $($_.Exception.Message)")
      $_cd.Add(@{ Error = $_.Exception.Message })
    }
  }) | Out-Null
  $cfHandle = $cfPs.BeginInvoke()

  # ── Progress window ────────────────────────────────────────────────────────
  $cp = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="560" Height="460" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/><RowDefinition Height="60"/></Grid.RowDefinitions>
  <Border x:Name="TitleBar" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74" Margin="20,0">
  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
  <StackPanel VerticalAlignment="Center">
 <TextBlock x:Name="CfTitle" Text="Deploying Cloudflare backend..." FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />
 <TextBlock x:Name="CfSub" Text="Please wait — usually takes about 20 seconds" FontSize="11" Foreground="#44445a" Margin="0,3,0,0" TextWrapping="Wrap" />
  </StackPanel>
  <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
  <Button x:Name="CfMinimize" Width="34" Height="34" Cursor="Hand" ToolTip="Minimise"
    Padding="0" Background="Transparent" BorderBrush="Transparent" BorderThickness="0" Foreground="#6666aa">
    <Button.Template><ControlTemplate TargetType="Button">
      <Border x:Name="bd2" Background="{TemplateBinding Background}" CornerRadius="6"
              Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd2" Property="Background" Value="#2a2a44"/>
          <Setter Property="Foreground" Value="#ccccee"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate></Button.Template>
 <TextBlock Text="&#8722;" FontSize="14" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" />
  </Button>
  <Button x:Name="CfX" Width="34" Height="34" Cursor="Hand" ToolTip="Close"
    Padding="0" Background="Transparent" BorderBrush="Transparent" BorderThickness="0"
    Foreground="#6666aa" IsEnabled="False">
    <Button.Template><ControlTemplate TargetType="Button">
      <Border x:Name="bd3" Background="{TemplateBinding Background}" CornerRadius="6"
              Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd3" Property="Background" Value="#5a1a1a"/>
          <Setter Property="Foreground" Value="#ff6060"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate></Button.Template>
 <TextBlock Text="&#10005;" FontSize="11" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" />
  </Button>
  </StackPanel>
  </Grid>
  </Border>
  <RichTextBox x:Name="CfLog" Grid.Row="1" Background="#07070f" Foreground="#666688"
  BorderThickness="0" Padding="16" IsReadOnly="True"
  FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Grid Margin="20,0">
  <TextBlock x:Name="CfStatusLink" Text="" FontSize="11" Foreground="#2255aa"
    TextDecorations="Underline" Cursor="Hand" VerticalAlignment="Center"
    HorizontalAlignment="Left" Visibility="Collapsed"/>
  <Button x:Name="CfClose" Content="Deploying..." Style="{StaticResource Btn}"
  Width="140" HorizontalAlignment="Right" IsEnabled="False"/>
  </Grid>
  </Border>
  </Grid>
</Window>
"@)

  $script:_cfSetupResult = $null
  if ($cp) {
    $cpEl   = Get-El $cp @('CfTitle','CfSub','CfLog','CfClose','CfStatusLink','TitleBar','CfMinimize','CfX')
    $cpDoc  = $cpEl['CfLog'].Document
    $cpDoc.Blocks.Clear()
    $cpPara = [Windows.Documents.Paragraph]::new()
    $cpDoc.Blocks.Add($cpPara)
    $cpEl['TitleBar'].Add_MouseLeftButtonDown({ $cp.DragMove() })
    $cpEl['CfMinimize'].Add_Click({ $cp.WindowState = [System.Windows.WindowState]::Minimized })
    $cpEl['CfX'].Add_Click({ $cp.Close() })
    $cpEl['CfClose'].Add_Click({ $cp.Close() })
    $cpCm = @{ ok='#4ec94e'; info='#6baadf'; warn='#f5c842'; err='#ff6060'; dim='#444460'; white='#e8e8f4'; gray='#666688' }
    $cpTmr = [System.Windows.Threading.DispatcherTimer]::new()
    $cpTmr.Interval = [TimeSpan]::FromMilliseconds(200)
    $cpTmr.Add_Tick({
      $msg = ''
      while ($cfQueue.TryDequeue([ref]$msg)) {
        $parts = $msg -split '\|',2
        $col  = if ($cpCm.ContainsKey($parts[0])) { $cpCm[$parts[0]] } else { '#888888' }
        $text = if ($parts.Count -gt 1) { $parts[1] } else { $msg }
        $run  = [Windows.Documents.Run]::new("$text`n")
        $r2 = [Convert]::ToByte($col.Substring(1,2),16)
        $g2 = [Convert]::ToByte($col.Substring(3,2),16)
        $b2 = [Convert]::ToByte($col.Substring(5,2),16)
        $run.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($r2,$g2,$b2))
        $cpPara.Inlines.Add($run)
        $cpEl['CfLog'].ScrollToEnd()
      }
      if ($cfDone.Count -gt 0) {
        $cpTmr.Stop()
        $res = $cfDone[0]
        $ok2 = $res -is [hashtable] -and -not $res.Error -and $res.WorkerURL
        $cpEl['CfTitle'].Text = if ($ok2) { 'Cloudflare backend deployed!' } else { 'Setup finished with errors' }
        $cpEl['CfSub'].Text   = if ($ok2) { "Worker is live — build your first app package to get started" } else { 'Check the log above for details' }
        if ($ok2 -and $res.WorkerURL) {
          $cpStatusURL = "$($res.WorkerURL)/status"
          $cpEl['CfStatusLink'].Text       = "Open status page: $cpStatusURL"
          $cpEl['CfStatusLink'].Visibility = [System.Windows.Visibility]::Visible
          $cpEl['CfStatusLink'].Add_MouseLeftButtonUp({
            try { Start-Process $cpStatusURL } catch {}
          }.GetNewClosure())
        }
        $cpEl['CfClose'].IsEnabled = $true
        $cpEl['CfX'].IsEnabled     = $true
        $cpEl['CfX'].Foreground    = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x66,0x66,0xaa))
        $cpCloseStyle = if ($ok2) { 'BtnSuccess' } else { 'Btn' }
        $cpEl['CfClose'].Style   = $cp.Resources[$cpCloseStyle]
        $cpEl['CfClose'].Content = if ($ok2) { 'Start building  ›' } else { 'Close' }
        $script:_cfSetupResult = $res
        $cfPs.EndInvoke($cfHandle) | Out-Null
        $cfRs.Close()
      }
    })
    $cp.Add_ContentRendered({ $cpTmr.Start() })
    $cp.Add_Closing({ if ($cpTmr.IsEnabled) { $cpTmr.Stop() } })
    $cp.ShowDialog() | Out-Null
  } else {
    # Fallback: no WPF window — wait synchronously (console/headless mode)
    while ($cfDone.Count -eq 0) { Start-Sleep -Milliseconds 200 }
    $cfPs.EndInvoke($cfHandle) | Out-Null
    $cfRs.Close()
    $script:_cfSetupResult = $cfDone[0]
  }

  $result = $script:_cfSetupResult
  if (-not $result -or $result.Error) {
    $errMsg = if ($result -and $result.Error) { $result.Error } else { 'Setup did not complete' }
    Write-AppLog "Cloudflare setup FAILED: $errMsg" -Level ERROR
    if ($result -and $result.Error) {
      Show-WpfMsg -Title 'Setup Failed' -Message $errMsg -Type 'error'
    }
    return @{ Error = $errMsg }
  }
  Write-AppLog "Cloudflare setup completed: WorkerURL=$($result.WorkerURL)"

  # Step 7/7: inform user to set password via browser (never handled by PS1 app).
  $deployedURL = if ($result.WorkerURL) { $result.WorkerURL } else { $result.WorkerDevURL }
  $esc2       = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
  $urlSafe    = & $esc2 $deployedURL
  $statusSafe = & $esc2 "$deployedURL/status"
  $successXaml = (@'
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  ResizeMode="NoResize" SizeToContent="WidthAndHeight" MinWidth="460" MaxWidth="540"
  WindowStartupLocation="CenterScreen" Background="#0f0f1a" FontFamily="Segoe UI">
__STYLES__
  <StackPanel>
    <Border Background="#1a3a1a" BorderBrush="#2a5a2a" BorderThickness="0,0,0,1" Padding="20,15">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="&#10003;" FontSize="18" FontWeight="Bold" Foreground="#4ec94e" VerticalAlignment="Center" Margin="0,0,10,0"/>
        <TextBlock Text="Worker deployed!" FontSize="15" FontWeight="SemiBold" Foreground="#4ec94e" VerticalAlignment="Center"/>
      </StackPanel>
    </Border>
    <StackPanel Margin="20,16,20,0">
      <TextBlock Text="Setup complete. Your Worker is live at:" FontSize="13" Foreground="#bbbbcc"/>
      <Border Background="#0a0a14" BorderBrush="#2a3a2a" BorderThickness="1" CornerRadius="5" Padding="12,9" Margin="0,8,0,0" Cursor="Hand" x:Name="UrlCopyBox" ToolTip="Click to copy">
        <StackPanel Orientation="Horizontal">
          <TextBlock x:Name="UrlText" Text="__URL__" FontSize="12" FontFamily="Consolas" Foreground="#4ec94e" TextWrapping="Wrap"/>
          <TextBlock x:Name="CopiedLabel" Text=" &#10003; Copied!" FontSize="12" Foreground="#4ec94e" Visibility="Collapsed" Margin="6,0,0,0"/>
        </StackPanel>
      </Border>
    </StackPanel>
    <Border Background="#0d1a0d" BorderBrush="#1a3a1a" BorderThickness="1" CornerRadius="6" Margin="20,12,20,0" Padding="14,11">
      <StackPanel>
        <TextBlock Text="Next: log in to your dashboard" FontSize="12" FontWeight="SemiBold" Foreground="#4ec94e" Margin="0,0,0,5"/>
        <TextBlock Text="__STATUS__" FontSize="12" FontFamily="Consolas" Foreground="#6baadf" TextWrapping="Wrap" Margin="0,0,0,4"/>
        __PWD_BLOCK__
        <TextBlock Text="Open this URL in a browser to log in." FontSize="12" Foreground="#7799aa" TextWrapping="Wrap"/>
      </StackPanel>
    </Border>
    <Border Background="#141220" BorderBrush="#28264a" BorderThickness="1" CornerRadius="6" Margin="20,10,20,0" Padding="14,10">
      <TextBlock FontSize="12" Foreground="#55557a" TextWrapping="Wrap">
        <Run Text="Tip&#160;&#160;" FontWeight="SemiBold" Foreground="#6655aa"/>
        <Run Text="Want a custom domain? Open "/>
        <Run Text="Worker / app options" FontWeight="SemiBold" Foreground="#7777aa"/>
        <Run Text=" &gt; "/>
        <Run Text="Set up custom domain" FontWeight="SemiBold" Foreground="#7777aa"/>
        <Run Text=" from the main menu."/>
      </TextBlock>
    </Border>
    <StackPanel HorizontalAlignment="Right" Margin="20,16,20,16">
      <Button x:Name="BtnOk" Content="OK" Style="{StaticResource BtnSuccess}" MinWidth="100" Padding="14,0"/>
    </StackPanel>
  </StackPanel>
</Window>
'@).Replace('__STYLES__', $script:S).Replace('__URL__', $urlSafe).Replace('__STATUS__', $statusSafe)
  # Password was set by the user during the wizard — no temporary password to display.
  $pwdBlockXaml = '<TextBlock Text="Dashboard password set. Sign in at /status." FontSize="11" Foreground="#55aa77" TextWrapping="Wrap" Margin="0,4,0,0"/>'
  $successXaml = $successXaml.Replace('__PWD_BLOCK__', $pwdBlockXaml)
  $dWin = New-WpfWin $successXaml
  if ($dWin) {
    $dWin.FindName('UrlCopyBox').Add_MouseLeftButtonUp({
      [System.Windows.Clipboard]::SetText($deployedURL)
      $lbl = $dWin.FindName('CopiedLabel')
      $lbl.Visibility = 'Visible'
      $timer = [System.Windows.Threading.DispatcherTimer]::new()
      $timer.Interval = [TimeSpan]::FromSeconds(2)
      $timer.Add_Tick({ $lbl.Visibility = 'Collapsed'; $timer.Stop() }.GetNewClosure())
      $timer.Start()
    }.GetNewClosure())
    $dWin.FindName('BtnOk').Add_Click({
      Start-Process "$deployedURL/status"
      $dWin.Close()
    }.GetNewClosure())
    $dWin.ShowDialog() | Out-Null
  } else {
    Show-WpfMsg -Title 'Worker deployed!' `
      -Message "Setup complete. Your Worker is live at:`n$deployedURL" `
      -Detail  "Visit $deployedURL/status in a browser to set a password — takes 30 seconds." `
      -Type 'success'
  }

  return $result
}



# =============================================================================
# Show-WpfPicker — modal single-select list. Returns the 0-based index of the
# chosen item, or $null on cancel/close. Enter activates; Escape cancels.
# =============================================================================
function Show-WpfPicker {
  [CmdletBinding()]
  param(
    [string]   $Title    = 'Pick one',
    [string]   $Subtitle = '',
    [string[]] $Items    = @()
  )
  $esc = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
  $titleEsc    = & $esc $Title
  $subtitleEsc = & $esc $Subtitle
  $xaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="480" Height="370" WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="56"/>
    </Grid.RowDefinitions>
    <StackPanel Margin="24,20,24,12">
      <TextBlock Text="$titleEsc" FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4"/>
      <TextBlock Text="$subtitleEsc" FontSize="12" Foreground="#55577a" Margin="0,4,0,0"
                 Visibility="$(if($Subtitle){'Visible'}else{'Collapsed'})"/>
    </StackPanel>
    <ListBox x:Name="LB" Grid.Row="1" Margin="24,0,24,0"
             Background="#0a0a0a" BorderBrush="#1a1a2e" BorderThickness="1"
             Foreground="#e8e8f4" FontSize="13"
             ScrollViewer.HorizontalScrollBarVisibility="Disabled">
      <ListBox.ItemContainerStyle>
        <Style TargetType="ListBoxItem">
          <Setter Property="Padding" Value="12,9"/>
          <Setter Property="Foreground" Value="#e8e8f4"/>
          <Setter Property="Background" Value="Transparent"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ListBoxItem">
                <Border x:Name="Bd" Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
                  <ContentPresenter/>
                </Border>
                <ControlTemplate.Triggers>
                  <Trigger Property="IsSelected" Value="True">
                    <Setter TargetName="Bd" Property="Background" Value="#1e1e3a"/>
                  </Trigger>
                  <Trigger Property="IsMouseOver" Value="True">
                    <Setter TargetName="Bd" Property="Background" Value="#15152a"/>
                  </Trigger>
                </ControlTemplate.Triggers>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Style>
      </ListBox.ItemContainerStyle>
    </ListBox>
    <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
                  VerticalAlignment="Center" Margin="0,0,24,0">
        <Button x:Name="BtnCancel" Content="Cancel" Style="{StaticResource Btn}" MinWidth="90" Padding="14,0" Margin="0,0,10,0"/>
        <Button x:Name="BtnOk" Content="Select" Style="{StaticResource BtnPrimary}" MinWidth="90" Padding="14,0"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
"@
  $w = New-WpfWin $xaml
  if (-not $w) { return $null }
  $el = Get-El $w @('LB','BtnOk','BtnCancel')
  Set-WinBehavior $w
  foreach ($item in $Items) { $el['LB'].Items.Add($item) | Out-Null }
  if ($el['LB'].Items.Count -gt 0) { $el['LB'].SelectedIndex = 0 }
  $script:_pickerIdx = $null
  $el['BtnCancel'].Add_Click({ $w.Close() })
  $el['BtnOk'].Add_Click({
    if ($el['LB'].SelectedIndex -ge 0) { $script:_pickerIdx = $el['LB'].SelectedIndex }
    $w.Close()
  }.GetNewClosure())
  $el['LB'].Add_MouseDoubleClick({
    if ($el['LB'].SelectedIndex -ge 0) { $script:_pickerIdx = $el['LB'].SelectedIndex }
    $w.Close()
  }.GetNewClosure())
  $w.Add_PreviewKeyDown({
    if ($_.Key -eq 'Return') {
      if ($el['LB'].SelectedIndex -ge 0) { $script:_pickerIdx = $el['LB'].SelectedIndex }
      $w.Close(); $_.Handled = $true
    } elseif ($_.Key -eq 'Escape') { $w.Close(); $_.Handled = $true }
  }.GetNewClosure())
  $w.Add_ContentRendered({ $el['LB'].Focus() | Out-Null })
  $w.ShowDialog() | Out-Null
  return $script:_pickerIdx
}

# =============================================================================
# Show-WpfInput — modal single-line text or password prompt. Returns the
# entered value, or $null on cancel/close. -Secret renders a PasswordBox.
# =============================================================================
function Show-WpfInput {
  [CmdletBinding()]
  param(
    [string] $Title   = 'Input',
    [string] $Label   = 'Enter a value',
    [string] $Default = '',
    [switch] $Secret
  )
  $esc = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
  $fieldXaml = if ($Secret) {
    '<PasswordBox x:Name="Val" Grid.Row="2" Margin="0,8,0,16" FontSize="13" Padding="8,6" Background="#0a0a0a" Foreground="#e8e8f4" BorderBrush="#333" BorderThickness="1"/>'
  } else {
    '<TextBox x:Name="Val" Grid.Row="2" Text="{0}" Margin="0,8,0,16" FontSize="13" Padding="8,6" Background="#0a0a0a" Foreground="#e8e8f4" BorderBrush="#333" BorderThickness="1" CaretBrush="#e8e8f4"/>' -f (& $esc $Default)
  }
  $titleEsc = & $esc $Title
  $labelEsc = & $esc $Label
  $xaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="440" Height="210" WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid Margin="28,22,28,22">
  <Grid.RowDefinitions>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="Auto"/>
  </Grid.RowDefinitions>
 <TextBlock Grid.Row="0" Text="$titleEsc" FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,10" TextWrapping="Wrap" />
  <TextBlock Grid.Row="1" Text="$labelEsc" FontSize="12" Foreground="#55577a"/>
$fieldXaml
  <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right">
  <Button x:Name="BtnCancel" Content="Cancel" Style="{StaticResource Btn}" MinWidth="90" Padding="14,0" Margin="0,0,10,0"/>
  <Button x:Name="BtnOk" Content="OK" Style="{StaticResource BtnPrimary}" MinWidth="90" Padding="14,0"/>
  </StackPanel>
  </Grid>
</Window>
"@
  $w = New-WpfWin $xaml
  if (-not $w) { return $null }
  $isSecret = [bool]$Secret
  $el = Get-El $w @('Val','BtnOk','BtnCancel')
  Set-WinBehavior $w
  $script:_wpiVal = $null
  $el['BtnCancel'].Add_Click({ $w.Close() })
  $el['BtnOk'].Add_Click({
    $script:_wpiVal = if ($isSecret) { $el['Val'].Password } else { $el['Val'].Text }
    $w.Close()
  }.GetNewClosure())
  $w.Add_PreviewKeyDown({
    if ($_.Key -eq 'Return') {
      $script:_wpiVal = if ($isSecret) { $el['Val'].Password } else { $el['Val'].Text }
      $w.Close()
      $_.Handled = $true
    } elseif ($_.Key -eq 'Escape') { $w.Close(); $_.Handled = $true }
  }.GetNewClosure())
  $w.Add_ContentRendered({ $el['Val'].Focus() | Out-Null })
  $w.ShowDialog() | Out-Null
  return $script:_wpiVal
}

function Read-Prompt {
  param([string]$Label,[string]$Default="",[switch]$Secret,[switch]$Required)
  $val = Show-WpfInput -Title $Label -Label $Label -Default $Default -Secret:$Secret
  if (-not $val -and $Default) { return $Default }
  return $val
}
function Read-YesNo {
  param([string]$Label,[bool]$Default=$true)
  return Show-WpfMsg -Title $Label -Message "" -YesLabel "Yes" -NoLabel "No" -Confirm
}

# =============================================================================
# CLOUDFLARE API LAYER
# Invoke-CF — single REST entry point. Reads $script:ApiToken (set per request
# scope, never persisted). On non-2xx the WebException body is parsed for the
# Cloudflare error-array shape; the throw message is always actionable.
# =============================================================================
function Invoke-CF {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string] $Method,
    [Parameter(Mandatory)][ValidatePattern('^/')][string] $Path,
    [object]   $Body        = $null,
    [string]   $ContentType = 'application/json',
    [byte[]]   $RawBody     = $null,
    [int]      $TimeoutSec  = 30
  )
  if (-not $script:ApiToken) { throw 'Cloudflare API token is not set in this scope.' }
  $uri = $CF_API + $Path
  $headers = @{ Authorization = "Bearer $script:ApiToken" }

  try {
    if ($RawBody) {
      $headers['Content-Type'] = $ContentType
      return Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $RawBody `
                               -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    if ($null -ne $Body) {
      $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 -Compress }
      return Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $json `
                               -ContentType $ContentType -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    return Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers `
                             -TimeoutSec $TimeoutSec -ErrorAction Stop
  } catch {
    $detail = $_.Exception.Message
    # PS 5.1: extract the response body for a useful error string.
    try {
      $resp = $_.Exception.Response
      if ($resp) {
        $reader = [System.IO.StreamReader]::new($resp.GetResponseStream())
        $raw = $reader.ReadToEnd(); $reader.Close()
        if ($raw) {
          $parsed = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
          if ($parsed -and $parsed.errors) {
            $detail = ($parsed.errors | ForEach-Object { '{0}: {1}' -f $_.code, $_.message }) -join '; '
          } elseif ($raw.Length -lt 500) {
            $detail = "$detail | $raw"
          }
        }
      }
    } catch { }
    # PS 7+: ErrorDetails.Message is already populated.
    try {
      $extra = $_.ErrorDetails.Message
      if ($extra -and $extra -ne $detail) { $detail = "$detail | $extra" }
    } catch { }
    Write-AppLog "Cloudflare API failed: $Method $Path -> $detail" ERROR
    throw "Cloudflare API error on $Method $Path`: $detail"
  }
}

# -----------------------------------------------------------------------------
# New-MultipartBody — builds a multipart/form-data body for the Workers
# script-upload endpoint. Generates a CSPRNG boundary so a hostile body field
# can't accidentally collide with the boundary marker.
# -----------------------------------------------------------------------------
function New-MultipartBody {
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable[]] $Parts)

  $boundaryBytes = [byte[]]::new(16)
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($boundaryBytes)
  $boundary = '----CFBoundary' + ([System.BitConverter]::ToString($boundaryBytes) -replace '-','')

  $enc = [System.Text.Encoding]::UTF8
  $ms  = [System.IO.MemoryStream]::new()
  try {
    foreach ($part in $Parts) {
      $disposition = 'form-data; name="{0}"' -f $part.Name
      if ($part.ContentType -match 'javascript') {
        $disposition += '; filename="{0}"' -f $part.Name
      }
      $headerBlock = "--$boundary`r`nContent-Disposition: $disposition`r`nContent-Type: $($part.ContentType)`r`n`r`n"
      $hb = $enc.GetBytes($headerBlock); $ms.Write($hb, 0, $hb.Length)

      if ($part.Data -is [byte[]]) { $ms.Write($part.Data, 0, $part.Data.Length) }
      else { $db = $enc.GetBytes([string]$part.Data); $ms.Write($db, 0, $db.Length) }

      $crlf = $enc.GetBytes("`r`n"); $ms.Write($crlf, 0, $crlf.Length)
    }
    $closing = $enc.GetBytes("--$boundary--`r`n")
    $ms.Write($closing, 0, $closing.Length)
    return @{ Body = $ms.ToArray(); ContentType = "multipart/form-data; boundary=$boundary" }
  } finally {
    $ms.Dispose()
  }
}

# =============================================================================
# INSTALLER INSPECTOR
# =============================================================================
# =============================================================================
# INSTALLER INSPECTION HELPERS
# Get-InstallerType — fingerprint by binary signature; defaults to 'Unknown'.
# Get-SilentArgs    — canonical silent-install arguments per installer family.
# Read-MsiProperties — extracts the Property table from an MSI via the
#                      WindowsInstaller COM API. ComObject is always released.
# =============================================================================
function Get-InstallerType {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'Unknown' }
  if ($Path -match '\.msi$') { return 'MSI' }
  try {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $sampleLen = [Math]::Min(65535, $bytes.Length - 1)
    $sample = [System.Text.Encoding]::ASCII.GetString($bytes[0..$sampleLen])
    switch -Regex ($sample) {
      'Nullsoft'              { return 'NSIS' }
      'Inno Setup'            { return 'InnoSetup' }
      'WiX Toolset|WiX Burn'  { return 'WiX' }
      'InstallShield'         { return 'InstallShield' }
      'Setup Factory'         { return 'SetupFactory' }
      '7-Zip|7zS\.sfx'        { return '7ZipSFX' }
    }
  } catch {
    Write-AppLog "Get-InstallerType: $($_.Exception.Message)" WARN
  }
  return 'Unknown'
}

function Get-SilentArgs {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Type)
  switch ($Type) {
    'MSI'           { '/qn /norestart' }
    'NSIS'          { '/S' }
    'InnoSetup'     { '/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART' }
    'WiX'           { '/qn /norestart' }
    'InstallShield' { '/s /v"/qn REBOOT=Suppress"' }
    'SetupFactory'  { '/S' }
    '7ZipSFX'       { '/S' }
    default         { '/silent' }
  }
}

function Read-MsiProperties {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Path)
  $props = @{}
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $props }

  $wi = $null; $db = $null; $view = $null
  try {
    $wi   = New-Object -ComObject WindowsInstaller.Installer
    $db   = $wi.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$wi,@($Path,0))
    $view = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@('SELECT Property,Value FROM Property'))
    $view.GetType().InvokeMember('Execute','InvokeMethod',$null,$view,$null) | Out-Null
    while ($true) {
      $rec = $view.GetType().InvokeMember('Fetch','InvokeMethod',$null,$view,$null)
      if (-not $rec) { break }
      $k = $rec.GetType().InvokeMember('StringData','GetProperty',$null,$rec,@(1))
      $v = $rec.GetType().InvokeMember('StringData','GetProperty',$null,$rec,@(2))
      if ($k) { $props[$k] = $v }
      [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($rec)
    }
    $view.GetType().InvokeMember('Close','InvokeMethod',$null,$view,$null) | Out-Null
  } catch {
    Write-AppLog "Read-MsiProperties failed for '$Path': $($_.Exception.Message)" WARN
  } finally {
    foreach ($obj in @($view, $db, $wi)) {
      if ($obj) {
        try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) } catch { }
      }
    }
  }
  return $props
}
function Invoke-InstallerInspector {
  # Pure data function — returns a hashtable of detected installer properties.
  # No console output: Write-Host throws in WPF-only mode (hidden console) and
  # would crash any Add_Click delegate that calls this function.
  param([string]$InstallerPath)
  $r = @{ DisplayName=''; Version=''; Publisher=''; AppID=''; SilentArgs='';
  RegistryName=''; InstallerType=''; LaunchExe=''; ProcessesToKill='' }

  # Strip surrounding quotes that Windows / drag-and-drop may add
  $InstallerPath = $InstallerPath.Trim().Trim('"').Trim("'")
  if ([string]::IsNullOrWhiteSpace($InstallerPath)) { return $r }
  if (-not (Test-Path $InstallerPath))  { return $r }

  $type  = Get-InstallerType -Path $InstallerPath
  $r.InstallerType = $type
  $r.SilentArgs  = Get-SilentArgs -Type $type

  # --- Gather metadata from installer file ---
  if ($type -eq 'MSI') {
  $msi  = Read-MsiProperties -Path $InstallerPath
  $r.DisplayName  = $msi['ProductName']
  $r.Version  = $msi['ProductVersion']
  $r.Publisher  = $msi['Manufacturer']
  $r.RegistryName = $msi['ProductName']
  } else {
  $vi = (Get-Item $InstallerPath -ErrorAction SilentlyContinue).VersionInfo
  if ($vi) {
  $r.DisplayName  = if ($vi.ProductName  -and $vi.ProductName.Trim())  { $vi.ProductName.Trim() }  else { $vi.FileDescription.Trim() }
  $r.Version  = if ($vi.ProductVersion -and $vi.ProductVersion.Trim()) { $vi.ProductVersion.Trim() } else { $vi.FileVersion.Trim() }
  $r.Publisher  = $vi.CompanyName.Trim()
  $r.RegistryName = $r.DisplayName
  }
  }

  # --- Fallback: if DisplayName still blank try registry (app may already be installed) ---
  if (-not $r.DisplayName) {
  foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
  $match = Get-ItemProperty $base -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.Publisher -and
  ($_.Publisher -eq $r.Publisher -or
  ($_.InstallLocation -and (Test-Path $_.InstallLocation))) } |
  Sort-Object { $_.DisplayVersion } -Descending |
  Select-Object -First 1
  if ($match) {
  if (-not $r.DisplayName)  { $r.DisplayName  = $match.DisplayName }
  if (-not $r.RegistryName) { $r.RegistryName = $match.DisplayName }
  if (-not $r.Version)  { $r.Version  = $match.DisplayVersion }
  if (-not $r.Publisher)  { $r.Publisher  = $match.Publisher }
  break
  }
  }
  }

  # --- Derive App ID from DisplayName (or RegistryName as fallback) ---
  $nameForID = if ($r.DisplayName) { $r.DisplayName } elseif ($r.RegistryName) { $r.RegistryName } else { '' }
  if ($nameForID) {
  $clean  = $nameForID -replace '[^A-Za-z0-9 ]',''
  $r.AppID = ($clean -split '\s+' | Where-Object { $_ } |
  ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) }) -join ''
  }

  # --- Try to detect launch exe and processes to kill from install location ---
  # Looks in registry InstallLocation and common Program Files paths.
  # Only reads filesystem metadata — no execution, no network, no elevation.
  $searchName = ($r.DisplayName -replace '[^A-Za-z0-9]','').ToLower()
  $candidates = @()

  # 1. Pull InstallLocation from registry if present
  foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
  Get-ItemProperty $base -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.InstallLocation -and $_.InstallLocation.Trim() -ne '' } |
  Where-Object { ($_.DisplayName -replace '[^A-Za-z0-9]','').ToLower() -like "*$searchName*" } |
  ForEach-Object { $candidates += $_.InstallLocation.Trim() }
  }

  # 2. Check standard Program Files folders using the app name
  foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:ProgramFiles\Nitro")) {
  if ($root -and (Test-Path $root)) {
  Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
  Where-Object { ($_.Name -replace '[^A-Za-z0-9]','').ToLower() -like "*$searchName*" } |
  ForEach-Object { $candidates += $_.FullName }
  }
  }

  # 3. Search candidate folders for the most likely main exe
  # Ranked by: largest exe that is NOT an uninstaller / updater / helper
  $excludePattern = 'unins|uninstall|setup|update|helper|crash|report|squirrel|redist'
  $bestExe = $null
  $bestSize = 0
  foreach ($dir in ($candidates | Select-Object -Unique)) {
  if (-not (Test-Path $dir)) { continue }
  $exeFiles = Get-ChildItem $dir -Filter '*.exe' -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notmatch $excludePattern }
  foreach ($exe in $exeFiles) {
  if ($exe.Length -gt $bestSize) {
  $bestSize = $exe.Length
  $bestExe  = $exe.FullName
  }
  }
  }

  if ($bestExe) {
  $r.LaunchExe = $bestExe
  # Processes to kill = exe name without extension, from the same folder
  # Collect all non-excluded exes in that folder as candidate kill targets
  $killFolder = Split-Path $bestExe
  $killProcs  = Get-ChildItem $killFolder -Filter '*.exe' -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notmatch $excludePattern } |
  ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
  $r.ProcessesToKill = ($killProcs | Select-Object -Unique) -join ','
  }

  return $r
}

# =============================================================================
# Invoke-ResetStatusPassword — clears 'auth_password' from Cloudflare KV and
# rotates 'auth_session_secret', invalidating every active browser session.
# The new password is set later by the user via the Worker's /status page;
# AppUpdater never sees plaintext passwords.
# =============================================================================
function Invoke-ResetStatusPassword {
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Config)

  $confirmed = Show-WpfMsg `
    -Title    'Reset /status password' `
    -Message  ("This will clear the current password and sign out every active browser session.`n`n" +
               "You will set a new password in your browser via the /status page — the password never touches this machine.") `
    -YesLabel 'Reset password' `
    -NoLabel  'Cancel' `
    -Type     'warn' `
    -Confirm
  if (-not $confirmed) { return }

  $accountId = $Config.AccountID
  if (-not $accountId) {
    Show-WpfMsg -Title 'Not connected' -Message 'No Cloudflare account ID found in the saved configuration. Run setup first.' -Type 'error'
    return
  }

  # Resolve KV namespace ID for this Worker's bound store.
  $kvId = $null
  try {
    $namespaces = (Invoke-CF -Method GET -Path "/accounts/$accountId/storage/kv/namespaces").result
    $found = $namespaces | Where-Object { $_.title -eq $script:KVNamespace } | Select-Object -First 1
    if ($found) { $kvId = $found.id }
  } catch {
    Show-WpfMsg -Title 'KV lookup failed' -Message "Could not retrieve the Worker's KV namespace.`n`n$($_.Exception.Message)" -Type 'error'
    return
  }
  if (-not $kvId) {
    Show-WpfMsg -Title 'KV namespace missing' -Message "KV namespace '$($script:KVNamespace)' not found. Run a full re-deploy." -Type 'error'
    return
  }

  $base    = "$script:CF_API/accounts/$accountId/storage/kv/namespaces/$kvId/values"
  $headers = @{ Authorization = "Bearer $script:ApiToken" }

  # Step 1 — clear the stored password. 404 is benign (already gone).
  try {
    Invoke-RestMethod -Uri "$base/auth_password" -Method DELETE -Headers $headers -ErrorAction Stop | Out-Null
    Write-AppLog 'auth_password deleted from KV (password reset).' INFO
  } catch {
    $status = $null
    try { $status = $_.Exception.Response.StatusCode.value__ } catch { }
    if ($status -ne 404) {
      Show-WpfMsg -Title 'Reset failed' -Message "Could not clear the password.`n`n$($_.Exception.Message)" -Type 'error'
      return
    }
  }

  # Step 2 — rotate the HMAC session-signing secret.
  try {
    $secret = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
    $secretB64 = [Convert]::ToBase64String($secret)
    Invoke-RestMethod -Uri "$base/auth_session_secret" -Method PUT `
      -Headers ($headers + @{ 'Content-Type' = 'text/plain' }) `
      -Body $secretB64 -ErrorAction Stop | Out-Null
    Write-AppLog 'auth_session_secret rotated (all sessions invalidated).' INFO
  } catch {
    Write-AppLog "Session-secret rotation failed: $($_.Exception.Message)" WARN
  }

  $statusUrl = if ($Config.WorkerURL) { $Config.WorkerURL } else { $Config.WorkerDevURL }
  Show-WpfMsg `
    -Title   'Password cleared' `
    -Type    'success' `
    -Message ("All sessions have been signed out.`n`nVisit your status page in a browser to choose a new password:`n$statusUrl/status")
}

# =============================================================================
# CLOUDFLARE SETUP  (runs once, saves config)
# =============================================================================
function Invoke-CloudflareSetup {
  param(
    [string]$ApiToken="",
    [string]$OrgNameOverride="",
    [string]$SubdomainOverride="",
    # Pre-resolved by wizard STA thread — when supplied, skips interactive steps 1-3
    # and the "Deploy now?" confirmation (user already clicked Deploy in the wizard).
    [string]$PreAccountID="",
    [string]$PreAccountName="",
    [string]$PreZoneName="",
    [string]$PreCustomDomain="",
    # Dashboard password collected from the user in the wizard — never logged or auto-generated.
    [SecureString]$DashboardPassword
  )
  # Shadow Write-Host: routes to the setup runspace queue when $_cq is available
  # (wizard runspace mode), otherwise falls through to the real Write-Host.
  function Write-Host { param([object]$Object='',[string]$ForegroundColor='',[switch]$NoNewline)
    try {
      if ($null -ne $_cq) {
        $col = switch ($ForegroundColor) {
          'Green'    { 'ok'   } 'Cyan'    { 'info' } 'Yellow'   { 'warn' }
          'Red'      { 'err'  } 'DarkGray'{ 'dim'  } 'White'    { 'white' }
          default    { 'gray' }
        }
        $_cq.Enqueue("$col|$Object")
      } else {
        if ($ForegroundColor) { Microsoft.PowerShell.Utility\Write-Host $Object -ForegroundColor $ForegroundColor -NoNewline:$NoNewline }
        else { Microsoft.PowerShell.Utility\Write-Host $Object -NoNewline:$NoNewline }
      }
    } catch {}
  }

  # Flag: running headless from wizard runspace (account/zone already resolved on STA)
  $wizardMode = $PreAccountID -ne ''

  Write-Host "  FIRST TIME SETUP" -ForegroundColor Yellow
  Write-Host "  This runs once to deploy your Cloudflare backend." -ForegroundColor DarkGray
  Write-Host ""
  Write-Rule
  Write-Host ""

  # --- Token ---
  Write-Step "1/7" "API Token"
  # Use pre-supplied token (from WPF wizard) if available; otherwise prompt.
  $script:ApiToken = if ($ApiToken) { $ApiToken } else { Read-Prompt "Paste your Cloudflare API token" -Secret -Required }
  Write-Host ""

  if ($wizardMode) {
    # Token was already validated on the STA thread before this runspace started.
    Write-Step "1/7" "Token pre-validated"
    Write-OK "Token valid (verified before deployment started)"
  } else {
    Write-Step "1/7" "Validating..."
    try {
    $v = Invoke-CF -Method GET -Path "/user/tokens/verify"
    if ($v.result.status -ne "active") { throw "Status: $($v.result.status)" }
    Write-OK "Token valid"
    } catch { $errMsg="Invalid token: $_"; Write-Fail $errMsg; Write-AppLog "Token validation failed: $_" -Level ERROR; throw $errMsg }
  }

  # --- Account ---
  $AccountID = $null; $AccountName = $null
  if ($wizardMode) {
    $AccountID = $PreAccountID; $AccountName = $PreAccountName
    Write-Host ""
    Write-Step "2/7" "Account: $AccountName"
    Write-OK "Pre-selected"
  } else {
    # --- Auto-discover account ---
    Write-Host ""
    Write-Step "2/7" "Discovering account..."
    try {
    $accts = (Invoke-CF -Method GET -Path "/accounts?per_page=20").result
    if (-not $accts -or $accts.Count -eq 0) { throw "No accounts found" }
    if ($accts.Count -eq 1) {
    $AccountID = $accts[0].id; $AccountName = $accts[0].name
    Write-OK "Account: $AccountName"
    } else {
    $acctNames = $accts | ForEach-Object { $_.name }
    $pickedAcct = Show-WpfPicker -Title 'Select Cloudflare Account' -Items $acctNames
    if ($null -eq $pickedAcct) { $pickedAcct = 0 }   # cancel = first account
    $AccountID = $accts[$pickedAcct].id; $AccountName = $accts[$pickedAcct].name
    Write-OK "Selected: $AccountName"
    }
    } catch { $errMsg="Could not list accounts: $_"; Write-Fail $errMsg; Write-AppLog $errMsg -Level ERROR; throw $errMsg }
  }

  # --- Domain ---
  $CustomDomain = ""; $ZoneName = ""
  if ($wizardMode) {
    $ZoneName = $PreZoneName; $CustomDomain = $PreCustomDomain
    Write-Host ""
    Write-Step "3/7" "Domain: $(if($CustomDomain){$CustomDomain}else{'workers.dev (auto)'})"
    Write-OK "Pre-selected"
  } else {
    # --- Auto-discover domain ---
    Write-Host ""
    Write-Step "3/7" "Checking for domains..."
    try {
    $zones = (Invoke-CF -Method GET -Path "/zones?account.id=$AccountID&per_page=50").result
    if ($zones -and $zones.Count -gt 0) {
    $zoneItems = @('None — use free workers.dev URL') + ($zones | ForEach-Object { $_.name })
    $pickedZone = Show-WpfPicker -Title 'Select Domain' -Subtitle 'Choose a Cloudflare zone, or None to use the free workers.dev URL.' -Items $zoneItems
    if ($null -eq $pickedZone) { $pickedZone = 0 }   # cancel = workers.dev
    if ($pickedZone -gt 0) {
    $ZoneName  = $zones[$pickedZone - 1].name
    $sub  = if ($SubdomainOverride) { $SubdomainOverride } else { Read-Prompt "Subdomain prefix" -Default "updates" }
    $CustomDomain = "$sub.$ZoneName"
    Write-OK "Will deploy to: $CustomDomain"
    } else { Write-OK "Using workers.dev" }
    } else { Write-OK "No domains found — using workers.dev" }
    } catch { Write-Warn "Could not list domains — using workers.dev" }
  }

  # --- Org name for display in generated scripts ---
  Write-Host ""
  $OrgName = if ($OrgNameOverride) { $OrgNameOverride } else { Read-Prompt "Your organisation name (shown in update windows)" -Default "$OrgName" }

  # --- Generate manifest token ---
  # Use hex encoding: 20 random bytes -> exactly 40 hex chars, always alphanumeric
  $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
  $buf = New-Object byte[] 20; $rng.GetBytes($buf)
  $ManifestToken = ([System.BitConverter]::ToString($buf) -replace '-','')

  # Confirm — skipped in wizard mode (user already confirmed by clicking "Deploy Worker")
  if (-not $wizardMode) {
    Write-Host ""
    Write-Rule
    Write-Host "  Deploy:" -ForegroundColor DarkGray
    Write-Host "  Account : $AccountName" -ForegroundColor White
    Write-Host "  Domain  : $(if($CustomDomain){$CustomDomain}else{'workers.dev (auto)'})" -ForegroundColor White
    Write-Rule
    Write-Host ""
    if (-not (Read-YesNo "Deploy now" -Default $true)) { Write-AppLog "Setup cancelled by user" -Level INFO; throw "Setup cancelled." }
  }

  # --- KV Namespace ---
  Write-Host ""
  Write-Step "4/7" "KV namespace..."
  $KvId = $null
  try {
  $ex = (Invoke-CF -Method GET -Path "/accounts/$AccountID/storage/kv/namespaces").result
  $found = $ex | Where-Object { $_.title -eq $KVNamespace } | Select-Object -First 1
  if ($found) { $KvId = $found.id; Write-OK "Found existing: $KvId" }
  } catch {}
  if (-not $KvId) {
  try {
  $KvId = (Invoke-CF -Method POST -Path "/accounts/$AccountID/storage/kv/namespaces" -Body @{title=$KVNamespace}).result.id
  Write-OK "Created: $KvId"
  } catch { $errMsg="KV create failed: $_"; Write-Fail $errMsg; Write-AppLog $errMsg -Level ERROR; throw $errMsg }
  }

  # --- Deploy Worker ---
  Write-Host ""
  Write-Step "5/7" "Deploying Worker..."
  # Build metadata JSON manually — PS5.1 ConvertTo-Json collapses single-element
  # arrays to plain objects, which makes Cloudflare reject the request with 400.
  $meta = "{`"main_module`":`"worker.js`",`"compatibility_date`":`"2024-01-01`",`"bindings`":[{`"type`":`"kv_namespace`",`"name`":`"APP_MANIFEST`",`"namespace_id`":`"$KvId`"}]}"
  $mp = New-MultipartBody -Parts @(
  @{ Name="metadata";  ContentType="application/json";  Data=$meta }
  @{ Name="worker.js"; ContentType="application/javascript+module"; Data=$WorkerSource }
  )
  try {
  Invoke-CF -Method PUT -Path "/accounts/$AccountID/workers/scripts/$WorkerName" -RawBody $mp.Body -ContentType $mp.ContentType | Out-Null
  Write-OK "Worker deployed"
  } catch { $errMsg="Deploy failed: $_"; Write-Fail $errMsg; Write-AppLog $errMsg -Level ERROR; throw $errMsg }

  # --- Enable workers.dev subdomain routing for this script ---
  # Deploying a script does NOT automatically route workers.dev traffic to it.
  # This separate API call enables the *.workers.dev URL for this script name.
  try {
  Invoke-CF -Method POST -Path "/accounts/$AccountID/workers/scripts/$WorkerName/subdomain" -Body '{"enabled":true}' | Out-Null
  Write-OK "workers.dev routing enabled"
  } catch { Write-Warn "Could not enable workers.dev routing (may already be enabled): $($_.Exception.Message)" }

  # --- Secret ---
  try {
  Invoke-CF -Method PUT -Path "/accounts/$AccountID/workers/scripts/$WorkerName/secrets" -Body @{name="AUTH_TOKEN";text=$ManifestToken;type="secret_text"} | Out-Null
  Write-OK "Auth secret set"
  } catch { Write-Warn "Could not set secret: $_" }

  # --- Cron ---
  try {
  # Cloudflare schedules API expects a bare JSON array
  $cronBody = '[{"cron":"0 * * * *"}]'
  Invoke-CF -Method PUT -Path "/accounts/$AccountID/workers/scripts/$WorkerName/schedules" -Body $cronBody | Out-Null
  Write-OK "Hourly cron set"
  } catch { Write-Warn "Could not set cron: $_" }

  # --- Resolve URL ---
  Write-Host ""
  Write-Step "6/7" "Resolving Worker URL..."
  $WorkerURL  = $null  # preferred URL (custom domain if set)
  $WorkerDevURL  = $null  # always the workers.dev fallback

  try {
  $sub = (Invoke-CF -Method GET -Path "/accounts/$AccountID/workers/subdomain").result.subdomain
  if ($sub) {
  $WorkerDevURL = "https://$WorkerName.$sub.workers.dev"
  $WorkerURL  = $WorkerDevURL
  Write-OK "workers.dev URL: $WorkerDevURL"
  }
  } catch { Write-Warn "Could not get workers.dev subdomain" }

  if ($CustomDomain -and $ZoneName) {
  try {
  # Get zone ID (only needs Zone:Read — included in the Workers token template)
  $zoneId = (Invoke-CF -Method GET -Path "/zones?name=$ZoneName").result[0].id
  if (-not $zoneId) { throw "Zone '$ZoneName' not found in your Cloudflare account" }

  # Use the Workers Custom Domains API — handles DNS record + routing in one call
  # and only requires Workers permissions (no DNS:Edit needed)
  Invoke-CF -Method PUT -Path "/accounts/$AccountID/workers/domains" -Body @{
  hostname  = $CustomDomain
  service  = $WorkerName
  environment = "production"
  zone_id  = $zoneId
  } | Out-Null

  $WorkerURL = "https://$CustomDomain"
  Write-OK "Custom domain configured: $WorkerURL"
  Write-Info "Cloudflare is provisioning the certificate — usually live within 60 seconds."
  } catch {
  $script:_customDomainFailed = $true
  $script:_customDomainTarget = $CustomDomain
  Write-Fail "Custom domain setup failed: $($_.Exception.Message)"
  Write-Warn "Most common cause: the deploy token only has Zone:Read."
  Write-Warn "  The Workers Custom Domains API needs Workers Routes:Edit"
  Write-Warn "  AND Zone:Read on the parent zone."
  Write-Warn "Your Worker is live at: $WorkerDevURL"
  Write-Warn "Fix it after setup: Worker / app options -> Set up custom domain"
  Write-Warn "  (use a fresh token with Workers Routes:Edit)"
  $WorkerURL = $WorkerDevURL  # explicit fallback so config saves the working URL
  }
  }
  if (-not $WorkerURL) {
    if ($wizardMode) {
      # Can't prompt in runspace — fall back to workers.dev or fail cleanly
      if ($WorkerDevURL) { $WorkerURL = $WorkerDevURL; Write-Warn "WorkerURL not resolved — using workers.dev fallback" }
      else { throw "Worker URL could not be determined. Check your Cloudflare account and re-run setup." }
    } else {
      $WorkerURL = Read-Prompt "Worker URL not detected — paste it manually" -Required
    }
  }
  if (-not $WorkerDevURL) { $WorkerDevURL = $WorkerURL }

  # --- Upload starter XML ---
  Write-Host ""
  Write-Step "6/7" "Uploading starter manifest..."
  $starterXml = if (Test-Path $XmlFile) {
  Get-Content $XmlFile -Raw -Encoding UTF8
  } else {
  @'
<?xml version="1.0" encoding="UTF-8"?>
<AppManifest>
  <!-- Add your apps here. App-Builder adds entries automatically. -->
</AppManifest>
'@
  }
  Write-Info "Waiting for Worker to come online (15s propagation)..."
  for ($i=1; $i -le 3; $i++) { Start-Sleep -Seconds 5; Write-Info "  ... $($i*5)s / 15s" }
  $uploaded = $false
  # Try custom domain first, then fall back to workers.dev which is always instant
  $uploadTargets = @($WorkerURL)
  if ($WorkerDevURL -and $WorkerDevURL -ne $WorkerURL) { $uploadTargets += $WorkerDevURL }
  foreach ($target in $uploadTargets) {
  if ($uploaded) { break }
  Write-Info "Trying $target ..."
  for ($i=1; $i -le 3; $i++) {
  try {
  $resp = Invoke-RestMethod -Uri "$target/manifest" -Method POST `
  -Headers @{"X-Auth-Token"=$ManifestToken;"Content-Type"="application/xml"} `
  -Body $starterXml -TimeoutSec 20 -ErrorAction Stop
  if ($resp -match "success") {
  Write-OK "Manifest uploaded via $target"
  # If we uploaded via the workers.dev fallback (custom domain not live yet),
  # DO NOT overwrite $WorkerURL — the intended custom domain URL is saved to
  # config so generated scripts point to the right place once DNS propagates.
  if ($target -ne $WorkerURL) {
  Write-Warn "Custom domain not live yet — manifest uploaded via workers.dev fallback."
  Write-Info "Your custom domain ($WorkerURL) will become active within a few minutes as Cloudflare provisions the certificate."
  Write-Info "No action needed — generated scripts already point to the custom domain."
  }
  $uploaded = $true; break
  }
  } catch {
  if ($i -lt 3) { Write-Info "Attempt $i failed — retrying in 8s..."; Start-Sleep -Seconds 8 }
  }
  }
  }
  if (-not $uploaded) {
  Write-Warn "Manifest upload failed. The Worker is live but the manifest was not pushed."
  Write-Warn "Once DNS propagates, re-run AppUpdater.ps1 and it will push automatically."
  Write-Host ""
  Write-Host "  To push manually, run this in PowerShell:" -ForegroundColor DarkGray
  $pushCmd = "Invoke-RestMethod -Uri '$WorkerDevURL/manifest' -Method POST -Headers @{'X-Auth-Token'='[REDACTED — see .manifest-token file]';'Content-Type'='application/xml'} -Body (Get-Content '$XmlFile' -Raw)"
  Write-Host "  $pushCmd" -ForegroundColor DarkGray
  Write-Host ""
  }

  # --- Save config — token goes to Credential Manager, sentinel in JSON ---
  $encToken = Protect-ManifestToken $ManifestToken   # writes to Cred Mgr, returns 'CREDMGR'
  # CustomDomainPending = $true when the user picked a domain in the wizard but
  # the API call failed (typically a token-permission gap). The main thread uses
  # this flag to surface a clear "set it up via Worker / app options" notice.
  $cdPending = [bool]$script:_customDomainFailed
  $cdTarget  = if ($script:_customDomainTarget) { $script:_customDomainTarget } else { '' }
  $config = @{
    WorkerURL=$WorkerURL; WorkerDevURL=$WorkerDevURL; ManifestToken=$encToken
    AccountID=$AccountID; OrgName=$OrgName; SetupDate=(Get-Date -Format 'yyyy-MM-dd')
    CustomDomainPending=$cdPending; CustomDomainTarget=$cdTarget
  }
  $config | ConvertTo-Json | Set-Content $ConfigFile -Encoding UTF8
  # Token is in Credential Manager; restrict config file to SYSTEM + Admins only.
  icacls $ConfigFile /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(F)" /grant:r "BUILTIN\Administrators:(F)" 2>&1 | Out-Null
  Write-AppLog "Config locked to SYSTEM+Administrators. Token stored in Windows Credential Manager." INFO

  # --- Create starter appVersions.xml if not present ---
  if (-not (Test-Path $XmlFile)) {
  $starterXml | Set-Content $XmlFile -Encoding UTF8
  }


  # --- Step 7/7: /status password + secrets -----------------------------------
  # 1. Write auth_session_secret to KV (self-rotated by Worker on logout-all).
  # 2. Write evtsec as a Worker Secret (not KV) so it is not readable via the API.
  # 3. Set the dashboard password using the user-provided value (never auto-generated).
  Write-Host ""
  Write-Step "7/7" "Preparing /status auth + event telemetry..."
  try {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
      $sessBytes = New-Object byte[] 32; $rng.GetBytes($sessBytes)
      $evtBytes  = New-Object byte[] 32; $rng.GetBytes($evtBytes)
    } finally { $rng.Dispose() }
    $sessB64 = [Convert]::ToBase64String($sessBytes)
    $evtB64  = [Convert]::ToBase64String($evtBytes)
    Invoke-CF -Method PUT -Path "/accounts/$AccountID/storage/kv/namespaces/$KvId/values/auth_session_secret" -Body $sessB64 -ContentType 'text/plain' | Out-Null
    Write-OK "Session secret written to KV"
    # evtsec stored as a Worker Secret (not KV) — not readable via the KV API.
    Invoke-CF -Method PUT -Path "/accounts/$AccountID/workers/scripts/$WorkerName/secrets" `
      -Body @{name="EVTSEC";text=$evtB64;type="secret_text"} | Out-Null
    Write-OK "Event-telemetry secret set as Worker Secret (EVTSEC)"
    $script:EventSecretB64 = $evtB64
  } catch {
    Write-Warn "Could not pre-seed Worker secrets: $($_.Exception.Message)"
    Write-Info "The Worker will not self-generate them — set a password via Worker Options or visit /status."
  }
  # Set dashboard password using the user-provided value — never auto-generated, never logged.
  # Uses /set-password endpoint (returns 403 if already set on re-deploy).
  if ($DashboardPassword -and $DashboardPassword.Length -gt 0) {
    try {
      $plainPwd = [System.Net.NetworkCredential]::new('', $DashboardPassword).Password
      $pwdBody = "password=$([Uri]::EscapeDataString($plainPwd))&confirm=$([Uri]::EscapeDataString($plainPwd))"
      $plainPwd = $null
      $DashboardPassword = $null   # clear SecureString from memory
      $pwdSet = $false
      foreach ($target in @($WorkerURL, $WorkerDevURL) | Where-Object { $_ } | Select-Object -Unique) {
        for ($pi = 1; $pi -le 3; $pi++) {
          try {
            Invoke-RestMethod -Uri "$target/set-password" -Method POST `
              -Headers @{'Content-Type'='application/x-www-form-urlencoded'} `
              -Body $pwdBody -TimeoutSec 20 -ErrorAction Stop | Out-Null
            Write-OK "Dashboard password set successfully"
            $pwdSet = $true; break
          } catch {
            $sc = $null; try { $sc = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($sc -eq 403) {
              Write-OK "Dashboard password already set — skipping (re-deploy scenario)"
              $pwdSet = $true; break
            }
            if ($pi -lt 3) { Write-Info "Password set attempt $pi failed — retrying in 8s..."; Start-Sleep -Seconds 8 }
          }
        }
        if ($pwdSet) { break }
      }
      if (-not $pwdSet) { Write-Warn "Could not set dashboard password — visit /status in a browser to set one." }
    } catch {
      Write-Warn "Dashboard password set failed: $($_.Exception.Message)"
    }
  } else {
    Write-Info "No dashboard password provided — visit /status to set one on first run."
  }
  # --- Create HOW TO USE.txt ---
  $howToPath = "$ScriptDir\HOW TO USE.txt"
  if (-not (Test-Path $howToPath)) {
  @'
HOW TO USE AppUpdater
=====================

TO BUILD A PACKAGE
-------------------
1. Run AppUpdater.ps1
2. In Explorer: hold Shift + right-click your installer (.exe/.msi)
3. Choose "Copy as path"
4. Paste (Ctrl+V) when AppUpdater prompts for the installer path

TO RUN OFFLINE (no Cloudflare)
-------------------------------
Run AppUpdater.ps1 and choose [2] Build only
OR:  .\AppUpdater.ps1 -Offline
'@ | Set-Content "$howToPath" -Encoding UTF8
  }

  # --- Summary ---
  Write-Host ""
  Write-OK "Cloudflare backend deployed successfully!"
  Write-Host ""
  Write-Host "  Worker URL  : $WorkerURL" -ForegroundColor White
  Write-Host "  Status page : $WorkerURL/status" -ForegroundColor White
  Write-Host "  Login       : Password required (set next, or on first /status visit)" -ForegroundColor Green
  Write-Host ""
  Write-Host "  Everything is saved. Go build your first app package." -ForegroundColor Cyan
  Write-Host ""
  Write-AppLog "Cloudflare setup complete: WorkerURL=$WorkerURL AccountID=$AccountID" -Level INFO
  return $config
}

# =============================================================================
# PSADT SUPPORT
# =============================================================================

# Downloads the PSADT v3 framework zip on first use, expands it to $PSADTCacheDir,
# and returns the cache path. Subsequent calls return immediately from cache.
# Returns $null if download fails and the user does not supply a manual path.
function Get-PSADTToolkit {
  param([string]$ManualPath = '')

  # Manual path takes priority — try exact layout first, then recursive search for v4 packages
  if ($ManualPath) {
    if (Test-Path (Join-Path $ManualPath 'AppDeployToolkit\AppDeployToolkitMain.ps1')) {
      return $ManualPath
    }
    $found = Get-ChildItem -Path $ManualPath -Recurse -Filter 'AppDeployToolkitMain.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
      $adtRoot = $found.Directory.Parent.FullName
      Write-AppLog "Found AppDeployToolkitMain.ps1 via recursive search. Toolkit root: $adtRoot" INFO
      return $adtRoot
    }
  }

  $markerFile  = Join-Path $PSADTCacheDir 'AppDeployToolkit\AppDeployToolkitMain.ps1'
  $versionFile = Join-Path $PSADTCacheDir 'psadt_cached_version.txt'
  $hashFile    = Join-Path $PSADTCacheDir 'psadt_cached_hash.txt'

  # Set TLS 1.2+ early — required for both the GitHub API call and the download
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

  # Query GitHub for the latest release tag
  $latestTag = $null
  $rel       = $null
  try {
    $rel       = Invoke-RestMethod -Uri 'https://api.github.com/repos/PSAppDeployToolkit/PSAppDeployToolkit/releases/latest' `
                   -UseBasicParsing -Headers @{'User-Agent'='AppUpdater/1.0'} -ErrorAction Stop
    $latestTag = $rel.tag_name
  } catch {
    Write-AppLog "Could not reach GitHub releases API: $($_.Exception.Message)" WARN
  }

  # Already cached and up-to-date — skip download
  $cachedTag = if (Test-Path $versionFile) { (Get-Content $versionFile -Raw).Trim() } else { $null }
  if ((Test-Path $markerFile) -and $cachedTag -and ($null -eq $latestTag -or $cachedTag -eq $latestTag)) {
    Write-AppLog "PSADT $cachedTag already cached at $PSADTCacheDir" INFO
    return $PSADTCacheDir
  }

  # Cache marker missing but AppDeployToolkitMain.ps1 may exist deeper (e.g. v4 release package placed in cache dir)
  if (-not (Test-Path $markerFile)) {
    $foundInCache = Get-ChildItem -Path $PSADTCacheDir -Recurse -Filter 'AppDeployToolkitMain.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($foundInCache) {
      $adtRoot = $foundInCache.Directory.Parent.FullName
      Write-AppLog "Found AppDeployToolkitMain.ps1 in cache dir via recursive search. Toolkit root: $adtRoot" INFO
      return $adtRoot
    }
  }

  $reason = if ($latestTag -and $cachedTag -and $cachedTag -ne $latestTag) { "update available ($cachedTag -> $latestTag)" } else { "not yet cached" }
  Write-AppLog "Downloading PSADT framework from GitHub ($reason)..." INFO
  try {
    $zipPath    = Join-Path $env:TEMP 'psadt_download.zip'
    $extractTmp = Join-Path $env:TEMP 'psadt_extract'
    if (Test-Path $extractTmp) { Remove-Item $extractTmp -Recurse -Force }

    # Build a prioritized list of download URLs to try in sequence
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($rel) {
      $asset = $rel.assets | Where-Object { $_.name -like 'PSAppDeployToolkit_Template_v3*' } | Select-Object -First 1
      if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like 'PSAppDeployToolkit*.zip' -and $_.name -notlike '*ModuleOnly*' } | Select-Object -First 1 }
      if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like 'PSAppDeployToolkit*.zip' } | Select-Object -First 1 }
      if ($asset) { $candidates.Add($asset.browser_download_url) }
      if ($rel.tag_name) {
        $tv = $rel.tag_name -replace '^v', ''   # strip leading 'v' so filename matches GitHub asset
        $candidates.Add("https://github.com/PSAppDeployToolkit/PSAppDeployToolkit/releases/download/$($rel.tag_name)/PSAppDeployToolkit_$tv.zip")
        $candidates.Add("https://github.com/PSAppDeployToolkit/PSAppDeployToolkit/releases/download/$($rel.tag_name)/PSAppDeployToolkit_$($rel.tag_name).zip")
      }
    }
    $candidates.Add($PSADTv3URL)   # last resort — works for v3; may 404 for v4-only releases

    $ProgressPreference = 'SilentlyContinue'
    $downloaded = $false
    foreach ($url in ($candidates | Select-Object -Unique)) {
      if (([Uri]$url).Scheme -ne 'https') { continue }
      try {
        Write-AppLog "Trying PSADT download from: $url" INFO
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
        $downloaded = $true
        Write-AppLog "Download succeeded: $url" INFO
        break
      } catch {
        Write-AppLog "Download attempt failed ($url): $($_.Exception.Message)" WARN
      }
    }
    if (-not $downloaded) { throw "All PSADT download URLs failed — check AppUpdater.log for details." }

    # SHA-256 integrity check (mirrors Get-FileHash pattern used for installers)
    $dlHash = (Get-FileHash -Path $zipPath -Algorithm SHA256 -ErrorAction Stop).Hash
    Write-AppLog "PSADT zip SHA256: $dlHash" INFO

    Expand-Archive -Path $zipPath -DestinationPath $extractTmp -Force -ErrorAction Stop
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

    # Find AppDeployToolkit at any nesting depth inside the zip
    $foundMain = Get-ChildItem -Path $extractTmp -Recurse -Filter 'AppDeployToolkitMain.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $foundMain) { throw "AppDeployToolkitMain.ps1 not found in downloaded zip." }

    $srcADT  = $foundMain.Directory.FullName
    $destADT = Join-Path $PSADTCacheDir 'AppDeployToolkit'
    if (-not (Test-Path $PSADTCacheDir)) { New-Item $PSADTCacheDir -ItemType Directory -Force | Out-Null }
    if (Test-Path $destADT) { Remove-Item $destADT -Recurse -Force }
    Copy-Item -Path $srcADT -Destination $destADT -Recurse -Force

    # Also extract PSAppDeployToolkit v4 module if present in the zip
    $foundPsd1 = Get-ChildItem -Path $extractTmp -Filter 'PSAppDeployToolkit.psd1' -Recurse `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike '*Extensions*' } |
        Sort-Object { ($_.FullName -split '\\').Count } |
        Select-Object -First 1
    if ($foundPsd1) {
        $srcModule  = $foundPsd1.Directory.FullName
        $destModule = Join-Path $PSADTCacheDir 'PSAppDeployToolkit'
        if (Test-Path $destModule) { Remove-Item $destModule -Recurse -Force }
        Copy-Item -Path $srcModule -Destination $destModule -Recurse -Force
        Write-AppLog "PSAppDeployToolkit module extracted to cache: $destModule" INFO
    } else {
        Write-AppLog "PSAppDeployToolkit.psd1 not in primary zip — attempting ModuleOnly download" INFO
        $modOnlyUrl = $null
        if ($rel) {
            $modAsset = $rel.assets | Where-Object { $_.name -like '*ModuleOnly*' } | Select-Object -First 1
            if ($modAsset) { $modOnlyUrl = $modAsset.browser_download_url }
        }
        if ($modOnlyUrl -and ([Uri]$modOnlyUrl).Scheme -eq 'https') {
            try {
                $modZip = Join-Path $env:TEMP 'psadt_module.zip'
                $modTmp = Join-Path $env:TEMP 'psadt_module_extract'
                if (Test-Path $modTmp) { Remove-Item $modTmp -Recurse -Force }
                Invoke-WebRequest -Uri $modOnlyUrl -OutFile $modZip -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
                Expand-Archive -Path $modZip -DestinationPath $modTmp -Force -ErrorAction Stop
                Remove-Item $modZip -Force -ErrorAction SilentlyContinue
                $foundPsd1 = Get-ChildItem -Path $modTmp -Filter 'PSAppDeployToolkit.psd1' -Recurse `
                    -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notlike '*Extensions*' } |
                    Sort-Object { ($_.FullName -split '\\').Count } | Select-Object -First 1
                if ($foundPsd1) {
                    $srcModule  = $foundPsd1.Directory.FullName
                    $destModule = Join-Path $PSADTCacheDir 'PSAppDeployToolkit'
                    if (Test-Path $destModule) { Remove-Item $destModule -Recurse -Force }
                    Copy-Item -Path $srcModule -Destination $destModule -Recurse -Force
                    Write-AppLog "PSAppDeployToolkit module extracted from ModuleOnly zip: $destModule" INFO
                } else {
                    Write-AppLog "PSAppDeployToolkit.psd1 not found in ModuleOnly zip — v4 module will not be bundled" WARN
                }
                Remove-Item $modTmp -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-AppLog "ModuleOnly download failed: $($_.Exception.Message)" WARN
            }
        } else {
            Write-AppLog "No ModuleOnly asset found in GitHub release — v4 module will not be bundled" WARN
        }
    }

    Remove-Item $extractTmp -Recurse -Force -ErrorAction SilentlyContinue

    # Unblock all extracted files — downloaded zips carry Zone.Identifier ADS which prevents .NET
    # from loading the DLLs (0x80131515). Unblocking here means bundled copies are already clean.
    Get-ChildItem -Path $PSADTCacheDir -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    Write-AppLog "Unblocked PSADT cache files at $PSADTCacheDir" INFO

    # Persist version tag and hash AFTER all copies complete — prevents partial state looking valid
    if ($latestTag) { Set-Content -Path $versionFile -Value $latestTag -Encoding UTF8 }
    Set-Content -Path $hashFile -Value $dlHash -Encoding UTF8

    Write-AppLog "PSADT $latestTag framework cached at $PSADTCacheDir" INFO
    return $PSADTCacheDir
  } catch {
    if (Test-Path $extractTmp) { Remove-Item $extractTmp -Recurse -Force -ErrorAction SilentlyContinue }
    $errMsg   = $_.Exception.Message
    $httpCode = if ($_.Exception.Response) { " [HTTP $([int]$_.Exception.Response.StatusCode)]" } else { '' }
    Write-AppLog "PSADT download failed: $errMsg$httpCode" ERROR
    return $null
  }
}

# Generates a PSADT-wrapped deployment package for an already-built AppUpdater app.
# PSADT handles enterprise pre-flight (close-apps prompts, elevation, progress UI),
# then calls the existing Deploy-{AppID}.ps1 which installs the AppUpdater runtime.
# The AppUpdater runtime (task, shortcut, auto-update) is identical to the standard build.
function Export-PSADTPackage {
  param(
    [Parameter(Mandatory)][string]$AppID,
    [Parameter(Mandatory)][string]$DisplayName,
    [string]$ProcessesToKill  = '',
    [string]$ExpectedPub      = '',
    [ValidateSet('v3','v4','both')][string]$PSADTVersion = 'v3',
    [string]$PSADTToolkitPath = '',
    [string]$OrgName          = 'IT Services'
  )

  $toolkitPath = Get-PSADTToolkit -ManualPath $PSADTToolkitPath
  if (-not $toolkitPath) {
    Show-WpfPSADTExport `
      -AppID           $AppID `
      -DisplayName     $DisplayName `
      -ProcessesToKill $ProcessesToKill `
      -ExpectedPub     $ExpectedPub `
      -OrgName         $OrgName `
      -InitialError    'Download failed — use Browse… to point to an existing PSADT folder'
    return
  }

  # Resolve source deploy script — must exist from a prior standard build
  $srcDeploy = Join-Path $OutputBase "$AppID\Deploy-$AppID.ps1"
  if (-not (Test-Path $srcDeploy)) {
    Show-WpfMsg -Title 'Build Required First' -Type 'error' `
      -Message "Deploy-$AppID.ps1 not found in C:\ProgramData\AppUpdater\_output\$AppID\.`n`nBuild the standard package first, then export as PSADT."
    return
  }

  $buildDate       = Get-Date -Format 'yyyy-MM-dd'
  $closeAppsArg    = if ($ProcessesToKill) { $ProcessesToKill } else { '' }

  $psadtModVersion = '4.1.8'
  $_pv = Get-ChildItem -Path $PSADTCacheDir -Filter 'PSAppDeployToolkit.psd1' -Recurse -Depth 4 `
      -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notlike '*Extensions*' } |
      Sort-Object { ($_.FullName -split '\\').Count } | Select-Object -First 1 -ExpandProperty FullName
  if ($_pv) { try { $psadtModVersion = (Import-PowerShellDataFile $_pv -ErrorAction Stop).ModuleVersion.ToString() } catch {} }
  Remove-Variable _pv -ErrorAction SilentlyContinue

  $variants = if ($PSADTVersion -eq 'both') { @('v3','v4') } else { @($PSADTVersion) }

  foreach ($ver in $variants) {
    $suffix    = if ($PSADTVersion -eq 'both') { "-PSADT-$ver" } else { '-PSADT' }
    $outputDir = Join-Path $OutputBase "$AppID$suffix"

    # Clean and create output folder
    if (Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item $outputDir                                  -ItemType Directory -Force | Out-Null
    New-Item (Join-Path $outputDir 'SupportFiles')       -ItemType Directory -Force | Out-Null

    # Copy PSADT framework
    $toolkitDest = Join-Path $outputDir 'AppDeployToolkit'
    Copy-Item (Join-Path $toolkitPath 'AppDeployToolkit') $toolkitDest -Recurse -Force -ErrorAction SilentlyContinue

    # v3 shim: AppDeployToolkitMain.ps1 looks for the module at $PSScriptRoot\PSAppDeployToolkit\
    # which resolves to AppDeployToolkit\PSAppDeployToolkit\ — copy it there so it works without
    # a system-wide module install on the target device.
    if ($ver -eq 'v3') {
      $_psadtModSrc = Join-Path $PSADTCacheDir 'PSAppDeployToolkit'
      if (Test-Path $_psadtModSrc) {
        Copy-Item -Path $_psadtModSrc -Destination (Join-Path $toolkitDest 'PSAppDeployToolkit') -Recurse -Force
        Write-AppLog "Copied PSAppDeployToolkit module into AppDeployToolkit\ for v3 shim" INFO
      }
    }

    # Copy source deploy script into SupportFiles
    Copy-Item $srcDeploy (Join-Path $outputDir "SupportFiles\Deploy-$AppID.ps1") -Force

    # Generate Deploy-Application.ps1
    if ($ver -eq 'v3') {
      $deployApp = @"
# Deploy-Application.ps1 — Generated by AppUpdater Builder ($buildDate)
# PSADT v3.x — wraps the AppUpdater initial deployment with enterprise pre-flight UI.
# The Deploy-$AppID.ps1 in SupportFiles creates the full AppUpdater runtime on the device
# (scheduled task, desktop shortcut, auto-update). Auto-updates then run as normal via shortcut.
#
# Drop this folder contents alongside AppDeployToolkit\ (copy from PSAppDeployToolkit release).
# Intune install:   powershell.exe -ExecutionPolicy Bypass -File Deploy-Application.ps1
# Intune uninstall: powershell.exe -ExecutionPolicy Bypass -File Deploy-Application.ps1 -DeploymentType Uninstall

[CmdletBinding()]
Param (
    [Parameter(Mandatory=`$false)][ValidateSet('Install','Uninstall','Repair')][string]`$DeploymentType = 'Install',
    [Parameter(Mandatory=`$false)][ValidateSet('Interactive','Silent','NonInteractive')][string]`$DeployMode = 'Interactive',
    [Parameter(Mandatory=`$false)][switch]`$AllowRebootPassThru = `$false,
    [Parameter(Mandatory=`$false)][switch]`$TerminalServerMode = `$false,
    [Parameter(Mandatory=`$false)][switch]`$DisableLogging = `$false
)
Try {
    [string]`$appVendor         = '$ExpectedPub'
    [string]`$appName           = '$DisplayName'
    [string]`$appVersion        = ''
    [string]`$appArch           = ''
    [string]`$appLang           = 'EN'
    [string]`$appRevision       = '01'
    [string]`$appScriptVersion  = '1.0.0'
    [string]`$appScriptDate     = '$buildDate'
    [string]`$appScriptAuthor   = '$OrgName'
    [string]`$installTitle      = "`$appName — AppUpdater"

    . "`$PSScriptRoot\AppDeployToolkit\AppDeployToolkitMain.ps1"

    If (`$deploymentType -ine 'Uninstall' -and `$deploymentType -ine 'Repair') {
        [string]`$installPhase = 'Installation'
        Show-InstallationWelcome$(if ($closeAppsArg) { " -CloseApps '$closeAppsArg'" }) -AllowDefer -DeferTimes 3 -CheckDiskSpace
        Show-InstallationProgress -StatusMessage "Setting up `$appName auto-updater..."
        Execute-Process -Path 'powershell.exe' ``
            -Parameters "-NonInteractive -NoProfile -ExecutionPolicy RemoteSigned -File ``"`$dirSupportFiles\Deploy-$AppID.ps1``"" ``
            -WindowStyle Hidden -IgnoreExitCodes '0'
    }
    ElseIf (`$deploymentType -ieq 'Uninstall') {
        [string]`$installPhase = 'Uninstallation'
        Show-InstallationWelcome$(if ($closeAppsArg) { " -CloseApps '$closeAppsArg'" }) -AllowDefer -DeferTimes 3
        Execute-Process -Path 'powershell.exe' ``
            -Parameters "-NonInteractive -NoProfile -ExecutionPolicy RemoteSigned -File ``"`$dirSupportFiles\Deploy-$AppID.ps1``" -Uninstall" ``
            -WindowStyle Hidden -IgnoreExitCodes '0'
    }
} Catch { [int32]`$mainExitCode = 60001; Write-Log -Message `$_.Exception.Message -Severity 3 -Source `$deployAppScriptFriendlyName }
Exit `$mainExitCode
"@
    } else {
      # v4.1.x — function-based API
      $deployApp = @"
# Deploy-Application.ps1 — Generated by AppUpdater Builder ($buildDate)
# PSADT v4.1.x — wraps the AppUpdater initial deployment with enterprise pre-flight UI.
[CmdletBinding()]
param(
    [ValidateSet('Install','Uninstall','Repair')][System.String]`$DeploymentType = 'Install',
    [ValidateSet('Auto','Interactive','NonInteractive','Silent')][System.String]`$DeployMode = 'Interactive',
    [System.Management.Automation.SwitchParameter]`$SuppressRebootPassThru,
    [System.Management.Automation.SwitchParameter]`$TerminalServerMode,
    [System.Management.Automation.SwitchParameter]`$DisableLogging
)

`$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
`$ProgressPreference    = [System.Management.Automation.ActionPreference]::SilentlyContinue
Set-StrictMode -Version 1

`$adtSession = @{
    AppVendor                   = '$ExpectedPub'
    AppName                     = '$DisplayName'
    AppVersion                  = ''
    AppScriptVersion            = '1.0.0'
    AppScriptDate               = '$buildDate'
    AppProcessesToClose         = @()
    RequireAdmin                = `$true
    DeployAppScriptFriendlyName = `$MyInvocation.MyCommand.Name
    DeployAppScriptParameters   = `$PSBoundParameters
    DeployAppScriptVersion      = '$psadtModVersion'
}

function Install-ADTDeployment {
    [CmdletBinding()] param()
    `$adtSession.InstallPhase = "Pre-`$(`$adtSession.DeploymentType)"
    Show-ADTInstallationWelcome$(if ($closeAppsArg) { " -CloseProcesses '$closeAppsArg'" }) -AllowDefer -DeferTimes 3 -CheckDiskSpace
    `$adtSession.InstallPhase = `$adtSession.DeploymentType
    Show-ADTInstallationProgress -StatusMessage "Setting up `$(`$adtSession.AppName) auto-updater..."
    Start-ADTProcess -FilePath 'powershell.exe' ``
        -ArgumentList @('-NonInteractive','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',"``"`$PSScriptRoot\SupportFiles\Deploy-$AppID.ps1``"") ``
        -IgnoreExitCodes @(0)
    `$adtSession.InstallPhase = "Post-`$(`$adtSession.DeploymentType)"
}

function Uninstall-ADTDeployment {
    [CmdletBinding()] param()
    `$adtSession.InstallPhase = "Pre-`$(`$adtSession.DeploymentType)"
    Show-ADTInstallationWelcome$(if ($closeAppsArg) { " -CloseProcesses '$closeAppsArg'" }) -AllowDefer -DeferTimes 3
    `$adtSession.InstallPhase = `$adtSession.DeploymentType
    Show-ADTInstallationProgress -StatusMessage "Uninstalling `$(`$adtSession.AppName)..."
    Start-ADTProcess -FilePath 'powershell.exe' ``
        -ArgumentList @('-NonInteractive','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',"``"`$PSScriptRoot\SupportFiles\Deploy-$AppID.ps1``"",'-Uninstall') ``
        -IgnoreExitCodes @(0)
    `$adtSession.InstallPhase = "Post-`$(`$adtSession.DeploymentType)"
}

function Repair-ADTDeployment {
    [CmdletBinding()] param()
    Install-ADTDeployment
}

try {
    `$_psd1 = `$null
    foreach (`$_sr in @((Join-Path `$PSScriptRoot 'PSAppDeployToolkit'), `$PSScriptRoot,
                         (Join-Path `$PSScriptRoot 'AppDeployToolkit\PSAppDeployToolkit'))) {
        if (-not (Test-Path `$_sr -PathType Container -ErrorAction SilentlyContinue)) { continue }
        `$_psd1 = Get-ChildItem -Path `$_sr -Filter 'PSAppDeployToolkit.psd1' -Recurse -Depth 3 ``
            -ErrorAction SilentlyContinue |
            Where-Object { `$_.FullName -notlike '*Extensions*' } |
            Sort-Object { (`$_.FullName -split '\\').Count } |
            Select-Object -First 1 -ExpandProperty FullName
        if (`$_psd1) { break }
    }
    if (`$_psd1) {
        Get-ChildItem -Path (Split-Path `$_psd1 -Parent) -Recurse -File ``
            -ErrorAction SilentlyContinue | Unblock-File -ErrorAction Ignore
        Import-Module `$_psd1 -Force -ErrorAction Stop
    } else {
        Import-Module PSAppDeployToolkit -MinimumVersion '4.0' -Force -ErrorAction Stop
    }
    Remove-Variable _psd1, _sr -ErrorAction SilentlyContinue
    if (Get-Command 'Get-ADTBoundParametersAndDefaultValues' -ErrorAction SilentlyContinue) {
        `$_iadtP = Get-ADTBoundParametersAndDefaultValues -Invocation `$MyInvocation
        if (Get-Command 'Remove-ADTHashtableNullOrEmptyValues' -ErrorAction SilentlyContinue) {
            `$adtSession = Remove-ADTHashtableNullOrEmptyValues -Hashtable `$adtSession
        }
        `$adtSession = Open-ADTSession @adtSession @_iadtP -PassThru
        Remove-Variable _iadtP -ErrorAction SilentlyContinue
    } else {
        `$adtSession = Open-ADTSession @adtSession -PassThru
    }
} catch {
    `$Host.UI.WriteErrorLine((Out-String -InputObject `$_ -Width ([System.Int32]::MaxValue)))
    exit 60008
}

try {
    `$_fn = "`$(`$adtSession.DeploymentType)-ADTDeployment"
    if (-not (Get-Command `$_fn -ErrorAction SilentlyContinue)) {
        throw "Deployment function '`$_fn' not found. Ensure DeploymentType is Install, Uninstall, or Repair."
    }
    & `$_fn
    Remove-Variable _fn -ErrorAction SilentlyContinue
    if (Get-Command 'Close-ADTSession' -ErrorAction SilentlyContinue) { Close-ADTSession }
} catch {
    `$Host.UI.WriteErrorLine((Out-String -InputObject `$_ -Width ([System.Int32]::MaxValue)))
    try { if (Get-Command 'Close-ADTSession' -ErrorAction SilentlyContinue) { Close-ADTSession -ExitCode 60001 } } catch {}
    exit 60001
}
"@
    }

    $deployApp | Out-File (Join-Path $outputDir 'Deploy-Application.ps1') -Encoding UTF8 -Force

    if (Test-Path $PSADTCacheDir) {
      $psadtDest = Join-Path $outputDir 'PSAppDeployToolkit'
      Copy-Item -Path $PSADTCacheDir -Destination $psadtDest -Recurse -Force
      Get-ChildItem -Path $psadtDest -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
      $verifyPsd1 = Get-ChildItem -Path $psadtDest -Filter 'PSAppDeployToolkit.psd1' -Recurse -Depth 4 `
        -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike '*Extensions*' } | Select-Object -First 1
      if ($verifyPsd1) {
        Write-AppLog "PSAppDeployToolkit module bundled at: $($verifyPsd1.FullName)" INFO
      } else {
        Write-AppLog "WARNING: PSAppDeployToolkit.psd1 not found in bundled output — target device will need the system module installed" WARN
      }
    } else {
      Write-AppLog "WARNING: PSADTCacheDir not found — module NOT bundled. Target device requires: Install-Module PSAppDeployToolkit" WARN
    }

    # Package with IntuneWinAppUtil if available
    $pkgOk = $false
    if (Test-Path -LiteralPath $IntuneWinUtilPath -PathType Leaf) {
      try {
        $proc = Start-Process -FilePath $IntuneWinUtilPath `
          -ArgumentList "-c `"$outputDir`" -s `"Deploy-Application.ps1`" -o `"$outputDir`" -q" `
          -Wait -PassThru -ErrorAction Stop
        if ($proc.ExitCode -eq 0) { $pkgOk = $true }
      } catch {
        Write-AppLog "IntuneWinAppUtil failed for PSADT package: $($_.Exception.Message)" WARN
      }
    }

    Write-AppLog "PSADT $ver package written to: $outputDir (packaged=$pkgOk)" INFO
  }



  $installCmd   = "powershell.exe -ExecutionPolicy Bypass -File Deploy-Application.ps1"
  $uninstallCmd = "powershell.exe -ExecutionPolicy Bypass -File Deploy-Application.ps1 -DeploymentType Uninstall"
  Show-WpfMsg -Title "PSADT Package Ready — $DisplayName" -Type 'ok' `
    -Message "PSADT-wrapped package generated successfully." `
    -Detail  "Intune install command:`n$installCmd`n`nIntune uninstall command:`n$uninstallCmd`n`nDetection: use the same Detect-$AppID.ps1 as the standard package."
}

# =============================================================================
# PACKAGE BUILDER  — generates the full NetDocuments-style deploy package
# =============================================================================
function Invoke-PackageBuilder {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable] $Config,
    [string]    $PreloadPath = '',
    [hashtable] $FormData    = $null
  )

  $WorkerURL     = $Config.WorkerURL
  $ManifestToken = Unprotect-ManifestToken ([string]$Config.ManifestToken)
  $OrgName       = if ($Config.ContainsKey('OrgName') -and $Config.OrgName) { $Config.OrgName } else { 'IT Services' }
  $isOffline     = $Config.ContainsKey('OfflineMode') -and $Config.OfflineMode
  $WorkerDevURL  = if ($Config.ContainsKey('WorkerDevURL')) { $Config.WorkerDevURL } else { $WorkerURL }

  # --- Worker reachability probe (best-effort, non-fatal) ----------------------
  $WorkerOnline = $false
  if (-not $isOffline -and $WorkerURL) {
    foreach ($candidate in (@($WorkerURL, $WorkerDevURL) | Where-Object { $_ } | Select-Object -Unique)) {
      try {
        $health = Invoke-RestMethod -Uri "$candidate/health" -TimeoutSec 10 -ErrorAction Stop
        if ($health.status -eq 'ok') {
          if ($candidate -ne $WorkerURL) { $WorkerURL = $candidate }
          $WorkerOnline = $true
          break
        }
      } catch { }
    }
  }

  # --- Acquire form data: from arg, or by inspecting the dropped installer ------
  if (-not $FormData) {
    $defaults = @{}
    $cleanPath = ([string]$PreloadPath).Trim().Trim('"').Trim("'")
    if ($cleanPath -and (Test-Path -LiteralPath $cleanPath -PathType Leaf)) {
      try {
        $detected = Invoke-InstallerInspector -InstallerPath $cleanPath 6>$null
        if ($detected) {
          $defaults = @{
            AppID         = $detected.AppID
            DisplayName   = $detected.DisplayName
            SilentArgs    = $detected.SilentArgs
            RegistryName  = $detected.RegistryName
            InstallerPath = $cleanPath
          }
        }
      } catch {
        Write-AppLog "Installer inspection failed for '$cleanPath': $($_.Exception.Message)" WARN
      }
    }
    $FormData = Show-WpfAppForm -Defaults $defaults -HasWorker ([bool]$WorkerURL)
    if (-not $FormData) { return }
  }

  # --- Validate form data at the trust boundary --------------------------------
  $AppID = ($FormData.AppID -as [string]) -replace '\s',''
  if (-not (Test-SafeAppId $AppID)) {
    Show-WpfMsg -Title 'Invalid App ID' -Type 'error' `
      -Message "App ID '$AppID' is not allowed.`n`nUse only letters, digits, '.', '_' or '-' (max 64 chars, must start with a letter or digit)."
    return
  }

  $DisplayName     = ($FormData.DisplayName -as [string])
  $DownloadURL     = ($FormData.DownloadURL -as [string])
  $FallbackURL     = ($FormData.FallbackURL -as [string])
  $SilentArgs      = ($FormData.SilentArgs  -as [string])
  $RegistryName    = ($FormData.RegistryName -as [string])
  $ProcessesToKill    = ($FormData.ProcessesToKill    -as [string])
  $LaunchExe          = ($FormData.LaunchExe          -as [string])
  $ExpectedPublisher  = ($FormData.ExpectedPublisher  -as [string])
  $InstallerSHA256    = ($FormData.InstallerSHA256    -as [string])
  $isOfflinePkg       = ($FormData.Mode -eq 'offline') -or ($FormData.IsOfflinePkg -eq $true)

  # SHA-256 must be exactly 64 hex chars if provided
  if ($InstallerSHA256 -and $InstallerSHA256 -notmatch '^[0-9a-fA-F]{64}$') {
    Show-WpfMsg -Title 'Invalid SHA-256' -Type 'error' `
      -Message "SHA-256 must be exactly 64 hexadecimal characters.`n`n$InstallerSHA256"
    return
  }

  # HTTPS-only download URLs — no http:// downgrade.
  if (-not $isOfflinePkg -and $DownloadURL -and -not (Test-SafeHttpsUrl $DownloadURL)) {
    Show-WpfMsg -Title 'Insecure download URL' -Type 'error' `
      -Message "Download URL must use https://`n`n$DownloadURL"
    return
  }
  if ($FallbackURL -and -not (Test-SafeHttpsUrl $FallbackURL)) {
    Show-WpfMsg -Title 'Insecure fallback URL' -Type 'error' `
      -Message "Fallback URL must use https://`n`n$FallbackURL"
    return
  }

  # --- Ensure manifest exists --------------------------------------------------
  if (-not (Test-Path -LiteralPath $XmlFile -PathType Leaf)) {
    "<?xml version=""1.0"" encoding=""UTF-8""?>`n<AppManifest>`n</AppManifest>" |
      Set-Content -LiteralPath $XmlFile -Encoding UTF8
  }

  # --- Fetch the event-telemetry HMAC secret to bake into the deploy script ---
  # Order: in-memory hint from this session's setup → /evtsec-export Worker endpoint
  # (bearer-auth, fetches from EVTSEC Worker Secret). Falls back to KV for Workers
  # not yet redeployed. If none work, event reporting is disabled in the package (non-fatal).
  $EventSecretB64 = ''
  if ($script:EventSecretB64) {
    $EventSecretB64 = $script:EventSecretB64
  } elseif (-not $isOffline -and $WorkerURL -and $ManifestToken) {
    try {
      $evtSecRaw = Invoke-RestMethod -Method GET `
        -Uri "$WorkerURL/evtsec-export" `
        -Headers @{ 'X-Auth-Token' = $ManifestToken } -TimeoutSec 15 -ErrorAction Stop
      $EventSecretB64 = ([string]$evtSecRaw).Trim()
      if ($EventSecretB64) { Write-AppLog "Event secret fetched from Worker." INFO }
    } catch {
      Write-AppLog "Could not fetch event secret from Worker: $($_.Exception.Message)" WARN
    }
  }
  $EventReportingEnabled = [bool]$EventSecretB64 -and -not $isOfflinePkg -and [bool]$WorkerURL

  # Warn before overwriting an existing entry.
  $existingXml = Get-Content -LiteralPath $XmlFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  if ($existingXml -and $existingXml -match "<ID>$([regex]::Escape($AppID))</ID>") {
    $proceed = Show-WpfMsg -Title 'App already exists' -Confirm `
      -Message "'$AppID' is already in your manifest." `
      -Detail  'Continuing will overwrite the existing entry and re-push the manifest.' `
      -YesLabel 'Overwrite' -NoLabel 'Cancel'
    if (-not $proceed) { return }
  }

  # --- Acquire IntuneWinAppUtil.exe with TLS 1.2 enforced ----------------------
  if (-not (Test-Path -LiteralPath $IntuneWinUtilPath -PathType Leaf)) {
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
      Invoke-WebRequest -Uri $IntuneWinUtilURL -OutFile $IntuneWinUtilPath `
        -UseBasicParsing -ErrorAction Stop
      Test-DownloadAuthenticode -FilePath $IntuneWinUtilPath -ExpectedPublisher 'Microsoft Corporation'
      Write-AppLog "Downloaded and verified IntuneWinAppUtil.exe" INFO
    } catch {
      Write-AppLog "IntuneWinAppUtil download/verify failed: $($_.Exception.Message)" ERROR
    }
  }

  # --- Working directories — paths are guarded by Resolve-SafeChildPath -------
  $TempDir   = Resolve-SafeChildPath -Parent $TempBase   -Child $AppID
  $OutputDir = Resolve-SafeChildPath -Parent $OutputBase -Child $AppID
  foreach ($dir in @($TempDir, $OutputDir)) {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  $AppDir   = "C:\ProgramData\AppUpdater\$AppID"
  $LogDir   = "$AppDir\logs"
  $TaskName = "AppUpdater_$AppID"

  Write-Host ""
  Write-Step "1/5" "Generating Deploy-$AppID.ps1..."

  # =========================================================================
  # BUILD ALL SUB-SCRIPTS AS STRINGS  (embedded inside Deploy script)
  # =========================================================================

  # --- Kill block: use manual override if supplied, else auto-detect at runtime ---
  # Auto-detect scans running processes whose name matches the app display name.
  # This runs inside the generated script at install time, not at build time.
  if ($ProcessesToKill) {
  # Validate names: allow only chars that are legal in Windows process names.
  # This prevents single-quote injection into the generated PowerShell string.
  $validKillNames = @(); $badKillNames = @()
  foreach ($kn in ($ProcessesToKill -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    if ($kn -match '^[A-Za-z0-9._-]+$') { $validKillNames += $kn }
    else { $badKillNames += $kn }
  }
  if ($badKillNames) {
    Show-WpfMsg -Title 'Invalid Process Names' -Type 'warn' `
      -Message "The following process names contain invalid characters and were removed:`n$($badKillNames -join ', ')`n`nWindows process names may only contain letters, digits, '.', '_', and '-'."
  }
  if ($validKillNames) {
    $ProcessesToKill = $validKillNames -join ','
    $killLines = ($validKillNames |
    ForEach-Object { "Get-Process -Name '$_' -ErrorAction SilentlyContinue | Stop-Process -Force" }) -join "`n"
  } else {
    # All names invalid — fall through to auto-detect
    $ProcessesToKill = ''
  }
  }
  if (-not $ProcessesToKill) {
  # No override — emit dynamic detection code into the generated script.
  # At install time this kills any process whose name loosely matches the app.
  $killLines = @'
# Auto-kill: stop any running processes whose name matches the app display name
$_appKillName = ($DisplayName -replace "[^A-Za-z0-9]","").ToLower()
Get-Process -ErrorAction SilentlyContinue | Where-Object {
  ($_.Name -replace "[^A-Za-z0-9]","").ToLower() -like "*$_appKillName*"
} | Stop-Process -Force -ErrorAction SilentlyContinue
'@
  }

  # --- Launch block: use manual override if supplied, else auto-detect at runtime ---
  # Auto-detect scans the install directory for the largest non-helper exe.
  if ($LaunchExe) {
  # User supplied explicit path — bake it in directly
  $launchBlock = @"
`$loggedOnUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
if (`$loggedOnUser -and (Test-Path "$LaunchExe")) {
  try {
  `$action  = New-ScheduledTaskAction -Execute "$LaunchExe"
  `$principal = New-ScheduledTaskPrincipal -UserId `$loggedOnUser -LogonType Interactive -RunLevel Limited
  `$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName "AppUpdaterLaunch_$AppID" -Action `$action -Principal `$principal -Settings `$settings -Force | Out-Null
  Start-ScheduledTask -TaskName "AppUpdaterLaunch_$AppID"
  Start-Sleep -Seconds 3
  } catch {}
  finally { Unregister-ScheduledTask -TaskName "AppUpdaterLaunch_$AppID" -Confirm:`$false -ErrorAction SilentlyContinue }
}
"@
  } else {
  # No override — emit dynamic detection code into the generated script.
  # At install time: find the largest non-helper exe in the install folder,
  # then launch it as the logged-on user via a transient scheduled task.
  $launchBlock = @'
# Auto-launch: find and run the main exe for the newly installed app
$_excludePat  = "unins|uninstall|setup|update|helper|crash|report|squirrel|redist"
$_appFindName = ($DisplayName -replace "[^A-Za-z0-9]","").ToLower()
$_installDir  = $null
foreach ($_base in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
  $_reg = Get-ItemProperty $_base -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.InstallLocation -and
  ($_.DisplayName -replace "[^A-Za-z0-9]","").ToLower() -like "*$_appFindName*" } |
  Select-Object -First 1
  if ($_reg) { $_installDir = $_reg.InstallLocation.Trim(); break }
}
if ($_installDir -and (Test-Path $_installDir)) {
  $_mainExe = Get-ChildItem $_installDir -Filter "*.exe" -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notmatch $_excludePat } |
  Sort-Object Length -Descending | Select-Object -First 1
  if ($_mainExe) {
  $_loggedOn = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
  if ($_loggedOn) {
  try {
  $_action  = New-ScheduledTaskAction -Execute $_mainExe.FullName
  $_principal = New-ScheduledTaskPrincipal -UserId $_loggedOn -LogonType Interactive -RunLevel Limited
  $_settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName "AppUpdaterAutoLaunch" -Action $_action -Principal $_principal -Settings $_settings -Force | Out-Null
  Start-ScheduledTask -TaskName "AppUpdaterAutoLaunch"
  Start-Sleep -Seconds 3
  } catch {}
  finally { Unregister-ScheduledTask -TaskName "AppUpdaterAutoLaunch" -Confirm:$false -ErrorAction SilentlyContinue }
  }
  }
}
'@
  }

  # =========================================================================
  # UPDATE SCRIPT  (Update-{AppID}.ps1) — generated for online or offline mode
  # Written by Deploy script to C:\ProgramData\AppUpdater\{AppID}\
  # =========================================================================
  # Common preamble for both modes
  $commonHeader = @"
# Update-$AppID.ps1  — Generated by AppUpdater Builder ($( if ($isOfflinePkg) {'OFFLINE MODE'} else {'ONLINE MODE'} ))
`$AppID  = '$AppID'
`$DisplayName  = '$DisplayName'
`$RegistryName  = '$RegistryName'
`$SilentArgs  = '$SilentArgs'
`$AppDir  = '$AppDir'
`$LogDir  = '$LogDir'
`$DetailLog  = "`$LogDir\update-detail.log"
`$StatusLog  = "`$LogDir\update-status.log"
`$StagingDir    = "`$AppDir\staging"
`$TempInstaller = "`$StagingDir\${AppID}-installer.exe"

# Force TLS 1.2 minimum for all web requests in this process
try {
  [System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13
} catch {
  [System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12
}

# SHA-256 of the expected installer — baked in from form for offline pkgs;
# overwritten at runtime from manifest for online pkgs (see online section below).
# Empty string = skip manifest hash check (TOCTOU re-check still runs).
`$manifestHash = '$InstallerSHA256'
# Authenticode publisher CN — if non-empty, signer must match this string.
# Empty = publisher check skipped; any valid signature is accepted.
`$ExpectedPublisher = '$ExpectedPublisher'

# --- Event telemetry (signed POST to Worker /event) -------------------------
`$EventEnabled = `$$($EventReportingEnabled.ToString().ToLower())
`$EventURL     = '$($WorkerURL)'
`$EventSecret  = '$EventSecretB64'
`$RunStart     = [DateTime]::UtcNow

# Stable per-device identifier (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid)
`$MachineGuid = ''
try {
  `$MachineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -EA SilentlyContinue).MachineGuid
} catch {}

function Send-Event {
  param([string]`$Status, [string]`$Version='', [string]`$ErrorMsg='')
  if (-not `$EventEnabled) { return }
  try {
    `$payload = @{
      appId       = `$AppID
      hostname    = `$env:COMPUTERNAME
      machineGuid = `$MachineGuid
      status      = `$Status
      version     = `$Version
      durationMs  = [int]([DateTime]::UtcNow - `$RunStart).TotalMilliseconds
      error       = `$ErrorMsg
    } | ConvertTo-Json -Compress
    `$ts    = [int][double]::Parse((Get-Date -UFormat %s))
    `$id    = if (`$MachineGuid) { `$MachineGuid } else { `$env:COMPUTERNAME }
    `$canon = "`$ts|`$AppID|`$id|`$payload"

    `$key = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String(`$EventSecret))
    try {
      `$sigBytes = `$key.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(`$canon))
    } finally { `$key.Dispose() }
    `$sig = -join (`$sigBytes | ForEach-Object { `$_.ToString('x2') })

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-RestMethod -Uri "`$EventURL/event" -Method POST `
      -Headers @{
        'Content-Type'      = 'application/json'
        'X-Event-Timestamp' = "`$ts"
        'X-Event-Sig'       = `$sig
      } -Body `$payload -TimeoutSec 10 -ErrorAction Stop | Out-Null
  } catch {
    # Telemetry must never fail the update — swallow and continue.
  }
}

if (-not (Test-Path `$LogDir)) { New-Item `$LogDir -ItemType Directory -Force | Out-Null }
# -Force overwrites without recreating — preserves the admin-only ACL on detail.log
`$transcriptStarted = `$false
try {
  Start-Transcript -Path `$DetailLog -Force | Out-Null
  `$transcriptStarted = `$true
} catch {
  Write-Status "WARNING: Start-Transcript failed (`$(`$_.Exception.GetType().Name)) - running without transcript"
}
Send-Event 'running'

# Write-Status writes to both the admin transcript and the sanitised status log
# that Show-Log reads. Only call it for lines Show-Log needs to display.
function Write-Status {
  param([string]`$line)
  Write-Host `$line
  `$line | Out-File `$StatusLog -Append -Encoding UTF8
}

# Clear status log at start so Show-Log does not pick up stale lines
"" | Out-File `$StatusLog -Force -Encoding UTF8

Write-Status "=== RUN START ==="
Write-Host "=== AppUpdater - `$DisplayName ==="

function Convert-GuidToPacked {
  param([string]`$Guid)
  `$g = (`$Guid -replace '[{}\-]','').ToUpper()
  if (`$g.Length -ne 32) { return `$null }
  return (-join `$g[7..0])+(-join `$g[11..8])+(-join `$g[15..12])+(`$g[17]+`$g[16]+`$g[19]+`$g[18])+(`$g[21]+`$g[20]+`$g[23]+`$g[22]+`$g[25]+`$g[24]+`$g[27]+`$g[26]+`$g[29]+`$g[28]+`$g[31]+`$g[30])
}
function Get-InstalledVersion {
  param([string]`$Name)

  # Build the list of uninstall-key roots to scan:
  #   * HKLM 64-bit + WOW6432Node (machine-wide installs)
  #   * Every loaded HKU\<SID> hive that looks like a real user (S-1-5-21-…)
  #     — this catches per-user installs (e.g. modern Chrome) when run as
  #     SYSTEM, because the signed-in user's HKCU is mounted under HKU.
  `$bases = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    try { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null } catch {}
  }
  if (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue) {
    Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue |
      Where-Object { `$_.PSChildName -match '^S-1-5-21-' -and `$_.PSChildName -notmatch '_Classes`$' } |
      ForEach-Object {
        `$bases += "HKU:\`$(`$_.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        `$bases += "HKU:\`$(`$_.PSChildName)\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
      }
  }

  foreach (`$base in `$bases) {
    `$m = Get-ItemProperty `$base -ErrorAction SilentlyContinue |
         Where-Object { `$_.DisplayName -eq `$Name } | Select-Object -First 1
    if (-not `$m) { continue }
    if (-not `$m.UninstallString) { continue }
    if (`$m.InstallLocation -and `$m.InstallLocation.Trim() -ne '' -and -not (Test-Path `$m.InstallLocation)) { continue }
    if (`$m.UninstallString -imatch 'msiexec' -and `$m.UninstallString -match '\{([A-Fa-f0-9-]{36})\}') {
      `$packed = Convert-GuidToPacked `$matches[1]
      if (`$packed -and -not (Test-Path "HKLM:\SOFTWARE\Classes\Installer\Products\`$packed")) { continue }
    }
    `$ver = if (`$m.DisplayVersion) { `$m.DisplayVersion } elseif (`$m.ProductVersion) { `$m.ProductVersion } else { `$null }
    if (`$ver) {
      Write-Host "  Detected `$Name `$ver via `$base"
      return `$ver
    }
  }
  return `$null
}
"@

  # Common install/kill/launch block shared by both modes
  $installBlock = @"
$killLines
Start-Sleep -Seconds 2
Write-Host "Installing `$DisplayName..."
`$elapsed = 0; `$timeoutSec = 7200; `$installError = `$false
try {
  # Re-verify SHA-256 hash before execution — catches file tampering between download and install (TOCTOU).
if (`$script:_dlHash) {
  `$currentHash = (Get-FileHash -Path `$TempInstaller -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
  if (`$currentHash -ne `$script:_dlHash) {
  Write-Host "  ERROR: Installer was modified after download -- refusing to execute"
  Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue
  Write-Host "=== COMPLETE WITH ERRORS: Hash mismatch ==="
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
  }
  Write-Host "  Hash verified OK"
}
  # Verify Authenticode signature before executing as SYSTEM
`$sig = Get-AuthenticodeSignature -FilePath `$TempInstaller -ErrorAction SilentlyContinue
if (`$sig -and `$sig.Status -eq 'Valid') {
  if (`$ExpectedPublisher -and `$sig.SignerCertificate.Subject -notmatch [regex]::Escape(`$ExpectedPublisher)) {
    Write-Host "  ERROR: Installer signed by '`$(`$sig.SignerCertificate.Subject)' but expected '`$ExpectedPublisher' — refusing to execute"
    Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue
    Write-Host "=== COMPLETE WITH ERRORS: Publisher mismatch ==="
    if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
  }
  Write-Host "  Signature valid: `$(`$sig.SignerCertificate.Subject)"
} elseif (`$sig -and `$sig.Status -eq 'NotSigned') {
  Write-Host "  WARNING: Installer is not digitally signed — proceeding with caution"
} elseif (`$sig -and `$sig.Status -ne 'Valid') {
  Write-Host "  ERROR: Signature check failed (Status=`$(`$sig.Status)) — refusing to execute"
  Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue
  Write-Host "=== COMPLETE WITH ERRORS: Signature check failed ==="
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
}
`$proc = Start-Process -FilePath `$TempInstaller -ArgumentList '$SilentArgs' -PassThru -ErrorAction Stop
  while (-not `$proc.HasExited -and `$elapsed -lt `$timeoutSec) {
  Start-Sleep -Seconds 2; `$elapsed += 2
  Write-Host "INSTALLING:`${AppID}:`${elapsed}"
  }
  if (-not `$proc.HasExited) {
  `$proc | Stop-Process -Force -ErrorAction SilentlyContinue
  Write-Host "INSTALLING:`${AppID}:DONE:TIMEOUT"
  `$installError = `$true
  } else {
  `$ec = `$proc.ExitCode
  Write-Host "INSTALLING:`${AppID}:DONE:`$ec"
  if (`$ec -ne 0 -and `$ec -ne 3010) { `$installError = `$true }
  }
} catch { Write-Host "  ERROR: `$(`$_.Exception.Message)"; `$installError = `$true }
finally { Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue }
if (`$installError) {
  Write-Host "=== COMPLETE WITH ERRORS: `$DisplayName install failed ==="
  Send-Event 'error' (Get-InstalledVersion `$RegistryName) "Install failed (exit code `$ec)"
} else {
  Write-Host "`$DisplayName install complete"; Write-Host "=== COMPLETE ==="
  Send-Event 'installed' (Get-InstalledVersion `$RegistryName)
}
if (`$transcriptStarted) { Stop-Transcript | Out-Null }
$launchBlock
return
"@

  if ($isOfflinePkg) {
  # ── OFFLINE update script — no Worker, downloads directly from hardcoded URL ─
  $updateScriptContent = $commonHeader + @"

# OFFLINE MODE — downloads directly, no Worker manifest needed
`$downloadURL = '$DownloadURL'
`$fallbackURL = '$FallbackURL'

`$installed = Get-InstalledVersion `$RegistryName
Write-Host "  Installed : `$(if(`$installed){`$installed}else{'Not installed'})"

if (-not `$downloadURL) {
  Write-Host "  ERROR: No download URL configured"
  Write-Host "=== COMPLETE WITH ERRORS: No download URL ==="
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
}

# Download — re-assert staging dir ACL before writing to it
New-Item `$StagingDir -ItemType Directory -Force | Out-Null
icacls `$StagingDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) {
  Write-Status "WARNING: Could not lock staging directory — aborting download for safety"
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
}
Write-Host "`$DisplayName : `$(if(`$installed){'OUTDATED (checking)'}else{'NOT INSTALLED'}) - downloading..."
`$downloaded = `$false
foreach (`$url in @(`$downloadURL,`$fallbackURL) | Where-Object { `$_ -and `$_.Trim() }) {
  Write-Host "  Trying: `${url}:"
  `$fileStream = `$null; `$respStream = `$null; `$resp = `$null
  try {
  `$req = [System.Net.HttpWebRequest]::Create(`$url)
  `$req.Timeout = 180000; `$req.AllowAutoRedirect = `$true; `$req.MaximumAutomaticRedirections = 10
  `$req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
  `$resp = `$req.GetResponse(); `$totalLen = `$resp.ContentLength
  `$respStream = `$resp.GetResponseStream()
  `$fileStream = [System.IO.File]::Create(`$TempInstaller)
  `$buf = New-Object byte[] 65536; `$bytesRead = 0; `$lastPct = -1
  while ((`$chunk = `$respStream.Read(`$buf,0,`$buf.Length)) -gt 0) {
  `$fileStream.Write(`$buf,0,`$chunk); `$bytesRead += `$chunk
  if (`$totalLen -gt 0) {
  `$pct = [int]((`$bytesRead/`$totalLen)*100)
  if (`$pct -ne `$lastPct -and `$pct % 5 -eq 0) { Write-Host "PROGRESS:`${AppID}:`${pct}:`${bytesRead}:`${totalLen}"; `$lastPct = `$pct }
  }
  }
  Write-Host "PROGRESS:`${AppID}:100:`${totalLen}:`${totalLen}"; `$downloaded = `$true; break
  } catch { Write-Host "  Failed from `${url}: `$(`$_.Exception.GetType().Name)" }
  finally {
  if (`$fileStream) { `$fileStream.Close(); `$fileStream = `$null }
  if (`$respStream) { `$respStream.Close(); `$respStream = `$null }
  if (`$resp)  { `$resp.Close();  `$resp  = `$null }
  }
}
if (-not `$downloaded) { Write-Host "=== COMPLETE WITH ERRORS: Download failed ==="; if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return }
`$script:_dlHash = (Get-FileHash -Path `$TempInstaller -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
Write-Host "  Hash recorded (SHA-256: `$script:_dlHash)"

# Manifest SHA-256 check (offline mode — hash baked in from form, if provided)
if (-not [string]::IsNullOrWhiteSpace(`$manifestHash)) {
  if (`$script:_dlHash -ne `$manifestHash.ToUpper()) {
    Write-Host "  ERROR: Hash mismatch (got `$script:_dlHash, expected `$manifestHash)"
    Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue
    Write-Host "=== COMPLETE WITH ERRORS: Hash mismatch ==="
    if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
  }
  Write-Host "  Manifest SHA-256 verified OK"
} else {
  Write-Host "  WARNING: No SHA-256 configured — skipping manifest hash check (Authenticode + pre-run re-check still apply)"
}

# Check file version vs installed — skip install if already up to date
`$fv = (Get-Item `$TempInstaller -ErrorAction SilentlyContinue).VersionInfo.FileVersion
if (`$fv -and `$installed) {
  try {
  if ([version](`$fv -replace ',','.') -le [version]`$installed) {
  Write-Host "`$DisplayName : UP TO DATE (installed=`$installed, file=`$fv)"
  Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue
  Write-Host "Nothing to install - all products are up to date."
  Send-Event 'current' `$installed
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }
  $launchBlock
  return
  }
  } catch { Write-Host "  Version compare failed — proceeding with install" }
}
Write-Host "`$DisplayName : UPDATING (installed=`$(if(`$installed){`$installed}else{'none'}), file=`$(if(`$fv){`$fv}else{'unknown'}))"
"@ + $installBlock
  } else {
  # ── ONLINE update script — fetches manifest from Worker ──────────────────
  $updateScriptContent = $commonHeader + @"

# ONLINE MODE — fetches version and URL from Worker manifest
`$WorkerURL = '$WorkerURL'

if ([string]::IsNullOrWhiteSpace(`$WorkerURL)) {
  Write-Host "  ERROR: WorkerURL is not set. Re-build with Cloudflare configured."
  Write-Host "=== COMPLETE WITH ERRORS: No WorkerURL ==="
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
}
`$workerOK = `$false
try {
  if ((Invoke-RestMethod -Uri "`$WorkerURL/health" -TimeoutSec 15 -ErrorAction Stop).status -eq "ok") { `$workerOK = `$true }
} catch { Write-Host "  WARNING: Worker not reachable - `$(`$_.Exception.Message)" }
if (-not `$workerOK) { Write-Host "=== COMPLETE WITH ERRORS: Worker unreachable ==="; if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return }

`$appEntry = `$null
try {
  `$manifest = (Invoke-RestMethod -Uri "`$WorkerURL/appVersions.xml" -TimeoutSec 30 -ErrorAction Stop)
  `$appEntry = `$manifest.AppManifest.App | Where-Object { `$_.ID -eq `$AppID } | Select-Object -First 1
} catch { Write-Host "  ERROR: `$(`$_.Exception.Message)"; Write-Host "=== COMPLETE WITH ERRORS: Manifest fetch failed ==="; if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return }

# Removal flag check
try {
  `$removed = `$manifest.AppManifest.RemovedApps.App | Where-Object { `$_.id -eq `$AppID } | Select-Object -First 1
  if (`$removed) {
  Write-Host "  App flagged for removal — uninstalling..."
  foreach (`$hive in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
    `$reg = Get-ItemProperty `$hive -ErrorAction SilentlyContinue | Where-Object { `$_.DisplayName -eq `$RegistryName } | Select-Object -First 1
    if (`$reg -and `$reg.UninstallString) {
      `$us = `$reg.UninstallString.Trim('"').Trim()
      try {
        if (`$us -imatch 'msiexec' -and `$us -match '\{[A-Fa-f0-9-]{36}\}') {
          Start-Process msiexec -ArgumentList "/x `$(`$matches[0]) /qn /norestart" -Wait -ErrorAction SilentlyContinue
        } else {
          # Validate path before running as SYSTEM — must be absolute, exist, and in a known safe location.
          `$_allowedPfx = @('C:\Program Files\','C:\Program Files (x86)\','C:\Windows\','C:\ProgramData\')
          `$_usValid = [System.IO.Path]::IsPathRooted(`$us) -and (Test-Path `$us -PathType Leaf) -and
            (`$_allowedPfx | Where-Object { `$us.StartsWith(`$_,[System.StringComparison]::OrdinalIgnoreCase) })
          if (-not `$_usValid) {
            Write-Host "  SECURITY: UninstallString '`$us' failed path validation — skipping execution"
          } else {
            Start-Process -FilePath `$us -ArgumentList '/S' -Wait -ErrorAction SilentlyContinue
          }
        }
        Write-Host "  Uninstall complete"
      } catch { Write-Host "  Uninstall attempt failed: `$(`$_.Exception.Message)" }
      break
    }
  }
  Unregister-ScheduledTask -TaskName "AppUpdater_`$AppID" -Confirm:`$false -ErrorAction SilentlyContinue
  `$sc = "C:\Users\Public\Desktop\Update `$DisplayName.lnk"
  if (Test-Path `$sc) { Remove-Item `$sc -Force -ErrorAction SilentlyContinue }
  if (Test-Path `$AppDir) { Remove-Item `$AppDir -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Host "=== COMPLETE: SELF-REMOVED ==="; try { Stop-Transcript | Out-Null } catch {}; return
  }
} catch {}

if (-not `$appEntry) { Write-Host "  ERROR: App not in manifest"; Write-Host "=== COMPLETE WITH ERRORS: App not in manifest ==="; if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return }
`$downloadURL = `$appEntry.DownloadURL; `$fallbackURL = `$appEntry.FallbackURL
# Validate URLs from manifest before use — HTTPS-only, no path traversal
foreach (`$urlToCheck in @(`$downloadURL, `$fallbackURL) | Where-Object { `$_ -and `$_.Trim() }) {
  try {
    `$parsedUrl = [System.Uri]::new(`$urlToCheck)
    if (`$parsedUrl.Scheme -ne 'https') {
      Write-Host "  ERROR: Manifest URL '`$urlToCheck' is not HTTPS — refusing to use"
      Write-Host "=== COMPLETE WITH ERRORS: Insecure manifest URL ==="
      if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
    }
    if (`$parsedUrl.AbsolutePath -match '\.\.') {
      Write-Host "  ERROR: Manifest URL contains path traversal — refusing: `$urlToCheck"
      Write-Host "=== COMPLETE WITH ERRORS: Invalid manifest URL ==="
      if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
    }
  } catch {
    Write-Host "  ERROR: Could not parse manifest URL '`$urlToCheck' — skipping"
  }
}
# Read optional SHA-256 from manifest (overrides the offline-baked value if present)
if (-not [string]::IsNullOrWhiteSpace(`$appEntry.SHA256)) {
  if (`$appEntry.SHA256 -match '^[0-9a-fA-F]{64}$') {
    `$manifestHash = `$appEntry.SHA256.ToUpper()
    Write-Host "  Manifest SHA-256 found — will verify after download"
  } else {
    Write-Host "  ERROR: Manifest SHA-256 has unexpected format — skipping hash check"
    `$manifestHash = `$null
  }
}
# Validate version format from manifest before use in comparisons
if (`$xmlVersion -and `$xmlVersion -notmatch '^\d+\.\d+(\.\d+){0,2}$') {
  Write-Host "  ERROR: Manifest version '`$xmlVersion' has unexpected format -- skipping"
  Write-Host "=== COMPLETE WITH ERRORS: Invalid manifest version ==="
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
}; `$xmlVersion = `$appEntry.Version

if (-not `$downloadURL) { Write-Host "=== COMPLETE WITH ERRORS: No download URL ==="; if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return }

`$installed = Get-InstalledVersion `$RegistryName
Write-Host "  Installed : `$(if(`$installed){`$installed}else{'Not installed'})"
Write-Host "  Manifest  : `$(if(`$xmlVersion){`$xmlVersion}else{'Auto-detect'})"

if (`$xmlVersion -and `$installed) {
  try {
  if ([version]`$installed -ge [version]`$xmlVersion) {
  Write-Host "`$DisplayName : UP TO DATE"
  Write-Host "Nothing to install - all products are up to date."
  Send-Event 'current' `$installed
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }
  $launchBlock
  return
  }
  } catch { Write-Host "  Version compare failed — downloading to verify" }
}

# Re-assert staging dir ACL before download
New-Item `$StagingDir -ItemType Directory -Force | Out-Null
icacls `$StagingDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) {
  Write-Status "WARNING: Could not lock staging directory — aborting download for safety"
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
}
Write-Host "`$DisplayName : `$(if(`$installed){'OUTDATED'}else{'NOT INSTALLED'}) - downloading..."
Write-Host "  URL: `$downloadURL"
`$downloaded = `$false
foreach (`$url in @(`$downloadURL,`$fallbackURL) | Where-Object { `$_ -and `$_.Trim() }) {
  Write-Host "  Trying: `${url}:"
  `$fileStream = `$null; `$respStream = `$null; `$resp = `$null
  try {
  `$req = [System.Net.HttpWebRequest]::Create(`$url)
  `$req.Timeout = 180000; `$req.AllowAutoRedirect = `$true; `$req.MaximumAutomaticRedirections = 10
  `$req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
  `$resp = `$req.GetResponse(); `$totalLen = `$resp.ContentLength
  `$respStream = `$resp.GetResponseStream()
  `$fileStream = [System.IO.File]::Create(`$TempInstaller)
  `$buf = New-Object byte[] 65536; `$bytesRead = 0; `$lastPct = -1
  while ((`$chunk = `$respStream.Read(`$buf,0,`$buf.Length)) -gt 0) {
  `$fileStream.Write(`$buf,0,`$chunk); `$bytesRead += `$chunk
  if (`$totalLen -gt 0) {
  `$pct = [int]((`$bytesRead/`$totalLen)*100)
  if (`$pct -ne `$lastPct -and `$pct % 5 -eq 0) { Write-Host "PROGRESS:`${AppID}:`${pct}:`${bytesRead}:`${totalLen}"; `$lastPct = `$pct }
  }
  }
  Write-Host "PROGRESS:`${AppID}:100:`${totalLen}:`${totalLen}"; `$downloaded = `$true; break
  } catch { Write-Host "  Failed from `${url}: `$(`$_.Exception.GetType().Name)" }
  finally {
  if (`$fileStream) { `$fileStream.Close(); `$fileStream = `$null }
  if (`$respStream) { `$respStream.Close(); `$respStream = `$null }
  if (`$resp)  { `$resp.Close();  `$resp  = `$null }
  }
}
if (-not `$downloaded) { Write-Host "=== COMPLETE WITH ERRORS: Download failed ==="; if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return }
`$script:_dlHash = (Get-FileHash -Path `$TempInstaller -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
Write-Host "  Hash recorded (SHA-256: `$script:_dlHash)"

# Manifest SHA-256 check (online mode — hash from appEntry.SHA256, if present)
if (-not [string]::IsNullOrWhiteSpace(`$manifestHash)) {
  if (`$script:_dlHash -ne `$manifestHash.ToUpper()) {
    Write-Host "  ERROR: Hash mismatch (got `$script:_dlHash, expected `$manifestHash)"
    Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue
    Write-Host "=== COMPLETE WITH ERRORS: Hash mismatch ==="
    if (`$transcriptStarted) { Stop-Transcript | Out-Null }; return
  }
  Write-Host "  Manifest SHA-256 verified OK"
} else {
  Write-Host "  WARNING: No SHA-256 in manifest — skipping manifest hash check (Authenticode + pre-run re-check still apply)"
}
if (-not `$xmlVersion) {
  `$fv = (Get-Item `$TempInstaller -ErrorAction SilentlyContinue).VersionInfo.FileVersion
  if (`$fv -and `$installed) {
  try {
  if ([version](`$fv -replace ',','.') -le [version]`$installed) {
  Write-Host "`$DisplayName : UP TO DATE (file version check)"
  Remove-Item `$TempInstaller -Force -ErrorAction SilentlyContinue
  Write-Host "Nothing to install - all products are up to date."
  if (`$transcriptStarted) { Stop-Transcript | Out-Null }
  $launchBlock
  return
  }
  } catch {}
  }
}
"@ + $installBlock
  }

  # =========================================================================
  # IN-TASK WRAPPER  ({AppID}-in-task.ps1)
  # Mirrors ndupdate-in-task.ps1 exactly
  # =========================================================================
  $inTaskContent = @"
# $AppID-in-task.ps1 — Scheduled task wrapper for $DisplayName
`$logFile  = "$LogDir\update-task-run.log"
`$detailLog = "$LogDir\update-detail.log"
`$statusLog = "$LogDir\update-status.log"
if (-not (Test-Path "$LogDir")) { New-Item "$LogDir" -ItemType Directory -Force | Out-Null }
# Trim task log only when > 500KB — trimming every run erases historical failure evidence
if (Test-Path `$logFile) {
  try { if ((Get-Item `$logFile).Length -gt 512000) { Get-Content `$logFile -Tail 500 -ErrorAction SilentlyContinue | Set-Content `$logFile -Force } } catch {}
}
# Re-assert ACLs each run in case they were reset
icacls `$detailLog  /inheritance:r /grant "NT AUTHORITY\SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) { "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WARNING] icacls re-assert failed on detail log (exit `$LASTEXITCODE)" | Out-File `$logFile -Append }
icacls `$statusLog  /inheritance:r /grant "NT AUTHORITY\SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)" /grant "BUILTIN\Users:(R)" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) { "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WARNING] icacls re-assert failed on status log (exit `$LASTEXITCODE)" | Out-File `$logFile -Append }
icacls `$logFile  /inheritance:r /grant "NT AUTHORITY\SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)" /grant "BUILTIN\Users:(R)" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) { "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WARNING] icacls re-assert failed on task-run log (exit `$LASTEXITCODE)" | Out-File `$logFile -Append }
# Overwrite sentinels so Show-Log knows a fresh run started
"=== TASK STARTING ===" | Out-File `$detailLog -Force -Encoding UTF8
"=== TASK STARTING ===" | Out-File `$statusLog -Force -Encoding UTF8
"`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [START] Task triggered" | Out-File `$logFile -Append
try {
  & "$AppDir\Update-$AppID.ps1"
  `$detail = if (Test-Path `$detailLog) { Get-Content `$detailLog -Raw -ErrorAction SilentlyContinue } else { "" }
  if (`$detail -match '=== COMPLETE WITH ERRORS') {
  "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ERROR] Update completed with errors (check detail log)" | Out-File `$logFile -Append
  } else {
  "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [SUCCESS] Update finished" | Out-File `$logFile -Append
  }
} catch {
  # Log type only — full message may expose internal network details
  "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ERROR] Script failed (`$(`$_.Exception.GetType().Name))" | Out-File `$logFile -Append
}
"@

  # =========================================================================
  # LIVE LOG VIEWER  (Show-{AppID}Log.ps1)
  # Full port of Show-NDLog.ps1 — parameterised for this app
  # =========================================================================
  # Write WPF Show-Log script directly to TempDir (avoids nested here-string)
  Write-Step "1.5/5" "Generating WPF status window..."
  $showLogPath = "$TempDir\Show-${AppID}Log.ps1"
  $wpfLines = [System.Collections.Generic.List[string]]::new()
  $wpfLines.Add('# Show-' + $AppID + 'Log.ps1 — WPF live update window for ' + $DisplayName)
  $wpfLines.Add('# Generated by AppUpdater Builder.')
  $wpfLines.Add('Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase')
  $wpfLines.Add('Add-Type -Name WinAPI -Namespace Native -MemberDefinition ''[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);''')
  $wpfLines.Add('[Native.WinAPI]::ShowWindow([Native.WinAPI]::GetConsoleWindow(), 0) | Out-Null')
  $wpfLines.Add('$DetailLog = "' + $LogDir + '\update-detail.log"')
  $wpfLines.Add('$TaskLog  = "' + $LogDir + '\update-task-run.log"')
  $wpfLines.Add('$AppName  = "' + $DisplayName + '"')
  $wpfLines.Add('$OrgName  = "' + $OrgName + '"')
  $isOfflineStr = if ($isOfflinePkg) { '$true' } else { '$false' }
  $wpfLines.Add('$IsOffline = ' + $isOfflineStr)
  $wpfLines.Add('$AppID  = "' + $AppID + '"')

  # XAML as escaped single-line string to avoid here-string nesting
 $xamlStr = '<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="' + $DisplayName + ' — AppUpdater" Width="480" MinWidth="480" MinHeight="480" SizeToContent="Height" WindowStartupLocation="CenterScreen" ResizeMode="CanMinimize" BorderBrush="#2a2a44" BorderThickness="1" Background="#0f0f17" FontFamily="Segoe UI"><Window.Resources><Style x:Key="PT" TargetType="TextBlock"><Setter Property="FontSize" Value="13" /><Setter Property="Foreground" Value="#888" /><Setter Property="VerticalAlignment" Value="Center" /></Style></Window.Resources><Grid><Grid.RowDefinitions><RowDefinition Height="72" /><RowDefinition Height="*" /><RowDefinition Height="44" /></Grid.RowDefinitions><Border Grid.Row="0" Background="#0a0a12" BorderBrush="#1e1e2e" BorderThickness="0,0,0,1"><Grid Margin="20,0"><Grid.ColumnDefinitions><ColumnDefinition Width="44" /><ColumnDefinition Width="12" /><ColumnDefinition Width="*" /><ColumnDefinition Width="Auto" /></Grid.ColumnDefinitions><Border Grid.Column="0" MinWidth="40" Height="40" CornerRadius="8" VerticalAlignment="Center"><Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,1"><GradientStop Color="#00b4d8" Offset="0" /><GradientStop Color="#7c3aed" Offset="1" /></LinearGradientBrush></Border.Background><TextBlock Text="U" FontSize="18" FontWeight="Bold" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" /></Border><StackPanel Grid.Column="2" VerticalAlignment="Center"><TextBlock x:Name="AppTitle" FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f0" TextWrapping="Wrap" /><TextBlock Text="' + $OrgName + '" FontSize="11" Foreground="#444" TextWrapping="Wrap" /></StackPanel><Border Grid.Column="3" x:Name="StatusPill" CornerRadius="12" Padding="10,4" VerticalAlignment="Center" Background="#1a2d1a" BorderBrush="#2a4a2a" BorderThickness="1"><StackPanel Orientation="Horizontal"><Ellipse x:Name="PulseOrb" MinWidth="7" Height="7" Fill="#4ec94e" VerticalAlignment="Center" Margin="0,0,6,0" /><TextBlock x:Name="StatusText" Text="Connecting..." FontSize="11" Foreground="#4ec94e" VerticalAlignment="Center" TextWrapping="Wrap" /></StackPanel></Border></Grid></Border><ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Hidden" HorizontalScrollBarVisibility="Disabled"><StackPanel x:Name="PhasePanel" Margin="20,16,20,16"><Grid x:Name="Phase1" Margin="0,0,0,12"><Grid.ColumnDefinitions><ColumnDefinition Width="26" /><ColumnDefinition Width="10" /><ColumnDefinition Width="*" /></Grid.ColumnDefinitions><Border x:Name="Phase1Icon" MinWidth="24" Height="24" CornerRadius="12" Background="#1e1e2e" BorderBrush="#2a2a3a" BorderThickness="1"><TextBlock x:Name="Phase1Text" Text="1" FontSize="10" FontWeight="Bold" Foreground="#444" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" /></Border><TextBlock Grid.Column="2" x:Name="Phase1Label" Text="Connecting to update server..." Style="{StaticResource PT}" TextWrapping="Wrap" /></Grid><Grid x:Name="Phase2" Margin="0,0,0,12"><Grid.ColumnDefinitions><ColumnDefinition Width="26" /><ColumnDefinition Width="10" /><ColumnDefinition Width="*" /></Grid.ColumnDefinitions><Border x:Name="Phase2Icon" MinWidth="24" Height="24" CornerRadius="12" Background="#1e1e2e" BorderBrush="#2a2a3a" BorderThickness="1"><TextBlock x:Name="Phase2Text" Text="2" FontSize="10" FontWeight="Bold" Foreground="#444" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" /></Border><TextBlock Grid.Column="2" x:Name="Phase2Label" Text="Checking version..." Style="{StaticResource PT}" TextWrapping="Wrap" /></Grid><Grid x:Name="Phase3" Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="26" /><ColumnDefinition Width="10" /><ColumnDefinition Width="*" /></Grid.ColumnDefinitions><Border x:Name="Phase3Icon" MinWidth="24" Height="24" CornerRadius="12" Background="#1e1e2e" BorderBrush="#2a2a3a" BorderThickness="1"><TextBlock x:Name="Phase3Text" Text="3" FontSize="10" FontWeight="Bold" Foreground="#444" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" /></Border><StackPanel Grid.Column="2" VerticalAlignment="Center"><TextBlock x:Name="Phase3Label" Text="Download" Style="{StaticResource PT}" TextWrapping="Wrap" /><TextBlock x:Name="Phase3Sub" Text="" FontSize="11" Foreground="#5b9bd5" Visibility="Collapsed" TextWrapping="Wrap" /></StackPanel></Grid><Grid x:Name="ProgressRow" Margin="36,0,0,12" Visibility="Collapsed"><Grid.RowDefinitions><RowDefinition Height="8" /><RowDefinition Height="14" /></Grid.RowDefinitions><Border Background="#1e1e2e" CornerRadius="4" ClipToBounds="True"><Border x:Name="ProgressFill" HorizontalAlignment="Left" MinWidth="0" CornerRadius="4"><Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,0"><GradientStop Color="#00b4d8" Offset="0" /><GradientStop Color="#7c3aed" Offset="1" /></LinearGradientBrush></Border.Background></Border></Border><TextBlock x:Name="ProgressLabel" Grid.Row="1" FontSize="10" Foreground="#444" Margin="0,2,0,0" TextWrapping="Wrap" /></Grid><Grid x:Name="Phase4" Margin="0,0,0,12"><Grid.ColumnDefinitions><ColumnDefinition Width="26" /><ColumnDefinition Width="10" /><ColumnDefinition Width="*" /></Grid.ColumnDefinitions><Border x:Name="Phase4Icon" MinWidth="24" Height="24" CornerRadius="12" Background="#1e1e2e" BorderBrush="#2a2a3a" BorderThickness="1"><TextBlock x:Name="Phase4Text" Text="4" FontSize="10" FontWeight="Bold" Foreground="#444" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" /></Border><StackPanel Grid.Column="2" VerticalAlignment="Center"><TextBlock x:Name="Phase4Label" Text="Install" Style="{StaticResource PT}" TextWrapping="Wrap" /><TextBlock x:Name="Phase4Sub" Text="" FontSize="11" Foreground="#5b9bd5" Visibility="Collapsed" TextWrapping="Wrap" /></StackPanel></Grid><Border x:Name="ResultPanel" Visibility="Collapsed" CornerRadius="8" Padding="16,14" Margin="0,8,0,0"><StackPanel HorizontalAlignment="Center"><TextBlock x:Name="ResultIcon" FontSize="32" HorizontalAlignment="Center" Margin="0,0,0,8" TextWrapping="Wrap" /><TextBlock x:Name="ResultTitle" FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f0" HorizontalAlignment="Center" TextWrapping="Wrap" /><TextBlock x:Name="ResultSub" FontSize="12" Foreground="#555" HorizontalAlignment="Center" Margin="0,4,0,0" TextWrapping="Wrap" /></StackPanel></Border></StackPanel></ScrollViewer><Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0"><Grid Margin="16,0"><TextBlock x:Name="FooterHint" Text="Please wait..." FontSize="11" Foreground="#333" VerticalAlignment="Center" TextWrapping="Wrap" /><Button x:Name="BtnDone" Content="Close" Visibility="Collapsed" HorizontalAlignment="Right" MinWidth="90" Height="30" FontSize="12" Cursor="Hand" Background="#1a3a1a" Foreground="#4ec94e" BorderBrush="#2a5a2a" BorderThickness="1" /></Grid></Border></Grid></Window>'

  $wpfLines.Add('[xml]$xaml = @"')
  $wpfLines.Add($xamlStr)
  $wpfLines.Add('"@')

  # Add the PowerShell logic as individual lines
  $wpfLogic = @(
  '$reader = New-Object System.Xml.XmlNodeReader $xaml',
  '$window = [Windows.Markup.XamlReader]::Load($reader)',
  '$el = @{}',
  'foreach ($name in @("AppTitle","StatusPill","StatusText","PulseOrb","Phase1Icon","Phase1Text","Phase1Label","Phase2Icon","Phase2Text","Phase2Label","Phase3Icon","Phase3Text","Phase3Label","Phase3Sub","ProgressRow","ProgressFill","ProgressLabel","Phase4Icon","Phase4Text","Phase4Label","Phase4Sub","ResultPanel","ResultIcon","ResultTitle","ResultSub","FooterHint","BtnDone")) {',
  '  $el[$name] = $window.FindName($name)',
  '}',
  '$el["AppTitle"].Text = $AppName',
  'if ($IsOffline) { $el["Phase1Label"].Text = "Offline mode — direct download" }',
  'if ($IsOffline) { $el["Phase2Label"].Text = "Checking installed version..." }',
  'function Set-PhaseDone { param($icon,$iconText,$label,[string]$text)',
  '  $icon.Background = [Windows.Media.Brushes]::Transparent',
  '  $icon.BorderBrush = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x2a,0x5a,0x2a))',
  '  $iconText.Text = [char]0x2713; $iconText.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))',
  '  $label.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x55,0x55,0x6a))',
  '  if ($text) { $label.Text = $text } }',
  'function Set-PhaseActive { param($icon,$iconText,$label,[string]$text)',
  '  $icon.Background = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x1a,0x2a,0x3a))',
  '  $icon.BorderBrush = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x2a,0x4a,0x6a))',
  '  $iconText.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x5b,0x9b,0xd5))',
  '  $label.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xe8,0xe8,0xf0))',
  '  if ($text) { $label.Text = $text } }',
  'function Set-Pill { param([string]$text,[string]$mode)',
  '  $el["StatusText"].Text = $text',
  '  if ($mode -eq "green") {',
  '  $el["StatusPill"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x1a,0x3a,0x1a))',
  '  $el["StatusPill"].BorderBrush=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x2a,0x5a,0x2a))',
  '  $el["StatusText"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))',
  '  $el["PulseOrb"].Fill=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))',
  '  } elseif ($mode -eq "red") {',
  '  $el["StatusPill"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x3a,0x1a,0x1a))',
  '  $el["StatusPill"].BorderBrush=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x6a,0x2a,0x2a))',
  '  $el["StatusText"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x55,0x55))',
  '  $el["PulseOrb"].Fill=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x55,0x55))',
  '  } else {',
  '  $el["StatusPill"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x1a,0x2a,0x3a))',
  '  $el["StatusPill"].BorderBrush=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x2a,0x4a,0x6a))',
  '  $el["StatusText"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x5b,0x9b,0xd5))',
  '  $el["PulseOrb"].Fill=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x5b,0x9b,0xd5))',
  '  } }',
  '$state=@{phase=0;done=$false;hadErrors=$false;hadUpdates=$false;runStarted=$false;seen=@{};pw=0;elapsed=0;maxWait=600;started=$false;errHint=$null}',
  '$timer=New-Object System.Windows.Threading.DispatcherTimer',
  '$timer.Interval=[TimeSpan]::FromMilliseconds(800)',
  '$timer.Add_Tick({',
  '  $state.elapsed++',
  '  if (-not (Test-Path $DetailLog)) {',
  '  if ($state.elapsed -gt 90) { Set-Pill "Timed out" "red"; $el["FooterHint"].Text="Could not start — contact IT support"; $state.done=$true }',
  '  return }',
  '  if (-not $state.started) { $state.started=$true; Set-Pill "Connected" "green"; Set-PhaseDone $el["Phase1Icon"] $el["Phase1Text"] $el["Phase1Label"] "Connected to update server" }',
  '  $lines = Get-Content $DetailLog -ErrorAction SilentlyContinue',
  '  if (-not $lines) { return }',
  '  foreach ($line in $lines) {',
  '  if ($line -match "=== RUN START ===") { if (-not $state.runStarted) { $state.runStarted=$true; $state.seen=@{} }; continue }',
  '  if (-not $state.runStarted) { continue }',
  '  if ($line -match "UP TO DATE" -and -not $state.seen["utd"]) {',
  '  $state.seen["utd"]=$true',
  '  Set-PhaseDone $el["Phase2Icon"] $el["Phase2Text"] $el["Phase2Label"] "Already up to date"',
  '  Set-PhaseDone $el["Phase3Icon"] $el["Phase3Text"] $el["Phase3Label"] "No download needed"',
  '  Set-PhaseDone $el["Phase4Icon"] $el["Phase4Text"] $el["Phase4Label"] "No install needed"',
  '  Set-Pill "Up to date" "green"',
  '  $el["ResultPanel"].Visibility="Visible"',
  '  $el["ResultPanel"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x06,0x14,0x06))',
  '  $el["ResultIcon"].Text=[char]0x2713; $el["ResultIcon"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))',
  '  $el["ResultTitle"].Text="' + $DisplayName + ' is already up to date"',
  '  $el["ResultSub"].Text="No action needed"',
  '  $el["FooterHint"].Text="You can close this window"',
  '  $state.done=$true }',
  '  if (($line -match "NOT INSTALLED|OUTDATED") -and -not $state.seen["dl"]) {',
  '  $state.seen["dl"]=$true',
  '  Set-PhaseDone $el["Phase2Icon"] $el["Phase2Text"] $el["Phase2Label"] "Update available"',
  '  Set-PhaseActive $el["Phase3Icon"] $el["Phase3Text"] $el["Phase3Label"] "Downloading..."',
  '  Set-Pill "Downloading" "blue"',
  '  $el["ProgressRow"].Visibility="Visible"; $el["Phase3Sub"].Visibility="Visible" }',
  '  if ($line -match "install complete" -and -not $state.seen["id"]) {',
  '  $state.seen["id"]=$true; $state.hadUpdates=$true',
  '  Set-PhaseDone $el["Phase4Icon"] $el["Phase4Text"] $el["Phase4Label"] "Installed successfully" }',
  '  if ($line -match "COMPLETE WITH ERRORS: Download failed") { $state.done=$true; $state.hadErrors=$true; $state.errHint="Download failed — check the installer URL is reachable." }',
  '  elseif ($line -match "COMPLETE WITH ERRORS: No download URL") { $state.done=$true; $state.hadErrors=$true; $state.errHint="No download URL is configured for this app." }',
  '  elseif ($line -match "COMPLETE WITH ERRORS: App not in manifest") { $state.done=$true; $state.hadErrors=$true; $state.errHint="App not found in manifest — rebuild the package in AppUpdater." }',
  '  elseif ($line -match "=== COMPLETE WITH ERRORS") { $state.done=$true; $state.hadErrors=$true }',
  '  if ($line -match "=== COMPLETE ===") { $state.done=$true }',
  '  if ($line -match "Worker not reachable|Worker unreachable|No WorkerURL") { Set-Pill "Server unreachable" "red"; $state.done=$true; $state.hadErrors=$true; $state.errHint="Cannot reach update server." } }',
  '  $lp = $lines | Where-Object { $_ -match "^PROGRESS:" } | Select-Object -Last 1',
  '  if ($lp -and $lp -match "^PROGRESS:[^:]+:(\d+):(\d+):(\d+)") {',
  '  $pct=[int]$Matches[1]; $dlMB=[math]::Round([long]$Matches[2]/1MB,1); $totMB=[math]::Round([long]$Matches[3]/1MB,1)',
  '  if ($state.pw -eq 0) { $el["ProgressRow"].UpdateLayout(); $state.pw=$el["ProgressRow"].ActualWidth }',
  '  $el["ProgressFill"].Width=[math]::Max(0,[math]::Min($state.pw,$state.pw*$pct/100))',
  '  $el["ProgressLabel"].Text="$pct%  $dlMB / $totMB MB"',
  '  $el["Phase3Sub"].Text="$dlMB MB of $totMB MB"',
  '  if ($pct -ge 100) {',
  '  Set-PhaseDone $el["Phase3Icon"] $el["Phase3Text"] $el["Phase3Label"] "Downloaded $totMB MB"',
  '  $el["Phase3Sub"].Visibility="Collapsed"; $el["ProgressRow"].Visibility="Collapsed"',
  '  Set-PhaseActive $el["Phase4Icon"] $el["Phase4Text"] $el["Phase4Label"] "Installing..."',
  '  $el["Phase4Sub"].Text="Please wait..."; $el["Phase4Sub"].Visibility="Visible"',
  '  Set-Pill "Installing" "blue" } }',
  '  $li = $lines | Where-Object { $_ -match "^INSTALLING:" } | Select-Object -Last 1',
  '  if ($li -and $li -match "^INSTALLING:[^:]+:(\d+)$") {',
  '  $sec=[int]$Matches[1]; $ts="{0:D2}:{1:D2}" -f [int]($sec/60),($sec%60)',
  '  $el["Phase4Sub"].Text="Running... $ts"; $el["Phase4Sub"].Visibility="Visible" }',
  '  if ($state.done) {',
  '  $timer.Stop()',
  '  $el["ResultPanel"].Visibility="Visible"',
  '  if ($state.hadErrors) {',
  '  Set-Pill "Error" "red"',
  '  $el["ResultPanel"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x1a,0x08,0x08))',
  '  $el["ResultIcon"].Text=[char]0x2717; $el["ResultIcon"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x55,0x55))',
  '  $el["ResultTitle"].Text=if($state.errHint){$state.errHint}else{"Something went wrong"}',
  '  $el["ResultSub"].Text=if($state.errHint){"Please contact ' + $OrgName + ' support if this persists."}else{"Please contact ' + $OrgName + ' support"}',
  '  $el["FooterHint"].Visibility="Collapsed"; $el["BtnDone"].Visibility="Visible"; $el["BtnDone"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x3a,0x1a,0x1a)); $el["BtnDone"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x55,0x55)); $el["BtnDone"].BorderBrush=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x6a,0x2a,0x2a))',
  '  $el["FooterHint"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x55,0x55))',
  '  } elseif ($state.hadUpdates) {',
  '  Set-Pill "Done" "green"',
  '  $el["ResultPanel"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x06,0x14,0x06))',
  '  $el["ResultIcon"].Text=[char]0x2713; $el["ResultIcon"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))',
  '  $el["ResultTitle"].Text="' + $DisplayName + ' updated successfully"',
  '  $el["ResultSub"].Text="You can continue as normal"',
  '  $el["FooterHint"].Text="You can close this window"; $el["BtnDone"].Visibility="Visible"; $el["FooterHint"].Visibility="Collapsed" } else { $el["ResultPanel"].Background=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x0a,0x18,0x0a)); $el["ResultIcon"].Text=[char]0x2713; $el["ResultIcon"].Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e)); $el["ResultTitle"].Text="Already up to date"; $el["ResultSub"].Text="No update was needed"; Set-Pill "Up to date" "green"; $el["BtnDone"].Visibility="Visible"; $el["FooterHint"].Visibility="Collapsed" } } })',
  '$el["BtnDone"].Add_Click({ $window.Close() })',
  '$window.Add_MouseLeftButtonDown({ try { $window.DragMove() } catch {} })',
  '$window.Add_ContentRendered({ $timer.Start() })',
  '$window.Add_Closed({ $timer.Stop() })',
  '$window.ShowDialog() | Out-Null'
  )
  foreach ($line in $wpfLogic) { $wpfLines.Add($line) }

  # Build the Launch script content at build time.
  # The launch script contains:
  #   1. WPF assembly load
  #   2. Console hide via GetConsoleWindow() P/Invoke
  #   3. WPF dark-themed "save your work" dialog (NOT a native MessageBox)
  #   4. schtasks /run trigger + WPF error dialog on failure
  #   5. The WPF live-progress window (wpfLines content)
  $launchHeader = @"
# $AppID.ps1 (UI branch) — Generated by AppUpdater Builder
# Hides the console, asks the user to save their work via a WPF dialog,
# triggers the scheduled task, then shows the WPF live-progress window.

# 1. Load WPF assemblies first so the dialogs below can use them
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# 2. Hide the console window using GetConsoleWindow() — MainWindowHandle is 0
#    for console-subsystem processes; GetConsoleWindow() returns the real handle.
Add-Type -Name WinAPI -Namespace Native -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);'
[Native.WinAPI]::ShowWindow([Native.WinAPI]::GetConsoleWindow(), 0) | Out-Null

# 3. WPF "save your work" dialog — dark themed, matches the progress window
`$warnXaml = '<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" WindowStyle="None" ResizeMode="NoResize" SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen" Background="#0f0f17" BorderBrush="#2a2a44" BorderThickness="1" FontFamily="Segoe UI"><Grid Margin="28,22,28,18"><Grid.RowDefinitions><RowDefinition Height="Auto" /><RowDefinition Height="10" /><RowDefinition Height="Auto" /><RowDefinition Height="18" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><StackPanel Grid.Row="0" Orientation="Horizontal"><TextBlock Text="&#x26A0;" FontSize="24" Foreground="#f0b429" VerticalAlignment="Center" Margin="0,0,12,0" /><StackPanel VerticalAlignment="Center"><TextBlock Text="Please save your work" FontSize="14" FontWeight="SemiBold" Foreground="#e8e8f0" /><TextBlock Text="Some applications may close during the update." FontSize="12" Foreground="#666" Margin="0,3,0,0" /></StackPanel></StackPanel><TextBlock Grid.Row="2" FontSize="12" Foreground="#555" TextWrapping="Wrap" MaxWidth="340"><Run Text="$DisplayName" /><Run Text=" will update in the background. This window closes when complete." /></TextBlock><StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right"><Button x:Name="BtnCancel" Content="Cancel" MinWidth="84" Height="30" FontSize="12" Margin="0,0,8,0" Background="#151523" Foreground="#888" BorderBrush="#2a2a3a" BorderThickness="1" Cursor="Hand" /><Button x:Name="BtnContinue" Content="Continue" MinWidth="84" Height="30" FontSize="12" Background="#0d3321" Foreground="#4ec94e" BorderBrush="#1a5c35" BorderThickness="1" Cursor="Hand" /></StackPanel></Grid></Window>'
[xml]`$warnXml = `$warnXaml
`$warnWin = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader `$warnXml))
`$warnResult = `$false
`$warnWin.FindName('BtnContinue').Add_Click({ `$script:warnResult = `$true; `$warnWin.Close() })
`$warnWin.FindName('BtnCancel').Add_Click({ `$warnWin.Close() })
`$warnWin.Add_MouseLeftButtonDown({ try { `$warnWin.DragMove() } catch {} })
`$warnWin.ShowDialog() | Out-Null
if (-not `$warnResult) { exit 0 }

# 4. Trigger the scheduled task
`$r = & schtasks /run /tn "$TaskName" 2>&1
if (`$LASTEXITCODE -ne 0) {
    `$errXaml = '<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" WindowStyle="None" ResizeMode="NoResize" SizeToContent="WidthAndHeight" WindowStartupLocation="CenterScreen" Background="#0f0f17" BorderBrush="#2a2a44" BorderThickness="1" FontFamily="Segoe UI"><Grid Margin="24,20,24,16"><Grid.RowDefinitions><RowDefinition Height="Auto" /><RowDefinition Height="14" /><RowDefinition Height="Auto" /></Grid.RowDefinitions><StackPanel Grid.Row="0" Orientation="Horizontal"><TextBlock Text="&#x2717;" FontSize="22" Foreground="#ff5555" VerticalAlignment="Center" Margin="0,0,12,0" /><StackPanel><TextBlock Text="Could not start update" FontSize="14" FontWeight="SemiBold" Foreground="#e8e8f0" /><TextBlock Text="Please contact $OrgName support." FontSize="12" Foreground="#666" Margin="0,3,0,0" /></StackPanel></StackPanel><Button x:Name="ErrOK" Grid.Row="2" Content="OK" HorizontalAlignment="Right" MinWidth="84" Height="30" FontSize="12" Background="#151523" Foreground="#888" BorderBrush="#2a2a3a" BorderThickness="1" Cursor="Hand" /></Grid></Window>'
    [xml]`$errXml = `$errXaml
    `$errWin = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader `$errXml))
    `$errWin.FindName('ErrOK').Add_Click({ `$errWin.Close() })
    `$errWin.Add_MouseLeftButtonDown({ try { `$errWin.DragMove() } catch {} })
    `$errWin.ShowDialog() | Out-Null
    exit 1
}

# 5. Show the WPF live-progress window
"@

  # Combine launch header with wpfLines (the WPF progress window), stripping
  # the first 5 lines: 2 comments, Add-Type AssemblyName, Add-Type WinAPI,
  # and ShowWindow call — all replaced by the launch header above.
  $wpfBody = ($wpfLines | Select-Object -Skip 5) -join "`n"
  $launchScriptContent = $launchHeader + "`n" + $wpfBody

  # Write to temp path for reference (still used for the combined script assembly below)
  $launchScriptContent | Out-File $showLogPath -Encoding UTF8 -Force
  Write-OK "$AppID.ps1 launch content prepared"

  # =========================================================================
  # COMBINED SCRIPT  ($AppID.ps1)
  # Merges the in-task wrapper + update logic (--Task branch) and the launch/
  # WPF UI (default branch) into ONE file.  The in-task content is inlined so
  # no separate Update-*.ps1 or *-in-task.ps1 need to exist on disk.
  # =========================================================================
  # Build the -Task branch: in-task preamble with the update body inlined
  # (replacing the old `& "$AppDir\Update-$AppID.ps1"` call).
  $inTaskInlined = $inTaskContent.Replace("& `"$AppDir\Update-$AppID.ps1`"", $updateScriptContent)

  # Use string concatenation (not a double-quoted here-string) to prevent
  # PowerShell from re-expanding $ signs already present in the embedded content.
  $combinedScriptContent = (
    "param([switch]`$Task)`r`n`r`n" +
    "if (`$Task.IsPresent) {`r`n" +
    "# -- SYSTEM / task context ------------------------------------------------------`r`n" +
    $inTaskInlined + "`r`n" +
    "} else {`r`n" +
    "# -- User / UI context ----------------------------------------------------------`r`n" +
    $launchScriptContent + "`r`n" +
    "}`r`n"
  )

  # Base64-encode the combined script so the deploy script carries it as a
  # self-contained literal that works on any target machine.
  $combinedB64 = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes($combinedScriptContent)
  )

  # =========================================================================
  # DEPLOY SCRIPT  — embeds all above scripts as here-strings
  # This is the one file packaged in .intunewin
  # =========================================================================
  $deployScript = @"
# Deploy-$AppID.ps1  — Generated by AppUpdater Builder
# Runs as SYSTEM via Intune. Creates all folders, scripts, task, and shortcut.
# No UAC needed by end users — task DACL grants standard users execute rights.

`$AppDir    = '$AppDir'
`$LogDir    = '$LogDir'
`$TaskName  = '$TaskName'
`$AppScript = "`$AppDir\$AppID.ps1"

# SECTION 0 — Script Block Logging (records all PS code to Event ID 4104)
# Without this there is no forensic record of what ran as SYSTEM.
`$sbLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
try {
  if (-not (Test-Path `$sbLogPath)) { New-Item `$sbLogPath -Force | Out-Null }
  Set-ItemProperty -Path `$sbLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
  Write-Host "  OK Script Block Logging enabled"
} catch { Write-Host "  WARNING: Could not enable Script Block Logging (`$(`$_.Exception.GetType().Name))" }

# SECTION 1 — Folders + permissions
Write-Host "Creating folder structure..."
foreach (`$dir in @(`$AppDir,`$LogDir)) {
  if (-not (Test-Path `$dir)) { New-Item `$dir -ItemType Directory -Force | Out-Null; Write-Host "  OK Created `$dir" }
  else { Write-Host "  OK `$dir already exists" }
}
Write-Host "Setting folder ownership and permissions..."
# Step 1 — take ownership so icacls cannot be blocked by a stale owner
& "`$env:SystemRoot\System32\takeown.exe" /F `$AppDir /A 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) {
  Write-Host "  FATAL: takeown failed on `$AppDir (exit `$LASTEXITCODE)"
  Write-Host "  Deployment aborted. Run this script as Administrator and retry."
  exit 1
}
# Step 2 — strip inherited ACEs and grant explicit permissions
icacls `$AppDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /grant:r "BUILTIN\Users:(OI)(CI)RX" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) {
  Write-Host "  FATAL: Could not set permissions on `$AppDir (exit `$LASTEXITCODE)"
  Write-Host "  Deployment aborted. Run this script as Administrator and retry."
  exit 1
}
# Step 3 — reassign owner to SYSTEM (non-fatal; Admins owner is still secure if this fails)
icacls `$AppDir /setowner "NT AUTHORITY\SYSTEM" 2>&1 | Out-Null
# Repeat non-recursively for LogDir to prevent junction-traversal issues on re-deploy
& "`$env:SystemRoot\System32\takeown.exe" /F `$LogDir /A 2>&1 | Out-Null
icacls `$LogDir /setowner "NT AUTHORITY\SYSTEM" 2>&1 | Out-Null
Write-Host "  OK `${AppDir}: SYSTEM+Admins=Full, Users=ReadExecute, Owner=SYSTEM"

# SECTION 2 — Write $AppID.ps1 (single combined script)
Write-Host "Writing $AppID.ps1..."
`$combinedContent = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$combinedB64'))
`$combinedContent | Out-File `$AppScript -Encoding UTF8 -Force
Write-Host "  OK $AppID.ps1 written"

# Pre-create log files with explicit ACLs before the task ever runs.
# detail.log: admin-only (raw transcript may contain internal network details)
# status.log: user-readable (sanitised lines only — what Show-Log reads)
# task-run.log: user-readable (timestamps and result codes)
Write-Host "Pre-creating log files with correct permissions..."
`$detailLog  = "`$LogDir\update-detail.log"
`$statusLog  = "`$LogDir\update-status.log"
`$taskRunLog = "`$LogDir\update-task-run.log"
foreach (`$lf in @(`$detailLog,`$statusLog,`$taskRunLog)) {
  if (-not (Test-Path `$lf)) { "" | Out-File `$lf -Force -Encoding UTF8 }
}
`$logAclFailed = `$false
icacls `$detailLog  /inheritance:r /grant "NT AUTHORITY\SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) { Write-Host "  WARNING: detail log ACL failed (exit `$LASTEXITCODE)"; `$logAclFailed = `$true }
icacls `$statusLog  /inheritance:r /grant "NT AUTHORITY\SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)" /grant "BUILTIN\Users:(R)" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) { Write-Host "  WARNING: status log ACL failed (exit `$LASTEXITCODE)"; `$logAclFailed = `$true }
icacls `$taskRunLog /inheritance:r /grant "NT AUTHORITY\SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)" /grant "BUILTIN\Users:(R)" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) { Write-Host "  WARNING: task-run log ACL failed (exit `$LASTEXITCODE)"; `$logAclFailed = `$true }
if (`$logAclFailed) {
  Write-Host ""
  Write-Host "  FATAL: Could not set required permissions on log files."
  Write-Host "  Deployment aborted. Run this script as Administrator and retry."
  Write-Host "  Verify with: icacls ``"`$LogDir``""
  exit 1
}
Write-Host "  OK Log file ACLs set (detail=admin-only, status+taskrun=user-readable)"

# SECTION 2b — Installer staging directory (SYSTEM+Admins only, no user access)
# Downloads land here; directory is emptied after each install run
Write-Host "Creating installer staging directory..."
`$StagingDir = "`$AppDir\staging"
New-Item `$StagingDir -ItemType Directory -Force | Out-Null
icacls `$StagingDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" 2>&1 | Out-Null
if (`$LASTEXITCODE -ne 0) {
  Write-Host "  FATAL: Could not lock down installer staging directory (exit `$LASTEXITCODE)"
  Write-Host "  Deployment aborted."
  exit 1
}
Write-Host "  OK Staging directory: SYSTEM+Admins only (no user access)"

# SECTION 4 — Register scheduled task as SYSTEM
Write-Host "Registering scheduled task as SYSTEM..."
Unregister-ScheduledTask -TaskName `$TaskName -Confirm:`$false -ErrorAction SilentlyContinue
try {
  `$action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy RemoteSigned -File ``"`$AppScript``" -Task"
  `$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  `$settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName `$TaskName -Action `$action -Principal `$principal -Settings `$settings -Force | Out-Null
  Write-Host "  OK Scheduled task registered as SYSTEM"
  # Verify task actually exists
  `$verify = Get-ScheduledTask -TaskName `$TaskName -ErrorAction SilentlyContinue
  if (`$verify) { Write-Host "  OK Task verified: `$(`$verify.TaskName) — State: `$(`$verify.State)" }
  else { Write-Host "  WARNING: Task registered but cannot be found — check Task Scheduler" }
} catch {
  Write-Host "  ERROR: Could not register task - `$(`$_.Exception.Message)"
  Write-Host "  Hint: This script must run as Administrator (SYSTEM via Intune, or elevated locally)"
  exit 1
}

# SECTION 4b — Grant standard users execute rights on task via COM DACL
# 0x1201bb = Read | Execute | Run — required for schtasks /run without UAC
Write-Host "Setting task DACL — users can trigger without UAC..."
`$daclAce  = "(A;;0x1201bb;;;BU)"
`$taskReady = `$false
`$sched  = New-Object -ComObject "Schedule.Service"
for (`$waited = 0; `$waited -lt 15; `$waited++) {
  try {
  `$sched.Connect()
  `$null = `$sched.GetFolder("\").GetTask(`$TaskName)
  `$taskReady = `$true
  break
  } catch { Start-Sleep -Seconds 1 }
}
if (`$taskReady) {
  try {
  `$sched.Connect()
  `$task = `$sched.GetFolder("\").GetTask(`$TaskName)
  `$sd  = `$task.GetSecurityDescriptor(0xF)
  # Always re-apply — remove existing BU ACE then add correct one
  `$sd = `$sd -replace '\(A;;[^)]*;;;BU\)', ''
  `$newSd = if (`$sd -match 'D:') { `$sd + `$daclAce } else { `$sd + "D:" + `$daclAce }
  `$task.SetSecurityDescriptor(`$newSd, 0)
  `$check = `$task.GetSecurityDescriptor(0xF)
  if (`$check -match [regex]::Escape(`$daclAce)) {
  Write-Host "  OK Task DACL set and verified"
  } else {
  Write-Host "  WARNING: DACL may not have applied"
  }
  } catch {
  Write-Host "  WARNING: Could not set DACL: `$(`$_.Exception.Message)"
  }
} else {
  Write-Host "  WARNING: Task not found after 15s — shortcut will not work for standard users"
}

# SECTION 6 — Desktop shortcut
# Try Public Desktop (all users) first; fall back to current user's Desktop.
Write-Host "Creating desktop shortcut..."
`$scName    = "Update $DisplayName.lnk"
`$scPublic  = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonDesktopDirectory) + "\`$scName"
`$scUser    = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory) + "\`$scName"
`$scCreated = `$false
foreach (`$scPath in @(`$scPublic, `$scUser)) {
  try {
    `$wsh = New-Object -ComObject WScript.Shell
    `$sc  = `$wsh.CreateShortcut(`$scPath)
    `$sc.TargetPath       = "powershell.exe"
    `$sc.Arguments        = '-NoProfile -ExecutionPolicy RemoteSigned -File "' + `$AppScript + '"'
    `$sc.WorkingDirectory = `$AppDir
    `$sc.IconLocation     = 'shell32.dll,270'
    `$sc.WindowStyle      = 1
    `$sc.Description      = 'Checks and updates $DisplayName — no admin rights needed'
    `$sc.Save()
    [Runtime.InteropServices.Marshal]::ReleaseComObject(`$sc) | Out-Null
    [Runtime.InteropServices.Marshal]::ReleaseComObject(`$wsh) | Out-Null
    # Verify the .lnk file was actually written to disk
    if (Test-Path `$scPath) {
      Write-Host "  OK Shortcut verified at: `$scPath"
      `$scCreated = `$true
      break
    } else {
      Write-Host "  WARNING: Save() did not throw but .lnk missing at `$scPath — trying next location"
    }
  } catch {
    Write-Host "  INFO: `$scPath — `$(`$_.Exception.Message)"
  }
}
if (-not `$scCreated) {
  Write-Host "  ERROR: Could not create shortcut in any desktop location."
  Write-Host "         To create manually: right-click Desktop > New > Shortcut"
  Write-Host "         Target: powershell.exe"
  Write-Host "         Arguments: -NoProfile -ExecutionPolicy RemoteSigned -File `"`$AppScript`""
}

Write-Host ""
Write-Host "=== DEPLOY COMPLETE: $DisplayName ===" -ForegroundColor Green
Write-Host "  Folder   : `$AppDir" -ForegroundColor White
Write-Host "  Script   : `$AppDir\$AppID.ps1 (run without args for UI, with -Task for update)" -ForegroundColor White
Write-Host "  Task     : `$TaskName (SYSTEM, calls $AppID.ps1 -Task)" -ForegroundColor White
Write-Host "  Shortcut : C:\Users\Public\Desktop\Update $DisplayName.lnk" -ForegroundColor White
Write-Host ""
exit 0
"@

  # =========================================================================
  # WRITE DEPLOY SCRIPT TO TEMP DIR
  # =========================================================================
  $deployScript | Out-File "$TempDir\Deploy-$AppID.ps1" -Encoding UTF8 -Force
  Write-OK "Deploy-$AppID.ps1 generated"

  # =========================================================================
  # DETECT SCRIPT  (separate upload to Intune)
  # =========================================================================
  Write-Step "2/5" "Generating Detect-$AppID.ps1..."
  $detectScript = @"
# Detect-$AppID.ps1  — Intune detection script for $DisplayName
`$taskExists  = Get-ScheduledTask -TaskName '$TaskName' -ErrorAction SilentlyContinue
`$scriptExists = Test-Path '$AppDir\$AppID.ps1'
if (`$taskExists -and `$scriptExists) { Write-Host "Detected"; exit 0 } else { exit 1 }
"@
  $detectScript | Out-File "$OutputDir\Detect-$AppID.ps1" -Encoding UTF8 -Force
  Write-OK "Detect-$AppID.ps1 generated"

  # =========================================================================
  # XML ENTRY + AUTO-MERGE + PUSH
  # =========================================================================
  Write-Step "3/5" "Updating manifest..."
  $xe = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
  $xmlEntry = "  <App>`n  <ID>$AppID</ID>`n  <DisplayName>$(& $xe $DisplayName)</DisplayName>`n  <Version></Version>`n  <DownloadURL>$(& $xe $DownloadURL)</DownloadURL>`n  <FallbackURL>$(& $xe $FallbackURL)</FallbackURL>`n  <SilentArgs>$(& $xe $SilentArgs)</SilentArgs>`n  <RegistryDisplayName>$(& $xe $RegistryName)</RegistryDisplayName>`n  <ProcessesToKill>$(& $xe $ProcessesToKill)</ProcessesToKill>`n  <LaunchExe>$(& $xe $LaunchExe)</LaunchExe>`n  </App>"
  $xmlEntry | Out-File "$OutputDir\XMLEntry-$AppID.xml" -Encoding UTF8 -Force

  $autoPushed = $false
  if (Test-Path $XmlFile) {
  $localXml = Get-Content $XmlFile -Raw -Encoding UTF8
  $escapedID = [regex]::Escape($AppID)
  if ($localXml -match "<ID>$escapedID</ID>") {
  $localXml = $localXml -replace "(?s)\s*<App>\s*<ID>$escapedID</ID>.*?</App>", "`n$xmlEntry"
  Write-OK "Updated existing entry for $AppID in appVersions.xml"
  } else {
  $localXml = $localXml -replace "</AppManifest>", "$xmlEntry`n</AppManifest>"
  Write-OK "Added $AppID to appVersions.xml"
  }
  $localXml | Set-Content $XmlFile -Encoding UTF8 -NoNewline
  if ($WorkerOnline -and $ManifestToken) {
  try {
  $r = Invoke-RestMethod -Uri "$WorkerURL/manifest" -Method POST `
  -Headers @{"X-Auth-Token"=$ManifestToken;"Content-Type"="application/xml"} `
  -Body $localXml -TimeoutSec 20 -ErrorAction Stop
  if ($r -match "success") { Write-OK "Manifest pushed to Worker — devices will update automatically"; $autoPushed = $true }
  } catch { Write-Warn "Could not push manifest: $($_.Exception.Message)" }

  # Also upload the deploy script so it's downloadable from /deploy/{AppID}
  $deployScriptPath = "$TempDir\Deploy-$AppID.ps1"
  if (Test-Path $deployScriptPath) {
  try {
  $deployScriptContent = Get-Content $deployScriptPath -Raw -Encoding UTF8
  Invoke-RestMethod -Uri "$WorkerURL/deploy-store/$AppID" -Method POST `
  -Headers @{"X-Auth-Token"=$ManifestToken;"Content-Type"="text/plain"} `
  -Body $deployScriptContent -TimeoutSec 20 -ErrorAction Stop | Out-Null
  Write-OK "Deploy script stored — downloadable from $WorkerURL/deploy/$AppID"
  } catch {
  # Non-fatal — deploy script upload is a nice-to-have
  }
  }
  }
  }

  # =========================================================================
  # OUTPUT — WPF choice dialog
  # =========================================================================
  $choiceMap = @{ intunewin='1'; local='2'; scripts='3'; psadt='4' }
  $outputChoice = $choiceMap[(Show-WpfOutputChoice -AppID $AppID)]

  $intuneWinCreated = $false
  $deployedLocally  = $false

  switch ($outputChoice) {

  "1" {
  # ── Package as .intunewin ─────────────────────────────────────────
  Write-Step "4/5" "Packaging .intunewin..."
  if (-not (Test-Path $IntuneWinUtilPath)) {
  Write-Warn "IntuneWinAppUtil.exe not found — downloading..."
  try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
  Invoke-WebRequest -Uri $IntuneWinUtilURL -OutFile $IntuneWinUtilPath -UseBasicParsing -ErrorAction Stop
  Test-DownloadAuthenticode -FilePath $IntuneWinUtilPath -ExpectedPublisher 'Microsoft Corporation'
  Write-OK "Downloaded and verified IntuneWinAppUtil.exe"
  } catch {
  Write-Fail "Could not download or verify IntuneWinAppUtil: $($_.Exception.Message)"
  Write-Info "Scripts saved to C:\ProgramData\AppUpdater\_output\$AppID\ — package manually when ready."
  break
  }
  }
  try {
  $proc = Start-Process -FilePath $IntuneWinUtilPath `
  -ArgumentList "-c `"$TempDir`" -s `"Deploy-$AppID.ps1`" -o `"$OutputDir`" -q" `
  -WindowStyle Hidden -PassThru -Wait -ErrorAction Stop
  if ($proc.ExitCode -ne 0) { Write-Fail "IntuneWinAppUtil exited with code $($proc.ExitCode)" }
  else { Write-OK "$AppID.intunewin created"; $intuneWinCreated = $true }
  } catch { Write-Fail "Could not run IntuneWinAppUtil: $($_.Exception.Message)" }
  }

  "2" {
  # ── Run deploy script on THIS machine right now ───────────────────
  $localDeploy = "$OutputDir\Deploy-$AppID.ps1"

  # Guard: TempDir must exist
  if (-not (Test-Path $TempDir)) {
  Show-WpfMsg "Deploy Failed" "Temp folder missing — please rebuild the package." 'error'
  break
  }
  try {
  Copy-Item "$TempDir\Deploy-$AppID.ps1" $localDeploy -Force -ErrorAction Stop
  } catch {
  Show-WpfMsg "Deploy Failed" "Could not copy deploy script:`n$($_.Exception.Message)" 'error'
  break
  }
  if (-not (Test-Path $localDeploy)) {
  Show-WpfMsg "Deploy Failed" "Deploy script not found at:`n$localDeploy" 'error'
  break
  }

  # Run deploy script in-process (admin-only option — grayed out for non-admins)
  # Capture and stream all stdout into the WPF log window.
  Write-Step "4/5" "Running deploy script on this machine..."
  Write-Info "Output will appear below — please wait..."
  $deployProc = $null
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = 'powershell.exe'
    $psi.Arguments              = "-NoLogo -ExecutionPolicy Bypass -File `"$localDeploy`""
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true
    $deployProc = New-Object System.Diagnostics.Process
    $deployProc.StartInfo = $psi
    $deployProc.Start() | Out-Null
  } catch {
    Write-Fail "Could not start deploy process: $($_.Exception.Message)"
    Show-WpfMsg "Deploy Failed" "Could not launch deploy script:`n$($_.Exception.Message)" 'error'
    break
  }

  # Stream stdout into the WPF log as each line arrives
  while (-not $deployProc.StandardOutput.EndOfStream) {
    $line = $deployProc.StandardOutput.ReadLine()
    if ($null -ne $line) { Write-Info $line }
  }
  # Drain stderr
  $errOut = $deployProc.StandardError.ReadToEnd()
  if ($errOut -and $errOut.Trim()) { Write-Warn "STDERR: $errOut" }
  $deployProc.WaitForExit()

  if ($deployProc.ExitCode -eq 0) {
    $deployedLocally = $true
    Write-OK "Deployed successfully — shortcut and task created on this machine"
    Show-WpfMsg "Deploy Complete" "Deployed to this machine.`n`nShortcut 'Update $DisplayName' has been placed on the desktop.`n`nIf you don't see it, check C:\Users\Public\Desktop" 'success'
  } else {
    $ec = $deployProc.ExitCode
    Write-Fail "Deploy script exited with code $ec — see output above for details"
    Show-WpfMsg "Deploy Failed" "Deploy script exited with code $ec.`n`nSee the build log for the full error." 'error'
  }
  }

  "4" {
  # ── Save scripts then export as PSADT ──────────────────────────────
  Write-Step "4/5" "Saving scripts to C:\ProgramData\AppUpdater\_output\$AppID\..."
  $copied = 0
  try {
  Get-ChildItem -Path $TempDir -File | ForEach-Object {
  Copy-Item $_.FullName -Destination "$OutputDir\$($_.Name)" -Force
  $copied++
  }
  Write-OK "$copied script(s) saved to C:\ProgramData\AppUpdater\_output\$AppID\"
  Write-Info "Deploy-$AppID.ps1  — run as admin to set up any machine"
  Write-Info "Detect-$AppID.ps1  — Intune detection script"
  Write-Info "XMLEntry-$AppID.xml — already merged into appVersions.xml"
  } catch {
  Write-Fail "Could not copy scripts: $($_.Exception.Message)"
  Write-Info "TempDir: $TempDir"
  break
  }
  Show-WpfPSADTExport `
    -AppID           $AppID `
    -DisplayName     $DisplayName `
    -ProcessesToKill $ProcessesToKill `
    -ExpectedPub     $ExpectedPublisher `
    -OrgName         $OrgName
  }

  default {
  # Copy all scripts from TempDir to OutputDir before cleanup
  Write-Step "4/5" "Saving scripts to C:\ProgramData\AppUpdater\_output\$AppID\..."
  $copied = 0
  try {
  Get-ChildItem -Path $TempDir -File | ForEach-Object {
  Copy-Item $_.FullName -Destination "$OutputDir\$($_.Name)" -Force
  $copied++
  }
  Write-OK "$copied script(s) saved to C:\ProgramData\AppUpdater\_output\$AppID\"
  Write-Info "Deploy-$AppID.ps1  — run as admin to set up any machine"
  Write-Info "  (Deploy writes $AppID.ps1 — the single combined UI+update script)"
  Write-Info "Detect-$AppID.ps1  — Intune detection script"
  Write-Info "XMLEntry-$AppID.xml — already merged into appVersions.xml"
  } catch {
  Write-Fail "Could not copy scripts: $($_.Exception.Message)"
  Write-Info "TempDir: $TempDir"
  }
}
  }

  # Clean up temp dir
  Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
  # HOW TO USE.txt created during setup

  # SUMMARY
  # =========================================================================
  Write-Host ""
  Write-BoxTop -C ([ConsoleColor]::DarkGreen)
  Write-BoxLine "[DONE]  $AppID  — C:\ProgramData\AppUpdater\_output\$AppID\" ([ConsoleColor]::Green)
  Write-BoxBot -C ([ConsoleColor]::DarkGreen)
  Write-Host ""
  Write-Host "  OUTPUT" -ForegroundColor Cyan
  if ($intuneWinCreated) {
  Write-Host "  ├── $AppID.intunewin  <- Upload to Intune as Win32 app" -ForegroundColor White
  Write-Host "  ├── Detect-$AppID.ps1  <- Upload to Intune as detection script" -ForegroundColor White
  Write-Host "  └── XMLEntry-$AppID.xml <- Merged into appVersions.xml" -ForegroundColor White
  Write-Host ""
  Write-Host "  INTUNE CONFIGURATION" -ForegroundColor Cyan
  Write-Host "  Install  : powershell.exe -ExecutionPolicy Bypass -File Deploy-$AppID.ps1" -ForegroundColor White
  Write-Host "  Uninstall : powershell.exe -ExecutionPolicy Bypass -File Deploy-$AppID.ps1 -Uninstall" -ForegroundColor White
  Write-Host "  Detection : Script — Detect-$AppID.ps1" -ForegroundColor White
  Write-Host "  Run as  : SYSTEM  |  Architecture: 64-bit" -ForegroundColor White
  } elseif ($deployedLocally) {
  Write-Host "  Deployed to this machine:" -ForegroundColor Green
  Write-Host "  ├── C:\ProgramData\AppUpdater\$AppID\$AppID.ps1  <- Single combined script (UI + update)" -ForegroundColor White
  Write-Host "  ├── Scheduled task  : AppUpdater_$AppID  (SYSTEM, runs $AppID.ps1 -Task)" -ForegroundColor White
  Write-Host "  ├── Desktop shortcut: Update $DisplayName.lnk  (all users)" -ForegroundColor White
  Write-Host "  └── C:\ProgramData\AppUpdater\_output\$AppID\Deploy-$AppID.ps1  <- Re-run on any other machine" -ForegroundColor DarkGray
  } else {
  Write-Host "  ├── Deploy-$AppID.ps1  <- Run as admin on any machine (writes $AppID.ps1)" -ForegroundColor White
  Write-Host "  ├── Detect-$AppID.ps1  <- Intune detection script" -ForegroundColor White
  Write-Host "  └── XMLEntry-$AppID.xml <- Merged into appVersions.xml" -ForegroundColor White
  Write-Host ""
  Write-Host "  To deploy manually: powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\AppUpdater\_output\$AppID\Deploy-$AppID.ps1" -ForegroundColor DarkGray
  }
  if (-not $deployedLocally) {
  Write-Host ""
  Write-Host "  HOW TO DEPLOY" -ForegroundColor Cyan
  Write-Host "  Run  Deploy-$AppID.ps1  as admin on each machine to set up:" -ForegroundColor DarkGray
  Write-Host "  ├── C:\ProgramData\AppUpdater\$AppID\$AppID.ps1  (single combined script)" -ForegroundColor DarkGray
  Write-Host "  ├── Scheduled task AppUpdater_$AppID  (SYSTEM, calls $AppID.ps1 -Task)" -ForegroundColor DarkGray
  Write-Host "  └── Desktop shortcut  'Update $DisplayName.lnk'  for all users" -ForegroundColor White
  }
  Write-Host ""
  if ($autoPushed) {
  Write-Host "  Manifest pushed — enrolled devices will auto-update on next task run." -ForegroundColor Green
  } else {
  Write-Host "  View status: $WorkerURL/status" -ForegroundColor Cyan
  }
  Write-Host ""

  $doneMsg = if ($intuneWinCreated) { "C:\ProgramData\AppUpdater\_output\$AppID\ ready to upload to Intune." } elseif ($deployedLocally) { "Deployed to this machine." } else { "Scripts saved to C:\ProgramData\AppUpdater\_output\$AppID\" }
  Show-WpfMsg -Title "Package Ready — $DisplayName" -Type 'success' -Message $doneMsg
  return
}

# =============================================================================
# SIMPLE PACKAGE BUILDER — PSADT toolkit picker
# Shown when Get-PSADTToolkit fails. Returns toolkit path or $null (cancelled).
# =============================================================================
function Show-WpfSimplePSADTToolkit {
  param([string]$InitialError = 'Auto-download failed — choose an option below.')

  $hdr = Get-HeaderXaml 'PSADT Toolkit' 'Could not download automatically.' `
    -showBack:$false -showClose:$true

  $x = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="500" SizeToContent="Height" MinHeight="180"
  WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions>
  <RowDefinition Height="74"/>
  <RowDefinition Height="Auto"/>
  <RowDefinition Height="64"/>
  </Grid.RowDefinitions>
  $hdr
  <StackPanel Grid.Row="1" Margin="24,16,24,12">
  <!-- Status line -->
  <TextBlock x:Name="StatusText" FontSize="11" FontFamily="Consolas"
  Foreground="#ff8844" TextWrapping="Wrap" Margin="0,0,0,14"/>
  <!-- Download retry -->
  <Button x:Name="BtnDownload" Content="&#8595;  Try download again"
  Style="{StaticResource Btn}" HorizontalAlignment="Left"
  Height="34" Padding="14,0" FontSize="12" Margin="0,0,0,14"/>
  <!-- Divider -->
  <Border BorderBrush="#1e1e32" BorderThickness="0,1,0,0" Margin="0,0,0,14"/>
  <!-- Browse row -->
  <TextBlock Text="Or browse to an existing PSADT folder:" FontSize="11"
  Foreground="#55557a" Margin="0,0,0,6"/>
  <Grid>
  <Grid.ColumnDefinitions>
  <ColumnDefinition Width="*"/>
  <ColumnDefinition Width="Auto"/>
  </Grid.ColumnDefinitions>
  <TextBox x:Name="FolderPath" Style="{StaticResource Field}" Height="34"
  FontFamily="Consolas" FontSize="11" VerticalContentAlignment="Center"/>
  <Button x:Name="BtnBrowse" Grid.Column="1" Content="Browse..."
  Style="{StaticResource Btn}" Height="34" Padding="12,0" Margin="8,0,0,0" FontSize="11"/>
  </Grid>
  </StackPanel>
  <!-- Footer -->
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
  VerticalAlignment="Center" Margin="0,0,24,0">
  <Button x:Name="BtnCancel" Content="Cancel"
  Style="{StaticResource Btn}" Height="34" Padding="16,0" Margin="0,0,8,0" FontSize="12"/>
  <Button x:Name="BtnUse" Content="Use this folder  &#8250;"
  Style="{StaticResource BtnPrimary}" Height="34" Padding="16,0" FontSize="12"/>
  </StackPanel>
  </Border>
  </Grid>
</Window>
"@

  $w = New-WpfWin $x
  if (-not $w) { return $null }

  $el = Get-El $w @('StatusText','BtnDownload','FolderPath','BtnBrowse','BtnCancel','BtnUse')
  Set-WinBehavior $w -OnClose { $script:_spt = $null; $w.Close() }.GetNewClosure()
  $script:_el    = $el
  $script:_spt   = $null

  $el['StatusText'].Text = $InitialError
  $el['FolderPath'].Text = $PSADTCacheDir

  # Browse folder
  $el['BtnBrowse'].Add_Click({
    $dlg = [System.Windows.Forms.FolderBrowserDialog]::new()
    $dlg.Description  = 'Select the folder containing AppDeployToolkit (your PSADT root)'
    $dlg.SelectedPath = $script:_el['FolderPath'].Text
    if ($dlg.ShowDialog() -eq 'OK') {
      $script:_el['FolderPath'].Text = $dlg.SelectedPath
      $script:_el['StatusText'].Text = 'Click "Use this folder" to validate and continue.'
      $script:_el['StatusText'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x55,0x55,0x7a))
    }
  })

  # Try download again
  $el['BtnDownload'].Add_Click({
    $script:_el['BtnDownload'].IsEnabled = $false
    $script:_el['StatusText'].Text = 'Downloading PSADT from GitHub...'
    $script:_el['StatusText'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x55,0x55,0x7a))
    $w.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    $result = Get-PSADTToolkit
    if ($result) {
      $script:_spt = $result
      $w.Close()
    } else {
      $script:_el['StatusText'].Text = 'Download failed again. Browse to an existing folder or try later.'
      $script:_el['StatusText'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x88,0x44))
      $script:_el['BtnDownload'].IsEnabled = $true
    }
  })

  # Use typed/browsed path
  $el['BtnUse'].Add_Click({
    $path = $script:_el['FolderPath'].Text.Trim()
    if (-not $path) {
      $script:_el['StatusText'].Text = 'Enter or browse to a PSADT folder first.'
      $script:_el['StatusText'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x88,0x44))
      return
    }
    $validated = Get-PSADTToolkit -ManualPath $path
    if ($validated) {
      $script:_spt = $validated
      $w.Close()
    } else {
      $script:_el['StatusText'].Text = "Not a valid PSADT folder — AppDeployToolkitMain.ps1 not found anywhere inside:`n$path`n`nFor a PSADT v4 release package, browse into:`n  PSAppDeployToolkit\Frontend\v3"
      $script:_el['StatusText'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x88,0x44))
    }
  })

  $el['BtnCancel'].Add_Click({ $script:_spt = $null; $w.Close() }.GetNewClosure())

  $w.ShowDialog() | Out-Null
  return $script:_spt
}

# =============================================================================
# SIMPLE PACKAGE BUILDER — result dialogs
# =============================================================================
function Show-WpfSimpleIntuneResult {
  param(
    [string]$AppID        = '',
    [string]$DisplayName  = '',
    [string]$OutputDir    = '',
    [string]$RegistryName = ''
  )
  Show-WpfPackageReadyDialog `
    -Title         "Simple Package Ready — $DisplayName" `
    -IntuneWinFile "$AppID.intunewin" `
    -OutputDir     $OutputDir `
    -InstallCmd    'powershell.exe -ExecutionPolicy Bypass -File install.ps1' `
    -UninstallCmd  'powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1' `
    -RegistryName  $RegistryName `
    -PSADTVer      ''
}

function Show-WpfSimplePSADTResult {
  param(
    [string]$AppID        = '',
    [string]$DisplayName  = '',
    [string]$OutputDir    = '',
    [string]$PSADTVer     = 'v3',
    [string]$RegistryName = ''
  )
  Show-WpfPackageReadyDialog `
    -Title            "PSADT Package Ready — $DisplayName" `
    -IntuneWinFile    "$AppID-Simple-PSADT-$PSADTVer.intunewin" `
    -OutputDir        $OutputDir `
    -InstallCmd       'powershell.exe -ExecutionPolicy Bypass -File Deploy-Application.ps1' `
    -UninstallCmd     'powershell.exe -ExecutionPolicy Bypass -File Deploy-Application.ps1 -DeploymentType Uninstall' `
    -RegistryName     $RegistryName `
    -PSADTVer         $PSADTVer `
    -DeployScriptPath (Join-Path $OutputDir 'Deploy-Application.ps1')
}

# =============================================================================
# SIMPLE BUILD PROGRESS WINDOW — step-tracker shown while runspace builds
# =============================================================================
function Show-WpfSimpleBuildProgress {
  param(
    [string[]] $Steps,
    [System.Collections.Concurrent.ConcurrentQueue[int]] $StepQueue,
    [System.Collections.Concurrent.ConcurrentBag[object]] $BuildDone,
    [System.Collections.Concurrent.ConcurrentBag[string]] $BuildError
  )

  # Build step rows XAML dynamically
  $stepRowsXaml = [System.Text.StringBuilder]::new()
  for ($si = 0; $si -lt $Steps.Count; $si++) {
    $name = [System.Security.SecurityElement]::Escape($Steps[$si])
    [void]$stepRowsXaml.Append(@"

  <Grid Margin="24,0,24,14">
    <Grid.ColumnDefinitions><ColumnDefinition Width="26"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <Grid Width="18" Height="18" VerticalAlignment="Center">
      <Ellipse x:Name="StepIcon_$si" Width="18" Height="18" Stroke="#444460" StrokeThickness="2" Fill="Transparent"/>
      <TextBlock x:Name="StepCheck_$si" Text="&#10003;" FontSize="11" FontWeight="Bold"
        HorizontalAlignment="Center" VerticalAlignment="Center"
        Foreground="#4ec94e" Visibility="Collapsed"/>
    </Grid>
    <TextBlock x:Name="StepLabel_$si" Grid.Column="1" Text="$name"
      Foreground="#444460" FontSize="13" VerticalAlignment="Center" Margin="10,0,0,0"/>
  </Grid>
"@)
  }
  $stepRowsXaml = $stepRowsXaml.ToString()

  $bp = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="480" SizeToContent="Height" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$S
  <Grid>
  <Grid.RowDefinitions>
    <RowDefinition Height="74"/>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="60"/>
  </Grid.RowDefinitions>
  <Border Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74" Margin="20,0">
    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
    <StackPanel VerticalAlignment="Center">
      <TextBlock x:Name="BldTitle" Text="Building package..." FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap"/>
      <TextBlock x:Name="BldSub"   Text="Please wait"         FontSize="11" Foreground="#44445a" Margin="0,3,0,0" TextWrapping="Wrap"/>
    </StackPanel>
    <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
      <Button x:Name="BldMinimize" Width="34" Height="34" Cursor="Hand" ToolTip="Minimise"
        Padding="0" Background="Transparent" BorderBrush="Transparent" BorderThickness="0" Foreground="#6666aa">
        <Button.Template><ControlTemplate TargetType="Button">
          <Border x:Name="bm" Background="{TemplateBinding Background}" CornerRadius="6"
                  Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="bm" Property="Background" Value="#2a2a44"/>
              <Setter Property="Foreground" Value="#ccccee"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate></Button.Template>
        <TextBlock Text="&#8722;" FontSize="14" HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Button>
      <Button x:Name="BldX" Width="34" Height="34" Cursor="Hand" ToolTip="Close"
        Padding="0" Background="Transparent" BorderBrush="Transparent" BorderThickness="0"
        Foreground="#6666aa" IsEnabled="False">
        <Button.Template><ControlTemplate TargetType="Button">
          <Border x:Name="bx" Background="{TemplateBinding Background}" CornerRadius="6"
                  Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="bx" Property="Background" Value="#5a1a1a"/>
              <Setter Property="Foreground" Value="#ff6060"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate></Button.Template>
        <TextBlock Text="&#10005;" FontSize="11" HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Button>
    </StackPanel>
  </Grid>
  </Border>
  <StackPanel Grid.Row="1" Margin="0,20,0,16">
$stepRowsXaml
  </StackPanel>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
    <Button x:Name="BldClose" Content="Building..." Style="{StaticResource Btn}"
      Width="120" HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
  </Border>
  </Grid>
</Window>
"@)
  if (-not $bp) { return }

  # Collect named elements
  $elNames = @('BldTitle','BldSub','BldClose','BldMinimize','BldX')
  for ($i = 0; $i -lt $Steps.Count; $i++) {
    $elNames += "StepIcon_$i"
    $elNames += "StepCheck_$i"
    $elNames += "StepLabel_$i"
  }
  $bpEl = Get-El $bp $elNames

  $bp.Add_MouseLeftButtonDown({ $bp.DragMove() })
  $bpEl['BldMinimize'].Add_Click({ $bp.WindowState = [System.Windows.WindowState]::Minimized })
  $bpEl['BldX'].Add_Click({ $bp.Close() })
  $bpEl['BldClose'].Add_Click({ $bp.Close() })

  $green = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x4e,0xc9,0x4e))
  $white = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xe8,0xe8,0xf4))
  $red   = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x60,0x60))

  $bpTmr = [System.Windows.Threading.DispatcherTimer]::new()
  $bpTmr.Interval = [TimeSpan]::FromMilliseconds(200)
  $bpTmr.Add_Tick({
    $idx = 0
    while ($StepQueue.TryDequeue([ref]$idx)) {
      $bpEl["StepIcon_$idx"].Fill   = $green
      $bpEl["StepIcon_$idx"].Stroke = $green
      $bpEl["StepCheck_$idx"].Visibility = [System.Windows.Visibility]::Visible
      $bpEl["StepLabel_$idx"].Foreground = $white
    }
    if ($BuildDone.Count -gt 0 -or $BuildError.Count -gt 0) {
      $bpTmr.Stop()
      $ok = $BuildDone.Count -gt 0
      $bpEl['BldTitle'].Text      = if ($ok) { 'Build complete'    } else { 'Build failed' }
      $bpEl['BldSub'].Text        = if ($ok) { 'Your package is ready' } else { $BuildError | Select-Object -First 1 }
      $bpEl['BldClose'].IsEnabled = $true
      $bpEl['BldClose'].Style     = $bp.Resources[$(if ($ok) { 'BtnSuccess' } else { 'Btn' })]
      $bpEl['BldClose'].Content   = if ($ok) { 'Done  ✓' } else { 'Close' }
      if (-not $ok) { $bpEl['BldSub'].Foreground = $red }
      $bpEl['BldX'].IsEnabled     = $true
    }
  })
  $bpTmr.Start()
  $bp.ShowDialog() | Out-Null
  $bpTmr.Stop()
}

# =============================================================================
# SIMPLE PACKAGE BUILDER — pure build core (runs on MTA background runspace)
# =============================================================================
function Invoke-SimpleBuildCore {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable] $Config,
    [hashtable] $FormData = $null,
    [System.Collections.Concurrent.ConcurrentQueue[int]] $StepQueue = $null,
    [System.Collections.Concurrent.ConcurrentBag[object]] $BuildDone = $null,
    [System.Collections.Concurrent.ConcurrentBag[string]] $BuildError = $null,
    [string] $PSADTToolkitPath = ''
  )
  $enq  = { param($i) if ($StepQueue)  { $StepQueue.Enqueue($i) } }
  $fail = { param($m) if ($BuildError) { $BuildError.Add($m) } }

  $OrgName = if ($Config.ContainsKey('OrgName') -and $Config.OrgName) { $Config.OrgName } else { 'IT Services' }

  # ── Collect and validate form data ─────────────────────────────────────────
  if (-not $FormData) { return }

  $AppID          = ($FormData.AppID       -as [string]).Trim() -replace '\s',''
  $DisplayName    = ($FormData.DisplayName -as [string]).Trim()
  $SilentArgs     = ($FormData.SilentArgs  -as [string]).Trim()
  $RegistryName   = ($FormData.RegistryName -as [string]).Trim()
  $ProcessesToKill= ($FormData.ProcessesToKill -as [string]).Trim()
  $InstallerPath  = ($FormData.InstallerPath  -as [string]).Trim()
  $BannerImagePath= ($FormData.BannerImagePath -as [string]).Trim()
  $SimplePkgTarget= ($FormData.SimplePkgTarget -as [string]).Trim()
  $ExpectedPub    = ($FormData.ExpectedPublisher -as [string]).Trim()

  if (-not (Test-SafeAppId $AppID)) {
    & $fail "Invalid App ID: '$AppID' contains invalid characters or is too long."; return
  }
  if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    & $fail "Installer Not Found: Cannot find installer at:`n$InstallerPath"; return
  }

  $InstallerExt = [System.IO.Path]::GetExtension($InstallerPath).ToLower()
  $isMsi        = ($InstallerExt -eq '.msi')
  $installerFileName = "installer$InstallerExt"

  # ── Directories ─────────────────────────────────────────────────────────────
  $TempDir   = Resolve-SafeChildPath -Parent $TempBase   -Child "$AppID-simple"
  $OutputDir = Resolve-SafeChildPath -Parent $OutputBase -Child "$AppID-Simple"
  foreach ($dir in @($TempDir, $OutputDir)) {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  Write-AppLog "Simple package build: AppID=$AppID Target=$SimplePkgTarget" INFO

  # ── ARP registry paths (embedded into generated scripts) ────────────────────
  $arpPathsLiteral = "`$regPaths = @(`n  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',`n  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'`n)"

  # ── Generate install.ps1 ────────────────────────────────────────────────────
  $installScript = if ($isMsi) { @"
# install.ps1 — Generated by AppUpdater Simple Package Builder
# Installs $DisplayName silently via msiexec.
`$installer = Join-Path `$PSScriptRoot '$installerFileName'
`$proc = Start-Process msiexec.exe -ArgumentList "/i ``"`$installer``" $SilentArgs /qn /norestart" -Wait -PassThru -NoNewWindow
exit `$proc.ExitCode
"@
  } else { @"
# install.ps1 — Generated by AppUpdater Simple Package Builder
# Installs $DisplayName silently.
`$installer = Join-Path `$PSScriptRoot '$installerFileName'
`$proc = Start-Process -FilePath `$installer -ArgumentList '$SilentArgs' -Wait -PassThru -NoNewWindow
exit `$proc.ExitCode
"@
  }

  # ── Generate detect.ps1 ─────────────────────────────────────────────────────
  $detectScript = @"
# detect.ps1 — Intune detection script for $DisplayName
# Checks Add/Remove Programs for: $RegistryName
$arpPathsLiteral
`$found = Get-ItemProperty `$regPaths -ErrorAction SilentlyContinue |
  Where-Object { `$_.DisplayName -like '$($RegistryName -replace "'","''")*' }
if (`$found) { Write-Host "Detected"; exit 0 } else { exit 1 }
"@

  # ── Generate uninstall.ps1 ──────────────────────────────────────────────────
  $uninstallScript = @"
# uninstall.ps1 — Generated by AppUpdater Simple Package Builder
# Reads the UninstallString from Add/Remove Programs at runtime.
# NOTE: ARP uninstall strings vary by installer type.
# If silent uninstall fails, provide the exact UninstallString manually.
$arpPathsLiteral
`$app = Get-ItemProperty `$regPaths -ErrorAction SilentlyContinue |
  Where-Object { `$_.DisplayName -eq '$($RegistryName -replace "'","''")' } |
  Select-Object -First 1
if (-not `$app) { Write-Host "App '$RegistryName' not found in ARP"; exit 1 }
`$cmd = `$app.UninstallString
Write-Host "Uninstall string: `$cmd"
if (`$cmd -match 'MsiExec\.exe|msiexec\.exe') {
  # MSI uninstall — extract product code and run quietly
  `$guid = if (`$cmd -match '\{[0-9A-Fa-f-]{36}\}') { `$Matches[0] } else { '' }
  if (`$guid) { `$p = Start-Process msiexec.exe -ArgumentList "/x `$guid /qn /norestart" -Wait -PassThru; exit `$p.ExitCode }
  else        { `$p = Start-Process msiexec.exe -ArgumentList (`$cmd -replace 'MsiExec.exe','').Trim(),'/quiet','/norestart' -Wait -PassThru; exit `$p.ExitCode }
} elseif (`$cmd -match '^"(.+?)"(.*)$') {
  `$exe  = `$Matches[1]; `$args = `$Matches[2].Trim()
  `$p = Start-Process -FilePath `$exe -ArgumentList "`$args /quiet /norestart" -Wait -PassThru; exit `$p.ExitCode
} else {
  `$p = Start-Process -FilePath `$cmd -ArgumentList '/quiet /norestart' -Wait -PassThru; exit `$p.ExitCode
}
"@

  # ── Write scripts and copy installer to TempDir ─────────────────────────────
  $installScript   | Out-File "$TempDir\install.ps1"   -Encoding UTF8 -Force
  & $enq 0  # Generate install script
  $uninstallScript | Out-File "$TempDir\uninstall.ps1" -Encoding UTF8 -Force
  & $enq 1  # Generate uninstall script
  $detectScript    | Out-File "$OutputDir\detect.ps1"  -Encoding UTF8 -Force
  # Also copy detect.ps1 to TempDir so it's bundled (reference copy in OutputDir)
  Copy-Item "$OutputDir\detect.ps1" "$TempDir\detect.ps1" -Force
  & $enq 2  # Generate detection script
  Copy-Item -LiteralPath $InstallerPath "$TempDir\$installerFileName" -Force

  Write-AppLog "Simple package scripts generated in $TempDir" INFO

  if ($SimplePkgTarget -eq 'intunewin') {
    # ── Intune path: package TempDir → .intunewin ───────────────────────────
    if (-not (Test-Path -LiteralPath $IntuneWinUtilPath -PathType Leaf)) {
      try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $IntuneWinUtilURL -OutFile $IntuneWinUtilPath -UseBasicParsing -ErrorAction Stop
        Test-DownloadAuthenticode -FilePath $IntuneWinUtilPath -ExpectedPublisher 'Microsoft Corporation'
      } catch {
        & $fail "Download Failed: Could not download or verify IntuneWinAppUtil.exe:`n$($_.Exception.Message)"; return
      }
    }
    try {
      $proc = Start-Process -FilePath $IntuneWinUtilPath `
        -ArgumentList "-c `"$TempDir`" -s `"install.ps1`" -o `"$OutputDir`" -q" `
        -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
      if ($proc.ExitCode -ne 0) {
        & $fail "Packaging Failed: IntuneWinAppUtil exited with code $($proc.ExitCode)"; return
      }
      # Rename the output to AppID-Simple.intunewin for clarity
      $rawOut = Join-Path $OutputDir 'install.intunewin'
      $finalOut = Join-Path $OutputDir "$AppID-Simple.intunewin"
      if (Test-Path $rawOut) { Move-Item $rawOut $finalOut -Force -ErrorAction SilentlyContinue }
    } catch {
      & $fail "Packaging Failed: Could not run IntuneWinAppUtil:`n$($_.Exception.Message)"; return
    }
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-AppLog "Simple Intune package created: $OutputDir" INFO
    & $enq 3  # Create .intunewin package
    $BuildDone.Add(@{ Target='intunewin'; AppID=$AppID; DisplayName=$DisplayName
                      OutputDir=$OutputDir; RegistryName=$RegistryName })
    return
  }

  # ── PSADT path ───────────────────────────────────────────────────────────────
  $psadtVer    = if ($SimplePkgTarget -eq 'psadt-v4') { 'v4' } else { 'v3' }
  $psadtOutDir = Resolve-SafeChildPath -Parent $OutputBase -Child "$AppID-Simple-PSADT-$psadtVer"
  if (Test-Path -LiteralPath $psadtOutDir) { Remove-Item -LiteralPath $psadtOutDir -Recurse -Force -ErrorAction SilentlyContinue }
  New-Item -ItemType Directory -Path $psadtOutDir -Force | Out-Null
  New-Item -ItemType Directory -Path "$psadtOutDir\SupportFiles" -Force | Out-Null

  # PSADT toolkit path resolved by caller on STA thread before runspace started
  $toolkitPath = $PSADTToolkitPath
  if (-not $toolkitPath) { & $fail 'PSADT toolkit path not provided.'; return }

  # Copy PSADT framework
  Copy-Item (Join-Path $toolkitPath 'AppDeployToolkit') "$psadtOutDir\AppDeployToolkit" -Recurse -Force -ErrorAction SilentlyContinue

  # v3 shim: AppDeployToolkitMain.ps1 looks for the module at $PSScriptRoot\PSAppDeployToolkit\
  # (i.e. AppDeployToolkit\PSAppDeployToolkit\) — copy it there so target devices don't need
  # a system-wide module install.
  if ($psadtVer -eq 'v3') {
    $_psadtModSrc = Join-Path $PSADTCacheDir 'PSAppDeployToolkit'
    if (Test-Path $_psadtModSrc) {
      Copy-Item -Path $_psadtModSrc -Destination "$psadtOutDir\AppDeployToolkit\PSAppDeployToolkit" -Recurse -Force
      Write-AppLog "Copied PSAppDeployToolkit module into AppDeployToolkit\ for v3 shim" INFO
    }
  }

  # Optional custom banner
  if ($BannerImagePath -and (Test-Path -LiteralPath $BannerImagePath)) {
    Copy-Item -LiteralPath $BannerImagePath "$psadtOutDir\AppDeployToolkit\AppDeployToolkitBanner.png" -Force -ErrorAction SilentlyContinue
    Write-AppLog "Custom PSADT banner applied from $BannerImagePath" INFO
  }

  # Copy installer to SupportFiles
  Copy-Item -LiteralPath $InstallerPath "$psadtOutDir\SupportFiles\$installerFileName" -Force

  # Copy detect.ps1 to the PSADT output folder
  Copy-Item "$OutputDir\detect.ps1" "$psadtOutDir\detect.ps1" -Force

  # Generate Deploy-Application.ps1
  $buildDate     = Get-Date -Format 'yyyy-MM-dd'
  $closeAppsLine = if ($ProcessesToKill) { " -CloseApps '$ProcessesToKill'" } else { '' }
  $closeAppsLineV4 = if ($ProcessesToKill) { " -CloseProcesses '$ProcessesToKill'" } else { '' }

  $psadtModVersion = '4.1.8'
  $_pv = Get-ChildItem -Path $PSADTCacheDir -Filter 'PSAppDeployToolkit.psd1' -Recurse -Depth 4 `
      -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notlike '*Extensions*' } |
      Sort-Object { ($_.FullName -split '\\').Count } | Select-Object -First 1 -ExpandProperty FullName
  if ($_pv) { try { $psadtModVersion = (Import-PowerShellDataFile $_pv -ErrorAction Stop).ModuleVersion.ToString() } catch {} }
  Remove-Variable _pv -ErrorAction SilentlyContinue

  $deployApp = if ($psadtVer -eq 'v3') { @"
# Deploy-Application.ps1 — Generated by AppUpdater Simple Package Builder ($buildDate)
# PSADT v3.x — installs $DisplayName directly (no AppUpdater runtime).
[CmdletBinding()]
Param (
    [Parameter(Mandatory=`$false)][ValidateSet('Install','Uninstall','Repair')][string]`$DeploymentType = 'Install',
    [Parameter(Mandatory=`$false)][ValidateSet('Interactive','Silent','NonInteractive')][string]`$DeployMode = 'Interactive',
    [Parameter(Mandatory=`$false)][switch]`$AllowRebootPassThru = `$false,
    [Parameter(Mandatory=`$false)][switch]`$TerminalServerMode = `$false,
    [Parameter(Mandatory=`$false)][switch]`$DisableLogging = `$false
)
Try {
    [string]`$appVendor        = '$ExpectedPub'
    [string]`$appName          = '$DisplayName'
    [string]`$appVersion       = ''
    [string]`$appArch          = ''
    [string]`$appLang          = 'EN'
    [string]`$appRevision      = '01'
    [string]`$appScriptVersion = '1.0.0'
    [string]`$appScriptDate    = '$buildDate'
    [string]`$appScriptAuthor  = '$OrgName'

    . "`$PSScriptRoot\AppDeployToolkit\AppDeployToolkitMain.ps1"

    If (`$deploymentType -ine 'Uninstall' -and `$deploymentType -ine 'Repair') {
        [string]`$installPhase = 'Installation'
        Show-InstallationWelcome$closeAppsLine -AllowDefer -DeferTimes 3 -CheckDiskSpace
        Show-InstallationProgress -StatusMessage "Installing `$appName..."
        Execute-Process -Path "`$dirSupportFiles\$installerFileName" -Parameters '$SilentArgs' -WindowStyle Hidden -IgnoreExitCodes '0,3010'
    }
    ElseIf (`$deploymentType -ieq 'Uninstall') {
        [string]`$installPhase = 'Uninstallation'
        Show-InstallationWelcome$closeAppsLine -AllowDefer -DeferTimes 3
        Show-InstallationProgress -StatusMessage "Uninstalling `$appName..."
        Execute-Process -Path 'powershell.exe' ``
            -Parameters "-NonInteractive -NoProfile -ExecutionPolicy RemoteSigned -File ``"`$PSScriptRoot\SupportFiles\uninstall.ps1``"" ``
            -WindowStyle Hidden -IgnoreExitCodes '0'
    }
} Catch { [int32]`$mainExitCode = 60001; Write-Log -Message `$_.Exception.Message -Severity 3 -Source `$deployAppScriptFriendlyName }
Exit `$mainExitCode
"@
  } else { @"
# Deploy-Application.ps1 — Generated by AppUpdater Simple Package Builder ($buildDate)
# PSADT v4.1.x — installs $DisplayName directly (no AppUpdater runtime).
[CmdletBinding()]
param(
    [ValidateSet('Install','Uninstall','Repair')][System.String]`$DeploymentType = 'Install',
    [ValidateSet('Auto','Interactive','NonInteractive','Silent')][System.String]`$DeployMode = 'Interactive',
    [System.Management.Automation.SwitchParameter]`$SuppressRebootPassThru,
    [System.Management.Automation.SwitchParameter]`$TerminalServerMode,
    [System.Management.Automation.SwitchParameter]`$DisableLogging
)

`$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
`$ProgressPreference    = [System.Management.Automation.ActionPreference]::SilentlyContinue
Set-StrictMode -Version 1

`$adtSession = @{
    AppVendor                   = '$ExpectedPub'
    AppName                     = '$DisplayName'
    AppVersion                  = ''
    AppScriptVersion            = '1.0.0'
    AppScriptDate               = '$buildDate'
    AppProcessesToClose         = @()
    RequireAdmin                = `$true
    DeployAppScriptFriendlyName = `$MyInvocation.MyCommand.Name
    DeployAppScriptParameters   = `$PSBoundParameters
    DeployAppScriptVersion      = '$psadtModVersion'
}

function Install-ADTDeployment {
    [CmdletBinding()] param()
    `$adtSession.InstallPhase = "Pre-`$(`$adtSession.DeploymentType)"
    Show-ADTInstallationWelcome$closeAppsLineV4 -AllowDefer -DeferTimes 3 -CheckDiskSpace
    `$adtSession.InstallPhase = `$adtSession.DeploymentType
    Show-ADTInstallationProgress -StatusMessage "Installing `$(`$adtSession.AppName)..."
    Start-ADTProcess -FilePath "`$PSScriptRoot\SupportFiles\$installerFileName" -ArgumentList '$SilentArgs' -IgnoreExitCodes @(0, 3010)
    `$adtSession.InstallPhase = "Post-`$(`$adtSession.DeploymentType)"
}

function Uninstall-ADTDeployment {
    [CmdletBinding()] param()
    `$adtSession.InstallPhase = "Pre-`$(`$adtSession.DeploymentType)"
    Show-ADTInstallationWelcome$closeAppsLineV4 -AllowDefer -DeferTimes 3
    `$adtSession.InstallPhase = `$adtSession.DeploymentType
    Show-ADTInstallationProgress -StatusMessage "Uninstalling `$(`$adtSession.AppName)..."
    Start-ADTProcess -FilePath 'powershell.exe' ``
        -ArgumentList @('-NonInteractive','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',"``"`$PSScriptRoot\SupportFiles\uninstall.ps1``"") ``
        -IgnoreExitCodes @(0)
    `$adtSession.InstallPhase = "Post-`$(`$adtSession.DeploymentType)"
}

function Repair-ADTDeployment {
    [CmdletBinding()] param()
    Install-ADTDeployment
}

try {
    `$_psd1 = `$null
    foreach (`$_sr in @((Join-Path `$PSScriptRoot 'PSAppDeployToolkit'), `$PSScriptRoot,
                         (Join-Path `$PSScriptRoot 'AppDeployToolkit\PSAppDeployToolkit'))) {
        if (-not (Test-Path `$_sr -PathType Container -ErrorAction SilentlyContinue)) { continue }
        `$_psd1 = Get-ChildItem -Path `$_sr -Filter 'PSAppDeployToolkit.psd1' -Recurse -Depth 3 ``
            -ErrorAction SilentlyContinue |
            Where-Object { `$_.FullName -notlike '*Extensions*' } |
            Sort-Object { (`$_.FullName -split '\\').Count } |
            Select-Object -First 1 -ExpandProperty FullName
        if (`$_psd1) { break }
    }
    if (`$_psd1) {
        Get-ChildItem -Path (Split-Path `$_psd1 -Parent) -Recurse -File ``
            -ErrorAction SilentlyContinue | Unblock-File -ErrorAction Ignore
        Import-Module `$_psd1 -Force -ErrorAction Stop
    } else {
        Import-Module PSAppDeployToolkit -MinimumVersion '4.0' -Force -ErrorAction Stop
    }
    Remove-Variable _psd1, _sr -ErrorAction SilentlyContinue
    if (Get-Command 'Get-ADTBoundParametersAndDefaultValues' -ErrorAction SilentlyContinue) {
        `$_iadtP = Get-ADTBoundParametersAndDefaultValues -Invocation `$MyInvocation
        if (Get-Command 'Remove-ADTHashtableNullOrEmptyValues' -ErrorAction SilentlyContinue) {
            `$adtSession = Remove-ADTHashtableNullOrEmptyValues -Hashtable `$adtSession
        }
        `$adtSession = Open-ADTSession @adtSession @_iadtP -PassThru
        Remove-Variable _iadtP -ErrorAction SilentlyContinue
    } else {
        `$adtSession = Open-ADTSession @adtSession -PassThru
    }
} catch {
    `$Host.UI.WriteErrorLine((Out-String -InputObject `$_ -Width ([System.Int32]::MaxValue)))
    exit 60008
}

try {
    `$_fn = "`$(`$adtSession.DeploymentType)-ADTDeployment"
    if (-not (Get-Command `$_fn -ErrorAction SilentlyContinue)) {
        throw "Deployment function '`$_fn' not found. Ensure DeploymentType is Install, Uninstall, or Repair."
    }
    & `$_fn
    Remove-Variable _fn -ErrorAction SilentlyContinue
    if (Get-Command 'Close-ADTSession' -ErrorAction SilentlyContinue) { Close-ADTSession }
} catch {
    `$Host.UI.WriteErrorLine((Out-String -InputObject `$_ -Width ([System.Int32]::MaxValue)))
    try { if (Get-Command 'Close-ADTSession' -ErrorAction SilentlyContinue) { Close-ADTSession -ExitCode 60001 } } catch {}
    exit 60001
}
"@
  }

  $deployApp | Out-File "$psadtOutDir\Deploy-Application.ps1" -Encoding UTF8 -Force

  if (Test-Path $PSADTCacheDir) {
    $psadtDest = Join-Path $psadtOutDir 'PSAppDeployToolkit'
    Copy-Item -Path $PSADTCacheDir -Destination $psadtDest -Recurse -Force
    Get-ChildItem -Path $psadtDest -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    $verifyPsd1 = Get-ChildItem -Path $psadtDest -Filter 'PSAppDeployToolkit.psd1' -Recurse -Depth 4 `
      -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike '*Extensions*' } | Select-Object -First 1
    if ($verifyPsd1) {
      Write-AppLog "PSAppDeployToolkit module bundled at: $($verifyPsd1.FullName)" INFO
    } else {
      Write-AppLog "WARNING: PSAppDeployToolkit.psd1 not found in bundled output — target device will need the system module installed" WARN
    }
  } else {
    Write-AppLog "WARNING: PSADTCacheDir not found — module NOT bundled. Target device requires: Install-Module PSAppDeployToolkit" WARN
  }

  # Copy uninstall.ps1 to PSADT SupportFiles so it can be referenced from Deploy-Application.ps1
  Copy-Item "$TempDir\uninstall.ps1" "$psadtOutDir\SupportFiles\uninstall.ps1" -Force -ErrorAction SilentlyContinue

  Write-AppLog "PSADT simple package generated in $psadtOutDir" INFO
  & $enq 3  # Apply PSADT vX wrapper

  # ── Wrap PSADT folder into .intunewin ───────────────────────────────────────
  if (-not (Test-Path -LiteralPath $IntuneWinUtilPath -PathType Leaf)) {
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
      Invoke-WebRequest -Uri $IntuneWinUtilURL -OutFile $IntuneWinUtilPath -UseBasicParsing -ErrorAction Stop
      Test-DownloadAuthenticode -FilePath $IntuneWinUtilPath -ExpectedPublisher 'Microsoft Corporation'
    } catch {
      & $fail "Download Failed: Could not download or verify IntuneWinAppUtil.exe:`n$($_.Exception.Message)"; return
    }
  }
  try {
    $proc = Start-Process -FilePath $IntuneWinUtilPath `
      -ArgumentList "-c `"$psadtOutDir`" -s `"Deploy-Application.ps1`" -o `"$psadtOutDir`" -q" `
      -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    if ($proc.ExitCode -ne 0) {
      & $fail "Packaging Failed: IntuneWinAppUtil exited with code $($proc.ExitCode)"; return
    }
    # Rename output for clarity
    $rawOut  = Join-Path $psadtOutDir 'Deploy-Application.intunewin'
    $finalOut = Join-Path $psadtOutDir "$AppID-Simple-PSADT-$psadtVer.intunewin"
    if (Test-Path $rawOut) { Move-Item $rawOut $finalOut -Force -ErrorAction SilentlyContinue }
  } catch {
    & $fail "Packaging Failed: Could not run IntuneWinAppUtil:`n$($_.Exception.Message)"; return
  }

  Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-AppLog "Simple PSADT package wrapped: $psadtOutDir" INFO
  & $enq 4  # Create .intunewin package
  $BuildDone.Add(@{ Target=$SimplePkgTarget; AppID=$AppID; DisplayName=$DisplayName
                    OutputDir=$psadtOutDir; PSADTVer=$psadtVer; RegistryName=$RegistryName })
}

# =============================================================================
# REDEPLOY WORKER  — pushes updated worker JS without full setup
# =============================================================================
function Invoke-RedeployWorker {
  param([hashtable]$Config)

  # Step 0 — choice: Re-deploy OR Disconnect / Go Offline
  $hdrRD = Get-HeaderXaml 'Worker Options' 'Choose an action' -showBack:$false -showClose:$true
  $rdChoiceXaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="500" SizeToContent="Height" WindowStartupLocation="CenterScreen"
  Background="#0f0f1a" FontFamily="Segoe UI">
$script:S
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/></Grid.RowDefinitions>
  $hdrRD
  <StackPanel Grid.Row="1" Margin="24,16,24,24">
  <Border x:Name="RC1" Background="#101820" BorderBrush="#1e3a5f" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Re-deploy Worker" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
 <TextBlock Text="Push updated Worker JS and re-upload the app manifest." FontSize="12" Foreground="#5577aa" TextWrapping="Wrap" />
  </StackPanel>
  </Border>
  <Border x:Name="RC5" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock x:Name="RC5Title" Text="Set up custom domain" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
  <TextBlock x:Name="RC5Sub" Text="Route a Cloudflare domain you own to your Worker (e.g. updates.yourcompany.com). Configures DNS and routing automatically." FontSize="12" Foreground="#55557a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  <Border x:Name="RC4" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Reset /status password" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
  <TextBlock Text="Clear the dashboard password and sign out all active sessions. You set the new password in your browser — it never touches this machine." FontSize="12" Foreground="#55557a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  <Border x:Name="RC3" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Manually update stored URL" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
  <TextBlock Text="Already set up a custom domain another way and the app still shows workers.dev? Just update the stored URL here." FontSize="12" Foreground="#55557a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  <Border x:Name="RC6" Background="#100c1e" BorderBrush="#2a1e4a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="TOTP MFA" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
  <TextBlock Text="Add a second factor (authenticator code) to the /status login. Works with Google Authenticator, Authy, Microsoft Authenticator, or a YubiKey." FontSize="12" Foreground="#6644aa" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  <Border x:Name="RC7" Background="#0c1a0c" BorderBrush="#1a3a1a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Margin="0,0,0,10" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Rotate manifest token" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
  <TextBlock Text="Generate a new auth token and push it to the Worker as a secret. Invalidates the current token immediately." FontSize="12" Foreground="#448844" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  <Border x:Name="RC2" Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1"
    CornerRadius="8" Padding="18,14" Cursor="Hand">
  <StackPanel>
 <TextBlock Text="Disconnect / Go Offline" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
  <TextBlock Text="Remove the Cloudflare connection from this machine. The Worker stays live — no API key needed." FontSize="12" Foreground="#55557a" TextWrapping="Wrap"/>
  </StackPanel>
  </Border>
  </StackPanel>
  </Grid>
</Window>
"@
  $rdChoiceWin = New-WpfWin $rdChoiceXaml
  if (-not $rdChoiceWin) { return $null }
  $rdChoiceEl = Get-El $rdChoiceWin @('RC1','RC2','RC3','RC4','RC5','RC5Title','RC5Sub','RC6','RC7')
  Set-WinBehavior $rdChoiceWin
  if ($Config.CustomDomainPending -and $Config.CustomDomainTarget) {
    $rdChoiceEl['RC5'].BorderBrush = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xaa,0x88,0x20))
    $rdChoiceEl['RC5Sub'].Text = "Finish setting up $($Config.CustomDomainTarget) — domain saved, form pre-filled."
    $rdChoiceEl['RC5Sub'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xaa,0x88,0x44))
  }
  $script:_rdChoice = $null
  $rdChoiceEl['RC1'].Add_MouseLeftButtonUp({ $script:_rdChoice = 'redeploy';      $rdChoiceWin.Close() })
  $rdChoiceEl['RC5'].Add_MouseLeftButtonUp({ $script:_rdChoice = 'customdomain';  $rdChoiceWin.Close() })
  $rdChoiceEl['RC4'].Add_MouseLeftButtonUp({ $script:_rdChoice = 'setpassword';   $rdChoiceWin.Close() })
  $rdChoiceEl['RC3'].Add_MouseLeftButtonUp({ $script:_rdChoice = 'updateurl';     $rdChoiceWin.Close() })
  $rdChoiceEl['RC6'].Add_MouseLeftButtonUp({ $script:_rdChoice = 'totp';          $rdChoiceWin.Close() })
  $rdChoiceEl['RC7'].Add_MouseLeftButtonUp({ $script:_rdChoice = 'rotatetoken';   $rdChoiceWin.Close() })
  $rdChoiceEl['RC2'].Add_MouseLeftButtonUp({ $script:_rdChoice = 'disconnect';    $rdChoiceWin.Close() })
  $rdChoiceWin.ShowDialog() | Out-Null
  if (-not $script:_rdChoice) { return $null }   # X / Cancel pressed

  # ── Set up custom domain ─────────────────────────────────────────────────────
  if ($script:_rdChoice -eq 'customdomain') {
    $cdXaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  ResizeMode="NoResize" Width="460" SizeToContent="Height"
  WindowStartupLocation="CenterScreen" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <StackPanel>
    <Border Background="#0f1a2a" BorderBrush="#1e3a5f" BorderThickness="0,0,0,1" Padding="22,14">
      <StackPanel>
 <TextBlock Text="Set up custom domain" FontSize="14" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,3" TextWrapping="Wrap" />
        <TextBlock Text="The domain must already be on Cloudflare (in your account)." FontSize="11" Foreground="#5577aa" TextWrapping="Wrap"/>
      </StackPanel>
    </Border>
    <StackPanel Margin="22,14,22,4">
      <TextBlock Text="Custom domain" FontSize="11" Foreground="#7788aa" Margin="0,0,0,4"/>
      <TextBox x:Name="CdDomain" Style="{StaticResource Field}" Height="36" Margin="0,0,0,4"/>
 <TextBlock Text="e.g. updates.yourcompany.com" FontSize="10" Foreground="#444466" Margin="0,0,0,14" TextWrapping="Wrap" />
      <TextBlock Text="Cloudflare API token" FontSize="11" Foreground="#7788aa" Margin="0,0,0,4"/>
      <PasswordBox x:Name="CdToken" Style="{StaticResource PwField}" Height="36" Margin="0,0,0,4"/>
      <TextBlock FontSize="10" Foreground="#444466" Margin="0,0,0,4" TextWrapping="Wrap">Token needs:  Account › Workers Scripts › Edit  +  Zone › Workers Routes › Edit  +  Zone › Zone › Read</TextBlock>
      <TextBlock FontSize="10" Foreground="#aa8844" Margin="0,0,0,10" TextWrapping="Wrap">Tip: this is a *different* token from the deploy one — the deploy token only had Zone:Read.</TextBlock>
    </StackPanel>
    <Border Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0" Padding="22,12">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="CdCancel" Content="Cancel" Height="32" MinWidth="80" Padding="14,0" Style="{StaticResource Btn}" Margin="0,0,10,0"/>
        <Button x:Name="CdGo"     Content="Set up" Height="32" MinWidth="80" Padding="14,0" Style="{StaticResource BtnPrimary}"/>
      </StackPanel>
    </Border>
  </StackPanel>
</Window>
"@
    $cdWin = New-WpfWin $cdXaml
    if (-not $cdWin) { return $null }
    Set-WinBehavior $cdWin
    $cdEl = Get-El $cdWin @('CdDomain','CdToken','CdCancel','CdGo')
    $script:_cdResult      = $null
    $script:_cdFinalDomain = $null   # always reset so a stale value can't slip through
    if ($Config.CustomDomainTarget) { $cdEl['CdDomain'].Text = $Config.CustomDomainTarget }
    $cdEl['CdCancel'].Add_Click({ $cdWin.Close() })
    $cdEl['CdGo'].Add_Click({
      $dm = $cdEl['CdDomain'].Text.Trim().TrimStart('https://').TrimStart('http://').TrimEnd('/')
      $tk = $cdEl['CdToken'].Password.Trim()
      if (-not $dm) { Show-WpfMsg -Title 'Required' -Message 'Enter your custom domain.' -Type 'warn'; return }
      if ($dm -notmatch '\.' ) { Show-WpfMsg -Title 'Invalid Domain' -Message 'Enter a full domain, e.g. updates.yourcompany.com' -Type 'warn'; return }
      $subLabel = ($dm -split '\.')[0]
      if ($subLabel -cmatch '[A-Z]') {
        Show-WpfMsg -Title 'Invalid Domain' -Message "Domain must be all lowercase. '$subLabel' contains uppercase letters." -Type 'warn'; return
      }
      if (-not (Test-SafeSubdomainLabel $subLabel)) {
        Show-WpfMsg -Title 'Invalid Domain' -Message "The subdomain '$subLabel' is invalid. It must start and end with a letter or number and use only lowercase letters, numbers, and hyphens." -Type 'warn'; return
      }
      if (-not $tk) { Show-WpfMsg -Title 'Required' -Message 'Enter your Cloudflare API token.' -Type 'warn'; return }
      $script:_cdResult = @{ Domain = $dm; Token = $tk }
      $cdWin.Close()
    })
    $cdWin.ShowDialog() | Out-Null
    if (-not $script:_cdResult) { return $null }

    $cdDomain  = $script:_cdResult.Domain
    $cdToken   = $script:_cdResult.Token
    $cdAccID   = $Config.AccountID
    $cdWkrName = if ($Config.WorkerName) { $Config.WorkerName } else { $script:WorkerName }

    # Derive root zone from subdomain: "updates.foo.com" -> "foo.com"
    $cdParts    = $cdDomain -split '\.'
    $cdRootZone = if ($cdParts.Count -ge 3) { ($cdParts[-2..-1]) -join '.' } else { $cdDomain }

    # Run in background runspace
    $cdQ  = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $cdD  = [System.Collections.Generic.List[string]]::new()
    $cdRs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $cdRs.ApartmentState = 'MTA'; $cdRs.ThreadOptions = 'ReuseThread'; $cdRs.Open()
    $cdRs.SessionStateProxy.SetVariable('_q',        $cdQ)
    $cdRs.SessionStateProxy.SetVariable('_d',        $cdD)
    $cdRs.SessionStateProxy.SetVariable('_tok',      $cdToken)
    $cdRs.SessionStateProxy.SetVariable('_accid',    $cdAccID)
    $cdRs.SessionStateProxy.SetVariable('_domain',   $cdDomain)
    $cdRs.SessionStateProxy.SetVariable('_rootzone', $cdRootZone)
    $cdRs.SessionStateProxy.SetVariable('_worker',   $cdWkrName)
    $cdRs.SessionStateProxy.SetVariable('CF_API',    $script:CF_API)
    $_cdFns = (@('Invoke-CF') | ForEach-Object {
      $fn=Get-Item "Function:\$_" -EA SilentlyContinue; if($fn){"function $_ {`n$($fn.ScriptBlock)`n}"}
    }) -join "`n"
    $cdRs.SessionStateProxy.SetVariable('_fnSrc',$_cdFns)
    $cdPs = [System.Management.Automation.PowerShell]::Create(); $cdPs.Runspace = $cdRs
    $cdPs.AddScript({
      function Write-Host{param([object]$Object,[string]$ForegroundColor='Gray',[switch]$NoNewline)
        $c=switch($ForegroundColor){'Green'{'ok'}'Cyan'{'info'}'Yellow'{'warn'}'Red'{'err'}'DarkGray'{'dim'}'White'{'white'}default{'gray'}}
        $_q.Enqueue("$c|$Object")}
      function Write-OK  {param([string]$M) Write-Host "  [OK]  $M" -ForegroundColor Green}
      function Write-Warn{param([string]$M) Write-Host "  [!!]  $M" -ForegroundColor Yellow}
      function Write-Fail{param([string]$M) Write-Host "  [XX]  $M" -ForegroundColor Red}
      function Write-Step{param([string]$n,[string]$M) Write-Host "  [$n] $M" -ForegroundColor Cyan}
      function Write-Info{param([string]$M) Write-Host "        $M" -ForegroundColor DarkGray}
      try{Invoke-Expression $_fnSrc}catch{$_q.Enqueue("err|Load failed: $($_.Exception.Message)");$_d.Add('error');return}
      $script:ApiToken = $_tok

      Write-Step "1/3" "Validating token..."
      try {
        $v = Invoke-CF -Method GET -Path "/user/tokens/verify"
        if ($v.result.status -ne "active") { throw "Status: $($v.result.status)" }
        Write-OK "Token valid"
      } catch { Write-Fail "Invalid token: $_"; $_d.Add('error'); return }

      Write-Step "2/3" "Looking up zone for $_rootzone..."
      try {
        $zones = (Invoke-CF -Method GET -Path "/zones?name=$_rootzone").result
        $zoneId = if ($zones -and $zones.Count -gt 0) { $zones[0].id } else { $null }
        if (-not $zoneId) { throw "Zone '$_rootzone' not found. Make sure the domain is added to your Cloudflare account." }
        Write-OK "Zone found: $zoneId"
      } catch { Write-Fail "$($_.Exception.Message)"; $_d.Add('error'); return }

      Write-Step "3/3" "Configuring custom domain..."
      try {
        Invoke-CF -Method PUT -Path "/accounts/$_accid/workers/domains" -Body @{
          hostname    = $_domain
          service     = $_worker
          environment = "production"
          zone_id     = $zoneId
        } | Out-Null
        Write-OK "Custom domain configured: https://$_domain"
        Write-Info "Cloudflare is provisioning the SSL certificate — usually live within 60 seconds."
        $_d.Add("ok|$_domain")
      } catch { Write-Fail "Domain setup failed: $($_.Exception.Message)"; $_d.Add('error') }
    }) | Out-Null
    $cdHandle = $cdPs.BeginInvoke()

    $cdLogWin = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="540" Height="300" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="64"/><RowDefinition Height="*"/><RowDefinition Height="56"/></Grid.RowDefinitions>
  <Border x:Name="CDTB" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <StackPanel VerticalAlignment="Center" Margin="20,0">
 <TextBlock x:Name="CDT" Text="Setting up custom domain..." FontSize="14" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />
  <TextBlock x:Name="CDS" Text="Please wait" FontSize="11" Foreground="#44445a" Margin="0,3,0,0"/>
  </StackPanel></Border>
  <RichTextBox x:Name="CDL" Grid.Row="1" Background="#07070f" Foreground="#666688"
    BorderThickness="0" Padding="16" IsReadOnly="True" FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Button x:Name="CDC" Content="Working..." Style="{StaticResource Btn}" Width="120"
    HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
  </Border>
  </Grid>
</Window>
"@)
    if ($cdLogWin) {
      $cdlEl  = Get-El $cdLogWin @('CDT','CDS','CDL','CDC','CDTB')
      $cdlDoc = $cdlEl['CDL'].Document; $cdlDoc.Blocks.Clear()
      $cdlPar = [Windows.Documents.Paragraph]::new(); $cdlDoc.Blocks.Add($cdlPar)
      $cdlEl['CDTB'].Add_MouseLeftButtonDown({$cdLogWin.DragMove()})
      $cdlCm  = @{ok='#4ec94e';info='#6baadf';warn='#f5c842';err='#ff6060';dim='#444460';white='#e8e8f4';gray='#666688'}
      $cdlTmr = [System.Windows.Threading.DispatcherTimer]::new()
      $cdlTmr.Interval = [TimeSpan]::FromMilliseconds(200)
      $cdlTmr.Add_Tick({
        $mi=''
        while($cdQ.TryDequeue([ref]$mi)){
          $pi=$mi -split '\|',2; $ci=$cdlCm[$pi[0]]; if(-not $ci){$ci='#888'}
          $ti=if($pi.Count -gt 1){$pi[1]}else{$mi}
          $ri=[Windows.Documents.Run]::new("$ti`n")
          $rb=[Convert]::ToByte($ci.Substring(1,2),16)
          $gb=[Convert]::ToByte($ci.Substring(3,2),16)
          $bb=[Convert]::ToByte($ci.Substring(5,2),16)
          $ri.Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($rb,$gb,$bb))
          $cdlPar.Inlines.Add($ri); $cdlEl['CDL'].ScrollToEnd()
        }
        if($cdD.Count -gt 0){
          $cdlTmr.Stop()
          $raw=$cdD[0]; $ok=$raw.StartsWith('ok')
          $parts=$raw -split '\|'
          $cdlEl['CDT'].Text=if($ok){'Custom domain active'}else{'Setup failed'}
          $cdlEl['CDS'].Text=if($ok){"Live at https://$($parts[1]) — may take up to 60s for SSL"}else{'Check the log above'}
          $cdlEl['CDC'].IsEnabled=$true
          $cdlEl['CDC'].Content=if($ok){'Done  ✓'}else{'Close'}
          $cdlEl['CDC'].Style=$cdLogWin.Resources[$(if($ok){'BtnSuccess'}else{'Btn'})]
          $cdPs.EndInvoke($cdHandle)|Out-Null; $cdRs.Close()
          if($ok){ $script:_cdFinalDomain = $parts[1] }
        }
      })
      $cdlEl['CDC'].Add_Click({$cdLogWin.Close()})
      $cdLogWin.Add_ContentRendered({$cdlTmr.Start()})
      $cdLogWin.Add_Closing({if($cdlTmr.IsEnabled){$cdlTmr.Stop()}})
      $cdLogWin.ShowDialog() | Out-Null
      # Update config with new URL
      if ($script:_cdFinalDomain) {
        $oldDevURL = if ($Config.WorkerDevURL) { $Config.WorkerDevURL } else { $Config.WorkerURL }
        $Config.WorkerURL             = "https://$($script:_cdFinalDomain)"
        $Config.WorkerDevURL          = $oldDevURL
        $Config.CustomDomainPending   = $false
        $Config.CustomDomainTarget    = ''
        $saveFailed = $false
        try {
          $Config | ConvertTo-Json -Depth 5 | Set-Content $script:ConfigFile -Encoding UTF8 -Force
          Write-AppLog "Custom domain set: $($Config.WorkerURL)" -Level INFO
        } catch {
          $saveFailed = $true
          Write-AppLog "Failed to save custom domain config: $($_.Exception.Message)" -Level ERROR
        }
        if ($saveFailed) {
          Show-WpfMsg -Title 'Config not saved' `
            -Message "Domain is live, but the config file could not be updated.`n`nTo fix: Worker Options → Manually update stored URL → paste:`nhttps://$($script:_cdFinalDomain)" `
            -Type 'warn'
        }
      }
    } else {
      $cdPs.EndInvoke($cdHandle)|Out-Null; $cdRs.Close()
    }
    return $null
  }

  # ── Update Worker URL (manual fallback) ──────────────────────────────────────
  if ($script:_rdChoice -eq 'updateurl') {
    $newURL = Show-WpfInput -Title 'Update Worker URL' `
      -Label 'Enter your Worker URL (https only, e.g. https://updates.yourcompany.com)'
    if (-not $newURL) { return $null }
    $newURL = $newURL.Trim().TrimEnd('/')
    # Auto-prepend https:// only if no scheme is present.
    if ($newURL -notmatch '^[a-zA-Z][a-zA-Z0-9+\-.]*://') { $newURL = "https://$newURL" }
    # Hard-reject http:// — the dashboard ships passwords + signed sessions.
    if (-not (Test-SafeHttpsUrl $newURL)) {
      Show-WpfMsg -Title 'URL rejected' -Type 'error' `
        -Message "URL must use https:// and have a valid hostname.`n`n$newURL"
      return $null
    }
    $oldDevURL = if ($Config.WorkerDevURL) { $Config.WorkerDevURL } else { $Config.WorkerURL }
    $Config.WorkerURL    = $newURL
    $Config.WorkerDevURL = $oldDevURL
    try {
      $Config | ConvertTo-Json -Depth 5 | Set-Content $ConfigFile -Encoding UTF8 -Force
      Write-AppLog "WorkerURL updated to $newURL" INFO
    } catch {
      Write-AppLog "Failed to save updated URL: $($_.Exception.Message)" ERROR
      Show-WpfMsg -Title 'Save failed' -Type 'error' `
        -Message "URL accepted but the config file could not be written.`n`n$($_.Exception.Message)"
      return $null
    }
    Show-WpfMsg -Title 'URL updated' -Type 'success' `
      -Message ("Worker URL set to:`n$newURL`n`nThe main menu and /status link will now use this URL.")
    return $null
  }

  # ── Reset /status password ───────────────────────────────────────────────────
  if ($script:_rdChoice -eq 'setpassword') {
    Invoke-ResetStatusPassword -Config $Config
    return $null
  }

  # ── TOTP MFA setup ───────────────────────────────────────────────────────────
  if ($script:_rdChoice -eq 'totp') {
    $totpURL = if ($Config.WorkerURL) { $Config.WorkerURL } else { $Config.WorkerDevURL }
    if (-not $totpURL) {
      Show-WpfMsg -Title 'No Worker URL' -Type 'error' `
        -Message 'No Worker URL is configured. Re-deploy or connect to Cloudflare first.'
      return $null
    }
    if (-not (Test-SafeHttpsUrl $totpURL)) {
      Show-WpfMsg -Title 'Invalid Worker URL' -Type 'error' `
        -Message "Worker URL is not a valid https:// URL — refusing to open.`n`n$totpURL"
      return $null
    }
    $setupURL = "$totpURL/totp-setup"
    Show-WpfMsg -Title 'TOTP MFA setup' -Type 'info' `
      -Message ("Your browser will open the TOTP setup page.`n`n" +
                "If this is your first visit you will need to sign in to /status with your dashboard password first. " +
                "Then scan the QR code with Google Authenticator, Authy, Microsoft Authenticator, or YubiKey Authenticator.`n`n" +
                "URL: $setupURL")
    Start-Process $setupURL
    return $null
  }

  # ── Disconnect / Go Offline ─────────────────────────────────────────────────
  if ($script:_rdChoice -eq 'disconnect') {
    $dcWorkerName = if ($Config.WorkerName) { $Config.WorkerName } else { $script:WorkerName }
    $dcWorkerURL  = if ($Config.WorkerURL)  { $Config.WorkerURL  } else { $Config.WorkerDevURL }

    # Custom dialog: explain what each option does, show the Worker name
    $script:_dcChoice = $null
    $dcXaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  ResizeMode="NoResize" Width="480" SizeToContent="Height"
  WindowStartupLocation="CenterScreen" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <StackPanel>
    <Border Background="#1a0a0a" BorderBrush="#4a1a1a" BorderThickness="0,0,0,1" Padding="22,16">
      <StackPanel>
 <TextBlock Text="Disconnect from Cloudflare" FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,4" TextWrapping="Wrap" />
        <TextBlock FontSize="12" Foreground="#884444" TextWrapping="Wrap">
          Worker: <Run FontWeight="SemiBold" Foreground="#cc6666">$dcWorkerName</Run>
        </TextBlock>
        <TextBlock Text="$dcWorkerURL" FontSize="10" Foreground="#553333" FontFamily="Consolas" Margin="0,2,0,0" TextWrapping="Wrap"/>
      </StackPanel>
    </Border>
    <StackPanel Margin="22,16,22,4">
      <!-- Option A: go offline only -->
      <Border x:Name="OptOffline" Background="#101820" BorderBrush="#1e3a5f" BorderThickness="1"
        CornerRadius="7" Padding="16,12" Margin="0,0,0,10" Cursor="Hand">
        <StackPanel>
 <TextBlock Text="Go offline on this machine only" FontSize="13" FontWeight="SemiBold" Foreground="#e8e8f4" Margin="0,0,0,3" TextWrapping="Wrap" />
          <TextBlock FontSize="11" Foreground="#55557a" TextWrapping="Wrap">Removes the connection from this app. The Worker on Cloudflare stays live — enrolled devices keep working and you can reconnect any time.</TextBlock>
        </StackPanel>
      </Border>
      <!-- Option B: delete worker -->
      <Border x:Name="OptDelete" Background="#1a0808" BorderBrush="#4a1a1a" BorderThickness="1"
        CornerRadius="7" Padding="16,12" Margin="0,0,0,16" Cursor="Hand">
        <StackPanel>
 <TextBlock Text="Go offline + permanently delete Worker" FontSize="13" FontWeight="SemiBold" Foreground="#cc4444" Margin="0,0,0,3" TextWrapping="Wrap" />
          <TextBlock FontSize="11" Foreground="#664444" TextWrapping="Wrap">Deletes the Worker and all manifest data from Cloudflare. Enrolled devices will lose their update source. This cannot be undone.</TextBlock>
        </StackPanel>
      </Border>
    </StackPanel>
    <Border Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0" Padding="22,12">
      <Button x:Name="BtnCancel" Content="Cancel" Height="32" MinWidth="90" Padding="14,0"
        HorizontalAlignment="Right" Style="{StaticResource Btn}"/>
    </Border>
  </StackPanel>
</Window>
"@
    $dcWin = New-WpfWin $dcXaml
    if (-not $dcWin) { return $null }
    Set-WinBehavior $dcWin
    $dcEl = Get-El $dcWin @('OptOffline','OptDelete','BtnCancel')
    $dcEl['OptOffline'].Add_MouseLeftButtonUp({ $script:_dcChoice = 'offline'; $dcWin.Close() })
    $dcEl['OptDelete'].Add_MouseLeftButtonUp({ $script:_dcChoice = 'delete';  $dcWin.Close() })
    $dcEl['BtnCancel'].Add_Click({ $dcWin.Close() })
    $dcWin.ShowDialog() | Out-Null
    if (-not $script:_dcChoice) { return $null }

    # ── If deleting: type-to-confirm then API token ───────────────────────────
    if ($script:_dcChoice -eq 'delete') {
      $typed = Show-WpfInput -Title 'Confirm deletion' `
        -Label "Type  $dcWorkerName  to permanently delete the Worker from Cloudflare"
      if ($typed.Trim() -ne $dcWorkerName) {
        if ($null -ne $typed) {
          Show-WpfMsg -Title 'Name did not match' `
            -Message "You typed:`n$($typed.Trim())`n`nExpected:`n$dcWorkerName`n`nDeletion cancelled." `
            -Type 'error'
        }
        return $null
      }

      $delToken = Show-WpfInput -Title 'API token required' `
        -Label 'Cloudflare API token (needs Workers Scripts — Edit permission)' -Secret
      if (-not $delToken) { return $null }

      # Run deletion in a background runspace
      $dlQ  = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
      $dlD  = [System.Collections.Generic.List[string]]::new()
      $dlRs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
      $dlRs.ApartmentState = 'MTA'; $dlRs.ThreadOptions = 'ReuseThread'; $dlRs.Open()
      $dlRs.SessionStateProxy.SetVariable('_q',   $dlQ)
      $dlRs.SessionStateProxy.SetVariable('_d',   $dlD)
      $dlRs.SessionStateProxy.SetVariable('_cfg', $Config)
      $dlRs.SessionStateProxy.SetVariable('_tok', $delToken)
      foreach ($vn in @('CF_API','WorkerName','KVNamespace')) {
        $dlRs.SessionStateProxy.SetVariable($vn,(Get-Variable $vn -ValueOnly -EA SilentlyContinue))
      }
      $_dlFns = (@('Invoke-CF') | ForEach-Object {
        $fn=Get-Item "Function:\$_" -EA SilentlyContinue; if($fn){"function $_ {`n$($fn.ScriptBlock)`n}"}
      }) -join "`n"
      $dlRs.SessionStateProxy.SetVariable('_fnSrc',$_dlFns)
      $dlPs = [System.Management.Automation.PowerShell]::Create(); $dlPs.Runspace = $dlRs
      $dlPs.AddScript({
        function Write-Host{param([object]$Object,[string]$ForegroundColor='Gray',[switch]$NoNewline)
          $c=switch($ForegroundColor){'Green'{'ok'}'Cyan'{'info'}'Yellow'{'warn'}'Red'{'err'}'DarkGray'{'dim'}'White'{'white'}default{'gray'}}
          $_q.Enqueue("$c|$Object")}
        function Write-OK  {param([string]$M) Write-Host "  [OK]  $M" -ForegroundColor Green}
        function Write-Warn{param([string]$M) Write-Host "  [!!]  $M" -ForegroundColor Yellow}
        function Write-Fail{param([string]$M) Write-Host "  [XX]  $M" -ForegroundColor Red}
        function Write-Step{param([string]$n,[string]$M) Write-Host "  [$n] $M" -ForegroundColor Cyan}
        function Write-Info{param([string]$M) Write-Host "        $M" -ForegroundColor DarkGray}
        try{Invoke-Expression $_fnSrc}catch{$_q.Enqueue("err|Load failed: $($_.Exception.Message)");$_d.Add('error');return}
        $script:ApiToken = $_tok
        $AccountID = $_cfg.AccountID
        Write-Step "1/3" "Validating token..."
        try {
          $v = Invoke-CF -Method GET -Path "/user/tokens/verify"
          if ($v.result.status -ne "active") { throw "Status: $($v.result.status)" }
          Write-OK "Token valid"
        } catch { Write-Fail "Invalid token: $_"; $_d.Add('error'); return }
        Write-Step "2/3" "Deleting KV namespace..."
        try {
          $ns = (Invoke-CF -Method GET -Path "/accounts/$AccountID/storage/kv/namespaces").result
          $found = $ns | Where-Object { $_.title -eq $KVNamespace } | Select-Object -First 1
          if ($found) {
            Invoke-CF -Method DELETE -Path "/accounts/$AccountID/storage/kv/namespaces/$($found.id)" | Out-Null
            Write-OK "KV namespace deleted"
          } else { Write-Warn "KV namespace not found — may already be deleted" }
        } catch { Write-Warn "KV delete failed: $($_.Exception.Message)" }
        Write-Step "3/3" "Deleting Worker script..."
        try {
          Invoke-CF -Method DELETE -Path "/accounts/$AccountID/workers/scripts/$WorkerName" | Out-Null
          Write-OK "Worker '$WorkerName' deleted from Cloudflare"
        } catch { Write-Warn "Worker delete failed: $($_.Exception.Message)" }
        Write-OK "Done"
        $_d.Add('ok')
      }) | Out-Null
      $dlHandle = $dlPs.BeginInvoke()
      $dlWin = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="560" Height="340" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/><RowDefinition Height="60"/></Grid.RowDefinitions>
  <Border x:Name="DLTB" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74" Margin="20,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
  <StackPanel VerticalAlignment="Center">
 <TextBlock x:Name="DLT" Text="Deleting $dcWorkerName..." FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />
  <TextBlock x:Name="DLS" Text="Please wait" FontSize="11" Foreground="#44445a" Margin="0,3,0,0"/>
  </StackPanel></Grid></Border>
  <RichTextBox x:Name="DLL" Grid.Row="1" Background="#07070f" Foreground="#666688"
    BorderThickness="0" Padding="16" IsReadOnly="True" FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Button x:Name="DLC" Content="Working..." Style="{StaticResource Btn}" Width="120" HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
  </Border>
  </Grid>
</Window>
"@)
      if ($dlWin) {
        $dlEl  = Get-El $dlWin @('DLT','DLS','DLL','DLC','DLTB')
        $dlDoc = $dlEl['DLL'].Document; $dlDoc.Blocks.Clear()
        $dlPar = [Windows.Documents.Paragraph]::new(); $dlDoc.Blocks.Add($dlPar)
        $dlEl['DLTB'].Add_MouseLeftButtonDown({$dlWin.DragMove()})
        $dlCm  = @{ok='#4ec94e';info='#6baadf';warn='#f5c842';err='#ff6060';dim='#444460';white='#e8e8f4';gray='#666688'}
        $dlTmr = [System.Windows.Threading.DispatcherTimer]::new()
        $dlTmr.Interval = [TimeSpan]::FromMilliseconds(200)
        $dlTmr.Add_Tick({
          $mi=''
          while($dlQ.TryDequeue([ref]$mi)){
            $pi=$mi -split '\|',2; $ci=$dlCm[$pi[0]]; if(-not$ci){$ci='#888'}
            $ti=if($pi.Count-gt 1){$pi[1]}else{$mi}
            $ri=[Windows.Documents.Run]::new("$ti`n")
            $rb=[Convert]::ToByte($ci.Substring(1,2),16);$gb=[Convert]::ToByte($ci.Substring(3,2),16);$bb=[Convert]::ToByte($ci.Substring(5,2),16)
            $ri.Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($rb,$gb,$bb))
            $dlPar.Inlines.Add($ri); $dlEl['DLL'].ScrollToEnd()
          }
          if($dlD.Count-gt 0){
            $dlTmr.Stop(); $ok=$dlD[0]-eq'ok'
            $dlEl['DLT'].Text=if($ok){'Deleted'}else{'Finished with errors'}
            $dlEl['DLS'].Text=if($ok){'Worker removed from Cloudflare — going offline'}else{'Some resources may need manual cleanup in the Cloudflare dashboard'}
            $dlEl['DLC'].IsEnabled=$true
            $dlEl['DLC'].Content=if($ok){'Done  ✓'}else{'Close'}
            $dlEl['DLC'].Style=$dlWin.Resources[$(if($ok){'BtnSuccess'}else{'Btn'})]
            $dlPs.EndInvoke($dlHandle)|Out-Null; $dlRs.Close()
          }
        })
        $dlEl['DLC'].Add_Click({$dlWin.Close()})
        $dlWin.Add_ContentRendered({$dlTmr.Start()})
        $dlWin.Add_Closing({if($dlTmr.IsEnabled){$dlTmr.Stop()}})
        $dlWin.ShowDialog() | Out-Null
      } else {
        $dlPs.EndInvoke($dlHandle)|Out-Null; $dlRs.Close()
      }
    }

    # Clear local config regardless of which path was taken
    foreach ($k in @('WorkerURL','WorkerDevURL','AccountID','ManifestToken')) { $Config[$k] = '' }
    $Config['OfflineMode'] = $true
    try {
      $Config | ConvertTo-Json -Depth 5 | Set-Content $script:ConfigFile -Encoding UTF8 -Force
      Write-AppLog "Disconnected — local config cleared" -Level INFO
    } catch {
      Write-AppLog "Failed to save offline config: $($_.Exception.Message)" -Level ERROR
    }
    Remove-Item $script:ManifestTokenFile -Force -ErrorAction SilentlyContinue
    Show-WpfMsg -Title 'Offline' `
      -Message "AppUpdater is now in offline mode.`n`nPackages and scripts you've built are unaffected." `
      -Type 'success'
    return 'disconnected'
  }

  # ── Rotate manifest token ────────────────────────────────────────────────────
  if ($script:_rdChoice -eq 'rotatetoken') {
    if (-not $Config.AccountID) {
      Show-WpfMsg -Title 'Not connected' -Message 'No Cloudflare account ID in config. Run setup first.' -Type 'error'
      return $null
    }
    if (-not $script:ApiToken) {
      $script:ApiToken = Show-WpfInput -Title 'Rotate Token' `
        -Label 'Cloudflare API token (same one used during setup)' -Secret
      if (-not $script:ApiToken) { return $null }
    }
    $confirmed = Show-WpfMsg `
      -Title    'Rotate manifest token' `
      -Message  ("A new random auth token will be generated and pushed to Cloudflare as a Worker secret.`n`nThe current token stops working immediately. Finish any in-progress package builds before rotating.`n`nAppUpdater will save the new token automatically.") `
      -YesLabel 'Rotate token' `
      -NoLabel  'Cancel' `
      -Type     'warn' `
      -Confirm
    if (-not $confirmed) { return $null }
    try {
      $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      $tokenBytes = New-Object byte[] 32
      $rng.GetBytes($tokenBytes)
      $rng.Dispose()
      $newToken = [BitConverter]::ToString($tokenBytes).Replace('-','').ToLower()
      Invoke-CF -Method PUT -Path "/accounts/$($Config.AccountID)/workers/scripts/$WorkerName/secrets" `
        -Body @{name="AUTH_TOKEN";text=$newToken;type="secret_text"} | Out-Null
      $sentinel = Protect-ManifestToken $newToken   # writes to Cred Mgr, returns 'CREDMGR'
      $Config.ManifestToken = $sentinel
      $Config | ConvertTo-Json -Depth 5 | Set-Content $script:ConfigFile -Encoding UTF8 -Force
      icacls $script:ConfigFile /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(F)" /grant:r "BUILTIN\Administrators:(F)" 2>&1 | Out-Null
      Write-AppLog "[AUTH_TOKEN rotated — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')]" INFO
      Show-WpfMsg -Title 'Token rotated' `
        -Message "New manifest token generated and saved.`n`nThe Worker secret has been updated on Cloudflare. The new token is active immediately." `
        -Type 'success'
    } catch {
      Show-WpfMsg -Title 'Rotation failed' `
        -Message "Could not rotate the token.`n`n$($_.Exception.Message)" `
        -Type 'error'
    }
    return $null
  }

  # ── Re-deploy ────────────────────────────────────────────────────────────────
  # Step 1 — collect API token via WPF dialog (non-blocking, on UI thread)
  $rdToken = Show-WpfInput -Title 'Re-deploy Worker' `
    -Label 'Cloudflare API token (same one used during setup)' -Secret
  if (-not $rdToken) { return $null }   # user cancelled

  # Step 2 — run everything else in a background runspace behind a log window
  $rdQ  = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
  $rdD  = [System.Collections.Generic.List[string]]::new()
  $rdRs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
  $rdRs.ApartmentState = 'MTA'; $rdRs.ThreadOptions = 'ReuseThread'; $rdRs.Open()
  $rdRs.SessionStateProxy.SetVariable('_q',   $rdQ)
  $rdRs.SessionStateProxy.SetVariable('_d',   $rdD)
  $rdRs.SessionStateProxy.SetVariable('_cfg', $Config)
  $rdRs.SessionStateProxy.SetVariable('_tok', $rdToken)
  foreach ($vn in @('CF_API','WorkerName','KVNamespace','WorkerSource','XmlFile','ManifestTokenFile')) {
    $rdRs.SessionStateProxy.SetVariable($vn,(Get-Variable $vn -ValueOnly -EA SilentlyContinue))
  }
  # Capture Invoke-CF, New-MultipartBody, and the DPAPI helpers used when
  # saving the rotated manifest token after redeploy. Write-* are defined inline below.
  $_rdFns = (@('Invoke-CF','New-MultipartBody','Protect-ManifestToken','Unprotect-ManifestToken') | ForEach-Object {
    $fn=Get-Item "Function:\$_" -EA SilentlyContinue; if($fn){"function $_ {`n$($fn.ScriptBlock)`n}"}
  }) -join "`n"
  $rdRs.SessionStateProxy.SetVariable('_fnSrc',$_rdFns)

  $rdPs = [System.Management.Automation.PowerShell]::Create(); $rdPs.Runspace = $rdRs
  $rdPs.AddScript({
    function Write-Host{param([object]$Object,[string]$ForegroundColor='Gray',[switch]$NoNewline)
      $c=switch($ForegroundColor){'Green'{'ok'}'Cyan'{'info'}'Yellow'{'warn'}'Red'{'err'}'DarkGray'{'dim'}'White'{'white'}default{'gray'}}
      $_q.Enqueue("$c|$Object")}
    function Write-OK  {param([string]$M) Write-Host "  [OK]  $M" -ForegroundColor Green}
    function Write-Warn{param([string]$M) Write-Host "  [!!]  $M" -ForegroundColor Yellow}
    function Write-Fail{param([string]$M) Write-Host "  [XX]  $M" -ForegroundColor Red}
    function Write-Step{param([string]$n,[string]$M) Write-Host "  [$n] $M" -ForegroundColor Cyan}
    function Write-Info{param([string]$M) Write-Host "        $M" -ForegroundColor DarkGray}
    function Write-Rule{}
    function Write-AppLog{param([string]$Message,[string]$Level='INFO')}
    try{Invoke-Expression $_fnSrc}catch{$_q.Enqueue("err|Load failed: $($_.Exception.Message)");$_d.Add('error');return}

    $script:ApiToken = $_tok

    Write-Step "1/3" "Validating API token..."
    try {
      $v = Invoke-CF -Method GET -Path "/user/tokens/verify"
      if ($v.result.status -ne "active") { throw "Status: $($v.result.status)" }
      Write-OK "Token valid"
    } catch { Write-Fail "Invalid token: $_"; $_d.Add('error'); return }

    $AccountID     = $_cfg.AccountID
    $WorkerDevURL  = if ($_cfg.ContainsKey("WorkerDevURL")) { $_cfg.WorkerDevURL } else { $_cfg.WorkerURL }
    # Token is pre-decrypted by the main thread before being passed in $_cfg
    $ManifestToken = if ($_cfg.ContainsKey("ManifestToken") -and $_cfg.ManifestToken) { $_cfg.ManifestToken } else { "" }

    Write-Step "2/3" "Deploying updated Worker..."
    $KvId = $null
    try {
      $ex = (Invoke-CF -Method GET -Path "/accounts/$AccountID/storage/kv/namespaces").result
      $found = $ex | Where-Object { $_.title -eq $KVNamespace } | Select-Object -First 1
      if ($found) { $KvId = $found.id }
    } catch {}
    if (-not $KvId) { Write-Fail "KV namespace not found — run full setup instead."; $_d.Add('error'); return }

    # Build metadata JSON manually — PS5.1 ConvertTo-Json collapses single-element
    # arrays to plain objects, causing Cloudflare to return 400.
    $meta = "{`"main_module`":`"worker.js`",`"compatibility_date`":`"2024-01-01`",`"bindings`":[{`"type`":`"kv_namespace`",`"name`":`"APP_MANIFEST`",`"namespace_id`":`"$KvId`"}]}"
    $mp = New-MultipartBody -Parts @(
      @{ Name="metadata";  ContentType="application/json";                Data=$meta }
      @{ Name="worker.js"; ContentType="application/javascript+module";   Data=$WorkerSource }
    )
    try {
      Invoke-CF -Method PUT -Path "/accounts/$AccountID/workers/scripts/$WorkerName" `
        -RawBody $mp.Body -ContentType $mp.ContentType | Out-Null
      Write-OK "Worker script updated"
    } catch { Write-Fail "Deploy failed: $_"; $_d.Add('error'); return }

    # Rotate the event-telemetry HMAC secret so any device script with the
    # previous secret can no longer post events. Devices get the new secret
    # next time you rebuild + redeploy their package.
    try {
      $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      $evtBytes = New-Object byte[] 32
      try { $rng.GetBytes($evtBytes) } finally { $rng.Dispose() }
      $evtB64Local = [Convert]::ToBase64String($evtBytes)
      Invoke-CF -Method PUT -Path "/accounts/$AccountID/storage/kv/namespaces/$KvId/values/evtsec" `
        -Body $evtB64Local -ContentType 'text/plain' | Out-Null
      Write-OK "Event-telemetry secret rotated"
    } catch { Write-Warn "Could not rotate event secret: $($_.Exception.Message)" }

    Write-Step "3/3" "Re-pushing manifest..."
    if ($ManifestToken -and (Test-Path $XmlFile)) {
      Write-Info "Waiting for Worker to come online (15s propagation)..."
      for ($i=1; $i -le 3; $i++) { Start-Sleep -Seconds 5; Write-Info "  ... $($i*5)s / 15s" }
      $xml = Get-Content $XmlFile -Raw -Encoding UTF8
      $pushed = $false
      foreach ($url in @($WorkerDevURL, $_cfg.WorkerURL) | Where-Object { $_ } | Select-Object -Unique) {
        try {
          $r = Invoke-RestMethod -Uri "$url/manifest" -Method POST `
            -Headers @{"X-Auth-Token"=$ManifestToken;"Content-Type"="application/xml"} `
            -Body $xml -TimeoutSec 20 -ErrorAction Stop
          if ($r -match "success") { Write-OK "Manifest pushed to $url"; $pushed = $true; break }
        } catch { Write-Warn "Push to $url failed: $($_.Exception.Message)" }
      }
      if (-not $pushed) { Write-Warn "Manifest push failed — push manually or rebuild an app" }
    } else {
      Write-Warn "No manifest token or appVersions.xml — skipping manifest push"
    }

    Write-OK "Re-deploy complete"
    $_d.Add('ok')
  }) | Out-Null

  $rdHandle = $rdPs.BeginInvoke()

  # Step 3 — log/progress window (same pattern as build)
  $rdWin = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="560" Height="420" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/><RowDefinition Height="60"/></Grid.RowDefinitions>
  <Border x:Name="RDTB" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74" Margin="20,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
  <StackPanel VerticalAlignment="Center">
 <TextBlock x:Name="RDT" Text="Re-deploying Worker..." FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />
  <TextBlock x:Name="RDS" Text="Please wait" FontSize="11" Foreground="#44445a" Margin="0,3,0,0"/>
  </StackPanel></Grid></Border>
  <RichTextBox x:Name="RDL" Grid.Row="1" Background="#07070f" Foreground="#666688"
    BorderThickness="0" Padding="16" IsReadOnly="True" FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Button x:Name="RDC" Content="Working..." Style="{StaticResource Btn}" Width="120" HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
  </Border>
  </Grid>
</Window>
"@)
  if ($rdWin) {
    $rdEl  = Get-El $rdWin @('RDT','RDS','RDL','RDC','RDTB')
    $rdDoc = $rdEl['RDL'].Document; $rdDoc.Blocks.Clear()
    $rdPar = [Windows.Documents.Paragraph]::new(); $rdDoc.Blocks.Add($rdPar)
    $rdEl['RDTB'].Add_MouseLeftButtonDown({$rdWin.DragMove()})
    $rdCm  = @{ok='#4ec94e';info='#6baadf';warn='#f5c842';err='#ff6060';dim='#444460';white='#e8e8f4';gray='#666688'}
    $rdTmr = [System.Windows.Threading.DispatcherTimer]::new()
    $rdTmr.Interval = [TimeSpan]::FromMilliseconds(200)
    $rdTmr.Add_Tick({
      $mi=''
      while($rdQ.TryDequeue([ref]$mi)){
        $pi=$mi -split '\|',2; $ci=$rdCm[$pi[0]]; if(-not$ci){$ci='#888'}
        $ti=if($pi.Count-gt 1){$pi[1]}else{$mi}
        $ri=[Windows.Documents.Run]::new("$ti`n")
        $rb=[Convert]::ToByte($ci.Substring(1,2),16);$gb=[Convert]::ToByte($ci.Substring(3,2),16);$bb=[Convert]::ToByte($ci.Substring(5,2),16)
        $ri.Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($rb,$gb,$bb))
        $rdPar.Inlines.Add($ri); $rdEl['RDL'].ScrollToEnd()
      }
      if($rdD.Count-gt 0){
        $rdTmr.Stop(); $ok=$rdD[0]-eq'ok'
        $rdEl['RDT'].Text=if($ok){'Re-deploy complete'}else{'Re-deploy finished with errors'}
        $rdEl['RDS'].Text=if($ok){"Refresh $($Config.WorkerURL)/status to confirm"}else{'Check output above'}
        $rdEl['RDC'].IsEnabled=$true
        $rdEl['RDC'].Content=if($ok){'Done  ✓'}else{'Close'}
        $rdEl['RDC'].Style=$rdWin.Resources[$(if($ok){'BtnSuccess'}else{'Btn'})]
        $rdPs.EndInvoke($rdHandle)|Out-Null; $rdRs.Close()
      }
    })
    $rdEl['RDC'].Add_Click({$rdWin.Close()})
    $rdWin.Add_ContentRendered({$rdTmr.Start()})
    $rdWin.Add_Closing({if($rdTmr.IsEnabled){$rdTmr.Stop()}})
    $rdWin.ShowDialog() | Out-Null
  } else {
    $rdPs.EndInvoke($rdHandle)|Out-Null; $rdRs.Close()
  }
}
# =============================================================================
# STARTUP — WPF-based entry point
# =============================================================================

# =============================================================================
# MAIN ENTRY — runs after the WPF subsystem is fully initialised. Hidden
# helpers above this point are pure functions; below is the imperative flow.
# =============================================================================

Write-AppLog "=== AppUpdater v$($script:Version) started === Script=$ScriptPath"
Write-AppLog "Thread: ID=$([System.Threading.Thread]::CurrentThread.ManagedThreadId) Apt=$([System.Threading.Thread]::CurrentThread.ApartmentState)"

# -----------------------------------------------------------------------------
# Read-PersistedConfig — single source of truth for loading the JSON config
# file. Returns a hashtable or $null on failure. Never throws.
# -----------------------------------------------------------------------------
function Read-PersistedConfig {
  [CmdletBinding()] param([Parameter(Mandatory)][string] $Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    $ht  = @{}
    foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = $p.Value }
    return $ht
  } catch {
    Write-AppLog "Config load failed for '$Path': $($_.Exception.Message)" ERROR
    return $null
  }
}

# -----------------------------------------------------------------------------
# Resolve the runtime config. Order:
#   1. -Offline flag overrides everything (preserves OrgName / WorkerURL hints).
#   2. Otherwise read $ConfigFile.
#   3. ManifestToken is read from the dedicated file when present (DPAPI blob);
#      otherwise from any legacy in-config token. Always decrypted into memory.
# -----------------------------------------------------------------------------
# Migrate legacy plaintext tokens and harden file ACLs on first run after update.
Invoke-TokenFileMigration

$config = $null

if ($Offline) {
  $config = @{
    WorkerURL     = ''
    WorkerDevURL  = ''
    ManifestToken = ''
    AccountID     = ''
    OrgName       = 'IT Services'
    OfflineMode   = $true
    SetupDate     = (Get-Date -Format 'yyyy-MM-dd')
  }
  $existing = Read-PersistedConfig -Path $ConfigFile
  if ($existing) {
    if ($existing.OrgName)   { $config.OrgName   = $existing.OrgName }
    if ($existing.WorkerURL) { $config.WorkerURL = $existing.WorkerURL }
  }
} else {
  $config = Read-PersistedConfig -Path $ConfigFile
}

if ($config) {
  # Load plaintext token from Credential Manager (falls back to DPAPI/file for migration)
  $config.ManifestToken = Get-StoredManifestToken
}

# -----------------------------------------------------------------------------
# First run — pop the WPF setup chooser (Cloudflare / offline) and either run
# the Cloudflare wizard or fall through to a minimal offline config. Either
# way, $config is a populated hashtable when this block exits.
# -----------------------------------------------------------------------------
$script:_firstRunWizardCompleted = $false
if (-not $config) {
  $firstRun = Show-WpfFirstRun
  if ($firstRun.mode -eq 'cloudflare') {
    $cfResult = Show-WpfCloudflareWizard -OrgName $firstRun.orgName
    if ($cfResult -and -not $cfResult.Error) {
      # Wizard succeeded — re-read the freshly-written config + token.
      $reloaded = Read-PersistedConfig -Path $ConfigFile
      if ($reloaded) { $config = $reloaded } else { $config = $cfResult }
      $config.ManifestToken = Get-StoredManifestToken
      # Carry the wizard's CustomDomainPending hint into the live config so the
      # main menu can surface a one-time "set it up here" notice on first visit.
      if ($cfResult.CustomDomainPending) {
        $config.CustomDomainPending = $true
        $config.CustomDomainTarget  = $cfResult.CustomDomainTarget
      }
      $script:_firstRunWizardCompleted = $true
    }
  }
  if (-not $config) {
    $config = @{
      WorkerURL     = ''
      WorkerDevURL  = ''
      ManifestToken = ''
      AccountID     = ''
      OrgName       = $firstRun.orgName
      OfflineMode   = $true
      SetupDate     = (Get-Date -Format 'yyyy-MM-dd')
    }
  }
}

# One-shot: if the wizard left a custom-domain task pending, point the user
# straight at the right menu before they see the main menu for the first time.
if ($script:_firstRunWizardCompleted -and $config.CustomDomainPending) {
  $proceed = Show-WpfMsg `
    -Title    'Set up your custom domain now?' `
    -Type     'info' `
    -YesLabel 'Open Worker / app options' `
    -NoLabel  'Later' `
    -Confirm `
    -Message  ("Your Worker is live at $($config.WorkerURL).`n`n" +
               "You picked the custom domain $($config.CustomDomainTarget) but the " +
               "deploy token did not have permission to create it. The dedicated " +
               "menu option uses a separate token and gives you a step-by-step flow.")
  if ($proceed) { Invoke-RedeployWorker -Config $config | Out-Null }
  # Clear the flag — show this notice once, not on every launch.
  $config.CustomDomainPending = $false
  try { $config | ConvertTo-Json -Depth 5 | Set-Content $ConfigFile -Encoding UTF8 -Force } catch { }
}

Write-AppLog "Entering main menu (WorkerURL='$($config.WorkerURL)')"
while ($true) {
  $choice = Show-WpfMainMenu -Config $config
  switch ($choice) {
  1 {
  $formData = Show-WpfAppForm -Defaults @{} -HasWorker ([bool]($config -and $config.WorkerURL))
  if ($null -eq $formData)  { exit 0 }  # X pressed — close entirely
  if ($formData -is [hashtable]) {
  # ── Simple Package mode: background runspace + step-tracker progress window ──
  if ($formData.Mode -eq 'simple') {
    $target = ($formData.SimplePkgTarget -as [string]).Trim()

    $stepList = switch ($target) {
      'intunewin' { @('Generate install script','Generate uninstall script',
                      'Generate detection script','Create .intunewin package') }
      'psadt-v3'  { @('Generate install script','Generate uninstall script',
                      'Generate detection script','Apply PSADT v3 wrapper',
                      'Create .intunewin package') }
      default     { @('Generate install script','Generate uninstall script',
                      'Generate detection script','Apply PSADT v4 wrapper',
                      'Create .intunewin package') }
    }

    # Pre-flight: resolve PSADT toolkit on STA thread (may need to show picker dialog)
    $resolvedToolkitPath = ''
    if ($target -ne 'intunewin') {
      $resolvedToolkitPath = Get-PSADTToolkit
      if (-not $resolvedToolkitPath) {
        $resolvedToolkitPath = Show-WpfSimplePSADTToolkit -InitialError 'Auto-download failed — browse to an existing PSADT folder or try downloading again.'
        if (-not $resolvedToolkitPath) { break }  # user cancelled
      }
    }

    # Shared state between STA and runspace
    $simpStepQ = [System.Collections.Concurrent.ConcurrentQueue[int]]::new()
    $simpDone  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $simpErr   = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

    # Background MTA runspace
    $simpRs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $simpRs.ApartmentState = 'MTA'
    $simpRs.ThreadOptions  = 'ReuseThread'
    $simpRs.Open()
    foreach ($pair in @(
      [pscustomobject]@{N='_sq';V=$simpStepQ}, [pscustomobject]@{N='_sd';V=$simpDone},
      [pscustomobject]@{N='_se';V=$simpErr},   [pscustomobject]@{N='_fd';V=$formData},
      [pscustomobject]@{N='_cfg';V=$config},   [pscustomobject]@{N='_tkPath';V=$resolvedToolkitPath},
      [pscustomobject]@{N='ScriptPath';V=$ScriptPath},       [pscustomobject]@{N='ScriptDir';V=$ScriptDir},
      [pscustomobject]@{N='TempBase';V=$TempBase},           [pscustomobject]@{N='OutputBase';V=$OutputBase},
      [pscustomobject]@{N='IntuneWinUtilURL';V=$IntuneWinUtilURL},
      [pscustomobject]@{N='IntuneWinUtilPath';V=$IntuneWinUtilPath},
      [pscustomobject]@{N='PSADTCacheDir';V=$PSADTCacheDir}
    )) { $simpRs.SessionStateProxy.SetVariable($pair.N, $pair.V) }

    $_simpFns    = @('Invoke-SimpleBuildCore','Test-SafeAppId','Resolve-SafeChildPath',
                     'Test-DownloadAuthenticode','Write-AppLog')
    $_simpFnSrc  = ($_simpFns | ForEach-Object {
      $fn = Get-Item "Function:\$_" -ErrorAction SilentlyContinue
      if ($fn) { "function $_ {`n$($fn.ScriptBlock)`n}" }
    }) -join "`n"
    $simpRs.SessionStateProxy.SetVariable('_fnSrc', $_simpFnSrc)

    $simpPs = [System.Management.Automation.PowerShell]::Create()
    $simpPs.Runspace = $simpRs
    $simpPs.AddScript({
      . ([scriptblock]::Create($_fnSrc))
      Invoke-SimpleBuildCore -Config $_cfg -FormData $_fd `
        -StepQueue $_sq -BuildDone $_sd -BuildError $_se -PSADTToolkitPath $_tkPath
    }) | Out-Null
    $simpHandle = $simpPs.BeginInvoke()

    # Progress window blocks via ShowDialog while runspace works
    Show-WpfSimpleBuildProgress -Steps $stepList `
      -StepQueue $simpStepQ -BuildDone $simpDone -BuildError $simpErr

    $simpPs.EndInvoke($simpHandle) | Out-Null
    $simpPs.Dispose()
    $simpRs.Close(); $simpRs.Dispose()

    # Show result dialog on STA thread
    if ($simpDone.Count -gt 0) {
      $r = $null; $simpDone.TryTake([ref]$r) | Out-Null
      if ($r -and $r.Target -eq 'intunewin') {
        Show-WpfSimpleIntuneResult -AppID $r.AppID -DisplayName $r.DisplayName `
          -OutputDir $r.OutputDir -RegistryName $r.RegistryName
      } elseif ($r) {
        Show-WpfSimplePSADTResult -AppID $r.AppID -DisplayName $r.DisplayName `
          -OutputDir $r.OutputDir -PSADTVer $r.PSADTVer -RegistryName $r.RegistryName
      }
    } elseif ($simpErr.Count -gt 0) {
      $errMsg = $null; $simpErr.TryTake([ref]$errMsg) | Out-Null
      Show-WpfMsg -Title 'Build Failed' -Type 'error' -Message $errMsg
    }
    break
  }
  # ── Runtime mode: ask output choice on MAIN (STA) thread BEFORE starting runspace ──
  $outputChoiceStr = Show-WpfOutputChoice -AppID $formData.AppID
  if (-not $outputChoiceStr) { break }  # user closed without choosing — back to main menu

  # ── Step 2: Start background (MTA) runspace for CPU-bound file generation ────
  $buildQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
  $buildDone  = [System.Collections.Generic.List[string]]::new()
  $buildRs    = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
  $buildRs.ApartmentState = 'MTA'
  $buildRs.ThreadOptions  = 'ReuseThread'
  $buildRs.Open()
  $buildRs.SessionStateProxy.SetVariable('_bq',     $buildQueue)
  $buildRs.SessionStateProxy.SetVariable('_bd',     $buildDone)
  $buildRs.SessionStateProxy.SetVariable('_cfg',    $config)
  $buildRs.SessionStateProxy.SetVariable('_fd',     $formData)
  $buildRs.SessionStateProxy.SetVariable('_oc',     $outputChoiceStr)
  $buildRs.SessionStateProxy.SetVariable('_script', $ScriptPath)

  # Pass all script-scope constants — these are not visible in the child runspace.
  $buildRs.SessionStateProxy.SetVariable('ScriptPath',        $ScriptPath)
  $buildRs.SessionStateProxy.SetVariable('ScriptDir',         $ScriptDir)
  $buildRs.SessionStateProxy.SetVariable('XmlFile',           $XmlFile)
  $buildRs.SessionStateProxy.SetVariable('ConfigFile',        $ConfigFile)
  $buildRs.SessionStateProxy.SetVariable('ManifestTokenFile', $ManifestTokenFile)
  $buildRs.SessionStateProxy.SetVariable('IntuneWinUtilURL',  $IntuneWinUtilURL)
  $buildRs.SessionStateProxy.SetVariable('IntuneWinUtilPath', $IntuneWinUtilPath)
  $buildRs.SessionStateProxy.SetVariable('TempBase',          $TempBase)
  $buildRs.SessionStateProxy.SetVariable('OutputBase',        $OutputBase)
  $buildRs.SessionStateProxy.SetVariable('CF_API',            $CF_API)
  $buildRs.SessionStateProxy.SetVariable('WorkerName',        $WorkerName)
  $buildRs.SessionStateProxy.SetVariable('KVNamespace',       $KVNamespace)

  # Capture only the functions the build thread needs.
  # Passing function source instead of dot-sourcing the whole script prevents
  # top-level UI code (Show-WpfMainMenu etc.) from running on the MTA thread.
  $_buildFnNames = @(
    'Invoke-PackageBuilder','Invoke-InstallerInspector','Get-InstalledVersion',
    'Read-MsiProperties','Get-InstallerType','Get-SilentArgs',
    'Protect-ManifestToken','Unprotect-ManifestToken','Get-StoredManifestToken',
    'Test-SafeAppId','Test-SafeFileName','Test-SafeHttpsUrl','Test-SafeSubdomainLabel',
    'ConvertTo-SafeFsName','Resolve-SafeChildPath',
    'Set-PhaseActive','Set-PhaseDone','Set-Pill',
    'Write-AppLog','Write-OK','Write-Warn','Write-Fail','Write-Step','Write-Info',
    'Write-Rule','Write-BoxTop','Write-BoxBot','Write-BoxLine'
  )
  $_fnSrc = ($_buildFnNames | ForEach-Object {
    $fn = Get-Item "Function:\$_" -ErrorAction SilentlyContinue
    if ($fn) { "function $_ {`n$($fn.ScriptBlock)`n}" }
  }) -join "`n"
  $buildRs.SessionStateProxy.SetVariable('_fnSrc', $_fnSrc)

  $buildPs = [System.Management.Automation.PowerShell]::Create()
  $buildPs.Runspace = $buildRs
  $buildPs.AddScript({
    # ── This runspace is MTA — WPF requires STA. ─────────────────────────────────
    # Stub EVERY WPF function before dot-sourcing the script.
    # New-WpfWin returning $null causes all Show-Wpf* to silently fall through
    # to their non-WPF fallback paths. No STA calls can reach this thread.
    function New-WpfWin          { param([string]$xaml) return $null }
    function Get-El              { param($w,[string[]]$names) return @{} }
    function Get-HeaderXaml      { param([string]$title,[string]$sub='',[bool]$showBack=$false,[bool]$showClose=$true,[bool]$showBadge=$false) return '' }
    function Set-WinBehavior     { param($w,[scriptblock]$OnClose=$null,[scriptblock]$OnBack=$null) }
    function Show-WpfMsg         {
      param([string]$Title='',[string]$Message='',[string]$Type='info',[switch]$Confirm)
      $_bq.Enqueue("info|[$Title] $Message"); return $true
    }
    function Show-WpfOutputChoice  { param([string]$AppID='') return $_oc }
    function Show-WpfFirstRun      { return @{mode='offline';orgName='IT Services'} }
    function Show-WpfMainMenu      { param([hashtable]$Config) return 6 }
    function Show-WpfAppForm       { param([hashtable]$Defaults=@{},[bool]$HasWorker=$false) return $null }
    function Show-WpfCloudflareWizard { param([string]$OrgName='') return $null }
    function Show-WpfPSADTExport { param([string]$AppID='',[string]$DisplayName='',[string]$ProcessesToKill='',[string]$ExpectedPub='',[string]$OrgName='') $_bq.Enqueue("info|Build complete. Use the PSADT button in the app list to export as a PSADT package.") }
    function Export-PSADTPackage { param([string]$AppID='',[string]$DisplayName='',[string]$ProcessesToKill='',[string]$ExpectedPub='',[string]$PSADTVersion='v3',[string]$PSADTToolkitPath='',[string]$OrgName='') }
    function Get-PSADTToolkit { param([string]$ManualPath='') return $null }
    function Invoke-SimpleBuildCore { param([hashtable]$Config=@{},[hashtable]$FormData=@{}) }
    function Show-WpfSimpleIntuneResult { param([string]$AppID='',[string]$DisplayName='',[string]$OutputDir='',[string]$RegistryName='') }
    function Show-WpfSimplePSADTResult { param([string]$AppID='',[string]$DisplayName='',[string]$OutputDir='',[string]$PSADTVer='v3',[string]$RegistryName='') }
    function Show-WpfPackageReadyDialog { param([string]$Title='',[string]$IntuneWinFile='',[string]$OutputDir='',[string]$InstallCmd='',[string]$UninstallCmd='',[string]$RegistryName='',[string]$PSADTVer='') }
    function Show-WpfSimplePSADTToolkit { param([string]$InitialError='') return $null }
    function Write-AppLog { param([string]$Message,[string]$Level='INFO') $_bq.Enqueue("dim|[LOG:$Level] $Message") }

    # Redirect Write-Host to the WPF log queue on the main thread
    function Write-Host {
      param([object]$Object,[string]$ForegroundColor='Gray',[switch]$NoNewline)
      $col = switch ($ForegroundColor) {
        'Green'   {'ok'}  'Cyan'    {'info'} 'Yellow'  {'warn'}
        'Red'     {'err'} 'DarkGray'{'dim'}  'White'   {'white'}
        default   {'gray'}
      }
      $_bq.Enqueue("$col|$Object")
    }
    function Write-OK    { param([string]$M) Write-Host "  OK  $M" -ForegroundColor Green  }
    function Write-Warn  { param([string]$M) Write-Host "  !!  $M" -ForegroundColor Yellow }
    function Write-Fail  { param([string]$M) Write-Host "  XX  $M" -ForegroundColor Red    }
    function Write-Step  { param([string]$n,[string]$M) Write-Host "  [$n] $M" -ForegroundColor Cyan }
    function Write-Info  { param([string]$M) Write-Host "       $M" -ForegroundColor DarkGray }
    function Write-Rule  { }
    function Write-BoxTop  { param($C) }
    function Write-BoxBot  { param($C) }
    function Write-BoxLine { param([string]$m,$C) Write-Host "  $m" -ForegroundColor $C }

    # Load only the required build functions from pre-captured source.
    # Avoids dot-sourcing the whole script which re-runs top-level UI code
    # (Show-WpfMainMenu etc.) on this MTA thread and hangs permanently.
    $_bq.Enqueue("info|Loading build functions...")
    try {
      Invoke-Expression $_fnSrc
    } catch {
      $_bq.Enqueue("err|ERROR: Failed to load build functions: $($_.Exception.Message)")
      $_bd.Add('error')
      return
    }
    if (-not (Get-Command Invoke-PackageBuilder -ErrorAction SilentlyContinue)) {
      $_bq.Enqueue("err|ERROR: Invoke-PackageBuilder not available after function load")
      $_bd.Add('error')
      return
    }
    $_bq.Enqueue("info|Starting build: $($_fd.AppID)...")
    try {
      Invoke-PackageBuilder -Config $_cfg -FormData $_fd
      $_bd.Add('ok')
    } catch {
      $_bq.Enqueue("err|ERROR: $($_.Exception.Message)")
      $_bq.Enqueue("err|At: $($_.InvocationInfo.PositionMessage -replace "`r",'' -replace "`n",' ')")
      $_bd.Add('error')
    }
  }) | Out-Null
  $buildHandle = $buildPs.BeginInvoke()

  # WPF build progress window
  $bp = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="560" Height="460" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize"
  Background="#0f0f1a" FontFamily="Segoe UI">
$S
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/><RowDefinition Height="60"/></Grid.RowDefinitions>
  <Border x:Name="TitleBar" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74" Margin="20,0">
  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
  <StackPanel VerticalAlignment="Center">
 <TextBlock x:Name="BldTitle" Text="Building package..." FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />
 <TextBlock x:Name="BldSub" Text="Please wait" FontSize="11" Foreground="#44445a" Margin="0,3,0,0" TextWrapping="Wrap" />
  </StackPanel>
  <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
  <Button x:Name="BldMinimize" Width="34" Height="34" Cursor="Hand" ToolTip="Minimise"
    Padding="0" Background="Transparent" BorderBrush="Transparent" BorderThickness="0"
    Foreground="#6666aa">
    <Button.Template><ControlTemplate TargetType="Button">
      <Border x:Name="bd2" Background="{TemplateBinding Background}" CornerRadius="6"
              Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd2" Property="Background" Value="#2a2a44"/>
          <Setter Property="Foreground" Value="#ccccee"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate></Button.Template>
 <TextBlock Text="&#8722;" FontSize="14" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" />
  </Button>
  <Button x:Name="BldX" Width="34" Height="34" Cursor="Hand" ToolTip="Close"
    Padding="0" Background="Transparent" BorderBrush="Transparent" BorderThickness="0"
    Foreground="#6666aa" IsEnabled="False">
    <Button.Template><ControlTemplate TargetType="Button">
      <Border x:Name="bd3" Background="{TemplateBinding Background}" CornerRadius="6"
              Width="{TemplateBinding Width}" Height="{TemplateBinding Height}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter TargetName="bd3" Property="Background" Value="#5a1a1a"/>
          <Setter Property="Foreground" Value="#ff6060"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate></Button.Template>
 <TextBlock Text="&#10005;" FontSize="11" HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" />
  </Button>
  </StackPanel>
  </Grid>
  </Border>
  <RichTextBox x:Name="BldLog" Grid.Row="1" Background="#07070f" Foreground="#666688"
  BorderThickness="0" Padding="16" IsReadOnly="True"
  FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Button x:Name="BldClose" Content="Building..." Style="{StaticResource Btn}"
  Width="120" HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
  </Border>
  </Grid>
</Window>
"@)
  if ($bp) {
  $bpEl  = Get-El $bp @('BldTitle','BldSub','BldLog','BldClose','TitleBar','BldMinimize','BldX')
  $bpDoc = $bpEl['BldLog'].Document
  $bpDoc.Blocks.Clear()
  $bpPara = [Windows.Documents.Paragraph]::new()
  $bpDoc.Blocks.Add($bpPara)
  $bpEl['TitleBar'].Add_MouseLeftButtonDown({ $bp.DragMove() })
  $bpEl['BldMinimize'].Add_Click({ $bp.WindowState = [System.Windows.WindowState]::Minimized })
  $bpEl['BldX'].Add_Click({ $bp.Close() })
  $bpEl['BldClose'].Add_Click({ $bp.Close() })
  $bpCm  = @{ ok='#4ec94e'; info='#6baadf'; warn='#f5c842'; err='#ff6060'; dim='#444460'; white='#e8e8f4'; gray='#666688' }
  $bpTmr = [System.Windows.Threading.DispatcherTimer]::new()
  $bpTmr.Interval = [TimeSpan]::FromMilliseconds(200)
  $bpTmr.Add_Tick({
  $msg = ''
  while ($buildQueue.TryDequeue([ref]$msg)) {
  $parts = $msg -split '\|',2
  $col  = if ($bpCm.ContainsKey($parts[0])) { $bpCm[$parts[0]] } else { '#888' }
  $text  = if ($parts.Count -gt 1) { $parts[1] } else { $msg }
  $run  = [Windows.Documents.Run]::new("$text`n")
  $r2 = [Convert]::ToByte($col.Substring(1,2),16)
  $g2 = [Convert]::ToByte($col.Substring(3,2),16)
  $b2 = [Convert]::ToByte($col.Substring(5,2),16)
  $run.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($r2,$g2,$b2))
  $bpPara.Inlines.Add($run)
  $bpEl['BldLog'].ScrollToEnd()
  }
  if ($buildDone.Count -gt 0) {
  $bpTmr.Stop()
  $ok2 = $buildDone[0] -eq 'ok'
  $titleTxt2 = if ($ok2) { 'Build complete' } else { 'Build finished with errors' }
  $bpEl['BldTitle'].Text = $titleTxt2
  $subTxt2   = if ($ok2) { 'Your package is ready' } else { 'Check output above for details' }
  $bpEl['BldSub'].Text  = $subTxt2
  $bpEl['BldClose'].IsEnabled = $true
  $bpEl['BldX'].IsEnabled = $true
  $bpEl['BldX'].Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x66,0x66,0xaa))
  $styleKey2 = if ($ok2) { 'BtnSuccess' } else { 'Btn' }
  $bpEl['BldClose'].Style  = $bp.Resources[$styleKey2]
  $closeLabel2 = if ($ok2) { 'Done  ✓' } else { 'Close' }
  $bpEl['BldClose'].Content = $closeLabel2
  $buildPs.EndInvoke($buildHandle) | Out-Null
  $buildRs.Close()
  }
  })
  $bp.Add_ContentRendered({ $bpTmr.Start() })
  $bp.Add_Closing({ if ($bpTmr.IsEnabled) { $bpTmr.Stop() } })
  $bp.ShowDialog() | Out-Null
  if ($outputChoiceStr -eq 'psadt') {
    Show-WpfPSADTExport `
      -AppID           $formData.AppID `
      -DisplayName     $formData.DisplayName `
      -ProcessesToKill $formData.ProcessesToKill `
      -ExpectedPub     $formData.ExpectedPublisher `
      -OrgName         $config.OrgName
  }
  } else {
  # Fallback: run synchronously (visible in hidden console)
  Invoke-PackageBuilder -Config $config -FormData $formData
  $buildPs.EndInvoke($buildHandle) | Out-Null
  $buildRs.Close()
  }
  }
  # 'back' string = back button pressed — fall through to loop back to main menu
  }
  2 {
    # Open the build-output folder. Create it if it does not yet exist so the
    # user does not see a blank explorer error on a fresh install.
    if (-not (Test-Path -LiteralPath $OutputBase)) {
      New-Item -ItemType Directory -Path $OutputBase -Force | Out-Null
    }
    Start-Process explorer.exe -ArgumentList ('"{0}"' -f $OutputBase)
  }
  3 {
    # Connected: open /status in the default browser.
    # Offline: launch the Cloudflare connect wizard, then refresh local config.
    if ($config.WorkerURL) {
      Start-Process ("{0}/status" -f $config.WorkerURL)
    } else {
      $cfRes = Show-WpfCloudflareWizard -OrgName $config.OrgName
      if ($cfRes -and -not $cfRes.Error) {
        $reloaded = Read-PersistedConfig -Path $ConfigFile
        $config = if ($reloaded) { $reloaded } else { $cfRes }
        $config.ManifestToken = Get-StoredManifestToken
      }
    }
  }
  4 {
    # Worker / app options. After it returns, always refresh the live config
    # from disk — the user may have redeployed, changed URL, disconnected, or
    # rotated the manifest token in the sub-flows.
    $rdResult = Invoke-RedeployWorker -Config $config
    $reloaded = Read-PersistedConfig -Path $ConfigFile
    if ($reloaded) { $config = $reloaded }
    if ($rdResult -eq 'disconnected') {
      # Belt-and-suspenders for the disconnect path — zero out worker keys in
      # the live config regardless of what disk re-read returned.
      $config.WorkerURL = ''; $config.WorkerDevURL = ''
      $config.AccountID = ''; $config.ManifestToken = ''
    } else {
      $config.ManifestToken = Get-StoredManifestToken
    }
  }
  5 {
    # =========================================================================
    # FULL RESET — single comprehensive dialog with per-target checkboxes.
    # User picks exactly what to remove; type "RESET" to arm the button.
    # Targets:
    #   * Worker script on Cloudflare
    #   * KV namespace (manifest, password, secrets, event logs)
    #   * Custom-domain binding(s) on the Worker
    #   * All app artefacts on THIS machine (tasks, ProgramData, shortcuts, Output)
    #   * Local config + DPAPI-protected manifest token (always required)
    # =========================================================================
    Write-AppLog '=== FULL RESET DIAGNOSTIC TRACE START ===' INFO
    Write-AppLog "FR: user clicked B5 (config.WorkerURL='$($config.WorkerURL)')" INFO
    $isConnected = [bool]$config.WorkerURL
    Write-AppLog "FR: isConnected=$isConnected" INFO

    # Discover the custom-domain hostname (only if it differs from workers.dev).
    $customDomainHost = ''
    try {
      if ($config.WorkerURL -and $config.WorkerURL -notmatch 'workers\.dev') {
        $customDomainHost = ([Uri]$config.WorkerURL).Host
      }
      Write-AppLog "FR: customDomainHost='$customDomainHost'" INFO
    } catch {
      Write-AppLog "FR: customDomainHost lookup threw: $($_.Exception.Message)" WARN
    }

    # Pre-load installed app IDs from the local manifest so we can show a count.
    $localAppIds = @()
    try {
      if (Test-Path -LiteralPath $XmlFile) {
        [xml]$mxLocal = Get-Content -LiteralPath $XmlFile -Raw -Encoding UTF8 -ErrorAction Stop
        $localAppIds = @($mxLocal.AppManifest.App | Where-Object { $_ -ne $null -and $_.ID } | ForEach-Object {
          [pscustomobject]@{ ID = [string]$_.ID; DisplayName = if ($_.DisplayName) { [string]$_.DisplayName } else { [string]$_.ID } }
        })
      }
      Write-AppLog "FR: localAppIds count=$($localAppIds.Count) ids=[$(($localAppIds | Select-Object -First 5 -ExpandProperty ID) -join ',')]" INFO
    } catch {
      Write-AppLog "FR: manifest read failed: $($_.Exception.Message)" WARN
    }
    $localAppCount = $localAppIds.Count
    Write-AppLog "FR: visibility flags: cloud=$(if($isConnected){'Visible'}else{'Collapsed'}) cd=$(if($customDomainHost){'Visible'}else{'Collapsed'}) apps=$(if($localAppCount){'Visible'}else{'Collapsed'})" INFO

    # Build the checklist + confirmation dialog. Each item is collapsed when
    # not applicable (e.g. Worker / KV checkboxes hidden when not connected).
    $cdHostEsc       = [System.Security.SecurityElement]::Escape($customDomainHost)
    $cdRowVis        = if ($customDomainHost) { 'Visible' } else { 'Collapsed' }
    $cloudRowVis     = if ($isConnected)      { 'Visible' } else { 'Collapsed' }
    $appsRowVis      = if ($localAppCount)    { 'Visible' } else { 'Collapsed' }
    $appsLabel       = if ($localAppCount -eq 1) { '1 app' } else { "$localAppCount apps" }
    $kvLabelSuffix   = "'$KVNamespace' (manifest, password, secrets, all event logs)"
    $wkLabelSuffix   = "'$WorkerName'"
    # Collapsed checkboxes retain their IsChecked value in WPF, so hidden CF
    # boxes would still trigger the token-required validation. Default them to
    # unchecked when their section isn't visible to avoid the trap.
    $cfChecked       = if ($isConnected)      { 'True' } else { 'False' }
    $cdChecked       = if ($customDomainHost) { 'True' } else { 'False' }

    $rsConfirmXaml = @"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" ResizeMode="NoResize"
  Width="600" SizeToContent="Height" WindowStartupLocation="CenterScreen"
  Topmost="True" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <StackPanel>
    <Border Background="#3a1a1a" BorderBrush="#7a2a2a" BorderThickness="0,0,0,1" Padding="22,14">
      <StackPanel>
        <TextBlock Text="Full Reset" FontSize="16" FontWeight="SemiBold" Foreground="#ff8888"/>
        <TextBlock Text="Pick exactly what to delete. Each item runs only if its box is ticked." FontSize="11" Foreground="#aa6666" Margin="0,3,0,0"/>
      </StackPanel>
    </Border>

    <StackPanel Margin="22,16,22,4">
      <TextBlock Text="CLOUDFLARE" FontSize="9" FontWeight="SemiBold" Foreground="#5577aa" Margin="0,0,0,6" Visibility="$cloudRowVis"/>
      <CheckBox x:Name="CbWorker"  Visibility="$cloudRowVis" IsChecked="$cfChecked" Foreground="#cccccc" FontSize="12" Margin="0,0,0,8">
        <TextBlock TextWrapping="Wrap"><Run FontWeight="SemiBold" Foreground="#e8e8f4">Delete Worker</Run> &#160;<Run Foreground="#7788aa">$wkLabelSuffix</Run></TextBlock>
      </CheckBox>
      <CheckBox x:Name="CbKv"      Visibility="$cloudRowVis" IsChecked="$cfChecked" Foreground="#cccccc" FontSize="12" Margin="0,0,0,8">
        <TextBlock TextWrapping="Wrap"><Run FontWeight="SemiBold" Foreground="#e8e8f4">Delete KV namespace</Run> &#160;<Run Foreground="#7788aa">$kvLabelSuffix</Run></TextBlock>
      </CheckBox>
      <CheckBox x:Name="CbDomain"  Visibility="$cdRowVis"    IsChecked="$cdChecked" Foreground="#cccccc" FontSize="12" Margin="0,0,0,8">
        <TextBlock TextWrapping="Wrap"><Run FontWeight="SemiBold" Foreground="#e8e8f4">Delete custom domain</Run> &#160;<Run Foreground="#7788aa">$cdHostEsc</Run></TextBlock>
      </CheckBox>

      <TextBlock Text="THIS MACHINE" FontSize="9" FontWeight="SemiBold" Foreground="#5577aa" Margin="0,8,0,6"/>
      <CheckBox x:Name="CbApps"    Visibility="$appsRowVis"  IsChecked="True" Foreground="#cccccc" FontSize="12" Margin="0,0,0,8">
        <TextBlock TextWrapping="Wrap"><Run FontWeight="SemiBold" Foreground="#ff9988">Remove all app artefacts on this machine</Run> &#160;<Run Foreground="#aa7766">($appsLabel)</Run><LineBreak/><Run Foreground="#7788aa">scheduled tasks, ProgramData folders, desktop shortcuts, Output\ build files</Run></TextBlock>
      </CheckBox>
      <CheckBox x:Name="CbLocal"   IsChecked="True" IsEnabled="False" Foreground="#cccccc" FontSize="12" Margin="0,0,0,8">
        <TextBlock TextWrapping="Wrap"><Run FontWeight="SemiBold" Foreground="#e8e8f4">Delete local config + manifest token</Run> &#160;<Run Foreground="#7788aa">(always required)</Run></TextBlock>
      </CheckBox>
    </StackPanel>

    <Border Background="#16161e" BorderBrush="#2a2a3a" BorderThickness="1" CornerRadius="6" Margin="22,4,22,4" Padding="14,10" Visibility="$cloudRowVis">
      <StackPanel>
        <TextBlock Text="Cloudflare API token" FontSize="11" Foreground="#7788aa" Margin="0,0,0,2"/>
        <TextBlock Text="Required ONLY if any Cloudflare box above is ticked. Permissions: Workers Scripts: Edit + Workers KV Storage: Edit." FontSize="10" Foreground="#55557a" Margin="0,0,0,6" TextWrapping="Wrap"/>
        <PasswordBox x:Name="RsToken" Style="{StaticResource PwField}" Height="34"/>
        <TextBlock x:Name="RsTokenError" Text="" FontSize="11" Foreground="#ff6060" Margin="0,6,0,0" TextWrapping="Wrap"/>
      </StackPanel>
    </Border>

    <Border Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0" Padding="22,14" Margin="0,16,0,0">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <Button x:Name="RsBtnCancel" Grid.Column="0" Content="Cancel" Height="38" MinWidth="120" Padding="14,0" HorizontalAlignment="Left" Style="{StaticResource Btn}" FontSize="13"/>
        <Button x:Name="RsBtnGo"     Grid.Column="1" Content="Reset selected items"     Height="38" MinWidth="200" Padding="18,0" HorizontalAlignment="Right" Style="{StaticResource BtnDanger}" FontSize="13" FontWeight="SemiBold"/>
      </Grid>
    </Border>
  </StackPanel>
</Window>
"@
    Write-AppLog "FR: building reset dialog XAML (length=$($rsConfirmXaml.Length))" INFO
    $rsConfirmWin = New-WpfWin $rsConfirmXaml
    if (-not $rsConfirmWin) {
      Write-AppLog 'FR: New-WpfWin returned $null — XAML failed to parse.' ERROR
      Show-WpfMsg -Title 'Reset failed' -Type 'error' -Message 'Could not show the confirmation dialog. Check AppUpdater.log for the XAML error.'
      continue
    }
    Write-AppLog 'FR: dialog window created OK' INFO

    $rsCEl = Get-El $rsConfirmWin @('CbWorker','CbKv','CbDomain','CbApps','CbLocal','RsToken','RsTokenError','RsBtnCancel','RsBtnGo')
    foreach ($k in @('CbWorker','CbKv','CbDomain','CbApps','CbLocal','RsToken','RsTokenError','RsBtnCancel','RsBtnGo')) {
      if (-not $rsCEl[$k]) { Write-AppLog "FR: WARNING element '$k' is NULL in dialog" WARN }
    }
    Write-AppLog "FR: elements resolved (CbWorker=$($null -ne $rsCEl['CbWorker']) CbKv=$($null -ne $rsCEl['CbKv']) CbDomain=$($null -ne $rsCEl['CbDomain']) CbApps=$($null -ne $rsCEl['CbApps']) RsToken=$($null -ne $rsCEl['RsToken']) RsBtnGo=$($null -ne $rsCEl['RsBtnGo']))" INFO

    # Use a hashtable so closures and outer scope share the same reference object.
    # $script: variables written inside GetNewClosure() go to the closure's own
    # module scope, not the outer script scope, so they would always read back as
    # their initial values after ShowDialog() returns.
    $rsResult = @{ Confirmed = $false; Options = $null }
    # Cancel always closes; Alt+F4 / X also fall here via Set-WinBehavior.
    Set-WinBehavior $rsConfirmWin -OnClose {
      Write-AppLog 'FR: dialog OnClose fired (Set-WinBehavior path — X / Alt+F4)' INFO
      $rsResult.Confirmed = $false
      $rsConfirmWin.Close()
    }
    $rsCEl['RsBtnCancel'].Add_Click({
      Write-AppLog 'FR: Cancel button clicked' INFO
      $rsResult.Confirmed = $false
      $rsConfirmWin.Close()
    }.GetNewClosure())
    $rsCEl['RsBtnGo'].Add_Click({
      Write-AppLog 'FR: Reset selected items button clicked' INFO
      # Validate inline rather than after-the-fact. If cloud boxes are ticked
      # but the token is missing, light up the token field and stay on dialog.
      $cw = [bool]$rsCEl['CbWorker'].IsChecked
      $ck = [bool]$rsCEl['CbKv'].IsChecked
      $cd = [bool]$rsCEl['CbDomain'].IsChecked
      $ca = [bool]$rsCEl['CbApps'].IsChecked
      $tokLen = if ($rsCEl['RsToken'].Password) { $rsCEl['RsToken'].Password.Length } else { 0 }
      Write-AppLog "FR: button state at click — Worker=$cw KV=$ck Domain=$cd Apps=$ca tokenLen=$tokLen" INFO
      $cloudWanted = ($cw -or $ck -or $cd)
      if ($cloudWanted -and $tokLen -eq 0) {
        Write-AppLog 'FR: validation failed — cloud box(es) ticked but token is empty' WARN
        $rsCEl['RsTokenError'].Text = 'API token is required because one or more Cloudflare boxes are ticked. Paste a token or untick those boxes.'
        $rsCEl['RsToken'].BorderBrush = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xff,0x60,0x60))
        return
      }
      Write-AppLog 'FR: validation passed — building Options' INFO
      $rsResult.Options = @{
        DeleteWorker = $cw
        DeleteKv     = $ck
        DeleteDomain = $cd
        DeleteApps   = $ca
        DeleteLocal  = $true
        Token        = $rsCEl['RsToken'].Password
        AppIds       = $localAppIds
        DomainHost   = $customDomainHost
      }
      $rsResult.Confirmed = $true
      Write-AppLog 'FR: Confirmed=$true; closing dialog' INFO
      $rsConfirmWin.Close()
    }.GetNewClosure())
    $rsConfirmWin.Add_ContentRendered({
      Write-AppLog 'FR: dialog ContentRendered — activating + focusing token field' INFO
      $rsConfirmWin.Activate() | Out-Null
      if ($rsCEl['RsToken'] -and ($rsCEl['RsToken'].Visibility -eq [Windows.Visibility]::Visible)) {
        $rsCEl['RsToken'].Focus() | Out-Null
      }
    })
    Write-AppLog 'FR: about to call ShowDialog' INFO
    $rsConfirmWin.ShowDialog() | Out-Null
    Write-AppLog "FR: ShowDialog returned. Confirmed=$($rsResult.Confirmed) Options is null=$($null -eq $rsResult.Options)" INFO

    if (-not $rsResult.Confirmed -or -not $rsResult.Options) {
      Write-AppLog 'FR: post-dialog branch = cancelled (confirmed=false OR options=null)' INFO
      Write-AppLog '=== FULL RESET DIAGNOSTIC TRACE END (cancelled) ===' INFO
      continue
    }
    $opt = $rsResult.Options
    Write-AppLog ("FR: confirmed worker={0} kv={1} domain={2} apps={3} local={4} appCount={5} tokLen={6}" -f
      $opt.DeleteWorker, $opt.DeleteKv, $opt.DeleteDomain, $opt.DeleteApps, $opt.DeleteLocal, $opt.AppIds.Count, ($opt.Token.Length)) INFO
    Write-AppLog '=== FULL RESET DIAGNOSTIC TRACE END (proceeding) ===' INFO

    # Cleanup runspace — receives the option hashtable + supporting state.
    $rsQ  = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $rsD  = [System.Collections.Generic.List[string]]::new()
    $rsRs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rsRs.ApartmentState = 'MTA'; $rsRs.ThreadOptions = 'ReuseThread'; $rsRs.Open()
    $rsRs.SessionStateProxy.SetVariable('_q',     $rsQ)
    $rsRs.SessionStateProxy.SetVariable('_d',     $rsD)
    $rsRs.SessionStateProxy.SetVariable('_cfg',   $config)
    $rsRs.SessionStateProxy.SetVariable('_opt',   $opt)
    $rsRs.SessionStateProxy.SetVariable('_cfile', $ConfigFile)
    $rsRs.SessionStateProxy.SetVariable('_tfile', $ManifestTokenFile)
    $rsRs.SessionStateProxy.SetVariable('_xfile', $XmlFile)
    $rsRs.SessionStateProxy.SetVariable('OutputBase', $OutputBase)
    foreach ($vn in @('CF_API','WorkerName','KVNamespace')) {
      $rsRs.SessionStateProxy.SetVariable($vn,(Get-Variable $vn -ValueOnly -EA SilentlyContinue))
    }
    $_rsFnNames = @('Invoke-CF','Remove-AppLocalArtifacts','Write-AppLog')
    $_rsFns = ($_rsFnNames | ForEach-Object {
      $fn = Get-Item "Function:\$_" -EA SilentlyContinue
      if ($fn) { "function $_ {`n$($fn.ScriptBlock)`n}" }
    }) -join "`n"
    $rsRs.SessionStateProxy.SetVariable('_fnSrc', $_rsFns)

    $rsPs = [System.Management.Automation.PowerShell]::Create()
    $rsPs.Runspace = $rsRs
    $rsPs.AddScript({
      function Write-Host {
        param([object]$Object='',[string]$ForegroundColor='Gray',[switch]$NoNewline)
        $c = switch ($ForegroundColor) {
          'Green'   { 'ok' }   'Cyan'  { 'info' } 'Yellow' { 'warn' }
          'Red'     { 'err' }  'White' { 'white' } default { 'gray' }
        }
        $_q.Enqueue("$c|$Object")
      }
      function Write-OK   { param([string]$M) Write-Host "  [OK]  $M" -ForegroundColor Green }
      function Write-Warn { param([string]$M) Write-Host "  [!!]  $M" -ForegroundColor Yellow }
      function Write-Fail { param([string]$M) Write-Host "  [XX]  $M" -ForegroundColor Red }
      function Write-Step { param([string]$n,[string]$M) Write-Host "  [$n] $M" -ForegroundColor Cyan }

      try { Invoke-Expression $_fnSrc } catch {
        $_q.Enqueue("err|Load failed: $($_.Exception.Message)"); $_d.Add('error'); return
      }

      $tokenValid = $false
      $needsToken = ($_opt.DeleteWorker -or $_opt.DeleteKv -or $_opt.DeleteDomain) -and $_opt.Token
      if ($needsToken) {
        $script:ApiToken = $_opt.Token
        Write-Step '1' 'Validating Cloudflare API token...'
        try {
          $v = Invoke-CF -Method GET -Path '/user/tokens/verify'
          if ($v.result.status -ne 'active') { throw "Status: $($v.result.status)" }
          Write-OK 'Token valid'
          $tokenValid = $true
        } catch {
          Write-Fail "Invalid token: $($_.Exception.Message)"
          Write-Warn 'Skipping all Cloudflare cleanup steps.'
        }
      }

      $accountId = $_cfg.AccountID

      # ── Custom domain ────────────────────────────────────────────────────────
      if ($_opt.DeleteDomain) {
        Write-Step '2' "Deleting custom domain binding(s)..."
        if ($tokenValid -and $_opt.DomainHost) {
          try {
            $domains = (Invoke-CF -Method GET -Path "/accounts/$accountId/workers/domains?service=$WorkerName&environment=production").result
            $matched = @($domains | Where-Object {
              ($_.hostname -eq $_opt.DomainHost) -or ($_.service -eq $WorkerName)
            })
            if ($matched.Count -eq 0) {
              Write-Warn "No matching custom domain found for '$($_opt.DomainHost)'"
            } else {
              foreach ($d in $matched) {
                try {
                  Invoke-CF -Method DELETE -Path "/accounts/$accountId/workers/domains/$($d.id)" | Out-Null
                  Write-OK "Custom domain '$($d.hostname)' detached"
                } catch {
                  Write-Warn "Failed to detach '$($d.hostname)': $($_.Exception.Message)"
                }
              }
            }
          } catch {
            Write-Warn "Custom-domain enumeration failed: $($_.Exception.Message)"
          }
        } else {
          Write-Warn 'Skipped (no valid token or no custom domain in config)'
        }
      }

      # ── Worker script ────────────────────────────────────────────────────────
      if ($_opt.DeleteWorker) {
        Write-Step '3' 'Deleting Worker script...'
        if ($tokenValid) {
          try {
            Invoke-CF -Method DELETE -Path "/accounts/$accountId/workers/scripts/$WorkerName" | Out-Null
            Write-OK "Worker '$WorkerName' deleted"
          } catch {
            if ($_.Exception.Message -match '404') { Write-Warn "Worker '$WorkerName' already absent" }
            else { Write-Warn "Worker delete failed: $($_.Exception.Message)" }
          }
        } else {
          Write-Warn 'Skipped (no valid token)'
        }
      }

      # ── KV namespace ─────────────────────────────────────────────────────────
      if ($_opt.DeleteKv) {
        Write-Step '4' 'Deleting KV namespace...'
        if ($tokenValid) {
          try {
            $ns = (Invoke-CF -Method GET -Path "/accounts/$accountId/storage/kv/namespaces").result
            $found = $ns | Where-Object { $_.title -eq $KVNamespace } | Select-Object -First 1
            if ($found) {
              Invoke-CF -Method DELETE -Path "/accounts/$accountId/storage/kv/namespaces/$($found.id)" | Out-Null
              Write-OK "KV namespace '$KVNamespace' deleted (manifest, password, secrets, events)"
            } else {
              Write-Warn "KV namespace '$KVNamespace' not found — already absent"
            }
          } catch {
            Write-Warn "KV delete failed: $($_.Exception.Message)"
          }
        } else {
          Write-Warn 'Skipped (no valid token)'
        }
      }

      # ── Local app artefacts ──────────────────────────────────────────────────
      if ($_opt.DeleteApps -and $_opt.AppIds) {
        Write-Step '5' "Removing local artefacts for $($_opt.AppIds.Count) app(s)..."
        foreach ($entry in $_opt.AppIds) {
          $appId  = if ($entry -is [string]) { $entry } else { $entry.ID }
          $appDn  = if ($entry -is [string]) { $entry } else { $entry.DisplayName }
          try {
            $report = Remove-AppLocalArtifacts -AppID $appId -DisplayName $appDn
            foreach ($ln in $report.Lines) { Write-Host $ln -ForegroundColor $(if ($ln -match '\[!!\]') {'Yellow'} elseif ($ln -match '\[OK\]') {'Green'} else {'Gray'}) }
          } catch {
            Write-Warn "Cleanup failed for ${appId}: $($_.Exception.Message)"
          }
        }
      }

      # ── Local config (always required) ───────────────────────────────────────
      Write-Step '6' 'Deleting local config + manifest token...'
      try {
        if (Test-Path -LiteralPath $_cfile) { Remove-Item -LiteralPath $_cfile -Force -ErrorAction Stop; Write-OK 'Removed config file' }
        else { Write-Warn 'Config file already absent' }
        if (Test-Path -LiteralPath $_tfile) { Remove-Item -LiteralPath $_tfile -Force -ErrorAction Stop; Write-OK 'Removed manifest token' }
        else { Write-Warn 'Manifest token already absent' }
        if (Test-Path -LiteralPath $_xfile) { Remove-Item -LiteralPath $_xfile -Force -ErrorAction Stop; Write-OK 'Removed local appVersions.xml' }
      } catch {
        Write-Fail "Local cleanup failed: $($_.Exception.Message)"
        $_d.Add('error'); return
      }

      Write-Host '' -ForegroundColor White
      Write-Host '=== FULL RESET COMPLETE ===' -ForegroundColor Green
      Write-Host '' -ForegroundColor White
      Write-Host 'Close this window and re-run AppUpdater for a fresh first-run wizard.' -ForegroundColor White
      $_d.Add('ok')
    }) | Out-Null

    $rsHandle = $rsPs.BeginInvoke()

    # Progress window — shows every step live; user closes manually when done.
    $rsWin = New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="560" Height="440" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/><RowDefinition Height="60"/></Grid.RowDefinitions>
    <Border x:Name="RSTB" Background="#1a0a0a" BorderBrush="#4a1a1a" BorderThickness="0,0,0,1">
      <Grid Height="74" Margin="20,0">
        <StackPanel VerticalAlignment="Center">
          <TextBlock x:Name="RST" Text="Full Reset in progress..." FontSize="15" FontWeight="SemiBold" Foreground="#ff8888" TextWrapping="Wrap"/>
          <TextBlock x:Name="RSS" Text="Deleting Worker, KV namespace, and local config" FontSize="11" Foreground="#664444" Margin="0,3,0,0"/>
        </StackPanel>
      </Grid>
    </Border>
    <RichTextBox x:Name="RSL" Grid.Row="1" Background="#07070f" Foreground="#666688"
      BorderThickness="0" Padding="16" IsReadOnly="True" FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
    <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
      <Button x:Name="RSC" Content="Working..." Style="{StaticResource Btn}" Width="180" HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
    </Border>
  </Grid>
</Window>
"@)
    if ($rsWin) {
      $rsEl  = Get-El $rsWin @('RST','RSS','RSL','RSC','RSTB')
      $rsDoc = $rsEl['RSL'].Document; $rsDoc.Blocks.Clear()
      $rsPara = [Windows.Documents.Paragraph]::new(); $rsDoc.Blocks.Add($rsPara)
      $rsEl['RSTB'].Add_MouseLeftButtonDown({ $rsWin.DragMove() })
      $rsCm  = @{ ok='#4ec94e'; info='#6baadf'; warn='#f5c842'; err='#ff6060'; white='#e8e8f4'; gray='#666688' }
      $rsTmr = [System.Windows.Threading.DispatcherTimer]::new()
      $rsTmr.Interval = [TimeSpan]::FromMilliseconds(200)
      $rsTmr.Add_Tick({
        $line = ''
        while ($rsQ.TryDequeue([ref]$line)) {
          $parts = $line -split '\|', 2
          $hex   = $rsCm[$parts[0]]; if (-not $hex) { $hex = '#888' }
          $text  = if ($parts.Count -gt 1) { $parts[1] } else { $line }
          $run   = [Windows.Documents.Run]::new("$text`n")
          $rByte = [Convert]::ToByte($hex.Substring(1,2),16)
          $gByte = [Convert]::ToByte($hex.Substring(3,2),16)
          $bByte = [Convert]::ToByte($hex.Substring(5,2),16)
          $run.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($rByte,$gByte,$bByte))
          $rsPara.Inlines.Add($run); $rsEl['RSL'].ScrollToEnd()
        }
        if ($rsD.Count -gt 0) {
          $rsTmr.Stop()
          $ok = $rsD[0] -eq 'ok'
          $rsEl['RST'].Text = if ($ok) { 'Reset complete' } else { 'Reset finished with errors' }
          $rsEl['RSS'].Text = if ($ok) { 'Close this window, then run AppUpdater again' } else { 'See log above' }
          $rsEl['RSC'].IsEnabled = $true
          $rsEl['RSC'].Content   = if ($ok) { 'Close AppUpdater' } else { 'Close' }
          $rsPs.EndInvoke($rsHandle) | Out-Null; $rsRs.Close()
        }
      })
      $rsEl['RSC'].Add_Click({ $rsWin.Close() })
      $rsWin.Add_ContentRendered({ $rsTmr.Start() })
      $rsWin.Add_Closing({ if ($rsTmr.IsEnabled) { $rsTmr.Stop() } })
      $rsWin.ShowDialog() | Out-Null
    } else {
      $rsPs.EndInvoke($rsHandle) | Out-Null; $rsRs.Close()
    }

    # Whether successful or not, exit so the user has a clean slate to re-run.
    Write-AppLog 'Full Reset finished — exiting.' INFO
    exit 0
  }
  6 {
    $script:_importBuildList = $null
    $script:_amendFD = $null
    Show-WpfManifestManager -XmlFile $XmlFile -Config $config
    if ($script:_importBuildList -and $script:_importBuildList.Count -gt 0) {
      $importList = $script:_importBuildList; $script:_importBuildList = $null
      $outChoiceI = Show-WpfOutputChoice -AppID "Batch ($($importList.Count) apps)"
      if ($outChoiceI) {
        Write-AppLog "Import batch build: $($importList.Count) apps, output=$outChoiceI"
        foreach ($ifd in $importList) {
          Write-AppLog "Batch building: $($ifd.AppID)"
          $bqI=[System.Collections.Concurrent.ConcurrentQueue[string]]::new()
          $bdI=[System.Collections.Generic.List[string]]::new()
          $brsI=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
          $brsI.ApartmentState='MTA'; $brsI.ThreadOptions='ReuseThread'; $brsI.Open()
          $brsI.SessionStateProxy.SetVariable('_bq',$bqI)
          $brsI.SessionStateProxy.SetVariable('_bd',$bdI)
          $brsI.SessionStateProxy.SetVariable('_cfg',$config)
          $brsI.SessionStateProxy.SetVariable('_fd',$ifd)
          $brsI.SessionStateProxy.SetVariable('_oc',$outChoiceI)
          foreach ($vnI in @('ScriptPath','ScriptDir','XmlFile','ConfigFile','ManifestTokenFile',
            'IntuneWinUtilURL','IntuneWinUtilPath','TempBase','OutputBase','CF_API','WorkerName','KVNamespace')) {
            $brsI.SessionStateProxy.SetVariable($vnI,(Get-Variable $vnI -ValueOnly -EA SilentlyContinue))
          }
          $_fnsI=(@('Invoke-PackageBuilder','Invoke-InstallerInspector','Get-InstalledVersion',
            'Read-MsiProperties','Get-InstallerType','Get-SilentArgs',
            'Protect-ManifestToken','Unprotect-ManifestToken','Get-StoredManifestToken',
            'Test-SafeAppId','Test-SafeFileName','Test-SafeHttpsUrl','Test-SafeSubdomainLabel',
            'ConvertTo-SafeFsName','Resolve-SafeChildPath',
            'Set-PhaseActive','Set-PhaseDone','Set-Pill',
            'Write-AppLog','Write-OK','Write-Warn','Write-Fail','Write-Step','Write-Info',
            'Write-Rule','Write-BoxTop','Write-BoxBot','Write-BoxLine') | ForEach-Object {
              $fn=Get-Item "Function:\$_" -EA SilentlyContinue; if($fn){"function $_ {`n$($fn.ScriptBlock)`n}"}
          }) -join "`n"
          $brsI.SessionStateProxy.SetVariable('_fnSrc',$_fnsI)
          $bpsI=[System.Management.Automation.PowerShell]::Create(); $bpsI.Runspace=$brsI
          $bpsI.AddScript({
            function New-WpfWin{param([string]$x)return $null}; function Get-El{param($w,[string[]]$n)return @{}}
            function Get-HeaderXaml{param([string]$t,[string]$s='',[bool]$b=$false,[bool]$c=$true,[bool]$bg=$false)return ''}
            function Set-WinBehavior{param($w,[scriptblock]$OC=$null,[scriptblock]$OB=$null)}
            function Show-WpfMsg{param([string]$T='',[string]$M='',[string]$Ty='info',[switch]$Confirm)$_bq.Enqueue("info|[$T] $M");return $true}
            function Show-WpfOutputChoice{param([string]$AppID='')return $_oc}
            function Show-WpfFirstRun{return @{mode='offline';orgName='IT Services'}}
            function Show-WpfMainMenu{param([hashtable]$Config)return 6}
            function Show-WpfAppForm{param([hashtable]$D=@{},[bool]$H=$false,[bool]$AE=$true)return $null}
            function Show-WpfCloudflareWizard{param([string]$OrgName='')return $null}
            function Show-WpfPSADTExport{param([string]$AppID='',[string]$DisplayName='',[string]$ProcessesToKill='',[string]$ExpectedPub='',[string]$OrgName='')$_bq.Enqueue("info|Build complete. Use the PSADT button in the app list to export as a PSADT package.")}
            function Export-PSADTPackage{param([string]$AppID='',[string]$DisplayName='',[string]$ProcessesToKill='',[string]$ExpectedPub='',[string]$PSADTVersion='v3',[string]$PSADTToolkitPath='',[string]$OrgName='')}
            function Get-PSADTToolkit{param([string]$ManualPath='')return $null}
            function Invoke-SimpleBuildCore{param([hashtable]$Config=@{},[hashtable]$FormData=@{})}
            function Show-WpfSimpleIntuneResult{param([string]$AppID='',[string]$DisplayName='',[string]$OutputDir='',[string]$RegistryName='')}
            function Show-WpfSimplePSADTResult{param([string]$AppID='',[string]$DisplayName='',[string]$OutputDir='',[string]$PSADTVer='v3',[string]$RegistryName='')}
            function Show-WpfPackageReadyDialog{param([string]$Title='',[string]$IntuneWinFile='',[string]$OutputDir='',[string]$InstallCmd='',[string]$UninstallCmd='',[string]$RegistryName='',[string]$PSADTVer='',[string]$DeployScriptPath='')}
            function Show-WpfSimplePSADTToolkit{param([string]$InitialError='')return $null}
            function Write-AppLog{param([string]$Message,[string]$Level='INFO')}
            function Write-Host{param([object]$O,[string]$FC='Gray',[switch]$NL)
              $c=switch($FC){'Green'{'ok'}'Cyan'{'info'}'Yellow'{'warn'}'Red'{'err'}'DarkGray'{'dim'}'White'{'white'}default{'gray'}}
              $_bq.Enqueue("$c|$O")}
            function Write-OK{param([string]$M)Write-Host "  OK  $M" -FC Green}
            function Write-Warn{param([string]$M)Write-Host "  !!  $M" -FC Yellow}
            function Write-Fail{param([string]$M)Write-Host "  XX  $M" -FC Red}
            function Write-Step{param([string]$n,[string]$M)Write-Host "  [$n] $M" -FC Cyan}
            function Write-Info{param([string]$M)Write-Host "       $M" -FC DarkGray}
            function Write-Rule{}; function Write-BoxTop{param($C)}; function Write-BoxBot{param($C)}
            function Write-BoxLine{param([string]$m,$C)Write-Host "  $m" -FC $C}
            try{Invoke-Expression $_fnSrc}catch{$_bq.Enqueue("err|Load failed: $($_.Exception.Message)");$_bd.Add('error');return}
            try{Invoke-PackageBuilder -Config $_cfg -FormData $_fd;$_bd.Add('ok')}
            catch{$_bq.Enqueue("err|ERROR: $($_.Exception.Message)");$_bd.Add('error')}
          }) | Out-Null
          $bhI=$bpsI.BeginInvoke()
          $bpI=New-WpfWin (@"
<Window WindowStyle="None" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  Width="560" Height="460" WindowStartupLocation="CenterScreen"
  ResizeMode="CanMinimize" Background="#0f0f1a" FontFamily="Segoe UI">
$($script:S)
  <Grid>
  <Grid.RowDefinitions><RowDefinition Height="74"/><RowDefinition Height="*"/><RowDefinition Height="60"/></Grid.RowDefinitions>
  <Border x:Name="TBI" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,0,0,1">
  <Grid Height="74" Margin="20,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
  <StackPanel VerticalAlignment="Center">
 <TextBlock x:Name="BTI" Text="Building $($ifd.AppID)..." FontSize="15" FontWeight="SemiBold" Foreground="#e8e8f4" TextWrapping="Wrap" />
  <TextBlock x:Name="BSI" Text="Please wait" FontSize="11" Foreground="#44445a" Margin="0,3,0,0"/>
  </StackPanel></Grid></Border>
  <RichTextBox x:Name="BLI" Grid.Row="1" Background="#07070f" Foreground="#666688"
    BorderThickness="0" Padding="16" IsReadOnly="True" FontFamily="Consolas" FontSize="11" VerticalScrollBarVisibility="Auto"/>
  <Border Grid.Row="2" Background="#09090f" BorderBrush="#1a1a2e" BorderThickness="0,1,0,0">
  <Button x:Name="BCI" Content="Building..." Style="{StaticResource Btn}" Width="120" HorizontalAlignment="Right" Margin="0,0,20,0" IsEnabled="False"/>
  </Border>
  </Grid>
</Window>
"@)
          if ($bpI) {
            $bpIEl=Get-El $bpI @('BTI','BSI','BLI','BCI','TBI')
            $bpIDoc=$bpIEl['BLI'].Document; $bpIDoc.Blocks.Clear()
            $bpIPara=[Windows.Documents.Paragraph]::new(); $bpIDoc.Blocks.Add($bpIPara)
            $bpIEl['TBI'].Add_MouseLeftButtonDown({$bpI.DragMove()})
            $bpCmI=@{ok='#4ec94e';info='#6baadf';warn='#f5c842';err='#ff6060';dim='#444460';white='#e8e8f4';gray='#666688'}
            $bpTmrI=[System.Windows.Threading.DispatcherTimer]::new()
            $bpTmrI.Interval=[TimeSpan]::FromMilliseconds(200)
            $bpTmrI.Add_Tick({
              $miI=''
              while($bqI.TryDequeue([ref]$miI)){
                $piI=$miI -split '\|',2; $ciI=$bpCmI[$piI[0]]; if(-not$ciI){$ciI='#888'}
                $tiI=if($piI.Count-gt 1){$piI[1]}else{$miI}
                $riI=[Windows.Documents.Run]::new("$tiI`n")
                $rbI=[Convert]::ToByte($ciI.Substring(1,2),16);$gbI=[Convert]::ToByte($ciI.Substring(3,2),16);$bbI=[Convert]::ToByte($ciI.Substring(5,2),16)
                $riI.Foreground=[Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb($rbI,$gbI,$bbI))
                $bpIPara.Inlines.Add($riI); $bpIEl['BLI'].ScrollToEnd()
              }
              if($bdI.Count-gt 0){
                $bpTmrI.Stop(); $okI=$bdI[0]-eq'ok'
                $bpIEl['BTI'].Text=if($okI){'Build complete'}else{'Build finished with errors'}
                $bpIEl['BSI'].Text=if($okI){'Package ready'}else{'Check output above'}
                $bpIEl['BCI'].IsEnabled=$true
                $bpIEl['BCI'].Content=if($okI){'Done  ✓'}else{'Close'}
                $bpIEl['BCI'].Style=$bpI.Resources[$(if($okI){'BtnSuccess'}else{'Btn'})]
                $bpsI.EndInvoke($bhI)|Out-Null; $brsI.Close()
              }
            })
            $bpIEl['BCI'].Add_Click({$bpI.Close()})
            $bpI.Add_ContentRendered({$bpTmrI.Start()})
            $bpI.Add_Closing({if($bpTmrI.IsEnabled){$bpTmrI.Stop()}})
            $bpI.ShowDialog() | Out-Null
          } else {
            $bpsI.EndInvoke($bhI)|Out-Null; $brsI.Close()
          }
        }
        Write-AppLog "Import batch build complete"
      }
    }
    continue
  }
  7 { exit 0 }
  0 { continue }  # window failed to show — loop back safely
  }
}
