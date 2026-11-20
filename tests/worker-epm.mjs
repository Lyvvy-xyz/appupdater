// Vendor release check routes of the Cloudflare worker embedded in host.ps1, against an in-memory KV and a local signing key.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const hostPs1 = readFileSync(process.argv[2] || new URL('../host.ps1', import.meta.url), 'utf8');
const chunks = /^\$__CoreB64Chunks = @\(\r?\n([\s\S]*?)^\)/m.exec(hostPs1)[1].match(/'[A-Za-z0-9+\/=]+'/g).map(c => c.slice(1, -1)).join('');
const engine = Buffer.from(chunks, 'base64').toString('utf8');
const start = engine.indexOf("$WorkerSource = @'\n") + "$WorkerSource = @'\n".length;
const file = join(mkdtempSync(join(tmpdir(), 'worker-')), 'worker.mjs');
writeFileSync(file, engine.slice(start, engine.indexOf("\n'@", start)));
const mod = (await import(file)).default;
const kv = new Map();
const env = { AUTH_TOKEN: 'app-token', APP_MANIFEST: { get: async k => kv.get(k) ?? null, put: async (k, v) => { kv.set(k, v); } } };
const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const other = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
globalThis.fetch = async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: 'k1', use: 'sig', alg: 'RS256' }] }));
const b64u = b => Buffer.from(b).toString('base64url');
async function jwt(claims, key = kp.privateKey) {
  const h = b64u(JSON.stringify({ alg: 'RS256', kid: 'k1' })), p = b64u(JSON.stringify(claims));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(h + '.' + p));
  return h + '.' + p + '.' + b64u(sig);
}
const O = 'https://w.example.workers.dev', now = Math.floor(Date.now() / 1000);
const good = { iss: 'https://token.actions.githubusercontent.com', aud: O, exp: now + 300, repository_id: 42, run_id: 7, workflow_ref: 'o/appupdater-checks/.github/workflows/epm-check.yml@refs/heads/main' };
const call = (path, init = {}) => mod.fetch(new Request(O + path, init), env);
const runner = async (path, claims, body, key) => call(path, { method: body ? 'POST' : 'GET', body, headers: { Authorization: 'Bearer ' + await jwt(claims, key) } });
const app = (method, body) => call('/epm/state', { method, body, headers: { 'X-Auth-Token': 'app-token' } });

assert.equal((await runner('/epm/apps', good)).status, 401, 'no repo configured yet');
assert.equal((await call('/epm/state')).status, 401, 'state needs the app token');
let r = await app('PUT', JSON.stringify({ cfg: { repo: 'o/appupdater-checks', repoId: 42 }, apps: [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }] }));
assert.equal(r.status, 200);
assert.equal((await runner('/epm/apps', good)).status, 200);
assert.ok(JSON.parse(kv.get('epm:last')).at, 'a run is recorded');
for (const [why, claims, key] of [
  ['other repo', { ...good, repository_id: 43 }], ['other audience', { ...good, aud: 'https://evil.example' }],
  ['expired', { ...good, exp: now - 10 }], ['other workflow', { ...good, workflow_ref: 'o/appupdater-checks/.github/workflows/evil.yml@refs/heads/main' }], ['other issuer', { ...good, iss: 'https://evil.example' }], ['other key', good, other.privateKey]]) {
  assert.equal((await runner('/epm/apps', claims, undefined, key)).status, 401, why);
}
r = await runner('/epm/result', good, JSON.stringify({ results: [
  { id: 'a', version: '2.0', status: 'ok', sha256: 'AB' }, { id: 'b', version: '9', status: 'error' }, { id: 'zz', version: '1', status: 'ok' }] }));
assert.equal(r.status, 200);
let st = await (await app('GET')).json();
assert.deepEqual(st.known, { a: '2.0' }, 'errors are retried, unknown ids ignored');
assert.deepEqual(Object.keys(st.results).sort(), ['a', 'b']);
st = await (await app('PUT', JSON.stringify({ apps: [{ id: 'b', name: 'B' }] }))).json();
assert.deepEqual(st.known, {}, 'removing an app drops its version');
assert.deepEqual(Object.keys(st.results), ['b']);
console.log('worker epm tests passed');
