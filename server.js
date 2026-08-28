const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const sessions = new Map();
const oauthStates = new Map();
const ONE_WEEK = 7 * 24 * 60 * 60;
const MIME_TYPES = { '.css': 'text/css', '.html': 'text/html', '.js': 'application/javascript', '.json': 'application/json', '.ico': 'image/x-icon' };

async function ensureUsersFile() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try { await fs.access(USERS_FILE); } catch { await fs.writeFile(USERS_FILE, '[]', 'utf8'); }
}
async function readUsers() { await ensureUsersFile(); return JSON.parse(await fs.readFile(USERS_FILE, 'utf8')); }
async function saveUsers(users) { await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8'); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) { return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (error, derivedKey) => error ? reject(error) : resolve({ salt, hash: derivedKey.toString('hex') }))); }
async function passwordsMatch(password, user) { const candidate = await hashPassword(password, user.salt); return crypto.timingSafeEqual(Buffer.from(candidate.hash, 'hex'), Buffer.from(user.passwordHash, 'hex')); }
function parseCookies(request) { return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map(item => { const [key, ...value] = item.trim().split('='); return [key, decodeURIComponent(value.join('='))]; })); }
function send(response, status, payload, headers = {}) { response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers }); response.end(JSON.stringify(payload)); }
function isSecureRequest(request) { return request.headers['x-forwarded-proto'] === 'https' || (!request.headers['x-forwarded-proto'] && process.env.NODE_ENV === 'production'); }
function cookieOptions(request) { return `HttpOnly; SameSite=Lax; Path=/;${isSecureRequest(request) ? ' Secure;' : ''}`; }
function appendCookie(response, value) { const previous = response.getHeader('Set-Cookie'); response.setHeader('Set-Cookie', previous ? [...(Array.isArray(previous) ? previous : [previous]), value] : value); }
function setSession(request, response, user) { const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, expires: Date.now() + ONE_WEEK * 1000 }); appendCookie(response, `nidhi_session=${token}; ${cookieOptions(request)} Max-Age=${ONE_WEEK}`); }
function currentUser(request) { const token = parseCookies(request).nidhi_session; const session = token && sessions.get(token); if (!session || session.expires < Date.now()) { if (token) sessions.delete(token); return null; } return session.userId; }
function publicUser(user) { return { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email }; }
async function bodyJson(request) { let raw = ''; for await (const chunk of request) { raw += chunk; if (raw.length > 1_000_000) throw new Error('Request too large'); } try { return JSON.parse(raw || '{}'); } catch { throw new Error('Invalid request'); } }
function redirect(response, location) { response.writeHead(302, { Location: location }); response.end(); }
function callbackUrl(request) { if (process.env.GOOGLE_CALLBACK_URL) return process.env.GOOGLE_CALLBACK_URL; const protocol = isSecureRequest(request) ? 'https' : 'http'; return `${protocol}://${request.headers.host}/auth/google/callback`; }
function loginError(response, message) { redirect(response, `/login.html?error=${encodeURIComponent(message)}`); }

async function startGoogleLogin(request, response) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId || !process.env.GOOGLE_CLIENT_SECRET) return loginError(response, 'Google sign-in has not been configured yet.');
  const state = crypto.randomBytes(32).toString('hex');
  oauthStates.set(state, Date.now() + 10 * 60 * 1000);
  const params = new URLSearchParams({ client_id: clientId, redirect_uri: callbackUrl(request), response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
  appendCookie(response, `nidhi_oauth_state=${state}; ${cookieOptions(request)} Max-Age=600`);
  redirect(response, `https://accounts.google.com/o/oauth2/v2/auth?${params}`);
}

async function finishGoogleLogin(request, response, url) {
  const code = url.searchParams.get('code'); const state = url.searchParams.get('state');
  if (url.searchParams.get('error')) return loginError(response, 'Google sign-in was cancelled.');
  const savedState = parseCookies(request).nidhi_oauth_state; const expires = state && oauthStates.get(state);
  if (state) oauthStates.delete(state);
  appendCookie(response, `nidhi_oauth_state=; ${cookieOptions(request)} Max-Age=0`);
  if (!code || !state || state !== savedState || !expires || expires < Date.now()) return loginError(response, 'Your Google sign-in link expired. Please try again.');
  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, redirect_uri: callbackUrl(request), grant_type: 'authorization_code' }) });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok || !tokens.access_token) throw new Error('Token exchange failed');
    const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.sub || !profile.email || profile.email_verified !== true) throw new Error('Profile could not be verified');
    const users = await readUsers(); let user = users.find(item => item.email === profile.email.toLowerCase());
    if (!user) { const names = (profile.name || '').trim().split(/\s+/).filter(Boolean); user = { id: crypto.randomUUID(), firstName: profile.given_name || names[0] || 'Google', lastName: profile.family_name || names.slice(1).join(' ') || 'User', email: profile.email.toLowerCase(), authProvider: 'google', googleSubject: profile.sub, createdAt: new Date().toISOString() }; users.push(user); await saveUsers(users); }
    setSession(request, response, user); return redirect(response, '/dashboard.html');
  } catch (error) { console.error('Google OAuth error:', error.message); return loginError(response, 'Google sign-in could not be completed. Please try again.'); }
}

async function handleApi(request, response, pathname) {
  if (request.method === 'POST' && pathname === '/api/register') {
    const { firstName = '', lastName = '', email = '', password = '' } = await bodyJson(request);
    const clean = { firstName: firstName.trim(), lastName: lastName.trim(), email: email.trim().toLowerCase(), password };
    if (!clean.firstName || !clean.lastName || !/^\S+@\S+\.\S+$/.test(clean.email) || clean.password.length < 6) return send(response, 400, { error: 'Please enter a first name, last name, valid email and password of at least 6 characters.' });
    const users = await readUsers();
    if (users.some(user => user.email === clean.email)) return send(response, 409, { error: 'An account already exists with this email. Please sign in instead.' });
    const { salt, hash } = await hashPassword(clean.password);
    const user = { id: crypto.randomUUID(), firstName: clean.firstName, lastName: clean.lastName, email: clean.email, salt, passwordHash: hash, createdAt: new Date().toISOString() };
    users.push(user); await saveUsers(users); setSession(request, response, user); return send(response, 201, { user: publicUser(user) });
  }
  if (request.method === 'POST' && pathname === '/api/login') {
    const { email = '', password = '' } = await bodyJson(request); const users = await readUsers(); const user = users.find(item => item.email === email.trim().toLowerCase());
    if (!user || !user.passwordHash || !(await passwordsMatch(password, user))) return send(response, 401, { error: 'Incorrect email or password.' });
    setSession(request, response, user); return send(response, 200, { user: publicUser(user) });
  }
  if (request.method === 'GET' && pathname === '/api/me') {
    const userId = currentUser(request); const user = userId && (await readUsers()).find(item => item.id === userId); return user ? send(response, 200, { user: publicUser(user) }) : send(response, 401, { error: 'Please sign in.' });
  }
  if (request.method === 'POST' && pathname === '/api/logout') {
    const token = parseCookies(request).nidhi_session; if (token) sessions.delete(token); return send(response, 200, { ok: true }, { 'Set-Cookie': `nidhi_session=; ${cookieOptions(request)} Max-Age=0` });
  }
  return send(response, 404, { error: 'Not found' });
}

async function serveStatic(response, pathname) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(ROOT, requested));
  if (!file.startsWith(ROOT) || path.extname(file) === '') { response.writeHead(404); return response.end('Not found'); }
  try { const content = await fs.readFile(file); response.writeHead(200, { 'Content-Type': `${MIME_TYPES[path.extname(file)] || 'application/octet-stream'}; charset=utf-8` }); response.end(content); } catch { response.writeHead(404); response.end('Not found'); }
}

const server = http.createServer(async (request, response) => {
  try { const url = new URL(request.url, `http://${request.headers.host}`); if (request.method === 'GET' && url.pathname === '/auth/google') return await startGoogleLogin(request, response); if (request.method === 'GET' && url.pathname === '/auth/google/callback') return await finishGoogleLogin(request, response, url); if (url.pathname.startsWith('/api/')) return await handleApi(request, response, url.pathname); return await serveStatic(response, decodeURIComponent(url.pathname)); }
  catch (error) { console.error(error); return send(response, 500, { error: 'Something went wrong. Please try again.' }); }
});
server.listen(PORT, () => console.log(`Nidhi Numerologist is running on http://localhost:${PORT}`));
