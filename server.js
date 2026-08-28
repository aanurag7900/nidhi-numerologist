const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const sessions = new Map();
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
function setSession(response, user) { const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, expires: Date.now() + ONE_WEEK * 1000 }); response.setHeader('Set-Cookie', `nidhi_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ONE_WEEK}`); }
function currentUser(request) { const token = parseCookies(request).nidhi_session; const session = token && sessions.get(token); if (!session || session.expires < Date.now()) { if (token) sessions.delete(token); return null; } return session.userId; }
function publicUser(user) { return { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email }; }
async function bodyJson(request) { let raw = ''; for await (const chunk of request) { raw += chunk; if (raw.length > 1_000_000) throw new Error('Request too large'); } try { return JSON.parse(raw || '{}'); } catch { throw new Error('Invalid request'); } }

async function handleApi(request, response, pathname) {
  if (request.method === 'POST' && pathname === '/api/register') {
    const { firstName = '', lastName = '', email = '', password = '' } = await bodyJson(request);
    const clean = { firstName: firstName.trim(), lastName: lastName.trim(), email: email.trim().toLowerCase(), password };
    if (!clean.firstName || !clean.lastName || !/^\S+@\S+\.\S+$/.test(clean.email) || clean.password.length < 6) return send(response, 400, { error: 'Please enter a first name, last name, valid email and password of at least 6 characters.' });
    const users = await readUsers();
    if (users.some(user => user.email === clean.email)) return send(response, 409, { error: 'An account already exists with this email. Please sign in instead.' });
    const { salt, hash } = await hashPassword(clean.password);
    const user = { id: crypto.randomUUID(), firstName: clean.firstName, lastName: clean.lastName, email: clean.email, salt, passwordHash: hash, createdAt: new Date().toISOString() };
    users.push(user); await saveUsers(users); setSession(response, user); return send(response, 201, { user: publicUser(user) });
  }
  if (request.method === 'POST' && pathname === '/api/login') {
    const { email = '', password = '' } = await bodyJson(request); const users = await readUsers(); const user = users.find(item => item.email === email.trim().toLowerCase());
    if (!user || !(await passwordsMatch(password, user))) return send(response, 401, { error: 'Incorrect email or password.' });
    setSession(response, user); return send(response, 200, { user: publicUser(user) });
  }
  if (request.method === 'GET' && pathname === '/api/me') {
    const userId = currentUser(request); const user = userId && (await readUsers()).find(item => item.id === userId); return user ? send(response, 200, { user: publicUser(user) }) : send(response, 401, { error: 'Please sign in.' });
  }
  if (request.method === 'POST' && pathname === '/api/logout') {
    const token = parseCookies(request).nidhi_session; if (token) sessions.delete(token); return send(response, 200, { ok: true }, { 'Set-Cookie': 'nidhi_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
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
  try { const url = new URL(request.url, `http://${request.headers.host}`); if (url.pathname.startsWith('/api/')) return await handleApi(request, response, url.pathname); return await serveStatic(response, decodeURIComponent(url.pathname)); }
  catch (error) { console.error(error); return send(response, 500, { error: 'Something went wrong. Please try again.' }); }
});
server.listen(PORT, () => console.log(`Nidhi Numerologist is running on http://localhost:${PORT}`));
