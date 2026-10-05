import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadStore, saveStore, hashText, hashPassword, verifyPassword } from './store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 4100);
const NODE_ENV = process.env.NODE_ENV || 'development';
const SESSION_SECRET = process.env.SESSION_SECRET || 'development-only-change-this-secret-32';
const CORS_ORIGIN = process.env.CORS_ORIGIN || `http://localhost:${PORT}`;
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
const sessions = new Map();
const rateBuckets = new Map();
const MAX_BODY = 32 * 1024;
let store;

if (NODE_ENV === 'production' && SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters in production');
if (NODE_ENV === 'production' && !process.env.CORS_ORIGIN) throw new Error('CORS_ORIGIN must be explicitly configured in production');

const json = (value) => JSON.stringify(value);
const now = () => new Date().toISOString();
const id = (prefix) => `${prefix}-${crypto.randomBytes(8).toString('hex')}`;
const safeUser = (user) => ({ id: user.id, name: user.name, email: user.email, role: user.role, patientId: user.patientId, doctorId: user.doctorId });
const requestId = () => crypto.randomBytes(8).toString('hex');

function sign(value) { return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url'); }
function issueSession(userId) {
  const sid = crypto.randomBytes(24).toString('base64url');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sid, { userId, expiresAt, revoked: false });
  return `${sid}.${sign(`${sid}.${userId}.${expiresAt}`)}`;
}
function revokeSession(cookie) {
  const [sid] = String(cookie || '').split('.');
  if (sid && sessions.has(sid)) sessions.get(sid).revoked = true;
}
function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(v => v.trim()).filter(Boolean).map(v => { const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))]; }));
}
function getUser(req) {
  const token = parseCookies(req).ms_session;
  const [sid, signature] = String(token || '').split('.');
  const session = sessions.get(sid);
  if (!session || session.revoked || session.expiresAt < Date.now()) return null;
  const expected = sign(`${sid}.${session.userId}.${session.expiresAt}`);
  if (!signature || signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  return store.users.find(u => u.id === session.userId && u.active) || null;
}
function setCookie(res, value, maxAge = SESSION_TTL_MS / 1000) {
  const flags = [`ms_session=${encodeURIComponent(value)}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${Math.max(0, Math.floor(maxAge))}`];
  if (NODE_ENV === 'production') flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
}
function headers(req, res, rid) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Request-Id', rid);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'");
  if (!req.headers.origin || req.headers.origin === CORS_ORIGIN) res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');
}
function respond(req, res, status, body, rid) { headers(req, res, rid); res.statusCode = status; res.end(json(body)); }
function fail(req, res, status, code, message, rid) { respond(req, res, status, { error: { code, message, requestId: rid } }, rid); }
function validEmail(value) { return typeof value === 'string' && value.length <= 160 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
function validId(value) { return typeof value === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(value); }
function validDate(value) { return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value); }
function validText(value, max = 500) { return typeof value === 'string' && value.trim().length > 0 && value.length <= max; }
function strongPassword(value) { return typeof value === 'string' && value.length >= 12 && value.length <= 128 && /[A-Z]/.test(value) && /[a-z]/.test(value) && /\d/.test(value) && /[^A-Za-z0-9]/.test(value); }
function body(req) {
  return new Promise((resolve, reject) => {
    let raw = ''; let tooLarge = false;
    req.on('data', chunk => { raw += chunk; if (raw.length > MAX_BODY) tooLarge = true; });
    req.on('end', () => { if (tooLarge) return reject(Object.assign(new Error('too_large'), { status: 413 })); try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(Object.assign(new Error('invalid_json'), { status: 400 })); } });
    req.on('error', reject);
  });
}
function rateLimit(key, limit, windowMs) {
  const current = rateBuckets.get(key) || { count: 0, start: Date.now() };
  if (Date.now() - current.start > windowMs) { current.count = 0; current.start = Date.now(); }
  current.count += 1; rateBuckets.set(key, current);
  return current.count <= limit;
}
function userFor(idValue) { return store.users.find(u => u.id === idValue); }
function audit(actor, action, resourceType, resourceId, result, reason, severity = 'INFO', rid = '') {
  const event = { id: id('audit'), actorId: actor?.id || 'anonymous', actorRole: actor?.role || 'ANONYMOUS', action, resourceType, resourceId: resourceId || null, timestamp: now(), result, reason: reason || null, severity, requestId: rid, previousHash: store.settings.previousAuditHash };
  event.hash = hashText(JSON.stringify(event));
  store.settings.previousAuditHash = event.hash;
  store.audit.push(event);
  if (['DENIED', 'BLOCKED', 'SUSPICIOUS'].includes(result) || severity === 'HIGH') store.security.push({ ...event, securityType: action === 'HONEYTOKEN_TRIGGER' ? 'HONEYTOKEN' : 'SECURITY_EVENT' });
  if (result === 'DENIED' && actor?.id) {
    const recentDenied = store.audit.filter(item => item.actorId === actor.id && item.result === 'DENIED' && Date.now() - Date.parse(item.timestamp) < 10 * 60 * 1000);
    if (recentDenied.length >= 3) store.security.push({ ...event, id: id('security'), action: 'ANOMALY_DETECTED', result: 'SUSPICIOUS', severity: 'HIGH', securityType: 'ANOMALY', reason: 'Repeated denied requests in a short window' });
  }
  return saveStore(store);
}
function lockdownBlocks(user) { return store.settings.lockdown && user?.role !== 'ADMIN'; }
function canDoctorAccess(doctor, patientId) { return store.consents.some(c => c.doctorId === doctor.doctorId && c.patientId === patientId && c.active && (!c.expiresAt || c.expiresAt > now())); }
function recordDenied(req, res, user, resourceId, reason, rid, status = 403) { audit(user, 'ACCESS_DENIED', 'MedicalRecord', resourceId, 'DENIED', reason, 'MEDIUM', rid); return fail(req, res, status, 'FORBIDDEN', 'You are not authorized to access this resource.', rid); }
function statsFor(user) {
  const appointments = store.appointments.filter(a => user.role === 'ADMIN' || (user.role === 'PATIENT' ? a.patientId === user.patientId : a.doctorId === user.doctorId));
  return { appointments: appointments.length, records: user.role === 'PATIENT' ? store.records.filter(r => r.patientId === user.patientId).length : user.role === 'DOCTOR' ? store.records.filter(r => canDoctorAccess(user, r.patientId)).length : store.records.length - 1, denied: store.security.filter(e => e.result === 'DENIED').length, alerts: store.security.filter(e => e.severity === 'HIGH').length, lockdown: store.settings.lockdown };
}
async function route(req, res) {
  const rid = requestId();
  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsed.pathname;
  if (req.method === 'OPTIONS') { headers(req, res, rid); res.statusCode = 204; return res.end(); }
  if (req.headers.origin && req.headers.origin !== CORS_ORIGIN) return fail(req, res, 403, 'ORIGIN_BLOCKED', 'Request origin is not allowed.', rid);
  if (pathname === '/api/health' && req.method === 'GET') return respond(req, res, 200, { status: 'ok', service: 'medishield-api', syntheticData: true, timestamp: now() }, rid);
  if (pathname === '/api/auth/register' && req.method === 'POST') {
    if (!rateLimit(`register:${req.socket.remoteAddress || 'unknown'}`, 4, 15 * 60 * 1000)) return fail(req, res, 429, 'RATE_LIMITED', 'Too many registration attempts. Try again later.', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    const email = String(input.email || '').toLowerCase();
    if (!validEmail(email) || !validText(input.name, 100) || !strongPassword(input.password)) return fail(req, res, 400, 'VALIDATION_ERROR', 'Name, valid email, and a strong password are required.', rid);
    if (store.users.some(existing => existing.email === email)) return fail(req, res, 409, 'REGISTRATION_UNAVAILABLE', 'Registration cannot be completed with these details.', rid);
    const patient = { id: id('patient'), name: input.name.trim(), email, role: 'PATIENT', patientId: id('patient-profile'), passwordHash: await hashPassword(input.password), active: true };
    store.users.push(patient); await audit(patient, 'REGISTER', 'User', patient.id, 'ALLOWED', 'Patient registration', 'INFO', rid); return respond(req, res, 201, { user: safeUser(patient) }, rid);
  }
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    const key = `login:${req.socket.remoteAddress || 'unknown'}`;
    if (!rateLimit(key, 8, 5 * 60 * 1000)) { await audit(null, 'LOGIN_RATE_LIMITED', 'Auth', null, 'BLOCKED', 'Too many login attempts', 'HIGH', rid); return fail(req, res, 429, 'RATE_LIMITED', 'Too many attempts. Try again later.', rid); }
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    const user = store.users.find(u => u.email === String(input.email || '').toLowerCase());
    const good = user && user.active && await verifyPassword(String(input.password || ''), user.passwordHash);
    if (!good) { await audit(null, 'LOGIN_FAILED', 'Auth', null, 'DENIED', 'Invalid credentials', 'MEDIUM', rid); return fail(req, res, 401, 'AUTH_FAILED', 'Invalid email or password.', rid); }
    const token = issueSession(user.id); setCookie(res, token); await audit(user, 'LOGIN', 'User', user.id, 'ALLOWED', 'Interactive login', 'INFO', rid); return respond(req, res, 200, { user: safeUser(user), stats: statsFor(user) }, rid);
  }
  const user = getUser(req);
  if (pathname === '/api/auth/logout' && req.method === 'POST') { if (user) { revokeSession(parseCookies(req).ms_session); await audit(user, 'LOGOUT', 'User', user.id, 'ALLOWED', 'Interactive logout', 'INFO', rid); } setCookie(res, '', 0); return respond(req, res, 200, { ok: true }, rid); }
  if (!user) return fail(req, res, 401, 'AUTH_REQUIRED', 'Authentication required.', rid);
  if (pathname === '/api/me' && req.method === 'GET') return respond(req, res, 200, { user: safeUser(user), stats: statsFor(user), lockdown: store.settings.lockdown }, rid);
  if (pathname === '/api/dashboard' && req.method === 'GET') return respond(req, res, 200, { user: safeUser(user), stats: statsFor(user), lockdown: store.settings.lockdown }, rid);
  if (pathname === '/api/profile' && req.method === 'GET') return respond(req, res, 200, { profile: { name: user.name, email: user.email, role: user.role, patientId: user.patientId, doctorId: user.doctorId } }, rid);
  if (pathname === '/api/profile' && req.method === 'PATCH') {
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (!validText(input.name, 100) || !validEmail(input.email)) return fail(req, res, 400, 'VALIDATION_ERROR', 'Name and valid email are required.', rid);
    const email = input.email.toLowerCase();
    if (store.users.some(existing => existing.id !== user.id && existing.email === email)) return fail(req, res, 409, 'EMAIL_UNAVAILABLE', 'That email is already in use.', rid);
    user.name = input.name.trim(); user.email = email; await audit(user, 'UPDATE_PROFILE', 'User', user.id, 'ALLOWED', 'Self-service profile update', 'INFO', rid); return respond(req, res, 200, { profile: { name: user.name, email: user.email, role: user.role, patientId: user.patientId, doctorId: user.doctorId } }, rid);
  }
  if (pathname === '/api/appointments' && req.method === 'GET') {
    const list = store.appointments.filter(a => user.role === 'ADMIN' || (user.role === 'PATIENT' ? a.patientId === user.patientId : a.doctorId === user.doctorId)).map(a => ({ ...a, patientName: userFor(a.patientId)?.name, doctorName: userFor(a.doctorId)?.name }));
    return respond(req, res, 200, { appointments: list }, rid);
  }
  if (pathname === '/api/appointments' && req.method === 'POST') {
    if (user.role !== 'PATIENT') return fail(req, res, 403, 'FORBIDDEN', 'Only patients can book appointments.', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (!validId(input.doctorId) || !userFor(input.doctorId)?.doctorId || !validDate(input.date) || !/^\d{2}:\d{2}$/.test(input.time || '') || !validText(input.reason, 200)) return fail(req, res, 400, 'VALIDATION_ERROR', 'Doctor, date, time, and reason are required.', rid);
    const appointment = { id: id('apt'), patientId: user.patientId, doctorId: input.doctorId, date: input.date, time: input.time, reason: input.reason.trim(), status: 'SCHEDULED', createdAt: now() };
    store.appointments.push(appointment); await audit(user, 'BOOK_APPOINTMENT', 'Appointment', appointment.id, 'ALLOWED', 'Patient booking', 'INFO', rid); return respond(req, res, 201, { appointment }, rid);
  }
  const appointmentMatch = pathname.match(/^\/api\/appointments\/([^/]+)\/status$/);
  if (appointmentMatch && req.method === 'PATCH') {
    const apt = store.appointments.find(a => a.id === appointmentMatch[1]);
    if (!apt) return fail(req, res, 404, 'NOT_FOUND', 'Appointment not found.', rid);
    const allowed = user.role === 'ADMIN' || (user.role === 'DOCTOR' && apt.doctorId === user.doctorId) || (user.role === 'PATIENT' && apt.patientId === user.patientId);
    if (!allowed) return recordDenied(req, res, user, apt.id, 'Appointment ownership mismatch', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    const statuses = user.role === 'PATIENT' ? ['CANCELLED'] : ['CONFIRMED', 'COMPLETED', 'CANCELLED', 'SCHEDULED'];
    if (!statuses.includes(input.status)) return fail(req, res, 400, 'VALIDATION_ERROR', 'Invalid appointment status.', rid);
    apt.status = input.status; await audit(user, input.status === 'CANCELLED' ? 'CANCEL_APPOINTMENT' : 'ADMIN_ACTION', 'Appointment', apt.id, 'ALLOWED', 'Appointment status update', 'INFO', rid); return respond(req, res, 200, { appointment: apt }, rid);
  }
  if (pathname === '/api/records' && req.method === 'GET') {
    if (lockdownBlocks(user)) { await audit(user, 'RECORD_ACCESS', 'MedicalRecord', null, 'BLOCKED', 'Incident lockdown active', 'HIGH', rid); return fail(req, res, 423, 'LOCKDOWN', 'Sensitive record access is blocked during incident lockdown.', rid); }
    const records = store.records.filter(r => r.id !== 'HONEY-001' && (user.role === 'ADMIN' || (user.role === 'PATIENT' && r.patientId === user.patientId) || (user.role === 'DOCTOR' && canDoctorAccess(user, r.patientId)))).map(r => ({ id: r.id, patientId: r.patientId, patientName: userFor(r.patientId)?.name, title: r.title, summary: r.summary, noteCount: r.notes.length }));
    await audit(user, 'VIEW_RECORD_LIST', 'MedicalRecord', null, 'ALLOWED', 'Authorized record listing', 'INFO', rid); return respond(req, res, 200, { records }, rid);
  }
  const recordMatch = pathname.match(/^\/api\/records\/([^/]+)$/);
  if (recordMatch && req.method === 'GET') {
    const recordId = recordMatch[1];
    if (recordId === 'HONEY-001') { await audit(user, 'HONEYTOKEN_TRIGGER', 'MedicalRecord', 'HONEY-001', 'SUSPICIOUS', 'Controlled decoy resource accessed', 'HIGH', rid); return fail(req, res, 403, 'FORBIDDEN', 'You are not authorized to access this resource.', rid); }
    if (lockdownBlocks(user)) { await audit(user, 'VIEW_RECORD', 'MedicalRecord', recordId, 'BLOCKED', 'Incident lockdown active', 'HIGH', rid); return fail(req, res, 423, 'LOCKDOWN', 'Sensitive record access is blocked during incident lockdown.', rid); }
    const record = store.records.find(r => r.id === recordId);
    if (!record) return fail(req, res, 404, 'NOT_FOUND', 'Record not found.', rid);
    const allowed = user.role === 'ADMIN' || (user.role === 'PATIENT' && record.patientId === user.patientId) || (user.role === 'DOCTOR' && canDoctorAccess(user, record.patientId));
    if (!allowed) return recordDenied(req, res, user, recordId, 'Resource relationship or consent check failed', rid);
    await audit(user, 'VIEW_RECORD', 'MedicalRecord', record.id, 'ALLOWED', user.role === 'DOCTOR' ? 'Active patient consent' : 'Owner/admin access', 'INFO', rid); return respond(req, res, 200, { record: { id: record.id, patientId: record.patientId, title: record.title, summary: record.summary, notes: record.notes.map(n => ({ ...n, authorName: userFor(n.authorId)?.name })) } }, rid);
  }
  const noteMatch = pathname.match(/^\/api\/records\/([^/]+)\/notes$/);
  if (noteMatch && req.method === 'POST') {
    if (user.role !== 'DOCTOR') return fail(req, res, 403, 'FORBIDDEN', 'Only doctors can add clinical notes.', rid);
    const record = store.records.find(r => r.id === noteMatch[1]);
    if (!record || record.id === 'HONEY-001') return recordDenied(req, res, user, noteMatch[1], 'Unknown or decoy record', rid, 403);
    if (lockdownBlocks(user)) return fail(req, res, 423, 'LOCKDOWN', 'Sensitive record access is blocked during incident lockdown.', rid);
    if (!canDoctorAccess(user, record.patientId)) return recordDenied(req, res, user, record.id, 'Doctor consent missing or revoked', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (!validText(input.text, 1000)) return fail(req, res, 400, 'VALIDATION_ERROR', 'Note text is required.', rid);
    const note = { id: id('note'), authorId: user.id, text: input.text.trim(), createdAt: now() }; record.notes.push(note); await audit(user, 'UPDATE_RECORD', 'MedicalRecord', record.id, 'ALLOWED', 'Synthetic clinical note added', 'INFO', rid); return respond(req, res, 201, { note: { ...note, authorName: user.name } }, rid);
  }
  if (pathname === '/api/access-history' && req.method === 'GET') {
    const events = store.audit.filter(e => user.role === 'ADMIN' || e.actorId === user.id || (user.role === 'PATIENT' && (e.resourceType === 'MedicalRecord' || e.resourceType === 'Consent') && (e.resourceId === user.patientId || store.records.some(r => r.id === e.resourceId && r.patientId === user.patientId)))).slice(-100).reverse();
    return respond(req, res, 200, { events }, rid);
  }
  if (pathname === '/api/consents' && req.method === 'GET') {
    const consents = store.consents.filter(c => user.role === 'ADMIN' || (user.role === 'PATIENT' ? c.patientId === user.patientId : c.doctorId === user.doctorId)).map(c => ({ ...c, patientName: userFor(c.patientId)?.name, doctorName: userFor(c.doctorId)?.name })); return respond(req, res, 200, { consents }, rid);
  }
  if (pathname === '/api/consents' && req.method === 'POST') {
    if (user.role !== 'PATIENT') return fail(req, res, 403, 'FORBIDDEN', 'Only patients manage consent.', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (!validId(input.doctorId) || !userFor(input.doctorId)?.doctorId) return fail(req, res, 400, 'VALIDATION_ERROR', 'A valid doctor is required.', rid);
    const existing = store.consents.find(c => c.patientId === user.patientId && c.doctorId === input.doctorId);
    if (existing) { existing.active = input.active !== false; existing.expiresAt = input.expiresAt || existing.expiresAt; await audit(user, 'CONSENT_CHANGE', 'Consent', existing.id, 'ALLOWED', existing.active ? 'Consent granted' : 'Consent revoked', 'INFO', rid); return respond(req, res, 200, { consent: existing }, rid); }
    const consent = { id: id('consent'), patientId: user.patientId, doctorId: input.doctorId, active: true, context: 'Patient-managed consent', expiresAt: input.expiresAt || '2026-12-31T23:59:59.000Z', createdAt: now() }; store.consents.push(consent); await audit(user, 'CONSENT_CHANGE', 'Consent', consent.id, 'ALLOWED', 'Consent granted', 'INFO', rid); return respond(req, res, 201, { consent }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/security/summary' && req.method === 'GET') return respond(req, res, 200, { lockdown: store.settings.lockdown, stats: { users: store.users.filter(u => u.active).length, securityEvents: store.security.length, denied: store.security.filter(e => e.result === 'DENIED').length, failedLogins: store.audit.filter(e => e.action === 'LOGIN_FAILED').length, honeytokens: store.security.filter(e => e.securityType === 'HONEYTOKEN').length, suspicious: store.security.filter(e => e.result === 'SUSPICIOUS').length }, recent: store.audit.slice(-25).reverse() }, rid);
  if (user.role === 'ADMIN' && pathname === '/api/security/events' && req.method === 'GET') return respond(req, res, 200, { events: store.security.slice(-200).reverse() }, rid);
  if (user.role === 'ADMIN' && pathname === '/api/security/lockdown' && req.method === 'POST') {
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (typeof input.enabled !== 'boolean') return fail(req, res, 400, 'VALIDATION_ERROR', 'enabled must be boolean.', rid);
    store.settings.lockdown = input.enabled; store.settings.lockdownAt = input.enabled ? now() : null; await audit(user, input.enabled ? 'LOCKDOWN_ENABLED' : 'LOCKDOWN_DISABLED', 'System', 'lockdown', 'ALLOWED', input.enabled ? 'Admin containment action' : 'Admin recovery action', input.enabled ? 'HIGH' : 'INFO', rid); return respond(req, res, 200, { lockdown: store.settings.lockdown }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/security/verify-audit' && req.method === 'GET') {
    let previous = 'GENESIS'; let valid = true;
    for (const event of store.audit) { const copy = { ...event }; delete copy.hash; const expected = hashText(JSON.stringify(copy)); if (event.previousHash !== previous || event.hash !== expected) { valid = false; break; } previous = event.hash; }
    return respond(req, res, 200, { valid, label: 'TAMPER-EVIDENT', checked: store.audit.length }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/users' && req.method === 'GET') return respond(req, res, 200, { users: store.users.map(safeUser) }, rid);
  const userStatusMatch = pathname.match(/^\/api\/users\/([^/]+)\/status$/);
  if (user.role === 'ADMIN' && userStatusMatch && req.method === 'PATCH') {
    const target = store.users.find(candidate => candidate.id === userStatusMatch[1]);
    if (!target) return fail(req, res, 404, 'NOT_FOUND', 'User not found.', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (typeof input.active !== 'boolean' || target.id === user.id && !input.active) return fail(req, res, 400, 'VALIDATION_ERROR', 'Invalid account status change.', rid);
    target.active = input.active;
    if (!input.active) {
      for (const session of sessions.values()) if (session.userId === target.id) session.revoked = true;
      await audit(user, 'SESSION_REVOKED', 'UserSession', target.id, 'ALLOWED', 'Sessions revoked after account deactivation', 'HIGH', rid);
    }
    await audit(user, 'ADMIN_ACTION', 'User', target.id, 'ALLOWED', input.active ? 'User activated' : 'User deactivated', 'INFO', rid); return respond(req, res, 200, { user: safeUser(target) }, rid);
  }
  return fail(req, res, 404, 'NOT_FOUND', 'Route not found.', rid);
}

async function serveStatic(req, res) {
  const pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  const requested = pathname === '/' ? '/index.html' : pathname;
  const safePath = path.normalize(requested).replace(/^([.][.][/\\])+/, '');
  const file = path.join(__dirname, 'public', safePath);
  const publicRoot = path.resolve(__dirname, 'public');
  if (!file.startsWith(`${publicRoot}${path.sep}`)) { res.statusCode = 404; return res.end('Not found'); }
  try { const content = await fs.readFile(file); const type = file.endsWith('.html') ? 'text/html' : file.endsWith('.css') ? 'text/css' : 'text/javascript'; res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'X-Content-Type-Options': 'nosniff' }); res.end(content); } catch { res.writeHead(404); res.end('Not found'); }
}

export async function startServer() {
  store = await loadStore();
  const handler = async (req, res) => {
    try { if (req.url.startsWith('/api/')) await route(req, res); else await serveStatic(req, res); }
    catch (error) { console.error(`[${now()}] request failure`, error.message); if (!res.headersSent) fail(req, res, 500, 'INTERNAL_ERROR', 'An unexpected server error occurred.', requestId()); }
  };
  const server = http.createServer(handler);
  server.appHandler = handler;
  return new Promise(resolve => server.listen(PORT, '127.0.0.1', () => { console.log(`MediShield listening on http://127.0.0.1:${PORT}`); resolve(server); }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) startServer();
