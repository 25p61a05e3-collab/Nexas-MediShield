import 'dotenv/config';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server as SocketIOServer } from 'socket.io';
import { loadStore, resetStore, saveStore, hashText, hashPassword, verifyPassword } from './store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 4100);
const NODE_ENV = process.env.NODE_ENV || 'development';
const HOST = NODE_ENV === 'production' ? '0.0.0.0' : (process.env.HOST || '127.0.0.1');
const SESSION_SECRET = process.env.SESSION_SECRET || 'development-only-change-this-secret-32';
const CORS_ORIGIN = process.env.CORS_ORIGIN || `http://localhost:${PORT}`;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';
const isTestEnvironment = process.env.NODE_ENV === 'test' || process.env.MEDISHIELD_TEST_MODE === '1';
const GEMINI_API_KEY = isTestEnvironment ? '' : (process.env.GEMINI_API_KEY || '');
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
const sessions = new Map();
const rateBuckets = new Map();
const MAX_BODY = 32 * 1024;
let store;
let io;

if (NODE_ENV === 'production') {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    throw new Error('SESSION_SECRET must be explicitly configured and at least 32 characters in production');
  }
  if (!process.env.CORS_ORIGIN) {
    throw new Error('CORS_ORIGIN must be explicitly configured in production');
  }
  if (!/^[0-9a-f]{64}$/i.test(ENCRYPTION_KEY)) {
    throw new Error('ENCRYPTION_KEY must be configured as 64 hexadecimal characters in production');
  }
}

const json = (value) => JSON.stringify(value);
const now = () => new Date().toISOString();
const id = (prefix) => `${prefix}-${crypto.randomBytes(8).toString('hex')}`;
const safeUser = (user) => ({ id: user.id, name: user.name, email: user.email, role: user.role, patientId: user.patientId, doctorId: user.doctorId });
const requestId = () => crypto.randomBytes(8).toString('hex');
function live(event, payload, rooms = []) { if (!io) return; for (const room of rooms) io.to(room).emit(event, payload); }
function safeLiveEvent(event) { return { id: event.id, actorId: event.actorId, actorRole: event.actorRole, action: event.action, resourceType: event.resourceType, resourceId: event.resourceId, timestamp: event.timestamp, result: event.result, reason: event.reason, severity: event.severity }; }
function publishAudit(event) {
  const payload = safeLiveEvent(event);
  live('audit.updated', payload, ['role:admin']);
  if (event.actorId !== 'anonymous') live('audit.updated', payload, [`user:${event.actorId}`]);
  if (event.resourceType === 'MedicalRecord' && event.resourceId) {
    const record = store.records.find(item => item.id === event.resourceId);
    if (record) live(event.result === 'ALLOWED' ? 'record.accessed' : 'record.denied', payload, [`patient:${record.patientId}`, 'role:admin']);
  }
  if (event.securityType === 'HONEYTOKEN' || event.securityType === 'SECURITY_EVENT' || event.severity === 'HIGH' || event.action === 'SESSION_REVOKED') {
    live('security.alert', payload, ['role:admin']);
  }
  if (event.action === 'ANOMALY_DETECTED' || event.securityType === 'ANOMALY' || (event.result === 'SUSPICIOUS' && event.securityType === 'SECURITY_EVENT')) {
    live('security.anomaly', payload, ['role:admin']);
  }
  if (event.action === 'HONEYTOKEN_TRIGGER') live('honeytoken.triggered', payload, ['role:admin']);
  if (event.action === 'SESSION_REVOKED') live('session.revoked', payload, [`user:${event.resourceId}`, 'role:admin']);
  if (event.action === 'LOCKDOWN_ENABLED') live('incident.lockdown', { active: true, timestamp: event.timestamp }, ['role:admin', 'role:doctor', 'role:patient']);
  if (event.action === 'LOCKDOWN_DISABLED') live('incident.recovered', { active: false, timestamp: event.timestamp }, ['role:admin', 'role:doctor', 'role:patient']);
}

function sign(value) { return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url'); }
function issueSession(userId, familyId = crypto.randomBytes(18).toString('base64url')) {
  const sid = crypto.randomBytes(24).toString('base64url');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sid, { userId, familyId, expiresAt, revoked: false, createdAt: now() });
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
function sessionDetails(req) {
  const token = parseCookies(req).ms_session;
  const [sid, signature] = String(token || '').split('.');
  const session = sessions.get(sid);
  if (!session) return { sid: null, session: null, replay: false };
  const expected = sign(`${sid}.${session.userId}.${session.expiresAt}`);
  const validSignature = signature && signature.length === expected.length && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  return { sid, session, replay: Boolean(validSignature && (session.revoked || session.expiresAt < Date.now())) };
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
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'");
  if (NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=63072000');
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
  let anomalyEvent;
  event.hash = hashText(JSON.stringify(event));
  store.settings.previousAuditHash = event.hash;
  store.audit.push(event);
  if (['DENIED', 'BLOCKED', 'SUSPICIOUS'].includes(result) || severity === 'HIGH') store.security.push({ ...event, securityType: action === 'HONEYTOKEN_TRIGGER' ? 'HONEYTOKEN' : 'SECURITY_EVENT' });
  if (result === 'DENIED' && actor?.id) {
    const recentDenied = store.audit.filter(item => item.actorId === actor.id && item.result === 'DENIED' && Date.now() - Date.parse(item.timestamp) < 10 * 60 * 1000);
    if (recentDenied.length >= 3) { anomalyEvent = { ...event, id: id('security'), action: 'ANOMALY_DETECTED', result: 'SUSPICIOUS', severity: 'HIGH', securityType: 'ANOMALY', reason: 'Repeated denied requests in a short window' }; store.security.push(anomalyEvent); }
  }
  publishAudit(event);
  if (anomalyEvent) publishAudit(anomalyEvent);
  return saveStore(store);
}
function lockdownBlocks(user) { return store.settings.lockdown && user?.role !== 'ADMIN'; }
function canDoctorAccess(doctor, patientId) { return store.consents.some(c => c.doctorId === doctor.doctorId && c.patientId === patientId && c.active && (!c.expiresAt || c.expiresAt > now())); }
async function triggerHoneytoken(actor, rid) { await audit(actor, 'HONEYTOKEN_TRIGGER', 'MedicalRecord', 'HONEY-001', 'SUSPICIOUS', 'Controlled decoy resource accessed', 'HIGH', rid); }
function publishAppointment(event, appointment) { live(event, { id: appointment.id, patientId: appointment.patientId, doctorId: appointment.doctorId, status: appointment.status, date: appointment.date, time: appointment.time }, [`user:${appointment.patientId}`, `user:${appointment.doctorId}`, 'role:admin']); }
function publishConsent(event, consent) { live(event, { id: consent.id, patientId: consent.patientId, doctorId: consent.doctorId, active: consent.active, expiresAt: consent.expiresAt }, [`user:${consent.patientId}`, `user:${consent.doctorId}`, 'role:admin']); }
function publishConsentRequest(event, request) { live(event, { id: request.id, patientId: request.patientId, doctorId: request.doctorId, reason: request.reason, requestedDurationMinutes: request.requestedDurationMinutes, status: request.status, createdAt: request.createdAt }, [`user:${request.patientId}`, `user:${request.doctorId}`, 'role:admin']); }
function encryptionKey() { if (!/^[0-9a-f]{64}$/i.test(ENCRYPTION_KEY)) throw new Error('ENCRYPTION_KEY must be 32 bytes represented as 64 hex characters.'); return Buffer.from(ENCRYPTION_KEY, 'hex'); }
function encryptClinical(value) { const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv); const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]); return { algorithm: 'aes-256-gcm', iv: iv.toString('base64url'), ciphertext: ciphertext.toString('base64url'), authTag: cipher.getAuthTag().toString('base64url') }; }
function decryptClinical(payload) { const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(payload.iv, 'base64url')); decipher.setAuthTag(Buffer.from(payload.authTag, 'base64url')); return Buffer.concat([decipher.update(Buffer.from(payload.ciphertext, 'base64url')), decipher.final()]).toString('utf8'); }
function aiSafeQuestion(question) { return validText(question, 500) && !/(show|reveal|give|dump|export).*(patient|record|secret|password|token|database)/i.test(question) && !/(ignore|bypass|disregard).*(instruction|policy|authorization)/i.test(question); }
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
  const sessionState = sessionDetails(req);
  if (!user && sessionState.replay) {
    for (const candidate of sessions.values()) if (candidate.familyId === sessionState.session.familyId) candidate.revoked = true;
    const replayUser = userFor(sessionState.session.userId);
    await audit(replayUser, 'SESSION_REPLAY_DETECTED', 'UserSession', sessionState.sid, 'BLOCKED', 'Revoked or expired session token reused; family revoked', 'HIGH', rid);
    live('session.replay', { actorId: replayUser?.id || null, familyId: sessionState.session.familyId, sessionId: sessionState.sid, timestamp: now() }, ['role:admin']);
  }
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
    store.appointments.push(appointment); await audit(user, 'BOOK_APPOINTMENT', 'Appointment', appointment.id, 'ALLOWED', 'Patient booking', 'INFO', rid); publishAppointment('appointment.created', appointment); return respond(req, res, 201, { appointment }, rid);
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
    apt.status = input.status; await audit(user, input.status === 'CANCELLED' ? 'CANCEL_APPOINTMENT' : 'ADMIN_ACTION', 'Appointment', apt.id, 'ALLOWED', 'Appointment status update', 'INFO', rid); publishAppointment(input.status === 'CANCELLED' ? 'appointment.cancelled' : 'appointment.updated', apt); return respond(req, res, 200, { appointment: apt }, rid);
  }
  if (pathname === '/api/records' && req.method === 'GET') {
    if (lockdownBlocks(user)) { await audit(user, 'RECORD_ACCESS', 'MedicalRecord', null, 'BLOCKED', 'Incident lockdown active', 'HIGH', rid); return fail(req, res, 423, 'LOCKDOWN', 'Sensitive record access is blocked during incident lockdown.', rid); }
    const records = store.records.filter(r => r.id !== 'HONEY-001' && (user.role === 'ADMIN' || (user.role === 'PATIENT' && r.patientId === user.patientId) || (user.role === 'DOCTOR' && canDoctorAccess(user, r.patientId)))).map(r => ({ id: r.id, patientId: r.patientId, patientName: userFor(r.patientId)?.name, title: r.title, summary: r.summary, noteCount: r.notes.length }));
    await audit(user, 'VIEW_RECORD_LIST', 'MedicalRecord', null, 'ALLOWED', 'Authorized record listing', 'INFO', rid); return respond(req, res, 200, { records }, rid);
  }
  const recordMatch = pathname.match(/^\/api\/records\/([^/]+)$/);
  if (recordMatch && req.method === 'GET') {
    const recordId = recordMatch[1];
    if (recordId === 'HONEY-001') { await triggerHoneytoken(user, rid); return fail(req, res, 403, 'FORBIDDEN', 'You are not authorized to access this resource.', rid); }
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
  if (pathname === '/api/consent-requests' && req.method === 'GET') {
    const requests = (store.consentRequests || []).filter(request => user.role === 'ADMIN' || (user.role === 'PATIENT' && request.patientId === user.patientId) || (user.role === 'DOCTOR' && request.doctorId === user.doctorId)).map(request => ({ ...request, patientName: userFor(request.patientId)?.name, doctorName: userFor(request.doctorId)?.name }));
    return respond(req, res, 200, { requests }, rid);
  }
  if (pathname === '/api/consent-requests' && req.method === 'POST') {
    if (user.role !== 'DOCTOR') return fail(req, res, 403, 'FORBIDDEN', 'Only doctors can request record access.', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    const patient = userFor(input.patientId); const duration = Number(input.durationMinutes);
    const relationship = patient?.role === 'PATIENT' && store.appointments.some(appointment => appointment.patientId === patient.patientId && appointment.doctorId === user.doctorId && appointment.status !== 'CANCELLED');
    if (!relationship || !validText(input.reason, 300) || !Number.isInteger(duration) || duration < 15 || duration > 24 * 60) return fail(req, res, 400, 'VALIDATION_ERROR', 'A valid scheduled patient relationship, reason, and duration between 15 minutes and 24 hours are required.', rid);
    const request = { id: id('consent-request'), patientId: patient.patientId, doctorId: user.doctorId, reason: input.reason.trim(), requestedDurationMinutes: duration, status: 'PENDING', createdAt: now(), decidedAt: null };
    store.consentRequests.push(request); await audit(user, 'CONSENT_REQUESTED', 'ConsentRequest', request.id, 'ALLOWED', 'Doctor requested time-bound patient consent', 'INFO', rid); publishConsentRequest('consent.requested', request); return respond(req, res, 201, { request }, rid);
  }
  const consentRequestMatch = pathname.match(/^\/api\/consent-requests\/([^/]+)$/);
  if (consentRequestMatch && req.method === 'PATCH') {
    const request = (store.consentRequests || []).find(candidate => candidate.id === consentRequestMatch[1]);
    if (!request) return fail(req, res, 404, 'NOT_FOUND', 'Consent request not found.', rid);
    if (user.role !== 'PATIENT' || request.patientId !== user.patientId) return recordDenied(req, res, user, request.id, 'Consent request ownership mismatch', rid);
    if (request.status !== 'PENDING') return fail(req, res, 409, 'REQUEST_CLOSED', 'Consent request has already been decided.', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (!['APPROVED', 'DENIED'].includes(input.decision)) return fail(req, res, 400, 'VALIDATION_ERROR', 'Decision must be APPROVED or DENIED.', rid);
    request.status = input.decision; request.decidedAt = now();
    if (input.decision === 'APPROVED') {
      const expiresAt = new Date(Date.now() + request.requestedDurationMinutes * 60 * 1000).toISOString();
      let consent = store.consents.find(candidate => candidate.patientId === request.patientId && candidate.doctorId === request.doctorId);
      if (consent) { consent.active = true; consent.expiresAt = expiresAt; consent.context = request.reason; } else { consent = { id: id('consent'), patientId: request.patientId, doctorId: request.doctorId, active: true, context: request.reason, expiresAt, createdAt: now() }; store.consents.push(consent); }
      await audit(user, 'CONSENT_APPROVED', 'Consent', consent.id, 'ALLOWED', 'Patient approved time-bound access', 'INFO', rid); publishConsent('consent.approved', consent);
    } else { await audit(user, 'CONSENT_DENIED', 'ConsentRequest', request.id, 'DENIED', 'Patient denied access request', 'MEDIUM', rid); publishConsentRequest('consent.denied', request); }
    publishConsentRequest(input.decision === 'APPROVED' ? 'consent.approved' : 'consent.denied', request); return respond(req, res, 200, { request }, rid);
  }
  if (pathname === '/api/consents' && req.method === 'POST') {
    if (user.role !== 'PATIENT') return fail(req, res, 403, 'FORBIDDEN', 'Only patients manage consent.', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (!validId(input.doctorId) || !userFor(input.doctorId)?.doctorId) return fail(req, res, 400, 'VALIDATION_ERROR', 'A valid doctor is required.', rid);
    const existing = store.consents.find(c => c.patientId === user.patientId && c.doctorId === input.doctorId);
    if (existing) { existing.active = input.active !== false; existing.expiresAt = input.expiresAt || existing.expiresAt; await audit(user, 'CONSENT_CHANGE', 'Consent', existing.id, 'ALLOWED', existing.active ? 'Consent granted' : 'Consent revoked', 'INFO', rid); publishConsent(existing.active ? 'consent.granted' : 'consent.revoked', existing); return respond(req, res, 200, { consent: existing }, rid); }
    const consent = { id: id('consent'), patientId: user.patientId, doctorId: input.doctorId, active: true, context: 'Patient-managed consent', expiresAt: input.expiresAt || '2026-12-31T23:59:59.000Z', createdAt: now() }; store.consents.push(consent); await audit(user, 'CONSENT_CHANGE', 'Consent', consent.id, 'ALLOWED', 'Consent granted', 'INFO', rid); publishConsent('consent.granted', consent); return respond(req, res, 201, { consent }, rid);
  }
  const exportMatch = pathname.match(/^\/api\/records\/([^/]+)\/export$/);
  if (exportMatch && req.method === 'POST') {
    if (lockdownBlocks(user)) return fail(req, res, 423, 'LOCKDOWN', 'Sensitive record export is blocked during incident lockdown.', rid);
    const record = store.records.find(candidate => candidate.id === exportMatch[1]);
    if (!record || record.id === 'HONEY-001') return recordDenied(req, res, user, exportMatch[1], 'Unknown or decoy record export', rid);
    const allowed = user.role === 'ADMIN' || (user.role === 'PATIENT' && record.patientId === user.patientId) || (user.role === 'DOCTOR' && canDoctorAccess(user, record.patientId));
    if (!allowed) return recordDenied(req, res, user, record.id, 'Record export authorization failed', rid);
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    const purpose = input.purpose || 'Synthetic medical summary'; if (!validText(purpose, 200)) return fail(req, res, 400, 'VALIDATION_ERROR', 'A valid export purpose is required.', rid);
    const provenance = { id: id('export'), traceId: `MS-${crypto.randomBytes(4).toString('hex').toUpperCase()}`, actorId: user.id, actorRole: user.role, resourceId: record.id, patientId: record.patientId, purpose: purpose.trim(), timestamp: now(), sessionId: sessionDetails(req).sid };
    store.provenance.push(provenance); await audit(user, 'RECORD_EXPORT', 'MedicalRecord', record.id, 'ALLOWED', `Forensic export ${provenance.traceId}`, 'INFO', rid); live('export.created', { traceId: provenance.traceId, resourceId: record.id, actorId: user.id, timestamp: provenance.timestamp }, [`user:${user.id}`, 'role:admin']); live('forensics.updated', { traceId: provenance.traceId, resourceId: record.id, timestamp: provenance.timestamp }, ['role:admin']);
    return respond(req, res, 201, { export: { traceId: provenance.traceId, createdBy: user.name, patientId: record.patientId, title: record.title, summary: record.summary, timestamp: provenance.timestamp, provenanceTracked: true } }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/forensics' && req.method === 'GET') {
    const traceId = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams.get('traceId');
    if (!validText(traceId, 100)) return fail(req, res, 400, 'VALIDATION_ERROR', 'A traceId is required.', rid);
    const provenance = (store.provenance || []).find(item => item.traceId === traceId); if (!provenance) return fail(req, res, 404, 'NOT_FOUND', 'Provenance record not found.', rid);
    return respond(req, res, 200, { provenance }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/security/breach-simulation' && req.method === 'POST') {
    if (!ENCRYPTION_KEY) return fail(req, res, 503, 'ENCRYPTION_UNAVAILABLE', 'Controlled breach simulation is unavailable until ENCRYPTION_KEY is configured.', rid);
    const sample = JSON.stringify({ recordId: 'record-a', clinicalSummary: 'Synthetic clinical data only', generatedAt: now() });
    try { const encrypted = encryptClinical(sample); const decrypted = decryptClinical(encrypted); return respond(req, res, 200, { simulation: 'DATABASE_COMPROMISE', identifier: 'record-a', passwordHash: 'scrypt$... (hash only)', clinicalData: { protection: 'AES-256-GCM', encryptionMetadata: { algorithm: encrypted.algorithm, ivPresent: true, authTagPresent: true }, roundTripVerified: decrypted === sample }, audit: 'TAMPER-EVIDENT' }, rid); } catch { return fail(req, res, 503, 'ENCRYPTION_UNAVAILABLE', 'Encryption configuration is invalid.', rid); }
  }
  if (pathname === '/api/assistant' && req.method === 'POST') {
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (!aiSafeQuestion(input.question)) return fail(req, res, 400, 'SAFE_SCOPE', 'The privacy-first assistant only answers clinic, navigation, synthetic-data, and security-control questions.', rid);
    if (!GEMINI_API_KEY) return respond(req, res, 503, { available: false, label: 'AI ASSISTANT UNAVAILABLE', message: 'Configure GEMINI_API_KEY on the server to enable the privacy-first assistant.' }, rid);
    try { const prompt = `You are MediShield privacy-first assistant. Answer only appointment FAQs, navigation, booking/cancellation explanations, consent explanations, security-control explanations, or synthetic demo explanations. Never diagnose, reveal records, access databases, change permissions, or reveal secrets. User role: ${user.role}. Question: ${input.question}`; const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }) }); if (!response.ok) throw new Error('provider'); const result = await response.json(); const answer = result.candidates?.[0]?.content?.parts?.[0]?.text; if (!answer || answer.length > 2000) throw new Error('unsafe'); return respond(req, res, 200, { available: true, privacy: 'Synthetic demonstration data only; no unrestricted medical-record access.', answer }, rid); } catch { return fail(req, res, 502, 'ASSISTANT_UNAVAILABLE', 'The privacy-first assistant is temporarily unavailable.', rid); }
  }
  if (user.role === 'ADMIN' && pathname === '/api/red-team/bola' && req.method === 'POST') {
    const simulatedDoctor = userFor('doctor-a'); const target = store.records.find(record => record.id === 'record-b'); const allowed = simulatedDoctor && target && canDoctorAccess(simulatedDoctor, target.patientId);
    if (!allowed) await audit(simulatedDoctor, 'ACCESS_DENIED', 'MedicalRecord', target?.id || 'record-b', 'DENIED', 'Red Team Lab BOLA simulation: unrelated patient', 'HIGH', rid);
    return respond(req, res, 200, { attack: 'BOLA / IDOR', expectedStatus: 403, actualStatus: allowed ? 200 : 403, blocked: !allowed, auditRecorded: true }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/red-team/honeytoken' && req.method === 'POST') {
    await triggerHoneytoken(userFor('doctor-a'), rid); return respond(req, res, 200, { attack: 'HONEYTOKEN', resource: 'HONEY-001', blocked: true, severity: 'HIGH', auditRecorded: true }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/red-team/anomaly' && req.method === 'POST') {
    const simulatedDoctor = userFor('doctor-a'); for (let attempt = 0; attempt < 3; attempt += 1) await audit(simulatedDoctor, 'ACCESS_DENIED', 'MedicalRecord', 'record-b', 'DENIED', 'Red Team Lab anomaly simulation', 'MEDIUM', rid);
    return respond(req, res, 200, { simulation: 'RULE_BASED_ANOMALY', actor: simulatedDoctor.id, result: 'SUSPICIOUS', reason: 'Repeated unauthorized record access' }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/demo/reset' && req.method === 'POST') {
    store = await resetStore(); sessions.clear(); await audit(user, 'DEMO_RESET', 'System', 'demo', 'ALLOWED', 'Admin reset of synthetic demonstration state', 'INFO', rid); live('demo.reset', { timestamp: now(), syntheticData: true }, ['role:admin', 'role:doctor', 'role:patient']); return respond(req, res, 200, { reset: true, syntheticData: true }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/security/summary' && req.method === 'GET') return respond(req, res, 200, { lockdown: store.settings.lockdown, stats: { users: store.users.filter(u => u.active).length, activeSessions: [...sessions.values()].filter(session => !session.revoked && session.expiresAt > Date.now()).length, securityEvents: store.security.length, denied: store.security.filter(e => e.result === 'DENIED').length, failedLogins: store.audit.filter(e => e.action === 'LOGIN_FAILED').length, honeytokens: store.security.filter(e => e.securityType === 'HONEYTOKEN').length, anomalies: store.security.filter(e => e.securityType === 'ANOMALY').length, suspicious: store.security.filter(e => e.result === 'SUSPICIOUS').length, activeConsents: store.consents.filter(consent => consent.active).length }, recent: store.audit.slice(-25).reverse() }, rid);
  if (user.role === 'ADMIN' && pathname === '/api/security/events' && req.method === 'GET') return respond(req, res, 200, { events: store.security.slice(-200).reverse() }, rid);
  if (user.role === 'ADMIN' && pathname === '/api/security/lockdown' && req.method === 'POST') {
    let input; try { input = await body(req); } catch (e) { return fail(req, res, e.status || 400, 'INVALID_REQUEST', 'Invalid request.', rid); }
    if (typeof input.enabled !== 'boolean') return fail(req, res, 400, 'VALIDATION_ERROR', 'enabled must be boolean.', rid);
    store.settings.lockdown = input.enabled; store.settings.lockdownAt = input.enabled ? now() : null; await audit(user, input.enabled ? 'LOCKDOWN_ENABLED' : 'LOCKDOWN_DISABLED', 'System', 'lockdown', 'ALLOWED', input.enabled ? 'Admin containment action' : 'Admin recovery action', input.enabled ? 'HIGH' : 'INFO', rid); return respond(req, res, 200, { lockdown: store.settings.lockdown }, rid);
  }
  if (user.role === 'ADMIN' && pathname === '/api/security/verify-audit' && req.method === 'GET') {
    let previous = 'GENESIS'; let valid = true;
    for (const event of store.audit) { const copy = { ...event }; delete copy.hash; const expected = hashText(JSON.stringify(copy)); if (event.previousHash !== previous || event.hash !== expected) { valid = false; break; } previous = event.hash; }
    return respond(req, res, 200, { valid, label: 'TAMPER-EVIDENT', checked: store.audit.length, latestHash: store.audit.at(-1)?.hash || 'GENESIS' }, rid);
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
  const publicRoot = path.resolve(__dirname, 'public');
  let decodedPath;
  try { decodedPath = decodeURIComponent(requested); } catch { res.statusCode = 404; return res.end('Not found'); }
  const file = path.resolve(publicRoot, `.${path.sep}${decodedPath.replace(/^[/\\]+/, '')}`);
  const relativePath = path.relative(publicRoot, file);
  if (relativePath === '..' || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) { res.statusCode = 404; return res.end('Not found'); }
  try { const content = await fs.readFile(file); const type = file.endsWith('.html') ? 'text/html' : file.endsWith('.css') ? 'text/css' : 'text/javascript'; res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'X-Content-Type-Options': 'nosniff' }); res.end(content); } catch { res.writeHead(404); res.end('Not found'); }
}

export async function startServer() {
  store = await loadStore();
  const handler = async (req, res) => {
    if (req.url.startsWith('/socket.io/')) return;
    try { if (req.url.startsWith('/api/')) await route(req, res); else await serveStatic(req, res); }
    catch (error) { console.error(`[${now()}] request failure`, error.message); if (!res.headersSent) fail(req, res, 500, 'INTERNAL_ERROR', 'An unexpected server error occurred.', requestId()); }
  };
  const server = http.createServer(handler);
  server.appHandler = handler;
  io = new SocketIOServer(server, { cors: { origin: CORS_ORIGIN, credentials: true }, maxHttpBufferSize: MAX_BODY });
  io.use((socket, next) => {
    const user = getUser({ headers: socket.handshake.headers });
    if (!user) return next(new Error('AUTH_REQUIRED'));
    socket.data.user = user;
    next();
  });
  io.on('connection', socket => {
    const user = socket.data.user;
    socket.join(`user:${user.id}`); socket.join(`role:${user.role.toLowerCase()}`);
    if (user.patientId) socket.join(`patient:${user.patientId}`);
    socket.emit('connected', { user: safeUser(user), lockdown: store.settings.lockdown, syntheticData: true });
  });
  return new Promise(resolve => server.listen(PORT, HOST, () => { console.log(`MediShield listening on http://${HOST}:${PORT}`); resolve(server); }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) startServer();
