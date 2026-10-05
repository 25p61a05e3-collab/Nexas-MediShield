import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';

const dataFile = path.join(os.tmpdir(), `medishield-test-${process.pid}.json`);
let server;
let loginAttempt = 0;

function request(pathname, options = {}, cookie = '') {
  return new Promise((resolve, reject) => {
    const payload = options.body || '';
    const req = Readable.from(payload ? [payload] : []);
    req.method = options.method || 'GET';
    req.url = pathname;
    req.headers = { host: 'localhost', ...(cookie ? { cookie } : {}), ...(options.headers || {}) };
    req.socket = { remoteAddress: options.remoteAddress || 'test-suite' };
    const chunks = [];
    const response = {
      statusCode: 200,
      headersSent: false,
      headers: {},
      setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
      writeHead(status, headers) { this.statusCode = status; Object.entries(headers || {}).forEach(([name, value]) => this.setHeader(name, value)); },
      end(chunk = '') { this.headersSent = true; chunks.push(Buffer.from(String(chunk))); resolve({ response: this, data: JSON.parse(Buffer.concat(chunks).toString() || '{}'), cookie: String(this.headers['set-cookie'] || cookie).split(';')[0] }); }
    };
    Promise.resolve(server.appHandler(req, response)).catch(reject);
  });
}
async function login(email, password) { const result = await request('/api/auth/login', { method: 'POST', remoteAddress: `test-login-${++loginAttempt}`, body: JSON.stringify({ email, password }) }); assert.equal(result.response.statusCode, 200); return result.cookie; }

before(async () => {
  await fs.rm(dataFile, { force: true });
  process.env.PORT = '0';
  process.env.SESSION_SECRET = 'test-session-secret-with-more-than-32-chars';
  process.env.MEDISHIELD_DATA_FILE = dataFile;
  const module = await import('../server.js');
  server = await module.startServer();
});
after(async () => { await new Promise(resolve => server.close(resolve)); await fs.rm(dataFile, { force: true }); });

test('health endpoint is public and does not expose secrets', async () => {
  const result = await request('/api/health');
  assert.equal(result.response.statusCode, 200);
  assert.equal(result.data.status, 'ok');
  assert.equal('sessionSecret' in result.data, false);
  assert.equal('passwordHash' in result.data, false);
});

test('authentication issues a cookie and logout invalidates it', async () => {
  const cookie = await login('patient.a@medishield.demo', 'DemoPatientA!2026');
  const me = await request('/api/me', {}, cookie);
  assert.equal(me.response.statusCode, 200);
  assert.equal(me.data.user.role, 'PATIENT');
  const loggedOut = await request('/api/auth/logout', { method: 'POST' }, cookie);
  assert.equal(loggedOut.response.statusCode, 200);
  const after = await request('/api/me', {}, cookie);
  assert.equal(after.response.statusCode, 401);
});

test('doctor can read consented patient but BOLA access is denied and audited', async () => {
  const doctor = await login('doctor.a@medishield.demo', 'DemoDoctorA!2026');
  const allowed = await request('/api/records/record-a', {}, doctor);
  assert.equal(allowed.response.statusCode, 200);
  const denied = await request('/api/records/record-b', {}, doctor);
  assert.equal(denied.response.statusCode, 403);
  const admin = await login('admin@medishield.demo', 'DemoAdmin!2026');
  const events = await request('/api/security/events', {}, admin);
  assert.ok(events.data.events.some(event => event.action === 'ACCESS_DENIED' && event.resourceId === 'record-b'));
});

test('honeytoken access creates a high-severity security event', async () => {
  const doctor = await login('doctor.a@medishield.demo', 'DemoDoctorA!2026');
  const result = await request('/api/records/HONEY-001', {}, doctor);
  assert.equal(result.response.statusCode, 403);
  const admin = await login('admin@medishield.demo', 'DemoAdmin!2026');
  const events = await request('/api/security/events', {}, admin);
  assert.ok(events.data.events.some(event => event.securityType === 'HONEYTOKEN' && event.severity === 'HIGH'));
});

test('admin lockdown blocks sensitive record operations and recovery is audited', async () => {
  const admin = await login('admin@medishield.demo', 'DemoAdmin!2026');
  const enabled = await request('/api/security/lockdown', { method: 'POST', body: JSON.stringify({ enabled: true }) }, admin);
  assert.equal(enabled.response.statusCode, 200);
  const patient = await login('patient.a@medishield.demo', 'DemoPatientA!2026');
  const blocked = await request('/api/records/record-a', {}, patient);
  assert.equal(blocked.response.statusCode, 423);
  const disabled = await request('/api/security/lockdown', { method: 'POST', body: JSON.stringify({ enabled: false }) }, admin);
  assert.equal(disabled.response.statusCode, 200);
});

test('malformed input is rejected server-side', async () => {
  const patient = await login('patient.a@medishield.demo', 'DemoPatientA!2026');
  const result = await request('/api/appointments', { method: 'POST', body: JSON.stringify({ doctorId: { $ne: null }, date: 'not-a-date', time: 'x', reason: '' }) }, patient);
  assert.equal(result.response.statusCode, 400);
});

test('registration enforces strong passwords and profile updates are scoped to the caller', async () => {
  const weak = await request('/api/auth/register', { method: 'POST', body: JSON.stringify({ name: 'Synthetic New Patient', email: 'new.patient@medishield.demo', password: 'weak' }) });
  assert.equal(weak.response.statusCode, 400);
  const created = await request('/api/auth/register', { method: 'POST', body: JSON.stringify({ name: 'Synthetic New Patient', email: 'new.patient@medishield.demo', password: 'StrongNewPatient!2026' }) });
  assert.equal(created.response.statusCode, 201);
  const patient = await login('patient.a@medishield.demo', 'DemoPatientA!2026');
  const updated = await request('/api/profile', { method: 'PATCH', body: JSON.stringify({ name: 'Aarav Updated', email: 'patient.a@medishield.demo' }) }, patient);
  assert.equal(updated.response.statusCode, 200);
  const other = await login('patient.b@medishield.demo', 'DemoPatientB!2026');
  const otherProfile = await request('/api/profile', {}, other);
  assert.equal(otherProfile.data.profile.name, 'Diya Rao');
});

test('repeated denied access raises a rule-based anomaly event', async () => {
  const doctor = await login('doctor.a@medishield.demo', 'DemoDoctorA!2026');
  await request('/api/records/record-b', {}, doctor);
  await request('/api/records/record-b', {}, doctor);
  await request('/api/records/record-b', {}, doctor);
  const admin = await login('admin@medishield.demo', 'DemoAdmin!2026');
  const events = await request('/api/security/events', {}, admin);
  assert.ok(events.data.events.some(event => event.action === 'ANOMALY_DETECTED' && event.securityType === 'ANOMALY'));
});

test('patient isolation and consent revocation are enforced server-side', async () => {
  const patient = await login('patient.a@medishield.demo', 'DemoPatientA!2026');
  const crossPatient = await request('/api/records/record-b', {}, patient);
  assert.equal(crossPatient.response.statusCode, 403);
  const doctor = await login('doctor.a@medishield.demo', 'DemoDoctorA!2026');
  const beforeRevoke = await request('/api/records/record-a', {}, doctor);
  assert.equal(beforeRevoke.response.statusCode, 200);
  const revoked = await request('/api/consents', { method: 'POST', body: JSON.stringify({ doctorId: 'doctor-a', active: false }) }, patient);
  assert.equal(revoked.response.statusCode, 200);
  const afterRevoke = await request('/api/records/record-a', {}, doctor);
  assert.equal(afterRevoke.response.statusCode, 403);
});

test('origin enforcement, rate limiting, malformed JSON, and body limits are active', async () => {
  const crossOrigin = await request('/api/health', { headers: { origin: 'https://evil.example' } });
  assert.equal(crossOrigin.response.statusCode, 403);
  let last;
  for (let attempt = 0; attempt < 9; attempt += 1) last = await request('/api/auth/login', { method: 'POST', remoteAddress: 'same-rate-test', body: JSON.stringify({ email: 'nobody@medishield.demo', password: 'wrong' }) });
  assert.equal(last.response.statusCode, 429);
  const patient = await login('patient.b@medishield.demo', 'DemoPatientB!2026');
  const malformed = await request('/api/profile', { method: 'PATCH', body: '{"name":' }, patient);
  assert.equal(malformed.response.statusCode, 400);
  const oversized = await request('/api/profile', { method: 'PATCH', body: JSON.stringify({ name: 'x'.repeat(40_000), email: 'patient.b@medishield.demo' }) }, patient);
  assert.equal(oversized.response.statusCode, 413);
});

test('tamper-evident audit verification detects a controlled record modification', async () => {
  let admin = await login('admin@medishield.demo', 'DemoAdmin!2026');
  const before = await request('/api/security/verify-audit', {}, admin);
  assert.equal(before.data.valid, true);
  await new Promise(resolve => server.close(resolve));
  const persisted = JSON.parse(await fs.readFile(dataFile, 'utf8'));
  persisted.audit[0].reason = 'CONTROLLED_TAMPER_TEST';
  await fs.writeFile(dataFile, JSON.stringify(persisted, null, 2));
  const module = await import('../server.js');
  server = await module.startServer();
  admin = await login('admin@medishield.demo', 'DemoAdmin!2026');
  const after = await request('/api/security/verify-audit', {}, admin);
  assert.equal(after.data.valid, false);
});
