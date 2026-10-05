import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const dataFile = process.env.MEDISHIELD_DATA_FILE || path.join(process.cwd(), 'data', 'store.json');

export function hashText(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (error, derived) => {
      if (error) return reject(error);
      resolve(`scrypt$${salt}$${derived.toString('hex')}`);
    });
  });
}

export function verifyPassword(password, encoded) {
  return new Promise((resolve, reject) => {
    const [scheme, salt, expected] = String(encoded || '').split('$');
    if (scheme !== 'scrypt' || !salt || !expected) return resolve(false);
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (error, derived) => {
      if (error) return reject(error);
      const actual = Buffer.from(derived.toString('hex'), 'utf8');
      const wanted = Buffer.from(expected, 'utf8');
      resolve(actual.length === wanted.length && crypto.timingSafeEqual(actual, wanted));
    });
  });
}

const seedUsers = [
  { id: 'patient-a', name: 'Aarav Mehta', email: 'patient.a@medishield.demo', role: 'PATIENT', patientId: 'patient-a', password: 'DemoPatientA!2026' },
  { id: 'patient-b', name: 'Diya Rao', email: 'patient.b@medishield.demo', role: 'PATIENT', patientId: 'patient-b', password: 'DemoPatientB!2026' },
  { id: 'doctor-a', name: 'Dr. Ananya Sharma', email: 'doctor.a@medishield.demo', role: 'DOCTOR', doctorId: 'doctor-a', password: 'DemoDoctorA!2026' },
  { id: 'doctor-b', name: 'Dr. Rohan Iyer', email: 'doctor.b@medishield.demo', role: 'DOCTOR', doctorId: 'doctor-b', password: 'DemoDoctorB!2026' },
  { id: 'admin-1', name: 'MediShield Security Admin', email: 'admin@medishield.demo', role: 'ADMIN', password: 'DemoAdmin!2026' }
];

async function makeSeed() {
  const users = [];
  for (const user of seedUsers) {
    const { password, ...safe } = user;
    users.push({ ...safe, passwordHash: await hashPassword(password), active: true });
  }
  const now = new Date().toISOString();
  return {
    version: 1,
    users,
    appointments: [
      { id: 'apt-001', patientId: 'patient-a', doctorId: 'doctor-a', date: '2026-10-08', time: '10:00', reason: 'Routine wellness review', status: 'CONFIRMED', createdAt: now },
      { id: 'apt-002', patientId: 'patient-b', doctorId: 'doctor-b', date: '2026-10-09', time: '14:30', reason: 'Follow-up consultation', status: 'SCHEDULED', createdAt: now }
    ],
    records: [
      { id: 'record-a', patientId: 'patient-a', title: 'Synthetic wellness record', summary: 'Synthetic demo record: stable vitals and routine follow-up recommended.', notes: [{ id: 'note-a1', authorId: 'doctor-a', text: 'Synthetic note: continue preventive care plan.', createdAt: now }] },
      { id: 'record-b', patientId: 'patient-b', title: 'Synthetic follow-up record', summary: 'Synthetic demo record: follow-up consultation scheduled.', notes: [] },
      { id: 'HONEY-001', patientId: 'honey-patient', title: 'Controlled decoy resource', summary: 'Synthetic decoy. Normal workflows must never access this resource.', notes: [] }
    ],
    consents: [
      { id: 'consent-001', patientId: 'patient-a', doctorId: 'doctor-a', active: true, context: 'Appointment apt-001', expiresAt: '2026-12-31T23:59:59.000Z', createdAt: now }
    ],
    consentRequests: [],
    provenance: [],
    audit: [],
    security: [],
    settings: { lockdown: false, lockdownAt: null, previousAuditHash: 'GENESIS' }
  };
}

export async function loadStore() {
  await fs.mkdir(path.dirname(dataFile), { recursive: true });
  try {
    const raw = await fs.readFile(dataFile, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const seeded = await makeSeed();
    await saveStore(seeded);
    return seeded;
  }
}

export async function resetStore() {
  const seeded = await makeSeed();
  await saveStore(seeded);
  return seeded;
}

let writeQueue = Promise.resolve();
export function saveStore(store) {
  writeQueue = writeQueue.then(async () => {
    const temp = `${dataFile}.tmp`;
    await fs.writeFile(temp, JSON.stringify(store, null, 2), { mode: 0o600 });
    await fs.rename(temp, dataFile);
  });
  return writeQueue;
}

export { dataFile };
