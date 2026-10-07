// index.js
// เซิร์ฟเวอร์ Pirate Crew Tactics — รวมทุกอย่างไว้ไฟล์เดียว (เพื่อให้อัพโหลดขึ้น GitHub ผ่านมือถือง่ายๆ
// ไม่ต้องสร้างโฟลเดอร์ย่อย ไม่มีปัญหาแตกไฟล์ zip) มีแค่ package.json คู่กันอีกไฟล์เดียวเท่านั้น
// dependency ภายนอกที่ต้องมี (npm install ให้อัตโนมัติตอน deploy): pg

const http = require('http');
const crypto = require('crypto');
const vm = require('vm');
const { Pool } = require('pg');

// ===== auth.js =====
// auth.js
// ฟังก์ชันความปลอดภัยพื้นฐาน: แฮชรหัสผ่าน + token ยืนยันตัวตน
// ใช้แค่ module "crypto" ที่มากับ Node.js เอง ไม่ต้อง npm install อะไรเพิ่มสำหรับไฟล์นี้

// ---------- รหัสผ่าน ----------

// สร้าง salt แบบสุ่ม + แฮชรหัสผ่านด้วย scrypt (มาตรฐานความปลอดภัยที่ยอมรับกันทั่วไป)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

// เช็ครหัสผ่านที่กรอกมา ตรงกับแฮชที่เก็บไว้ไหม (ใช้ timingSafeEqual กันโดนเดาเวลา)
function verifyPassword(password, salt, expectedHash) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  const hashBuf = Buffer.from(hash, 'hex');
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  if (hashBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(hashBuf, expectedBuf);
}

// ---------- Token (คล้าย JWT แต่เขียนเองสั้นๆ ไม่ต้องพึ่ง library ภายนอก) ----------

function base64url(str) {
  return Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString();
}

// secret ต้องมาจาก environment variable ตอนใช้งานจริง (ห้าม hardcode ในโค้ด)
function generateToken(payload, secret, expiresInSeconds = 60 * 60 * 24 * 30) {
  const body = Object.assign({}, payload, { exp: Math.floor(Date.now() / 1000) + expiresInSeconds });
  const payloadStr = base64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', secret).update(payloadStr).digest('hex');
  return `${payloadStr}.${sig}`;
}

// คืนค่า payload ถ้า token ถูกต้องและยังไม่หมดอายุ, คืน null ถ้าไม่ผ่าน
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadStr, sig] = parts;

  const expectedSig = crypto.createHmac('sha256', secret).update(payloadStr).digest('hex');
  const sigBuf = Buffer.from(sig, 'hex');
  const expectedBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;

  let body;
  try {
    body = JSON.parse(base64urlDecode(payloadStr));
  } catch (e) {
    return null;
  }
  if (!body.exp || Math.floor(Date.now() / 1000) > body.exp) return null;
  return body;
}

module.exports = { hashPassword, verifyPassword, generateToken, verifyToken };


// ===== validation.js =====
// validation.js
// เช็คข้อมูลที่ผู้เล่นส่งเข้ามาก่อนบันทึกลงฐานข้อมูลทุกครั้ง (ป้องกันข้อมูลแปลกๆ/ยาวเกินไป)

function validateUsername(username) {
  if (typeof username !== 'string') return 'ชื่อผู้ใช้ต้องเป็นข้อความ';
  const trimmed = username.trim();
  if (trimmed.length < 3 || trimmed.length > 20) return 'ชื่อผู้ใช้ต้องยาว 3-20 ตัวอักษร';
  if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) return 'ชื่อผู้ใช้ใช้ได้แค่ตัวอักษรอังกฤษ ตัวเลข และ _ เท่านั้น';
  return null;
}

function validatePassword(password) {
  if (typeof password !== 'string') return 'รหัสผ่านต้องเป็นข้อความ';
  if (password.length < 8) return 'รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร';
  if (password.length > 200) return 'รหัสผ่านยาวเกินไป';
  return null;
}

// กันไม่ให้ผู้เล่นส่งข้อมูลเซฟที่ใหญ่ผิดปกติ (เผื่อบั๊กหรือความพยายามโจมตี) - จำกัดไว้ที่ 2MB
const MAX_SAVE_SIZE_BYTES = 2 * 1024 * 1024;

// ล็อกต่อผู้เล่น: คำขอที่แก้เซฟคนเดียวกัน (อัพโหลดเซฟ / สุ่มกาชา) ทำทีละอัน กันสุ่มซ้อนใช้เพชรเดียวกันสองรอบ และกันเซฟเก่าทับผลสุ่ม
const userLocks = new Map();
async function acquireUserLock(userId) {
  const prev = userLocks.get(userId) || Promise.resolve();
  let release;
  const mine = new Promise(resolve => { release = resolve; });
  const chained = prev.then(() => mine);
  userLocks.set(userId, chained);
  await prev;
  return () => { release(); if (userLocks.get(userId) === chained) userLocks.delete(userId); };
}

// ==========================================
// ตรวจความสมเหตุสมผลของเซฟที่เกมส่งขึ้นมา (กันโกงเพชร/ตัวละคร ขั้นพื้นฐาน)
// เพชรที่ผู้เล่นหาได้เองในเกมมีทีละน้อย (2-80 ต่อครั้ง) ถ้าเซฟกระโดดสูงเกินกว่าที่รางวัลในเกม + ของที่ GM/เติมเงินส่งให้จะอธิบายได้
// = เข้าข่ายแก้เซฟ: บันทึกลงรายงานให้ GM ดู และถ้าเกินมาก "ไม่รับเซฟนั้น" (เซฟเดิมบนเซิร์ฟเวอร์ยังอยู่)
// ==========================================
const SAVE_GUARD = {
  FIRST_UPLOAD_GEMS_LIMIT: 3000,   // เซฟแรกที่ผู้เล่นเล่นออฟไลน์มาก่อนแล้วค่อยสมัคร
  BUDGET_CAP: 600,                 // เพชรที่เพิ่มได้ในคราวเดียวสูงสุด (ถังเต็ม) — รางวัลในเกมแต่ละอย่างได้ครั้งละ 2-80
  BUDGET_PER_HOUR: 60,             // ถังเติมเองชั่วโมงละเท่านี้ (ยิงอัพโหลดรัวๆ ก็ไม่ได้เพิ่ม เพราะนับรวมจากถังเดียวกัน)
  REJECT_MARGIN: 1500,             // เกินถังเท่านี้ขึ้นไป = ไม่รับเซฟ (เกินน้อยกว่านี้ = รับแต่แจ้งเตือน GM)
  MIN_PULL_COST: 2,                // ค่าสุ่มต่อครั้งที่ถูกที่สุด (เผื่อโปรโมชั่นสุ่มชุด)
  CREW_SLACK: 6                    // ตัวละครที่ได้จากรางวัลด่านฯ ได้เพิ่มโดยไม่เสียเพชร
};

// ----- งบการเพิ่มของที่ได้ "จากในเกมฝั่งเครื่อง" (กาชาเซิร์ฟเวอร์สุ่มให้เองแล้ว ฝั่งเครื่องจึงเพิ่มได้น้อยมาก: รางวัลเคลียร์ด่าน ล็อกอินรายวัน ตัวซ้ำจากด่าน) -----
SAVE_GUARD.CREW_CAP = 6;      SAVE_GUARD.CREW_PER_HOUR = 3;     SAVE_GUARD.CREW_MARGIN = 4;
SAVE_GUARD.DUPE_CAP = 12;     SAVE_GUARD.DUPE_PER_HOUR = 6;     SAVE_GUARD.DUPE_MARGIN = 10;
SAVE_GUARD.SPIRIT_CAP = 4;    SAVE_GUARD.SPIRIT_PER_HOUR = 2;   SAVE_GUARD.SPIRIT_MARGIN = 4;
SAVE_GUARD.FIRST_UPLOAD_CREW_LIMIT = 3;
// น้ำหนักคะแนนความเสี่ยงของเหตุการณ์ (ถึง 60 = จำกัดบัญชี 7 วันอัตโนมัติ)
const RISK_WEIGHTS = { gems_jump: 10, crew_budget: 15, dupe_budget: 12, spirit_budget: 12, first_upload_gems: 25, first_upload_crew: 25, bad_gems: 40, rejected_extra: 20, once_unclaim: 20, once_invalid: 20 };
const QUARANTINE_SCORE = 60;
const QUARANTINE_DAYS = 7;

function countCrew(save) { return save && save.crew ? Object.keys(save.crew).length : 0; }
function sumDupes(save) {
  let n = 0;
  if (save && save.crew) Object.keys(save.crew).forEach(id => { const c = save.crew[id] || {}; n += (Number(c.dupes) || 0) + (Number(c.pending_dupes) || 0); });
  return n;
}
function sumSpirits(save) {
  let n = 0;
  const sp = save && save.inventory && save.inventory.pirate_spirit;
  if (sp) Object.keys(sp).forEach(k => { n += Number(sp[k]) || 0; });
  return n;
}

// prev = เซฟเดิมบนเซิร์ฟเวอร์, next = เซฟที่เพิ่งส่งมา
// ctx = { budget, crewBudget, dupeBudget, spiritBudget (ถังที่เหลือ), hoursSince, grantGems, quarantined }
// คืน { flags, reject, newBudget (เพชร), newBudgets {gems,crew,dupes,spirits}, earnedByGame, risk (คะแนนที่จะบวกเพิ่ม) }
function checkSaveAgainstPrevious(prev, next, ctx) {
  const flags = [];
  ctx = ctx || {};
  const hours = Math.max(0, ctx.hoursSince || 0);
  const grantGems = Math.max(0, ctx.grantGems || 0);
  const refill = (cur, cap, perHour) => Math.min(cap, (Number.isFinite(cur) ? cur : cap) + hours * perHour);
  const budgets = {
    gems: refill(ctx.budget, SAVE_GUARD.BUDGET_CAP, SAVE_GUARD.BUDGET_PER_HOUR),
    crew: refill(ctx.crewBudget, SAVE_GUARD.CREW_CAP, SAVE_GUARD.CREW_PER_HOUR),
    dupes: refill(ctx.dupeBudget, SAVE_GUARD.DUPE_CAP, SAVE_GUARD.DUPE_PER_HOUR),
    spirits: refill(ctx.spiritBudget, SAVE_GUARD.SPIRIT_CAP, SAVE_GUARD.SPIRIT_PER_HOUR)
  };
  const result = (reject, extra) => {
    let risk = 0;
    flags.forEach(f => { risk += RISK_WEIGHTS[f.kind] || 0; });
    if (reject) risk += RISK_WEIGHTS.rejected_extra;
    return Object.assign({ flags, reject, newBudget: budgets.gems, newBudgets: budgets, earnedByGame: 0, risk }, extra || {});
  };
  const gemsNew = Number(next && next.gems);
  if (!Number.isFinite(gemsNew) || gemsNew < 0) {
    flags.push({ kind: 'bad_gems', detail: { gems: next ? String(next.gems) : null } });
    return result(true);
  }
  if (!prev) {
    let reject = false;
    const limit = SAVE_GUARD.FIRST_UPLOAD_GEMS_LIMIT + grantGems;
    if (gemsNew > limit) { flags.push({ kind: 'first_upload_gems', detail: { gems: gemsNew, limit } }); if (gemsNew > limit + SAVE_GUARD.REJECT_MARGIN) reject = true; }
    const crewN = countCrew(next);
    if (crewN > SAVE_GUARD.FIRST_UPLOAD_CREW_LIMIT || sumSpirits(next) > SAVE_GUARD.SPIRIT_CAP) { flags.push({ kind: 'first_upload_crew', detail: { crew: crewN, spirits: sumSpirits(next) } }); reject = true; }
    return result(reject);
  }
  // บัญชีที่ถูกจำกัด: ห้ามเพิ่มอะไรเลย (เพชร/ตัวละคร/ตัวซ้ำ/วิญญาณ) ที่เหลือเล่นต่อได้ — ไม่บวกคะแนนความเสี่ยงซ้ำ
  if (ctx.quarantined) {
    const inc = (Number(next.gems) || 0) > (Number(prev.gems) || 0) + grantGems || countCrew(next) > countCrew(prev) || sumDupes(next) > sumDupes(prev) || sumSpirits(next) > sumSpirits(prev);
    return Object.assign(result(inc), { risk: 0 });
  }

  let reject = false;
  const gemsPrev = Number(prev.gems) || 0;
  const earnedByGame = Math.max(0, gemsNew - gemsPrev - grantGems);
  if (earnedByGame > 0) {
    if (earnedByGame > budgets.gems) {
      flags.push({ kind: 'gems_jump', detail: { prev: gemsPrev, next: gemsNew, budget: Math.round(budgets.gems), grants: grantGems } });
      if (earnedByGame > budgets.gems + SAVE_GUARD.REJECT_MARGIN) reject = true;
    }
  }
  const spend = (key, added, cap, margin, kind, detail) => {
    if (!(added > 0)) return;
    if (added > budgets[key]) {
      flags.push({ kind, detail: Object.assign({ added, budget: Math.round(budgets[key] * 10) / 10 }, detail || {}) });
      if (added > budgets[key] + margin) reject = true;
    }
  };
  const addedCrew = countCrew(next) - countCrew(prev);
  const addedDupes = sumDupes(next) - sumDupes(prev);
  const addedSpirits = sumSpirits(next) - sumSpirits(prev);
  spend('crew', addedCrew, SAVE_GUARD.CREW_CAP, SAVE_GUARD.CREW_MARGIN, 'crew_budget');
  spend('dupes', addedDupes, SAVE_GUARD.DUPE_CAP, SAVE_GUARD.DUPE_MARGIN, 'dupe_budget');
  spend('spirits', addedSpirits, SAVE_GUARD.SPIRIT_CAP, SAVE_GUARD.SPIRIT_MARGIN, 'spirit_budget');
  if (!reject) {
    const floor = -SAVE_GUARD.REJECT_MARGIN;
    if (earnedByGame > 0) budgets.gems = Math.max(floor, budgets.gems - earnedByGame);
    if (addedCrew > 0) budgets.crew = Math.max(-SAVE_GUARD.CREW_MARGIN, budgets.crew - addedCrew);
    if (addedDupes > 0) budgets.dupes = Math.max(-SAVE_GUARD.DUPE_MARGIN, budgets.dupes - addedDupes);
    if (addedSpirits > 0) budgets.spirits = Math.max(-SAVE_GUARD.SPIRIT_MARGIN, budgets.spirits - addedSpirits);
  }
  return result(reject, { earnedByGame });
}

// ==========================================
// รางวัลครั้งเดียว: เซิร์ฟเวอร์จดไว้ว่าบัญชีนี้รับอะไรไปแล้ว (ล็อกอินรายวัน, achievement, ขั้นชื่อเสียง, เคลียร์ด่านครั้งแรก, milestone ตามเกรด)
// เซฟที่ส่งมาห้ามขาดรายการที่เคยจดไว้ (ลบออกเพื่อกดรับซ้ำ = ไม่รับเซฟ + บวกคะแนนความเสี่ยง)
// ==========================================
const REPUTATION_TIER_THRESHOLDS = { 1: 100, 2: 250, 3: 600, 4: 1200, 5: 2200, 6: 3800, 7: 6000, 8: 9000, 9: 13000, 10: 18000 };
function extractOnceKeys(save) {
  const keys = [];
  if (!save || typeof save !== 'object') return keys;
  const dl = save.daily_login;
  const days = dl && typeof dl === 'object' ? Math.min(7, Math.max(0, parseInt(dl.days_claimed, 10) || 0)) : 0;
  for (let n = 1; n <= days; n++) keys.push('login:' + n);
  if (Array.isArray(save.achievements_claimed)) {
    save.achievements_claimed.forEach(id => { if (typeof id === 'string' && id.length > 0 && id.length <= 60) keys.push('ach:' + id); });
  }
  if (Array.isArray(save.reputation_claimed_tiers)) {
    save.reputation_claimed_tiers.forEach(t => { const n = Number(t); if (Number.isInteger(n) && n >= 1 && n <= 10) keys.push('rep:' + n); });
  }
  if (save.progress && typeof save.progress === 'object') {
    Object.keys(save.progress).forEach(isl => {
      const pr = save.progress[isl];
      if (isl.length <= 30 && pr && Array.isArray(pr.stages_first_cleared)) {
        pr.stages_first_cleared.forEach(st => { const n = Number(st); if (Number.isInteger(n) && n > 0 && n < 10000) keys.push('clr:' + isl + ':' + n); });
      }
    });
  }
  if (save.grade_milestones && typeof save.grade_milestones === 'object') {
    ['C', 'B', 'A', 'S'].forEach(g => {
      const v = Math.min(200, Math.max(0, Math.floor(Number(save.grade_milestones[g]) || 0)));
      for (let n = 1; n <= v; n++) keys.push('ms:' + g + ':' + n);
    });
  }
  return Array.from(new Set(keys));
}
// stored = รายการที่เซิร์ฟเวอร์จดไว้ (null = ยังไม่เคยจด → ถือว่าเซฟนี้เป็นฐาน), next = เซฟที่ส่งมา
function checkOnceClaims(stored, next) {
  const nextKeys = extractOnceKeys(next);
  if (!stored) return { baseline: true, missing: [], invalid: [], keys: nextKeys };
  const nextSet = new Set(nextKeys);
  const storedSet = new Set(stored);
  const missing = stored.filter(k => !nextSet.has(k));
  const added = nextKeys.filter(k => !storedSet.has(k));
  const invalid = [];
  const rep = Number(next && next.reputation) || 0;
  added.forEach(k => {
    if (k.indexOf('rep:') === 0) { const th = REPUTATION_TIER_THRESHOLDS[Number(k.slice(4))]; if (!th || rep < th) invalid.push(k); }
  });
  if (added.filter(k => k.indexOf('login:') === 0).length > 1) invalid.push('login_jump');
  const keys = Array.from(new Set(stored.concat(nextKeys)));
  return { baseline: false, missing, invalid, keys };
}

// ==========================================
// ชื่อกัปตัน: ภาษาไทยได้ ห้ามซ้ำ (ไม่สนตัวพิมพ์ใหญ่เล็ก/ช่องว่าง/ขีด) และห้ามเหมือนชื่อบัญชีแอดมิน
// หมายเหตุ: ชื่อที่โชว์ใช้ NFC (ไม่แตะสระอำ) ส่วนกุญแจเทียบชื่อใช้ NFKC
// ==========================================
function captainNameKey(name) {
  return String(name == null ? '' : name).normalize('NFKC').toLowerCase().replace(/[\s_.\-]+/g, '');
}
function validateCaptainName(raw) {
  const name = String(raw == null ? '' : raw).normalize('NFC').replace(/\s+/g, ' ').trim();
  const len = Array.from(name).length;
  if (len < 2 || len > 20) return { error: 'ชื่อกัปตันต้องยาว 2-20 ตัวอักษร' };
  if (!/^[\p{L}\p{M}\p{N} _.\-]+$/u.test(name)) return { error: 'ชื่อกัปตันใช้ได้เฉพาะตัวอักษร ตัวเลข ช่องว่าง และ _ . -' };
  const key = captainNameKey(name);
  if (!key) return { error: 'ชื่อกัปตันไม่ถูกต้อง' };
  return { name, key };
}
function captainNameReserved(key) {
  return ADMIN_USERNAMES.some(u => captainNameKey(u) === key);
}
// คืน { ok:true, name } หรือ { ok:false, error }
async function tryClaimCaptainName(db, userId, raw) {
  const v = validateCaptainName(raw);
  if (v.error) return { ok: false, error: v.error };
  const taken = { ok: false, error: 'ชื่อกัปตันนี้มีคนใช้แล้ว ลองชื่ออื่น' };
  if (captainNameReserved(v.key)) {
    // เจ้าของบัญชีแอดมินใช้ชื่อบัญชีของตัวเองเป็นชื่อกัปตันได้ (คนอื่นยังใช้ไม่ได้)
    const own = await db.getUsername(userId);
    const isOwnAdminName = own && ADMIN_USERNAMES.includes(own) && captainNameKey(own) === v.key;
    if (!isOwnAdminName) return taken;
  }
  if (await db.captainNameClashesUsername(v.key, userId)) return taken;
  const c = await db.claimCaptainName(userId, v.name, v.key);
  return c.ok ? { ok: true, name: v.name } : taken;
}

function validateSavePayload(saveData) {
  if (saveData === undefined || saveData === null) return 'ไม่มีข้อมูลเซฟส่งมา';
  let sizeCheck;
  try {
    sizeCheck = Buffer.byteLength(JSON.stringify(saveData), 'utf8');
  } catch (e) {
    return 'ข้อมูลเซฟไม่ถูกต้อง';
  }
  if (sizeCheck > MAX_SAVE_SIZE_BYTES) return 'ข้อมูลเซฟใหญ่เกินไป';
  return null;
}

module.exports = { validateUsername, validatePassword, validateSavePayload, MAX_SAVE_SIZE_BYTES };


// ===== db.js =====
// db.js
// ชั้นเชื่อมต่อฐานข้อมูลจริง (Postgres) — ใช้ package "pg" (ต้อง npm install ตอน deploy จริง)
// ไฟล์นี้ไม่ได้ทดสอบในแซนด์บ็อกซ์นี้เพราะไม่มีเน็ตให้ต่อฐานข้อมูลจริง แต่ "pg" เป็น library
// มาตรฐานที่ใช้กันแพร่หลายมาก ความเสี่ยงต่ำ — โครงสร้าง SQL ตรงไปตรงมา ทดสอบง่ายตอน deploy จริง

function createDb(connectionString) {
  const pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false } // Render Postgres ต้องใช้ SSL
  });

  return {
    // เรียกครั้งเดียวตอนเซิร์ฟเวอร์เริ่มทำงาน สร้างตารางถ้ายังไม่มี
    async init() {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          password_salt TEXT NOT NULL,
          created_at TIMESTAMPTZ DEFAULT now()
        );
      `);
      // รหัสผู้เล่น 5 หลัก (สุ่ม ไม่ซ้ำ) ไว้ใช้เพิ่มเพื่อน/ให้ GM อ้างอิงผู้เล่น และเวลาที่เห็นผู้เล่นออนไลน์ล่าสุด
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS public_id INTEGER;`);
      await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_public_id_uq ON users(public_id);`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;`);
      // เซิร์ฟเวอร์จำเองว่าบัญชีนี้สุ่มผู้ช่วยคนแรกไปแล้ว (แก้เซฟให้ได้สุ่มฟรีซ้ำไม่ได้)
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS starter_done BOOLEAN NOT NULL DEFAULT false;`);
      // ชื่อกัปตันไม่ซ้ำ: เก็บชื่อที่แสดง + กุญแจเทียบชื่อ (ตัวพิมพ์เล็ก ไม่มีช่องว่าง/ขีด) ดัชนี unique กันซ้ำที่ระดับฐานข้อมูล
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS captain_name TEXT;`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS captain_name_key TEXT;`);
      await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_captain_name_key_uq ON users(captain_name_key) WHERE captain_name_key IS NOT NULL;`);
      // รางวัลครั้งเดียวที่ผู้เล่นรับไปแล้ว (เซิร์ฟเวอร์จำเอง ต่อให้เซฟที่ส่งมาลบรายการออกก็ไม่เชื่อ)
      await pool.query(`CREATE TABLE IF NOT EXISTS once_claims (user_id INTEGER PRIMARY KEY, keys JSONB NOT NULL DEFAULT '[]'::jsonb, updated_at TIMESTAMPTZ DEFAULT now());`);
      // กล่องรับของ: ทุกอย่างที่เซิร์ฟเวอร์ "ให้" ผู้เล่น (GM โอน, เติมเงิน, รางวัล PVP) เข้าตารางนี้ก่อน
      // แล้วให้ตัวเกมของผู้เล่นมารับไปบวกเองและกดยืนยันกลับ — ไม่แก้เซฟตรงๆ อีก เพราะเกมฝั่งผู้เล่นจะเซฟทับกลับมาจนเพชรหาย
      await pool.query(`
        CREATE TABLE IF NOT EXISTS grants (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL,
          source TEXT NOT NULL DEFAULT 'gm',
          gems INTEGER NOT NULL DEFAULT 0,
          doubloons INTEGER NOT NULL DEFAULT 0,
          note TEXT,
          created_at TIMESTAMPTZ DEFAULT now(),
          delivered_at TIMESTAMPTZ,
          gems_after INTEGER,
          doubloons_after INTEGER
        );
      `);
      await pool.query(`CREATE INDEX IF NOT EXISTS grants_user_idx ON grants(user_id, created_at DESC);`);
      const noId = await pool.query('SELECT id FROM users WHERE public_id IS NULL');
      for (const row of noId.rows) {
        await this.assignPublicId(row.id);
      }
      // ระบบเพื่อน: friendships เก็บ 2 ทิศทาง (A->B และ B->A), friend_requests = คำเชิญที่รอตอบ, messages = จดหมายระหว่างเพื่อน
      await pool.query(`CREATE TABLE IF NOT EXISTS friendships (user_id INTEGER NOT NULL, friend_id INTEGER NOT NULL, created_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY (user_id, friend_id));`);
      await pool.query(`CREATE TABLE IF NOT EXISTS friend_requests (id SERIAL PRIMARY KEY, from_user INTEGER NOT NULL, to_user INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT now());`);
      await pool.query(`CREATE INDEX IF NOT EXISTS friend_requests_to_idx ON friend_requests(to_user, status);`);
      await pool.query(`CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, from_user INTEGER NOT NULL, to_user INTEGER NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now(), read_at TIMESTAMPTZ);`);
      await pool.query(`CREATE INDEX IF NOT EXISTS messages_to_idx ON messages(to_user, id DESC);`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS player_saves (
          user_id INTEGER PRIMARY KEY REFERENCES users(id),
          save_data JSONB NOT NULL,
          updated_at TIMESTAMPTZ DEFAULT now()
        );
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS pvp_profiles (
          user_id INTEGER PRIMARY KEY REFERENCES users(id),
          points INTEGER NOT NULL DEFAULT 100,
          attack_team JSONB NOT NULL DEFAULT '[]',
          defense_team JSONB NOT NULL DEFAULT '[]',
          hide_today BOOLEAN NOT NULL DEFAULT false,
          season_start DATE NOT NULL,
          matches_played INTEGER NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ DEFAULT now()
        );
      `);
      // เผื่อ DB ที่ deploy จริงถูกสร้างไว้ก่อนมีคอลัมน์นี้ (CREATE TABLE IF NOT EXISTS ไม่แก้ตารางเดิม)
      await pool.query(`ALTER TABLE pvp_profiles ADD COLUMN IF NOT EXISTS matches_played INTEGER NOT NULL DEFAULT 0;`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS pvp_reward_log (
          season_start DATE NOT NULL,
          day_number INTEGER NOT NULL,
          distributed_at TIMESTAMPTZ DEFAULT now(),
          PRIMARY KEY (season_start, day_number)
        );
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS pvp_matches (
          id SERIAL PRIMARY KEY,
          season_start DATE NOT NULL,
          day_number INTEGER NOT NULL,
          player_a INTEGER NOT NULL REFERENCES users(id),
          player_b INTEGER REFERENCES users(id),
          attacker_id INTEGER,
          defender_id INTEGER,
          winner_id INTEGER,
          resolved BOOLEAN NOT NULL DEFAULT false,
          created_at TIMESTAMPTZ DEFAULT now()
        );
      `);
      // แมตช์กับบอท (ใช้เมื่อจำนวนผู้เล่นเป็นเลขคี่ แล้วเหลือคนเดียวไม่มีคู่)
      await pool.query(`ALTER TABLE pvp_matches ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;`);
      await pool.query(`ALTER TABLE player_saves ADD COLUMN IF NOT EXISTS gem_budget DOUBLE PRECISION;`);
      await pool.query(`ALTER TABLE player_saves ADD COLUMN IF NOT EXISTS crew_budget DOUBLE PRECISION;`);
      await pool.query(`ALTER TABLE player_saves ADD COLUMN IF NOT EXISTS dupe_budget DOUBLE PRECISION;`);
      await pool.query(`ALTER TABLE player_saves ADD COLUMN IF NOT EXISTS spirit_budget DOUBLE PRECISION;`);
      // คะแนนความเสี่ยงอัตโนมัติ + การจำกัดบัญชีชั่วคราว (หมดอายุเอง)
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS risk_score DOUBLE PRECISION NOT NULL DEFAULT 0;`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS risk_at TIMESTAMPTZ;`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS quarantined_until TIMESTAMPTZ;`);
      await pool.query(`ALTER TABLE player_saves ADD COLUMN IF NOT EXISTS budget_at TIMESTAMPTZ;`);
      // รายงานเซฟที่น่าสงสัย (ตรวจโกง) ให้ GM ดู
      await pool.query(`CREATE TABLE IF NOT EXISTS audit_flags (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL, detail JSONB, created_at TIMESTAMPTZ DEFAULT now());`);
      await pool.query(`CREATE INDEX IF NOT EXISTS audit_flags_user_idx ON audit_flags(user_id, created_at DESC);`);
      // สมุดบัญชีเพชร: ทุกครั้งที่เพชรของผู้เล่นเปลี่ยนตามที่เซิร์ฟเวอร์รู้ จดไว้พร้อมเหตุผล (ไว้ย้อนตรวจตอนสงสัยโกง/ตอนผู้เล่นร้องเรียน)
      await pool.query(`CREATE TABLE IF NOT EXISTS gem_ledger (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, delta INTEGER NOT NULL, balance_after BIGINT, reason TEXT NOT NULL, note JSONB, created_at TIMESTAMPTZ DEFAULT now());`);
      await pool.query(`CREATE INDEX IF NOT EXISTS gem_ledger_user_idx ON gem_ledger(user_id, id DESC);`);
      // บันทึกการต่อสู้ของแมตช์ที่ตัดสินแล้ว (เก็บ 7 วันแล้วลบทิ้งเพื่อไม่ให้ฐานข้อมูลโต)
      await pool.query(`ALTER TABLE pvp_matches ADD COLUMN IF NOT EXISTS battle_log TEXT;`);
      await pool.query(`ALTER TABLE pvp_matches ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS topup_requests (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          username TEXT NOT NULL,
          amount_baht INTEGER NOT NULL,
          gem_amount INTEGER NOT NULL,
          note TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at TIMESTAMPTZ DEFAULT now(),
          resolved_at TIMESTAMPTZ
        );
      `);
    },

    async getUserByUsername(username) {
      const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      return r.rows[0] || null;
    },

    async createUser(username, passwordHash, passwordSalt) {
      const r = await pool.query(
        'INSERT INTO users (username, password_hash, password_salt) VALUES ($1, $2, $3) RETURNING id, username',
        [username, passwordHash, passwordSalt]
      );
      const publicId = await this.assignPublicId(r.rows[0].id);
      return Object.assign({}, r.rows[0], { public_id: publicId });
    },

    // สุ่มเลข 5 หลัก (10000-99999) ที่ยังไม่มีใครใช้ ชนกันก็สุ่มใหม่
    async assignPublicId(userId) {
      for (let attempt = 0; attempt < 200; attempt++) {
        const candidate = 10000 + Math.floor(Math.random() * 90000);
        try {
          const r = await pool.query('UPDATE users SET public_id = $1 WHERE id = $2 AND public_id IS NULL RETURNING public_id', [candidate, userId]);
          if (r.rows[0]) return r.rows[0].public_id;
          const existing = await pool.query('SELECT public_id FROM users WHERE id = $1', [userId]);
          return existing.rows[0] ? existing.rows[0].public_id : null;
        } catch (e) {
          if (e && e.code === '23505') continue; // เลขซ้ำ สุ่มใหม่
          throw e;
        }
      }
      throw new Error('สุ่มรหัสผู้เล่นไม่สำเร็จ');
    },

    // เลเวลกัปตันของหลายคนในครั้งเดียว → { userId: level }
    async getCaptainLevels(userIds) {
      const ids = Array.from(new Set((userIds || []).filter(n => Number.isInteger(n))));
      if (ids.length === 0) return {};
      const r = await pool.query(`SELECT user_id, CASE WHEN (save_data->>'captain_level') ~ '^[0-9]+$' THEN LEAST(50, GREATEST(1, (save_data->>'captain_level')::int)) ELSE 1 END AS lv FROM player_saves WHERE user_id = ANY($1::int[])`, [ids]);
      const map = {};
      r.rows.forEach(row => { map[row.user_id] = row.lv; });
      return map;
    },

    async getStarterDone(userId) {
      const r = await pool.query('SELECT starter_done FROM users WHERE id = $1', [userId]);
      return !!(r.rows[0] && r.rows[0].starter_done);
    },
    async setStarterDone(userId) {
      await pool.query('UPDATE users SET starter_done = true WHERE id = $1', [userId]);
    },

    // รายการรางวัลครั้งเดียวที่รับแล้ว (null = ยังไม่เคยจด)
    async getOnceKeys(userId) {
      const r = await pool.query('SELECT keys FROM once_claims WHERE user_id = $1', [userId]);
      if (!r.rows[0]) return null;
      return Array.isArray(r.rows[0].keys) ? r.rows[0].keys : [];
    },
    async setOnceKeys(userId, keys) {
      await pool.query(
        `INSERT INTO once_claims (user_id, keys, updated_at) VALUES ($1, $2::jsonb, now())
         ON CONFLICT (user_id) DO UPDATE SET keys = $2::jsonb, updated_at = now()`,
        [userId, JSON.stringify(keys)]
      );
    },

    // ชื่อกัปตัน
    async getCaptainName(userId) {
      const r = await pool.query('SELECT captain_name FROM users WHERE id = $1', [userId]);
      return (r.rows[0] && r.rows[0].captain_name) || null;
    },
    async claimCaptainName(userId, name, key) {
      try {
        await pool.query('UPDATE users SET captain_name = $2, captain_name_key = $3 WHERE id = $1', [userId, name, key]);
        return { ok: true };
      } catch (e) {
        if (e && e.code === '23505') return { ok: false, taken: true };
        throw e;
      }
    },
    // ชื่อที่ชนกับ username ของคนอื่น (กันเลียนแบบชื่อแอดมิน/ผู้เล่นอื่น)
    async captainNameClashesUsername(key, userId) {
      const r = await pool.query(`SELECT 1 FROM users WHERE id <> $2 AND regexp_replace(lower(username), '[\\s_.\\-]', '', 'g') = $1 LIMIT 1`, [key, userId]);
      return r.rows.length > 0;
    },

    async getUserById(userId) {
      const r = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
      return r.rows[0] || null;
    },

    // ---------- เพื่อน ----------
    async areFriends(a, b) {
      const r = await pool.query('SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2', [a, b]);
      return r.rowCount > 0;
    },
    async countFriends(userId) {
      const r = await pool.query('SELECT count(*)::int AS n FROM friendships WHERE user_id = $1', [userId]);
      return r.rows[0].n;
    },
    async listFriends(userId) {
      const r = await pool.query(`SELECT u.id, u.public_id, COALESCE(NULLIF(btrim(ps.save_data->>'player_name'), ''), u.username) AS username, u.last_seen_at, f.created_at AS since
        FROM friendships f JOIN users u ON u.id = f.friend_id LEFT JOIN player_saves ps ON ps.user_id = u.id WHERE f.user_id = $1 ORDER BY 3 ASC`, [userId]);
      return r.rows;
    },
    async addFriendship(a, b) {
      await pool.query('INSERT INTO friendships (user_id, friend_id) VALUES ($1, $2), ($2, $1) ON CONFLICT DO NOTHING', [a, b]);
    },
    async removeFriendship(a, b) {
      await pool.query('DELETE FROM friendships WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)', [a, b]);
    },
    async findPendingRequest(fromUser, toUser) {
      const r = await pool.query("SELECT * FROM friend_requests WHERE from_user = $1 AND to_user = $2 AND status = 'pending' LIMIT 1", [fromUser, toUser]);
      return r.rows[0] || null;
    },
    async countRecentRequests(fromUser) {
      const r = await pool.query("SELECT count(*)::int AS n FROM friend_requests WHERE from_user = $1 AND created_at > now() - interval '1 hour'", [fromUser]);
      return r.rows[0].n;
    },
    async createFriendRequest(fromUser, toUser) {
      const r = await pool.query('INSERT INTO friend_requests (from_user, to_user) VALUES ($1, $2) RETURNING id', [fromUser, toUser]);
      return r.rows[0];
    },
    async getRequestForUser(requestId, toUser) {
      const r = await pool.query("SELECT * FROM friend_requests WHERE id = $1 AND to_user = $2 AND status = 'pending'", [requestId, toUser]);
      return r.rows[0] || null;
    },
    async resolveFriendRequest(requestId, status) {
      await pool.query('UPDATE friend_requests SET status = $2 WHERE id = $1', [requestId, status]);
    },
    async listPendingRequests(toUser) {
      const r = await pool.query(`SELECT fr.id, fr.created_at, fr.from_user, u.public_id AS from_public_id, COALESCE(NULLIF(btrim(ps.save_data->>'player_name'), ''), u.username) AS from_username
        FROM friend_requests fr JOIN users u ON u.id = fr.from_user LEFT JOIN player_saves ps ON ps.user_id = u.id WHERE fr.to_user = $1 AND fr.status = 'pending' ORDER BY fr.id DESC LIMIT 50`, [toUser]);
      return r.rows;
    },
    // ---------- จดหมาย ----------
    async countRecentMessages(fromUser) {
      const r = await pool.query("SELECT count(*)::int AS n FROM messages WHERE from_user = $1 AND created_at > now() - interval '1 hour'", [fromUser]);
      return r.rows[0].n;
    },
    async createMessage(fromUser, toUser, body) {
      const r = await pool.query('INSERT INTO messages (from_user, to_user, body) VALUES ($1, $2, $3) RETURNING id, created_at', [fromUser, toUser, body]);
      // เก็บในกล่องผู้รับไม่เกิน 100 ฉบับ ลบฉบับเก่าสุดทิ้ง
      await pool.query('DELETE FROM messages WHERE to_user = $1 AND id NOT IN (SELECT id FROM messages WHERE to_user = $1 ORDER BY id DESC LIMIT 100)', [toUser]);
      return r.rows[0];
    },
    async listMessages(toUser) {
      const r = await pool.query(`SELECT m.id, m.body, m.created_at, m.read_at, u.public_id AS from_public_id, COALESCE(NULLIF(btrim(ps.save_data->>'player_name'), ''), u.username) AS from_username
        FROM messages m JOIN users u ON u.id = m.from_user LEFT JOIN player_saves ps ON ps.user_id = u.id WHERE m.to_user = $1 ORDER BY m.id DESC LIMIT 50`, [toUser]);
      return r.rows;
    },
    async markAllMessagesRead(toUser) {
      await pool.query('UPDATE messages SET read_at = now() WHERE to_user = $1 AND read_at IS NULL', [toUser]);
    },
    async deleteMessage(id, toUser) {
      const r = await pool.query('DELETE FROM messages WHERE id = $1 AND to_user = $2', [id, toUser]);
      return r.rowCount;
    },
    async countUnreadMessages(toUser) {
      const r = await pool.query('SELECT count(*)::int AS n FROM messages WHERE to_user = $1 AND read_at IS NULL', [toUser]);
      return r.rows[0].n;
    },
    async countPendingRequests(toUser) {
      const r = await pool.query("SELECT count(*)::int AS n FROM friend_requests WHERE to_user = $1 AND status = 'pending'", [toUser]);
      return r.rows[0].n;
    },

    // ถังเพชรของตัวตรวจโกง: คืน { budget, at } ที่บันทึกไว้ (ถ้ายังไม่เคยมี at = เวลาเซฟล่าสุด)
    async getGuardState(userId) {
      const r = await pool.query('SELECT gem_budget, crew_budget, dupe_budget, spirit_budget, budget_at, updated_at FROM player_saves WHERE user_id = $1', [userId]);
      if (!r.rows[0]) return null;
      const x = r.rows[0];
      return { budget: x.gem_budget, crewBudget: x.crew_budget, dupeBudget: x.dupe_budget, spiritBudget: x.spirit_budget, at: x.budget_at || x.updated_at };
    },
    async setGuardState(userId, budgets) {
      const bd = (typeof budgets === 'object' && budgets) ? budgets : { gems: budgets };
      await pool.query('UPDATE player_saves SET gem_budget = $2, crew_budget = $3, dupe_budget = $4, spirit_budget = $5, budget_at = now() WHERE user_id = $1',
        [userId, bd.gems, bd.crew === undefined ? null : bd.crew, bd.dupes === undefined ? null : bd.dupes, bd.spirits === undefined ? null : bd.spirits]);
    },

    // ---- ความเสี่ยงอัตโนมัติ: คะแนนลดลงครึ่งหนึ่งทุก 24 ชม. ถึง 60 = จำกัดบัญชี 7 วัน (หมดอายุเอง) ----
    async getQuarantine(userId) {
      const r = await pool.query('SELECT risk_score, risk_at, quarantined_until FROM users WHERE id = $1', [userId]);
      const x = r.rows[0];
      if (!x) return { active: false, until: null, score: 0 };
      const active = !!(x.quarantined_until && new Date(x.quarantined_until).getTime() > Date.now());
      return { active, until: x.quarantined_until, score: x.risk_score || 0 };
    },
    async addRisk(userId, add, quarantineScore, quarantineDays) {
      const r = await pool.query('SELECT risk_score, risk_at, quarantined_until FROM users WHERE id = $1', [userId]);
      const x = r.rows[0];
      if (!x) return { score: 0, newlyQuarantined: false };
      const hours = x.risk_at ? Math.max(0, (Date.now() - new Date(x.risk_at).getTime()) / 3600000) : 0;
      const score = (x.risk_score || 0) * Math.pow(0.5, hours / 24) + add;
      const wasActive = !!(x.quarantined_until && new Date(x.quarantined_until).getTime() > Date.now());
      const newly = !wasActive && score >= quarantineScore;
      if (newly) {
        await pool.query("UPDATE users SET risk_score = $2, risk_at = now(), quarantined_until = now() + ($3 || ' days')::interval WHERE id = $1", [userId, score, String(quarantineDays)]);
      } else {
        await pool.query('UPDATE users SET risk_score = $2, risk_at = now() WHERE id = $1', [userId, score]);
      }
      return { score, newlyQuarantined: newly };
    },
    async clearQuarantine(userId) {
      await pool.query('UPDATE users SET risk_score = 0, risk_at = now(), quarantined_until = NULL WHERE id = $1', [userId]);
    },
    // เพชรที่เซิร์ฟเวอร์ "ให้" ไปแล้วเมื่อไม่นานนี้ หรือยังค้างส่ง — นับเป็นเพชรที่เพิ่มขึ้นได้อย่างถูกต้อง
    async getRecentGrantGems(userId) {
      const r = await pool.query("SELECT COALESCE(SUM(gems),0)::bigint AS s FROM grants WHERE user_id = $1 AND gems > 0 AND (delivered_at IS NULL OR created_at > now() - interval '72 hours')", [userId]);
      return Number(r.rows[0].s) || 0;
    },
    async addLedger(userId, delta, balanceAfter, reason, note) {
      await pool.query('INSERT INTO gem_ledger (user_id, delta, balance_after, reason, note) VALUES ($1, $2, $3, $4, $5)',
        [userId, Math.trunc(delta), Number.isFinite(balanceAfter) ? Math.trunc(balanceAfter) : null, reason, note ? JSON.stringify(note) : null]);
      // เก็บสมุดบัญชีย้อนหลังคนละไม่เกิน 500 รายการ กันฐานข้อมูลโต
      await pool.query('DELETE FROM gem_ledger WHERE user_id = $1 AND id NOT IN (SELECT id FROM gem_ledger WHERE user_id = $1 ORDER BY id DESC LIMIT 500)', [userId]);
    },
    async listLedger(userId, limit) {
      const r = await pool.query('SELECT id, delta, balance_after, reason, note, created_at FROM gem_ledger WHERE user_id = $1 ORDER BY id DESC LIMIT $2', [userId, limit || 100]);
      return r.rows;
    },
    // สำรองข้อมูล: เซฟทุกคน (ไม่รวมรหัสผ่าน)
    async exportAllSaves() {
      const r = await pool.query(`SELECT u.id, u.public_id, u.username, ps.save_data, ps.updated_at FROM users u LEFT JOIN player_saves ps ON ps.user_id = u.id ORDER BY u.id ASC`);
      return r.rows;
    },
    // บันทึกรายงาน (ชนิดเดียวกันของผู้เล่นคนเดียวกันไม่ซ้ำภายใน 10 นาที กันรายงานท่วม)
    async addFlag(userId, kind, detail) {
      await pool.query("INSERT INTO audit_flags (user_id, kind, detail) SELECT $1, $2, $3 WHERE NOT EXISTS (SELECT 1 FROM audit_flags WHERE user_id = $1 AND kind = $2 AND created_at > now() - interval '10 minutes')", [userId, kind, JSON.stringify(detail || {})]);
    },
    async listFlags(limit) {
      const r = await pool.query(`SELECT f.id, f.kind, f.detail, f.created_at, u.username, u.public_id FROM audit_flags f JOIN users u ON u.id = f.user_id ORDER BY f.id DESC LIMIT $1`, [limit || 50]);
      return r.rows;
    },

    async getPublicId(userId) {
      const r = await pool.query('SELECT public_id FROM users WHERE id = $1', [userId]);
      return r.rows[0] ? r.rows[0].public_id : null;
    },

    async getUserByPublicId(publicId) {
      const r = await pool.query('SELECT * FROM users WHERE public_id = $1', [publicId]);
      return r.rows[0] || null;
    },

    async touchLastSeen(userId) {
      await pool.query('UPDATE users SET last_seen_at = now() WHERE id = $1', [userId]);
    },

    // ---------- กล่องรับของ ----------
    async createGrant(userId, grant) {
      const r = await pool.query(
        'INSERT INTO grants (user_id, source, gems, doubloons, note) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at',
        [userId, grant.source || 'gm', grant.gems || 0, grant.doubloons || 0, grant.note || null]
      );
      return r.rows[0];
    },

    async getPendingGrants(userId) {
      const r = await pool.query('SELECT id, source, gems, doubloons, note, created_at FROM grants WHERE user_id = $1 AND delivered_at IS NULL ORDER BY id ASC LIMIT 50', [userId]);
      return r.rows;
    },

    // ผู้เล่นยืนยันว่าบวกเข้าเซฟแล้ว (และเซฟขึ้นเซิร์ฟเวอร์แล้ว) พร้อมยอดคงเหลือที่เห็นในเครื่องเขา ไว้ให้ GM ตรวจ
    async ackGrants(userId, acks) {
      let count = 0;
      for (const a of acks) {
        const r = await pool.query(
          'UPDATE grants SET delivered_at = now(), gems_after = $3, doubloons_after = $4 WHERE id = $1 AND user_id = $2 AND delivered_at IS NULL RETURNING gems, source, note',
          [a.id, userId, Number.isFinite(a.gemsAfter) ? Math.trunc(a.gemsAfter) : null, Number.isFinite(a.doubloonsAfter) ? Math.trunc(a.doubloonsAfter) : null]
        );
        if (r.rowCount > 0) {
          count += 1;
          const g = r.rows[0];
          if (g.gems) {
            try { await this.addLedger(userId, g.gems, Number.isFinite(a.gemsAfter) ? a.gemsAfter : null, 'grant_' + g.source, { grantId: a.id, note: g.note || null }); } catch (e) { /* สมุดบัญชีพลาดไม่ควรทำให้การรับของพัง */ }
          }
        }
      }
      return count;
    },

    async getGrantHistory(userId, limit) {
      const r = await pool.query('SELECT id, source, gems, doubloons, note, created_at, delivered_at, gems_after, doubloons_after FROM grants WHERE user_id = $1 ORDER BY id DESC LIMIT $2', [userId, limit || 30]);
      return r.rows;
    },

    // ภาพรวมผู้เล่นทุกคนให้ GM: รหัส, ชื่อ, ออนไลน์ล่าสุด, เพชร/ดับลูนในเซฟล่าสุดที่เซิร์ฟเวอร์รู้, โอนครั้งล่าสุด, ของที่ยังค้างส่ง
    async getUsersOverview() {
      const r = await pool.query(`
        SELECT u.id, u.public_id, u.username, u.last_seen_at, u.created_at,
               (ps.save_data->>'gems')::bigint AS gems,
               (ps.save_data->>'doubloons')::bigint AS doubloons,
               ps.save_data->>'player_name' AS player_name,
               u.risk_score, u.quarantined_until,
               (SELECT max(created_at) FROM grants g WHERE g.user_id = u.id) AS last_grant_at,
               (SELECT count(*) FROM grants g WHERE g.user_id = u.id AND g.delivered_at IS NULL) AS pending_grants
        FROM users u LEFT JOIN player_saves ps ON ps.user_id = u.id
        ORDER BY u.id ASC`);
      return r.rows;
    },

    // ลบบัญชีทั้งหมดของผู้เล่นคนนี้ (เซฟ, โปรไฟล์ PVP, แมตช์, คำขอเติมเงิน, ประวัติโอน) — ย้อนกลับไม่ได้
    async deleteUserCascade(userId) {
      await pool.query('DELETE FROM pvp_matches WHERE player_a = $1 OR player_b = $1', [userId]);
      await pool.query('DELETE FROM pvp_profiles WHERE user_id = $1', [userId]);
      await pool.query('DELETE FROM topup_requests WHERE user_id = $1', [userId]);
      await pool.query('DELETE FROM grants WHERE user_id = $1', [userId]);
      await pool.query('DELETE FROM audit_flags WHERE user_id = $1', [userId]);
      await pool.query('DELETE FROM gem_ledger WHERE user_id = $1', [userId]);
      await pool.query('DELETE FROM friendships WHERE user_id = $1 OR friend_id = $1', [userId]);
      await pool.query('DELETE FROM friend_requests WHERE from_user = $1 OR to_user = $1', [userId]);
      await pool.query('DELETE FROM messages WHERE from_user = $1 OR to_user = $1', [userId]);
      await pool.query('DELETE FROM player_saves WHERE user_id = $1', [userId]);
      await pool.query('DELETE FROM once_claims WHERE user_id = $1', [userId]);
      const r = await pool.query('DELETE FROM users WHERE id = $1', [userId]);
      return r.rowCount;
    },

    async getSave(userId) {
      const r = await pool.query('SELECT save_data FROM player_saves WHERE user_id = $1', [userId]);
      return r.rows[0] ? r.rows[0].save_data : null;
    },

    async setSave(userId, saveData) {
      await pool.query(
        `INSERT INTO player_saves (user_id, save_data, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (user_id) DO UPDATE SET save_data = $2, updated_at = now()`,
        [userId, saveData]
      );
    },

    // ชื่อที่โชว์ (ชื่อกัปตันก่อน แล้วค่อย username) ของหลายคน → { userId: name }
    async getDisplayNames(userIds) {
      const ids = Array.from(new Set((userIds || []).filter(n => Number.isInteger(n))));
      if (ids.length === 0) return {};
      const r = await pool.query(`SELECT u.id, COALESCE(NULLIF(btrim(ps.save_data->>'player_name'), ''), u.username) AS name FROM users u LEFT JOIN player_saves ps ON ps.user_id = u.id WHERE u.id = ANY($1::int[])`, [ids]);
      const map = {};
      r.rows.forEach(row => { map[row.id] = row.name; });
      return map;
    },
    async getDisplayName(userId) {
      const m = await this.getDisplayNames([userId]);
      return m[userId] || null;
    },

    async getUsername(userId) {
      const r = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
      return r.rows[0] ? r.rows[0].username : null;
    },

    // ดึงเซฟทุกคนพร้อมชื่อผู้ใช้ ใช้คำนวณ leaderboard (ชื่อเสียง/พลังสู้รบ/หมอกสุสาน)
    async getAllSavesWithUsernames() {
      const r = await pool.query('SELECT u.id AS user_id, u.username, ps.save_data FROM users u JOIN player_saves ps ON ps.user_id = u.id WHERE (u.quarantined_until IS NULL OR u.quarantined_until < now())');
      return r.rows.map(row => ({ userId: row.user_id, username: row.username, save: row.save_data }));
    },

    // คืน pvp_profile ของผู้เล่น สร้างให้อัตโนมัติถ้ายังไม่มี รีเซ็ตแต้ม+ทีมถ้าเป็นซีซั่นเก่า
    async ensurePvpProfile(userId, currentSeasonStartDateStr, startingPoints) {
      const existing = await pool.query('SELECT * FROM pvp_profiles WHERE user_id = $1', [userId]);
      if (existing.rows.length === 0) {
        const r = await pool.query(
          `INSERT INTO pvp_profiles (user_id, points, attack_team, defense_team, hide_today, season_start)
           VALUES ($1, $2, '[]', '[]', false, $3) RETURNING *`,
          [userId, startingPoints, currentSeasonStartDateStr]
        );
        return r.rows[0];
      }
      const row = existing.rows[0];
      const rowSeasonStr = row.season_start.toISOString().split('T')[0];
      if (rowSeasonStr !== currentSeasonStartDateStr) {
        const r = await pool.query(
          `UPDATE pvp_profiles SET points = $2, attack_team = '[]', defense_team = '[]', hide_today = false, season_start = $3, matches_played = 0, updated_at = now()
           WHERE user_id = $1 RETURNING *`,
          [userId, startingPoints, currentSeasonStartDateStr]
        );
        return r.rows[0];
      }
      return row;
    },

    // team เดียวใช้ทั้งบุกและตั้งรับ (รวมทีมโจมตี/ตั้งรับเป็นทีมเดียวตามสเปคใหม่)
    // เขียนค่าเดียวกันลงทั้ง attack_team และ defense_team เพื่อไม่ต้องแก้โครงสร้างตาราง
    async setPvpTeams(userId, team) {
      const teamJson = JSON.stringify(team);
      await pool.query(
        'UPDATE pvp_profiles SET attack_team = $2, defense_team = $2, updated_at = now() WHERE user_id = $1',
        [userId, teamJson]
      );
    },

    async setPvpHidden(userId, hidden) {
      await pool.query('UPDATE pvp_profiles SET hide_today = $2, updated_at = now() WHERE user_id = $1', [userId, hidden]);
    },

    // อัพเดตแต้ม + นับว่าแข่งไปแล้ว 1 แมตช์ (ใช้ตอนตัดสินผลแพ้/ชนะจริงเท่านั้น)
    async applyPvpMatchResult(userId, newPoints) {
      await pool.query(
        'UPDATE pvp_profiles SET points = $2, matches_played = matches_played + 1, updated_at = now() WHERE user_id = $1',
        [userId, newPoints]
      );
    },

    async getAllPvpProfilesForSeason(currentSeasonStartDateStr) {
      const r = await pool.query('SELECT p.* FROM pvp_profiles p JOIN users u ON u.id = p.user_id WHERE p.season_start = $1 AND (u.quarantined_until IS NULL OR u.quarantined_until < now())', [currentSeasonStartDateStr]);
      return r.rows;
    },

    // พยายาม "จอง" สิทธิ์แจกรางวัลของวันนี้ — คืน true ถ้าเป็นครั้งแรก (ควรแจก), false ถ้าแจกไปแล้ว (ข้าม)
    async tryClaimRewardDay(seasonStartDateStr, dayNumber) {
      const r = await pool.query(
        `INSERT INTO pvp_reward_log (season_start, day_number) VALUES ($1, $2)
         ON CONFLICT (season_start, day_number) DO NOTHING RETURNING season_start`,
        [seasonStartDateStr, dayNumber]
      );
      return r.rows.length > 0;
    },

    async hasMatchesForDay(seasonStartDateStr, dayNumber) {
      const r = await pool.query('SELECT 1 FROM pvp_matches WHERE season_start = $1 AND day_number = $2 LIMIT 1', [seasonStartDateStr, dayNumber]);
      return r.rows.length > 0;
    },

    async createMatches(rows) {
      for (const m of rows) {
        await pool.query(
          `INSERT INTO pvp_matches (season_start, day_number, player_a, player_b, attacker_id, defender_id, is_bot)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [m.seasonStart, m.dayNumber, m.playerA, m.playerB, m.attackerId, m.defenderId, !!m.isBot]
        );
      }
    },

    async getUnresolvedMatchesForDay(seasonStartDateStr, dayNumber) {
      const r = await pool.query(
        'SELECT * FROM pvp_matches WHERE season_start = $1 AND day_number = $2 AND resolved = false AND (player_b IS NOT NULL OR is_bot = true)',
        [seasonStartDateStr, dayNumber]
      );
      return r.rows;
    },

    async resolveMatch(matchId, winnerId, battleLogJson) {
      await pool.query('UPDATE pvp_matches SET winner_id = $2, resolved = true, resolved_at = now(), battle_log = $3 WHERE id = $1', [matchId, winnerId, battleLogJson || null]);
      await pool.query("UPDATE pvp_matches SET battle_log = NULL WHERE battle_log IS NOT NULL AND resolved_at < now() - interval '7 days'");
    },

    async getMatchForUserOnDay(seasonStartDateStr, dayNumber, userId) {
      const r = await pool.query(
        'SELECT * FROM pvp_matches WHERE season_start = $1 AND day_number = $2 AND (player_a = $3 OR player_b = $3)',
        [seasonStartDateStr, dayNumber, userId]
      );
      return r.rows[0] || null;
    },

    async createTopupRequest(userId, username, amountBaht, gemAmount, note) {
      const r = await pool.query(
        `INSERT INTO topup_requests (user_id, username, amount_baht, gem_amount, note, status)
         VALUES ($1, $2, $3, $4, $5, 'pending') RETURNING *`,
        [userId, username, amountBaht, gemAmount, note || null]
      );
      return r.rows[0];
    },

    async getTopupRequestsForUser(userId) {
      const r = await pool.query('SELECT * FROM topup_requests WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [userId]);
      return r.rows;
    },

    async getPendingTopupRequests() {
      const r = await pool.query("SELECT * FROM topup_requests WHERE status = 'pending' ORDER BY created_at ASC");
      return r.rows;
    },

    async getTopupRequestById(id) {
      const r = await pool.query('SELECT * FROM topup_requests WHERE id = $1', [id]);
      return r.rows[0] || null;
    },

    async resolveTopupRequest(id, status) {
      await pool.query('UPDATE topup_requests SET status = $2, resolved_at = now() WHERE id = $1', [id, status]);
    }
  };
}

module.exports = { createDb };


// ===== data_pvp.js =====
// data_pvp.js
// ค่าคงที่ของระบบ PVP — ตัวเลขที่ไม่ได้กำหนดไว้ชัดเจน (แต้มต่อแพ้/ชนะ, ขอบเขต % ที่แน่นอน)
// เป็นค่าที่กะไว้ก่อนตามสัดส่วนที่คุยกัน ปรับแก้ได้อิสระในไฟล์นี้ไฟล์เดียว

const PVP_CONFIG = {
  SEASON_LENGTH_DAYS: 28,       // 1 ซีซั่น = 28 วัน (4 สัปดาห์) นับจากวันที่ 1 ของเดือน 00:00
  STARTING_POINTS: 100,         // แต้มเริ่มต้นของทุกคนตอนซีซั่นใหม่เริ่ม (ตามสเปคใหม่)
  POINTS_ON_WIN: 20,
  POINTS_ON_LOSS: 10,           // ตามสเปคใหม่ (ชนะ/แพ้ไม่เท่ากัน)
  HIDE_TEAM_COST_GEMS: 3,
  REWARD_INTERVAL_DAYS: 7,      // แจกรางวัลทุก 7 วัน (วันที่ 7, 14, 21, 28 ของซีซั่น)
};

// ระบบจัดอันดับแบบ "กลุ่มแต้ม" (Score Brackets) ตามสเปคใหม่:
// จัดผู้เล่นที่มีแต้มเท่ากันเป็นกลุ่มเดียวกันก่อน แล้วค่อยแบ่งสัดส่วนจาก "จำนวนกลุ่ม" ไม่ใช่จำนวนคน
// ใช้ Math.floor() กับ 4 แรงค์บน แล้วเศษที่เหลือ (แรงโน้มถ่วง) ตกไปกอง Bronze ทั้งหมด
const BRACKET_PERCENTILES = {
  champion: 0.10,
  diamond: 0.15,
  gold: 0.20,
  silver: 0.25
  // bronze = ส่วนที่เหลือทั้งหมด (รวมเศษที่ปัดตกจากแรงค์บนๆ)
};

// รางวัลเพชรรายสัปดาห์ตามแรงค์ (แจกวันที่ 7/14/21/28 ของซีซั่น) — ตัวเลขทั้งหมดตามที่เขากำหนดเอง
const WEEKLY_REWARD_GEMS_BY_RANK = {
  bronze: 50,
  silver: 75,
  gold: 110,
  diamond: 150,
  champion: 200
};

module.exports = { PVP_CONFIG, BRACKET_PERCENTILES, WEEKLY_REWARD_GEMS_BY_RANK };


// ===== pvp_system.js =====
// pvp_system.js
// ตรรกะหลักของระบบ PVP — ฟังก์ชันล้วนๆ (pure functions) ไม่แตะฐานข้อมูลหรือ HTTP โดยตรง
// ทำให้ทดสอบได้ง่ายและมั่นใจว่าคำนวณถูกต้องก่อนเอาไปต่อกับส่วนอื่น
//
// ยังไม่รวม: การตัดสินผลการต่อสู้จริง (ต้องพอร์ต combat engine จากไฟล์เกมมาไว้ฝั่งเซิร์ฟเวอร์ - งานถัดไป)
// ไฟล์นี้จัดการแค่ "ปฏิทินซีซั่น", "แรงค์ใครอยู่ตรงไหน", "จับคู่ใครกับใคร", "แต้มขึ้นลงเท่าไหร่ตอนแพ้ชนะ"

// อ้างอิงเวลาไทย (UTC+7) เป็นเวลากลางของทั้งระบบ เพื่อให้ "เที่ยงคืน" ตรงกันสำหรับผู้เล่นทุกคน
const TIMEZONE_OFFSET_HOURS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;

// ---------- ปฏิทินซีซั่น ----------
// จุดเริ่มต้นของซีซั่นที่นับถอยไป/มา monthOffset เดือนจาก "ตอนนี้" (เวลาไทย) — ใช้คำนวณทั้งซีซั่นปัจจุบันและซีซั่นก่อนหน้า
function getSeasonStartForMonthOffset(now, monthOffset) {
  const localNow = new Date(now.getTime() + TIMEZONE_OFFSET_HOURS * 60 * 60 * 1000);
  const year = localNow.getUTCFullYear();
  const month = localNow.getUTCMonth();
  const startLocal = Date.UTC(year, month + monthOffset, 1, 0, 0, 0);
  return new Date(startLocal - TIMEZONE_OFFSET_HOURS * 60 * 60 * 1000);
}

// ซีซั่นเริ่มวันที่ 1 ของเดือน 00:00 (เวลาไทย) วิ่ง 28 วันเป๊ะ แล้วปิดจนกว่าจะถึงวันที่ 1 เดือนถัดไป
function getSeasonInfo(now = new Date()) {
  const seasonStart = getSeasonStartForMonthOffset(now, 0);
  const seasonEnd = new Date(seasonStart.getTime() + PVP_CONFIG.SEASON_LENGTH_DAYS * DAY_MS);
  const nextSeasonStart = getSeasonStartForMonthOffset(now, 1);

  const isActive = now >= seasonStart && now < seasonEnd;
  const dayNumber = isActive ? Math.floor((now.getTime() - seasonStart.getTime()) / DAY_MS) + 1 : null;

  return { seasonStart, seasonEnd, nextSeasonStart, isActive, dayNumber, isClosedGap: !isActive };
}

// วันที่ dayNumber (1-28) เป็นวันแจกรางวัลไหม (ทุก 7 วัน: 7, 14, 21, 28)
function isRewardDay(dayNumber) {
  return dayNumber !== null && dayNumber > 0 && dayNumber % PVP_CONFIG.REWARD_INTERVAL_DAYS === 0;
}

// ---------- แรงค์ ----------

// รับ players = [{id, points, matchesPlayed}, ...]
// คืนรายชื่อพร้อมแรงค์และอันดับ ตามสเปคใหม่ (กลุ่มแต้ม + เศษตกไป Bronze):
// - เฉพาะคนที่ matchesPlayed > 0 เท่านั้นที่ถูกจัดอันดับ คนที่ยังไม่เคยแข่งเลยได้ rank: 'unranked'
// - จัดกลุ่มคนแต้มเท่ากันเป็น "กลุ่มแต้ม" หนึ่งกลุ่ม แล้วแบ่งสัดส่วนจากจำนวนกลุ่ม (ไม่ใช่จำนวนคน)
function computeRanks(players) {
  const eligible = players.filter(p => (p.matchesPlayed || 0) > 0);
  const unranked = players.filter(p => !((p.matchesPlayed || 0) > 0));

  const sorted = [...eligible].sort((a, b) => b.points - a.points);

  // จัดกลุ่มแต้มเท่ากัน (คงลำดับจากมากไปน้อย)
  const groups = [];
  for (const p of sorted) {
    const lastGroup = groups[groups.length - 1];
    if (lastGroup && lastGroup.points === p.points) {
      lastGroup.members.push(p);
    } else {
      groups.push({ points: p.points, members: [p] });
    }
  }

  const groupCount = groups.length;
  const championGroups = Math.floor(groupCount * BRACKET_PERCENTILES.champion);
  const diamondGroups = Math.floor(groupCount * BRACKET_PERCENTILES.diamond);
  const goldGroups = Math.floor(groupCount * BRACKET_PERCENTILES.gold);
  const silverGroups = Math.floor(groupCount * BRACKET_PERCENTILES.silver);
  // bronzeGroups = ส่วนที่เหลือทั้งหมด (แรงโน้มถ่วง: เศษที่ปัดตกจากแรงค์บนๆ กองมารวมที่นี่)
  const bronzeGroups = groupCount - championGroups - diamondGroups - goldGroups - silverGroups;

  const rankedOut = [];
  let position = 0;
  groups.forEach((group, groupIndex) => {
    let rank;
    if (groupIndex < championGroups) rank = 'champion';
    else if (groupIndex < championGroups + diamondGroups) rank = 'diamond';
    else if (groupIndex < championGroups + diamondGroups + goldGroups) rank = 'gold';
    else if (groupIndex < championGroups + diamondGroups + goldGroups + silverGroups) rank = 'silver';
    else rank = 'bronze';

    group.members.forEach(p => {
      position += 1;
      rankedOut.push({ id: p.id, points: p.points, rank, position });
    });
  });

  const unrankedOut = unranked.map(p => ({ id: p.id, points: p.points, rank: 'unranked', position: null }));

  return [...rankedOut, ...unrankedOut];
}

// ---------- แต้มตอนแพ้/ชนะ ----------
function applyMatchPoints(winnerPoints, loserPoints) {
  return {
    winnerNewPoints: winnerPoints + PVP_CONFIG.POINTS_ON_WIN,
    loserNewPoints: Math.max(0, loserPoints - PVP_CONFIG.POINTS_ON_LOSS) // แต้มไม่ติดลบ
  };
}

// ---------- จับคู่ประจำวัน ----------
// สลับลำดับแบบสุ่ม (Fisher-Yates) แล้วจับคู่ทีละ 2 คน ถ้าจำนวนคี่ คนสุดท้ายจะไม่มีคู่วันนั้น (bye)
function pairPlayersForDay(playerIds, rngFn = Math.random) {
  const shuffled = [...playerIds];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(rngFn() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  const pairs = [];
  for (let i = 0; i < shuffled.length - 1; i += 2) {
    pairs.push([shuffled[i], shuffled[i + 1]]);
  }
  const bye = shuffled.length % 2 === 1 ? shuffled[shuffled.length - 1] : null;
  return { pairs, bye };
}

// สุ่มว่าใครเป็นฝ่ายรุก (ใช้ทีมโจมตี) ใครเป็นฝ่ายรับ (ใช้ทีมตั้งรับ) ในคู่นั้น
function assignAttackerRole(pair, rngFn = Math.random) {
  return rngFn() < 0.5
    ? { attackerId: pair[0], defenderId: pair[1] }
    : { attackerId: pair[1], defenderId: pair[0] };
}

module.exports = {
  getSeasonInfo, isRewardDay, computeRanks,
  applyMatchPoints, pairPlayersForDay, assignAttackerRole
};


// ===== pvp_daily_job.js =====
// pvp_daily_job.js
// งานประจำวันของ PVP — เรียกจาก endpoint ที่มี cron ภายนอกมาปลุกทุกวัน (ดู README ส่วน PVP)
// ทำ 2 อย่างทุกครั้งที่ถูกเรียก (เรียกซ้ำได้ปลอดภัย ไม่ทำงานซ้ำถ้าทำไปแล้ว):
//   1. ตัดสินผลแมตช์เมื่อวาน (ถ้ายังไม่ตัดสิน) โดยใช้ข้อมูลเซฟจริงของผู้เล่นแต่ละคน (กันโกง)
//   2. จับคู่ผู้เล่นสำหรับวันนี้ (ถ้ายังไม่เคยจับคู่)


function extractSquadData(saveData, teamCharIds) {
  if (!saveData || !saveData.crew || !Array.isArray(teamCharIds)) return [];
  return teamCharIds
    .filter(id => id)
    .map(id => ({ id, saveData: saveData.crew[id] }))
    .filter(entry => entry.saveData); // กันกรณี id ในทีมที่เลือกไว้ไม่มีอยู่จริงในเซฟแล้ว (ขายทิ้ง/บั๊ก)
}

function extractPlayerStateForEngine(saveData) {
  return { crew: (saveData && saveData.crew) || {}, equipment_inventory: (saveData && saveData.equipment_inventory) || [] };
}

async function resolveOneMatch(db, gameEngine, match, seasonStartStr) {
  // แมตช์กับบอท: ผู้เล่นชนะอัตโนมัติ ได้แต้มเท่ากับชนะปกติ (บอทไม่มีแต้มให้หัก)
  if (match.is_bot) {
    const botPlayerProfile = await db.ensurePvpProfile(match.player_a, seasonStartStr, PVP_CONFIG.STARTING_POINTS);
    const botPoints = applyMatchPoints(botPlayerProfile.points, 0);
    await db.resolveMatch(match.id, match.player_a);
    await db.applyPvpMatchResult(match.player_a, botPoints.winnerNewPoints);
    return { matchId: match.id, winnerId: match.player_a, loserId: null, isAttackerWin: true, vsBot: true };
  }
  const attackerProfile = await db.ensurePvpProfile(match.attacker_id, seasonStartStr, PVP_CONFIG.STARTING_POINTS);
  const defenderProfile = await db.ensurePvpProfile(match.defender_id, seasonStartStr, PVP_CONFIG.STARTING_POINTS);

  const attackerSave = await db.getSave(match.attacker_id);
  const defenderSave = await db.getSave(match.defender_id);

  const attackerSquad = extractSquadData(attackerSave, attackerProfile.attack_team);
  const defenderSquad = extractSquadData(defenderSave, defenderProfile.defense_team);

  let isAttackerWin;
  let battleLogJson = null;
  if (attackerSquad.length === 0 && defenderSquad.length === 0) {
    isAttackerWin = Math.random() < 0.5; // ไม่มีใครจัดทีมเลยทั้งคู่ (เคสหายาก) สุ่มเดา
  } else if (attackerSquad.length === 0) {
    isAttackerWin = false; // ไม่ได้จัดทีมโจมตี แพ้อัตโนมัติ
  } else if (defenderSquad.length === 0) {
    isAttackerWin = true; // ฝ่ายรับไม่จัดทีมป้องกันเลย แพ้อัตโนมัติ
  } else {
    const result = gameEngine.runPvpCombat(
      attackerSquad, defenderSquad,
      extractPlayerStateForEngine(attackerSave), extractPlayerStateForEngine(defenderSave)
    );
    isAttackerWin = result.isAttackerWin;
    // เก็บบันทึกการต่อสู้ไว้ให้ผู้เล่นทั้งสองฝ่ายย้อนดูได้ (ฝั่ง 'player' ในเอนจินคือฝ่ายรุก)
    try {
      battleLogJson = JSON.stringify({
        rounds: result.totalRounds,
        logs: (result.logs || []).slice(0, 600),
        summary: Object.keys(result.stats || {}).map(k => {
          const s = result.stats[k];
          return { side: s.side === 'player' ? 'attacker' : 'defender', name: s.name, dmgDealt: Math.round(s.dmg_dealt), dmgTaken: Math.round(s.dmg_taken), healGiven: Math.round(s.heal_given), stun: s.stun_count || 0, silence: s.silence_count || 0, dodge: s.dodge_count || 0, prevented: Math.round(s.dmg_prevented || 0), healProcCount: s.heal_proc_count || 0, healProcTotal: Math.round(s.heal_proc_total || 0), extraTurns: s.extra_turn_count || 0, eliminatedRound: s.elim_round };
        })
      });
    } catch (e) { battleLogJson = null; }
  }

  const winnerId = isAttackerWin ? match.attacker_id : match.defender_id;
  const loserId = isAttackerWin ? match.defender_id : match.attacker_id;
  const winnerProfile = isAttackerWin ? attackerProfile : defenderProfile;
  const loserProfile = isAttackerWin ? defenderProfile : attackerProfile;

  const pointsResult = applyMatchPoints(winnerProfile.points, loserProfile.points);

  await db.resolveMatch(match.id, winnerId, battleLogJson);
  await db.applyPvpMatchResult(winnerId, pointsResult.winnerNewPoints);
  await db.applyPvpMatchResult(loserId, pointsResult.loserNewPoints);

  return { matchId: match.id, winnerId, loserId, isAttackerWin };
}

// ปิดท้ายวันสุดท้าย (วันที่ 28) ของ "ซีซั่นก่อนหน้า" ให้เสร็จ — จำเป็นเพราะวันที่ 28 ไม่เคยมี "วันที่ 29" ให้มาตัดสินผล/แจกรางวัลของมันเอง
// (ซีซั่นถัดไปเริ่มวันที่ 1 ของเดือนใหม่ทันที ไม่ว่าเดือนนั้นจะยาว 28 วันพอดี (ก.พ.) หรือมีช่วงปิดคั่นกลางกี่วันก็ตาม)
// เรียกทุกครั้งที่ tick ทำงาน ปลอดภัยเรียกซ้ำได้เสมอ (query แค่ที่ยังไม่ตัดสิน + reward log กันแจกซ้ำ) แทบไม่มีต้นทุนถ้าไม่มีอะไรค้าง
async function finalizeFinalSeasonDayIfNeeded(db, gameEngine, now) {
  const previousSeasonStart = getSeasonStartForMonthOffset(now, -1);
  const previousSeasonStartStr = previousSeasonStart.toISOString().split('T')[0];
  const finalDay = PVP_CONFIG.SEASON_LENGTH_DAYS; // 28

  const pending = await db.getUnresolvedMatchesForDay(previousSeasonStartStr, finalDay);
  const resolvedMatches = [];
  for (const match of pending) {
    const r = await resolveOneMatch(db, gameEngine, match, previousSeasonStartStr);
    resolvedMatches.push(r);
  }

  let rewardsDistributed = null;
  if (isRewardDay(finalDay)) {
    const shouldDistribute = await db.tryClaimRewardDay(previousSeasonStartStr, finalDay);
    if (shouldDistribute) {
      const profiles = await db.getAllPvpProfilesForSeason(previousSeasonStartStr);
      if (profiles.length > 0) {
        const ranked = computeRanks(profiles.map(p => ({ id: p.user_id, points: p.points, matchesPlayed: p.matches_played })));
        let creditedCount = 0;
        for (const r of ranked) {
          if (r.rank === 'unranked') continue;
          const gems = WEEKLY_REWARD_GEMS_BY_RANK[r.rank] || 0;
          if (gems <= 0) continue;
          await db.createGrant(r.id, { source: 'pvp_reward', gems, note: 'รางวัลอันดับ PVP' });
          creditedCount++;
        }
        rewardsDistributed = { dayNumber: finalDay, creditedCount };
      }
    }
  }

  return { resolvedCount: resolvedMatches.length, resolvedMatches, rewardsDistributed };
}

async function runPvpDailyTick(db, gameEngine, now = new Date()) {
  // ปิดท้ายซีซั่นก่อนหน้าให้เสร็จก่อนเสมอ (ตัดสินแมตช์วันที่ 28 ค้าง + แจกรางวัลวันที่ 28 ถ้ายังไม่แจก)
  const finalDayResult = await finalizeFinalSeasonDayIfNeeded(db, gameEngine, now);

  const seasonInfo = getSeasonInfo(now);
  if (!seasonInfo.isActive) {
    return { ranTick: false, reason: 'season_closed', finalDayResult };
  }
  const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
  const dayNumber = seasonInfo.dayNumber;

  // 1. ตัดสินผลแมตช์เมื่อวาน (ถ้ามีและยังไม่ตัดสิน)
  let resolvedMatches = [];
  let rewardsDistributed = null;
  if (dayNumber > 1) {
    const finishedDay = dayNumber - 1;
    const pending = await db.getUnresolvedMatchesForDay(seasonStartStr, finishedDay);
    for (const match of pending) {
      const r = await resolveOneMatch(db, gameEngine, match, seasonStartStr);
      resolvedMatches.push(r);
    }

    // แจกรางวัลรายสัปดาห์ ถ้าวันที่เพิ่งจบไป (finishedDay) เป็นวันแจกรางวัล (7/14/21/28) และยังไม่เคยแจก
    if (isRewardDay(finishedDay)) {
      const shouldDistribute = await db.tryClaimRewardDay(seasonStartStr, finishedDay);
      if (shouldDistribute) {
        const profiles = await db.getAllPvpProfilesForSeason(seasonStartStr);
        const ranked = computeRanks(profiles.map(p => ({ id: p.user_id, points: p.points, matchesPlayed: p.matches_played })));
        let creditedCount = 0;
        for (const r of ranked) {
          if (r.rank === 'unranked') continue;
          const gems = WEEKLY_REWARD_GEMS_BY_RANK[r.rank] || 0;
          if (gems <= 0) continue;
          await db.createGrant(r.id, { source: 'pvp_reward', gems, note: 'รางวัลอันดับ PVP' });
          creditedCount++;
        }
        rewardsDistributed = { dayNumber: finishedDay, creditedCount };
      }
    }
  }

  // 2. จับคู่วันนี้ (ถ้ายังไม่เคยจับคู่มาก่อน)
  const alreadyPaired = await db.hasMatchesForDay(seasonStartStr, dayNumber);
  let pairedCount = 0;
  if (!alreadyPaired) {
    const profiles = await db.getAllPvpProfilesForSeason(seasonStartStr);
    const playerIds = profiles.map(p => p.user_id);
    const { pairs, bye } = pairPlayersForDay(playerIds);

    const matchRows = pairs.map(pair => {
      const { attackerId, defenderId } = assignAttackerRole(pair);
      return { seasonStart: seasonStartStr, dayNumber, playerA: pair[0], playerB: pair[1], attackerId, defenderId };
    });
    if (bye !== null) {
      matchRows.push({ seasonStart: seasonStartStr, dayNumber, playerA: bye, playerB: null, attackerId: null, defenderId: null, isBot: true });
    }
    if (matchRows.length > 0) await db.createMatches(matchRows);
    pairedCount = matchRows.length;
  }

  return { ranTick: true, dayNumber, resolvedCount: resolvedMatches.length, resolvedMatches, pairedCount, alreadyPaired, rewardsDistributed, finalDayResult };
}

module.exports = { runPvpDailyTick, resolveOneMatch, extractSquadData, extractPlayerStateForEngine };


// ===== data_payment.js =====
// data_payment.js
// ตั้งค่าระบบเติมเงิน — เติมด้วยมือ (โอนเงินจริง แล้วเขาเช็คสลิปเองแล้วกดอนุมัติ)
// ทุกค่าด้านล่างเป็น placeholder ต้องแก้เป็นข้อมูลจริงก่อนเปิดใช้งานจริง

const PAYMENT_CONFIG = {
  BANK_NAME: "ชื่อธนาคาร (แก้ตรงนี้)",
  BANK_ACCOUNT_NUMBER: "000-0-00000-0",
  BANK_ACCOUNT_NAME: "ชื่อบัญชี (แก้ตรงนี้)",

  // อัตราแลกเปลี่ยน: 1 บาท = กี่เพชร (ค่ากลางที่กะไว้ก่อน ปรับได้อิสระ)
  GEMS_PER_BAHT: 1,

  MIN_AMOUNT_BAHT: 20,
  MAX_AMOUNT_BAHT: 10000 // กันพิมพ์ผิดใส่เลขมั่วๆ (เช่น 10 หลัก) ไม่ใช่เพดานการเติมจริง ปรับได้
};

module.exports = { PAYMENT_CONFIG };


// ===== leaderboard_system.js =====
// leaderboard_system.js
// คำนวณ leaderboard ทั้ง 4 แบบ (ชื่อเสียง, พลังสู้รบ, หมอกสุสานโจรสลัด, PVP)
// ฟังก์ชันล้วนๆ (pure) รับ entries ที่ดึงมาจาก db แล้วมาเรียงลำดับ ไม่แตะฐานข้อมูลเอง

const TOP_N = 50; // แสดง top เท่านี้เสมอ ไม่ว่าคนเล่นจะเยอะแค่ไหน (กันหน้าจอ/response ยาวเกินไป)

// entries: [{userId, username, save}, ...] จาก db.getAllSavesWithUsernames()
// เลเวลกัปตัน (1-50) จากเซฟ — ใช้โชว์ในอันดับ/เพื่อน/PVP
// ชื่อที่โชว์ให้ผู้เล่นคนอื่นเห็น = ชื่อกัปตันที่ตั้งในเกม (ไม่ใช่ username ตอนสมัคร) ถ้ายังไม่ได้ตั้งค่อยใช้ username
function displayNameOf(save, username) {
  const n = save && typeof save.player_name === 'string' ? save.player_name.trim() : '';
  return n || username || 'ไม่ทราบชื่อ';
}

function captainLevelOfSave(save) {
  const n = parseInt(save && save.captain_level, 10);
  return n >= 1 && n <= 50 ? n : 1;
}

// PVP ปลดล็อกเมื่อเคลียร์ด่านทั้งหมดของเกาะที่ 2 (24 ด่าน) — ตรวจที่เซิร์ฟเวอร์ด้วย ไม่ใช่แค่ซ่อนปุ่มในเกม
function isPvpUnlockedSave(save) {
  const p = save && save.progress && save.progress.island_2;
  return !!p && (p.highest_stage_cleared || 0) >= 24;
}

function buildReputationLeaderboard(entries) {
  const list = entries.map(e => ({ userId: e.userId, username: displayNameOf(e.save, e.username), level: captainLevelOfSave(e.save), value: (e.save && e.save.reputation) || 0 }));
  return finalizeLeaderboard(list);
}

function buildWaveSurvivalLeaderboard(entries) {
  const list = entries.map(e => {
    const ws = e.save && e.save.wave_survival;
    return { userId: e.userId, username: displayNameOf(e.save, e.username), level: captainLevelOfSave(e.save), value: (ws && ws.best_score) || 0 };
  });
  return finalizeLeaderboard(list);
}

// gameEngine ต้องมี calculateSquadCombatPower() ที่อ่านจาก global "playerState" (ดู combat_power_system.js ต้นฉบับ)
// ต้องสลับ playerState ให้ตรงกับเซฟของแต่ละคนก่อนเรียกทุกครั้ง (เหมือนที่ทำใน combat_engine_pvp.js)
function buildCombatPowerLeaderboard(entries, gameEngine, setGlobalPlayerState) {
  const list = entries.map(e => {
    let value = 0;
    if (e.save && e.save.crew && e.save.squad) {
      setGlobalPlayerState(e.save);
      value = gameEngine.calculateSquadCombatPower();
    }
    return { userId: e.userId, username: displayNameOf(e.save, e.username), level: captainLevelOfSave(e.save), value };
  });
  return finalizeLeaderboard(list);
}

// รวมจำนวนด่านหลักทั้งหมดของแต่ละเกาะ ("ด่านสุดท้าย" ของทุกเกาะรวมกัน = 88) ใช้คำนวณอันดับ "ความคืบหน้าด่านหลัก" แบบนับต่อเนื่องข้ามเกาะ
const ISLAND_STAGE_TOTALS = { 1: 20, 2: 24, 3: 22, 4: 22 };

// นับด่านหลักแบบสะสมข้ามเกาะ: ผ่านเกาะก่อนหน้าไปกี่ด่านเต็มๆ บวกด่านที่ทำได้ในเกาะปัจจุบัน
// เช่น อยู่เกาะ 2 ด่าน 10 = เกาะ 1 เต็ม 20 ด่าน + 10 = ด่านสะสม 30, ผ่านครบเกาะ 4 = ด่านสะสม 88 (ด่านสุดท้ายของเกม)
function computeCumulativeStageProgress(save) {
  if (!save) return 0;
  const currentIsland = save.current_island || 1;
  let cumulative = 0;
  for (let i = 1; i < currentIsland; i++) {
    cumulative += ISLAND_STAGE_TOTALS[i] || 0;
  }
  const progress = save.progress || {};
  const currentProgress = progress['island_' + currentIsland];
  cumulative += (currentProgress && currentProgress.highest_stage_cleared) || 0;
  return cumulative;
}

function buildStageProgressLeaderboard(entries) {
  const list = entries.map(e => ({ userId: e.userId, username: displayNameOf(e.save, e.username), level: captainLevelOfSave(e.save), value: computeCumulativeStageProgress(e.save) }));
  return finalizeLeaderboard(list);
}

// เรียงจากมากไปน้อย ตัด top N พร้อมใส่อันดับ (position) ให้ทุกคน (ใช้หา "อันดับของฉัน" ได้แม้ไม่ติด top)
function finalizeLeaderboard(list) {
  const sorted = [...list].sort((a, b) => b.value - a.value);
  const withPosition = sorted.map((entry, index) => Object.assign({ position: index + 1 }, entry));
  return { top: withPosition.slice(0, TOP_N), all: withPosition };
}

// หา entry ของ userId ที่ระบุจากผลลัพธ์ finalizeLeaderboard (เผื่อไม่ติด top ก็ยังบอกอันดับได้)
function findMyEntry(leaderboardResult, userId) {
  return leaderboardResult.all.find(e => e.userId === userId) || null;
}

module.exports = {
  TOP_N, buildReputationLeaderboard, buildWaveSurvivalLeaderboard, buildCombatPowerLeaderboard,
  buildStageProgressLeaderboard,
  finalizeLeaderboard, findMyEntry
};



// ===== embedded game engine (characters/combat/etc, loaded in isolated vm context) =====
const GAME_ENGINE_SOURCE = "// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_characters.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e40\u0e01\u0e47\u0e1a\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e14\u0e34\u0e1a\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e04\u0e33\u0e19\u0e27\u0e13)\n// \u0e41\u0e1b\u0e25\u0e07\u0e15\u0e23\u0e07\u0e08\u0e32\u0e01\u0e44\u0e1f\u0e25\u0e4c\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a: characters.json (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e41\u0e01\u0e49\u0e44\u0e02/\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e40\u0e15\u0e34\u0e21\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e43\u0e14\u0e46)\n// \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14: 55 \u0e15\u0e31\u0e27\n// ==========================================\n\nconst CHARACTERS = [\n  {\n    \"id\": \"c001\",\n    \"name\": \"\u0e2d\u0e35\u0e18\u0e32\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P10\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 445.7,\n      \"attack\": 24.7,\n      \"defense_flat\": 19.3,\n      \"speed\": 12,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c008\",\n    \"name\": \"\u0e40\u0e04\u0e40\u0e25\u0e1a\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 226.5,\n      \"attack\": 57,\n      \"defense_flat\": 8.3,\n      \"speed\": 21.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c016\",\n    \"name\": \"\u0e42\u0e19\u0e2d\u0e32\u0e2b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P14\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 301.5,\n      \"attack\": 27.8,\n      \"defense_flat\": 11.6,\n      \"speed\": 32.4,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c023\",\n    \"name\": \"\u0e40\u0e08\u0e21\u0e2a\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 214.7,\n      \"attack\": 65.7,\n      \"defense_flat\": 7.5,\n      \"speed\": 23.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c030\",\n    \"name\": \"\u0e1f\u0e2d\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"assassin\",\n    \"passive\": \"P23\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 190.9,\n      \"attack\": 68.3,\n      \"defense_flat\": 5.9,\n      \"speed\": 29.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b001\",\n    \"name\": \"\u0e41\u0e08\u0e47\u0e04\",\n    \"grade\": \"B\",\n    \"role\": \"tank\",\n    \"passive\": \"P10\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 682.2,\n      \"attack\": 41.5,\n      \"defense_flat\": 24.9,\n      \"speed\": 18,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b011\",\n    \"name\": \"\u0e44\u0e23\u0e2d\u0e31\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 287.8,\n      \"attack\": 94.2,\n      \"defense_flat\": 11.6,\n      \"speed\": 38.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a001\",\n    \"name\": \"\u0e25\u0e39\u0e04\u0e31\u0e2a\",\n    \"grade\": \"A\",\n    \"role\": \"fighter\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 508.1,\n      \"attack\": 132.4,\n      \"defense_flat\": 21,\n      \"speed\": 45.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a002\",\n    \"name\": \"\u0e42\u0e25\u0e41\u0e01\u0e19\",\n    \"grade\": \"A\",\n    \"role\": \"support\",\n    \"passive\": \"P17\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 607.8,\n      \"attack\": 62.6,\n      \"defense_flat\": 25.4,\n      \"speed\": 65.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s001\",\n    \"name\": \"\u0e40\u0e08\u0e04\u0e2d\u0e1a\",\n    \"grade\": \"S\",\n    \"role\": \"tank\",\n    \"passive\": \"P10\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 1588.2,\n      \"attack\": 86.2,\n      \"defense_flat\": 63.9,\n      \"speed\": 36.3,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c002\",\n    \"name\": \"\u0e40\u0e21\u0e2a\u0e31\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P09\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 409.5,\n      \"attack\": 25.3,\n      \"defense_flat\": 16.6,\n      \"speed\": 10.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c003\",\n    \"name\": \"\u0e42\u0e19\u0e41\u0e25\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P13\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 458.6,\n      \"attack\": 26.6,\n      \"defense_flat\": 17.7,\n      \"speed\": 10.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c004\",\n    \"name\": \"\u0e40\u0e1a\u0e23\u0e15\u0e15\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P11\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 411.2,\n      \"attack\": 27.4,\n      \"defense_flat\": 18.3,\n      \"speed\": 10.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c005\",\n    \"name\": \"\u0e04\u0e32\u0e23\u0e4c\u0e25\u0e2d\u0e2a\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P12\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 432.7,\n      \"attack\": 24.3,\n      \"defense_flat\": 18.2,\n      \"speed\": 10.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c006\",\n    \"name\": \"\u0e14\u0e2d\u0e21\u0e34\u0e19\u0e34\u0e01\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P17\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 435.4,\n      \"attack\": 26.9,\n      \"defense_flat\": 18.1,\n      \"speed\": 11.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c007\",\n    \"name\": \"\u0e27\u0e32\u0e40\u0e25\u0e19\u0e15\u0e34\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P09\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 405.4,\n      \"attack\": 25.2,\n      \"defense_flat\": 18.7,\n      \"speed\": 11.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c009\",\n    \"name\": \"\u0e40\u0e25\u0e35\u0e22\u0e21\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 240.2,\n      \"attack\": 57.5,\n      \"defense_flat\": 9.3,\n      \"speed\": 19.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c010\",\n    \"name\": \"\u0e21\u0e32\u0e23\u0e4c\u0e04\u0e31\u0e2a\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P03\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 231.5,\n      \"attack\": 58.5,\n      \"defense_flat\": 8.2,\n      \"speed\": 21.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c011\",\n    \"name\": \"\u0e40\u0e14\u0e19\u0e40\u0e27\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P06\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 242.2,\n      \"attack\": 51.7,\n      \"defense_flat\": 9.5,\n      \"speed\": 20.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c012\",\n    \"name\": \"\u0e23\u0e34\u0e42\u0e2d\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 235.6,\n      \"attack\": 57.6,\n      \"defense_flat\": 9.1,\n      \"speed\": 20.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c013\",\n    \"name\": \"\u0e40\u0e0b\u0e35\u0e22\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 242.5,\n      \"attack\": 58.2,\n      \"defense_flat\": 8.1,\n      \"speed\": 22.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c014\",\n    \"name\": \"\u0e42\u0e04\u0e14\u0e35\u0e49\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P03\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 236,\n      \"attack\": 60.3,\n      \"defense_flat\": 9.1,\n      \"speed\": 19.3,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c015\",\n    \"name\": \"\u0e41\u0e21\u0e47\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 226.6,\n      \"attack\": 53.5,\n      \"defense_flat\": 8.1,\n      \"speed\": 20.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c017\",\n    \"name\": \"\u0e40\u0e2e\u0e19\u0e23\u0e35\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P16\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 280.8,\n      \"attack\": 27.4,\n      \"defense_flat\": 10.8,\n      \"speed\": 31.4,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c018\",\n    \"name\": \"\u0e2d\u0e2d\u0e2a\u0e01\u0e32\u0e23\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P18\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 259.6,\n      \"attack\": 29.9,\n      \"defense_flat\": 10.5,\n      \"speed\": 30.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c019\",\n    \"name\": \"\u0e1f\u0e34\u0e19\u0e19\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 275.5,\n      \"attack\": 29.3,\n      \"defense_flat\": 11.2,\n      \"speed\": 31,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c020\",\n    \"name\": \"\u0e2d\u0e40\u0e25\u0e47\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P20\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 300.8,\n      \"attack\": 28.2,\n      \"defense_flat\": 11.3,\n      \"speed\": 31.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c021\",\n    \"name\": \"\u0e41\u0e0b\u0e21\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P14\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 259,\n      \"attack\": 30.1,\n      \"defense_flat\": 10.7,\n      \"speed\": 33.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c022\",\n    \"name\": \"\u0e40\u0e08\u0e22\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P19\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 263.6,\n      \"attack\": 27.7,\n      \"defense_flat\": 11.8,\n      \"speed\": 31,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c024\",\n    \"name\": \"\u0e44\u0e17\u0e40\u0e25\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 189.8,\n      \"attack\": 62.7,\n      \"defense_flat\": 7.4,\n      \"speed\": 23.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c025\",\n    \"name\": \"\u0e40\u0e25\u0e19\u0e19\u0e47\u0e2d\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P05\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 197.8,\n      \"attack\": 62.2,\n      \"defense_flat\": 6.8,\n      \"speed\": 25.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c026\",\n    \"name\": \"\u0e23\u0e47\u0e2d\u0e04\u0e01\u0e35\u0e49\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 204.4,\n      \"attack\": 60,\n      \"defense_flat\": 7.4,\n      \"speed\": 24.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c027\",\n    \"name\": \"\u0e44\u0e04\u0e25\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 190,\n      \"attack\": 66.6,\n      \"defense_flat\": 7,\n      \"speed\": 26,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c028\",\n    \"name\": \"\u0e40\u0e1a\u0e25\u0e04\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 186,\n      \"attack\": 57,\n      \"defense_flat\": 6.9,\n      \"speed\": 26.4,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c029\",\n    \"name\": \"\u0e44\u0e23\u0e14\u0e2d\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 201.6,\n      \"attack\": 58.9,\n      \"defense_flat\": 6.9,\n      \"speed\": 24,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b002\",\n    \"name\": \"\u0e40\u0e2e\u0e04\u0e40\u0e15\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"B\",\n    \"role\": \"tank\",\n    \"passive\": \"P12\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 693.8,\n      \"attack\": 37.5,\n      \"defense_flat\": 25.1,\n      \"speed\": 16.6,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b003\",\n    \"name\": \"\u0e42\u0e23\u0e41\u0e21\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"tank\",\n    \"passive\": \"P13\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 675.9,\n      \"attack\": 40,\n      \"defense_flat\": 25,\n      \"speed\": 15.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b004\",\n    \"name\": \"\u0e41\u0e14\u0e40\u0e19\u0e35\u0e22\u0e25\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 363.7,\n      \"attack\": 90.3,\n      \"defense_flat\": 13,\n      \"speed\": 33.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b005\",\n    \"name\": \"\u0e27\u0e34\u0e01\u0e40\u0e15\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 342.5,\n      \"attack\": 78.8,\n      \"defense_flat\": 12.1,\n      \"speed\": 31.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b006\",\n    \"name\": \"\u0e40\u0e18\u0e42\u0e2d\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P06\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 354.8,\n      \"attack\": 82.8,\n      \"defense_flat\": 12.2,\n      \"speed\": 31.6,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b007\",\n    \"name\": \"\u0e40\u0e23\u0e21\u0e35\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P24\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 359.9,\n      \"attack\": 83,\n      \"defense_flat\": 13.9,\n      \"speed\": 32.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b008\",\n    \"name\": \"\u0e42\u0e2d\u0e25\u0e34\u0e40\u0e27\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"B\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 441.6,\n      \"attack\": 39.3,\n      \"defense_flat\": 17.2,\n      \"speed\": 46.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b009\",\n    \"name\": \"\u0e40\u0e0b\u0e1a\u0e32\u0e2a\u0e40\u0e15\u0e35\u0e22\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"support\",\n    \"passive\": \"P18\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 403.2,\n      \"attack\": 40.9,\n      \"defense_flat\": 17.6,\n      \"speed\": 49.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b010\",\n    \"name\": \"\u0e21\u0e32\u0e23\u0e4c\u0e40\u0e0b\u0e25\",\n    \"grade\": \"B\",\n    \"role\": \"support\",\n    \"passive\": \"P16\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 392.3,\n      \"attack\": 41.4,\n      \"defense_flat\": 15.5,\n      \"speed\": 43.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b012\",\n    \"name\": \"\u0e2d\u0e35\u0e27\u0e32\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P05\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 278.1,\n      \"attack\": 100,\n      \"defense_flat\": 11.2,\n      \"speed\": 39.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b013\",\n    \"name\": \"\u0e40\u0e25\u0e42\u0e2d\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 296.2,\n      \"attack\": 91.8,\n      \"defense_flat\": 10.6,\n      \"speed\": 36,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b014\",\n    \"name\": \"\u0e2e\u0e32\u0e23\u0e4c\u0e14\u0e35\u0e49\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 307.6,\n      \"attack\": 87.1,\n      \"defense_flat\": 11.4,\n      \"speed\": 37.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b015\",\n    \"name\": \"\u0e40\u0e07\u0e32\",\n    \"grade\": \"B\",\n    \"role\": \"assassin\",\n    \"passive\": \"P22\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 282.9,\n      \"attack\": 104,\n      \"defense_flat\": 9,\n      \"speed\": 39.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a003\",\n    \"name\": \"\u0e40\u0e2d\u0e40\u0e14\u0e19\",\n    \"grade\": \"A\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 568.2,\n      \"attack\": 127,\n      \"defense_flat\": 18.7,\n      \"speed\": 49.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a004\",\n    \"name\": \"\u0e40\u0e0b\u0e23\u0e32\u0e1f\u0e34\u0e19\",\n    \"grade\": \"A\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 594.4,\n      \"attack\": 67.6,\n      \"defense_flat\": 23.3,\n      \"speed\": 68.3,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a005\",\n    \"name\": \"\u0e04\u0e2d\u0e19\u0e23\u0e32\u0e14\",\n    \"grade\": \"A\",\n    \"role\": \"tank\",\n    \"passive\": \"P12\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 945.1,\n      \"attack\": 56.9,\n      \"defense_flat\": 41.2,\n      \"speed\": 24.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a006\",\n    \"name\": \"\u0e42\u0e0b\u0e42\u0e25\",\n    \"grade\": \"A\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 434.7,\n      \"attack\": 144.2,\n      \"defense_flat\": 15.1,\n      \"speed\": 60.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a007\",\n    \"name\": \"\u0e14\u0e32\u0e23\u0e4c\u0e01\",\n    \"grade\": \"A\",\n    \"role\": \"assassin\",\n    \"passive\": \"P23\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 425.8,\n      \"attack\": 161,\n      \"defense_flat\": 12.5,\n      \"speed\": 57.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s002\",\n    \"name\": \"\u0e44\u0e17\u0e17\u0e31\u0e19\",\n    \"grade\": \"S\",\n    \"role\": \"fighter\",\n    \"passive\": \"P24\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 799.9,\n      \"attack\": 184.4,\n      \"defense_flat\": 31.8,\n      \"speed\": 72.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s003\",\n    \"name\": \"\u0e2d\u0e2d\u0e23\u0e32\u0e40\u0e04\u0e34\u0e25\",\n    \"grade\": \"S\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 986.6,\n      \"attack\": 90.7,\n      \"defense_flat\": 36.5,\n      \"speed\": 100.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s004\",\n    \"name\": \"\u0e40\u0e14\u0e27\u0e34\u0e14\",\n    \"grade\": \"S\",\n    \"role\": \"tank\",\n    \"passive\": \"P25\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 1550,\n      \"attack\": 95,\n      \"defense_flat\": 48,\n      \"speed\": 62,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s005\",\n    \"name\": \"\u0e23\u0e32\u0e1f\u0e32\u0e40\u0e2d\u0e25\",\n    \"grade\": \"S\",\n    \"role\": \"assassin\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 850,\n      \"attack\": 180,\n      \"defense_flat\": 36,\n      \"speed\": 74,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s006\",\n    \"name\": \"\u0e42\u0e0b\u0e40\u0e1f\u0e35\u0e22\",\n    \"grade\": \"S\",\n    \"role\": \"support\",\n    \"passive\": \"P26\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 1200,\n      \"attack\": 110,\n      \"defense_flat\": 42,\n      \"speed\": 68,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a008\",\n    \"name\": \"\u0e14\u0e34\u0e40\u0e2d\u0e42\u0e01\u0e49\",\n    \"grade\": \"A\",\n    \"role\": \"ranger\",\n    \"passive\": \"P27\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 520,\n      \"attack\": 145,\n      \"defense_flat\": 20,\n      \"speed\": 52,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a009\",\n    \"name\": \"\u0e21\u0e31\u0e15\u0e40\u0e15\u0e42\u0e2d\",\n    \"grade\": \"A\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 780,\n      \"attack\": 130,\n      \"defense_flat\": 25,\n      \"speed\": 48,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b016\",\n    \"name\": \"\u0e19\u0e32\u0e15\u0e32\u0e40\u0e25\u0e35\u0e22\",\n    \"grade\": \"B\",\n    \"role\": \"assassin\",\n    \"passive\": \"P22\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 310,\n      \"attack\": 98,\n      \"defense_flat\": 12,\n      \"speed\": 40,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b017\",\n    \"name\": \"\u0e40\u0e04\u0e25\u0e27\u0e34\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 380,\n      \"attack\": 82,\n      \"defense_flat\": 16,\n      \"speed\": 28,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c031\",\n    \"name\": \"\u0e40\u0e2d\u0e19\u0e42\u0e0b\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P05\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 440,\n      \"attack\": 32,\n      \"defense_flat\": 13,\n      \"speed\": 14,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c032\",\n    \"name\": \"\u0e14\u0e32\u0e19\u0e34\u0e42\u0e25\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P16\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 260,\n      \"attack\": 28,\n      \"defense_flat\": 8,\n      \"speed\": 22,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  }\n];\n\nif (typeof module !== 'undefined' && module.exports) {\n  module.exports = { CHARACTERS };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_passives.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e40\u0e01\u0e47\u0e1a \"\u0e15\u0e31\u0e27\u0e40\u0e25\u0e02\u0e1e\u0e32\u0e23\u0e32\u0e21\u0e34\u0e40\u0e15\u0e2d\u0e23\u0e4c\" \u0e02\u0e2d\u0e07 passive \u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19\n// \u0e2b\u0e49\u0e32\u0e21\u0e43\u0e2a\u0e48\u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e04\u0e33\u0e19\u0e27\u0e13/\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e43\u0e14\u0e46 \u0e43\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\n// \u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e40\u0e1e\u0e34\u0e48\u0e21/\u0e41\u0e01\u0e49\u0e04\u0e48\u0e32\u0e1e\u0e25\u0e31\u0e07\u0e02\u0e2d\u0e07 passive -> \u0e41\u0e01\u0e49\u0e17\u0e35\u0e48\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e14\u0e35\u0e22\u0e27\n// ==========================================\n\n// \u0e2a\u0e32\u0e22 support \u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49\u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e44\u0e14\u0e49\u0e15\u0e31\u0e27\u0e21\u0e32\u0e40\u0e25\u0e22 (\u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b) \u0e41\u0e15\u0e48\u0e14\u0e32\u0e40\u0e21\u0e08\u0e25\u0e14\u0e40\u0e2b\u0e25\u0e37\u0e2d 60% \u0e02\u0e2d\u0e07\u0e17\u0e35\u0e48\u0e04\u0e33\u0e19\u0e27\u0e13\u0e44\u0e14\u0e49\u0e1b\u0e01\u0e15\u0e34\nconst SUPPORT_ATTACK_DAMAGE_MULT = 0.6;\n\nconst PASSIVE_PARAMS = {\n  \"P01\": { targets: 2, dmg_pct: 80 },                          // \u0e42\u0e08\u0e21\u0e15\u0e35 AoE 2 \u0e40\u0e1b\u0e49\u0e32 (\u0e23\u0e27\u0e21 160%)\n  \"P02\": { targets: 3, dmg_pct: 60 },                          // \u0e42\u0e08\u0e21\u0e15\u0e35 AoE 3 \u0e40\u0e1b\u0e49\u0e32 (\u0e23\u0e27\u0e21 180%)\n  \"P03\": { chance: 35, dmg_pct: 100 },                         // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\n  \"P04\": { condition: \"hp_below_50\", atk_bonus: 70 },          // ATK \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e40\u0e21\u0e37\u0e48\u0e2d HP \u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 50%\n  \"P05\": { chance: 30 },                                       // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e44\u0e14\u0e49\u0e15\u0e32\u0e40\u0e23\u0e47\u0e27\u0e1e\u0e34\u0e40\u0e28\u0e29\n  \"P06\": { lifesteal_pct: 25 },                                // \u0e14\u0e39\u0e14\u0e40\u0e25\u0e37\u0e2d\u0e14\n  \"P07\": { chance: 20, multiplier: 3 },                        // \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 x3\n  \"P08\": { chance: 15, multiplier: 3.6 },                      // \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 x3.6\n  \"P09\": { chance: 20, dmg_pct: 40 },                          // \u0e15\u0e35\u0e42\u0e15\u0e49\n  \"P10\": { reduce_pct: 35 },                                   // \u0e25\u0e14\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e35\u0e48\u0e44\u0e14\u0e49\u0e23\u0e31\u0e1a\n  \"P11\": { chance: 25 },                                       // \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\n  \"P12\": { chance: 30, receive_pct: 60 },                      // \u0e42\u0e25\u0e48\u0e21\u0e19\u0e38\u0e29\u0e22\u0e4c\n  \"P13\": { heal_pct: 8 },                                      // \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39\u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07\n  \"P14\": { heal_pct: 3 },                                      // \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39\u0e17\u0e35\u0e21\u0e17\u0e38\u0e01\u0e15\u0e32\n  \"P15\": { chance: 10, heal_pct: 50 },                         // \u0e23\u0e31\u0e01\u0e29\u0e32\u0e09\u0e38\u0e01\u0e40\u0e09\u0e34\u0e19\n  \"P16\": { chance: 40, atk_bonus: 25, duration: 2 },           // \u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a (\u0e1a\u0e31\u0e1f\u0e17\u0e35\u0e21)\n  \"P17\": { def_bonus: 7 },                                     // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e40\u0e1e\u0e34\u0e48\u0e21 DEF \u0e17\u0e35\u0e21\n  \"P18\": { chance: 12 },                                       // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e17\u0e2d\u0e07 (\u0e2a\u0e31\u0e48\u0e07\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e19\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33)\n  \"P19\": { spd_reduce: 10 },                                   // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e25\u0e14 SPD \u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P20\": { atk_reduce: 6 },                                    // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e25\u0e14 ATK \u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P21\": { chance: 30, stun_duration: 1 },                     // \u0e2a\u0e15\u0e31\u0e49\u0e19\n  \"P22\": { chance: 15, stun_duration: 2 },                     // \u0e2a\u0e15\u0e31\u0e49\u0e19\u0e2b\u0e19\u0e31\u0e01\n  \"P23\": { chance: 30, silence_duration: 2 },                  // \u0e1b\u0e34\u0e14 passive \u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P24\": { dmg_pct: 250 },                                     // \u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e15\u0e2d\u0e19\u0e15\u0e32\u0e22\n  \"P25\": { crit_chance_reduce: 30, crit_dmg_reduce: 40 },      // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e15\u0e49\u0e32\u0e19\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P26\": { evasion_bonus: 12 },                                // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e17\u0e35\u0e21\n  \"P27\": { chance: 30, poison_pct: 8, duration: 3 }            // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e15\u0e34\u0e14\u0e1e\u0e34\u0e29\n};\n\nconst PASSIVES = [\n  {\"id\":\"P01\",\"name\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e23\u0e30\u0e08\u0e32\u0e22 2\",\"description\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39 2 \u0e15\u0e31\u0e27\u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e01\u0e31\u0e19 \u0e17\u0e31\u0e49\u0e07\u0e2a\u0e2d\u0e07\u0e23\u0e31\u0e1a 80% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e2b\u0e25\u0e31\u0e01 \u0e23\u0e27\u0e21 160%\"},\n  {\"id\":\"P02\",\"name\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e23\u0e30\u0e08\u0e32\u0e22 3\",\"description\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39 3 \u0e15\u0e31\u0e27\u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e01\u0e31\u0e19 \u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\u0e23\u0e31\u0e1a 60% \u0e23\u0e27\u0e21 180%\"},\n  {\"id\":\"P03\",\"name\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 35% \u0e42\u0e08\u0e21\u0e15\u0e35\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22\u0e40\u0e14\u0e34\u0e21\u0e0b\u0e49\u0e33\u0e2d\u0e35\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e40\u0e15\u0e47\u0e21\"},\n  {\"id\":\"P04\",\"name\":\"\u0e40\u0e14\u0e37\u0e2d\u0e14\u0e14\u0e32\u0e25\",\"description\":\"\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e08\u0e21\u0e15\u0e35 70% \u0e40\u0e21\u0e37\u0e48\u0e2d HP \u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 50% \u0e40\u0e0a\u0e47\u0e04\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P05\",\"name\":\"\u0e2a\u0e32\u0e22\u0e1f\u0e49\u0e32\u0e41\u0e25\u0e1a\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e48\u0e2d\u0e19\u0e40\u0e2a\u0e21\u0e2d\u0e43\u0e19\u0e23\u0e2d\u0e1a\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P06\",\"name\":\"\u0e14\u0e39\u0e14\u0e40\u0e25\u0e37\u0e2d\u0e14\",\"description\":\"\u0e1f\u0e37\u0e49\u0e19 HP \u0e01\u0e25\u0e31\u0e1a 25% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e35\u0e48\u0e17\u0e33\u0e44\u0e14\u0e49\u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\"},\n  {\"id\":\"P07\",\"name\":\"\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 20% \u0e14\u0e32\u0e40\u0e21\u0e08\u0e04\u0e39\u0e13 3 \u0e40\u0e17\u0e48\u0e32 \u0e04\u0e48\u0e32\u0e40\u0e09\u0e25\u0e35\u0e48\u0e22\u0e14\u0e32\u0e40\u0e21\u0e08\u0e40\u0e1e\u0e34\u0e48\u0e21 40%\"},\n  {\"id\":\"P08\",\"name\":\"\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e2a\u0e39\u0e07\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 15% \u0e14\u0e32\u0e40\u0e21\u0e08\u0e04\u0e39\u0e13 3.6 \u0e40\u0e17\u0e48\u0e32 \u0e04\u0e48\u0e32\u0e40\u0e09\u0e25\u0e35\u0e48\u0e22\u0e14\u0e32\u0e40\u0e21\u0e08\u0e40\u0e1e\u0e34\u0e48\u0e21 39%\"},\n  {\"id\":\"P09\",\"name\":\"\u0e15\u0e35\u0e42\u0e15\u0e49\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 20% \u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e25\u0e31\u0e1a\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e31\u0e19\u0e17\u0e35\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35\u0e14\u0e49\u0e27\u0e22\u0e14\u0e32\u0e40\u0e21\u0e08 40%\"},\n  {\"id\":\"P10\",\"name\":\"\u0e40\u0e01\u0e23\u0e32\u0e30\u0e40\u0e2b\u0e25\u0e47\u0e01\",\"description\":\"\u0e25\u0e14\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e35\u0e48\u0e23\u0e31\u0e1a\u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07 35%\"},\n  {\"id\":\"P11\",\"name\":\"\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 25% \u0e2b\u0e25\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e44\u0e14\u0e49\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\"},\n  {\"id\":\"P12\",\"name\":\"\u0e42\u0e25\u0e48\u0e21\u0e19\u0e38\u0e29\u0e22\u0e4c\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e41\u0e17\u0e19\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e19\u0e17\u0e35\u0e48 HP \u0e19\u0e49\u0e2d\u0e22\u0e2a\u0e38\u0e14 \u0e41\u0e15\u0e48\u0e23\u0e31\u0e1a\u0e41\u0e04\u0e48 60% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P13\",\"name\":\"\u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39\u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07\",\"description\":\"\u0e1f\u0e37\u0e49\u0e19 HP \u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07 8% \u0e02\u0e2d\u0e07 HP \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P14\",\"name\":\"\u0e23\u0e31\u0e01\u0e29\u0e32\u0e17\u0e35\u0e21\",\"description\":\"\u0e1f\u0e37\u0e49\u0e19 HP \u0e25\u0e39\u0e01\u0e40\u0e23\u0e37\u0e2d\u0e17\u0e38\u0e01\u0e04\u0e19 3% \u0e02\u0e2d\u0e07 HP  \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P15\",\"name\":\"\u0e23\u0e31\u0e01\u0e29\u0e32\u0e09\u0e38\u0e01\u0e40\u0e09\u0e34\u0e19\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 10% \u0e1f\u0e37\u0e49\u0e19 HP \u0e17\u0e31\u0e49\u0e07\u0e17\u0e35\u0e21 50% \u0e43\u0e19\u0e23\u0e2d\u0e1a\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P16\",\"name\":\"\u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 40% \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e08\u0e21\u0e15\u0e35 25% \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e43\u0e19\u0e23\u0e2d\u0e1a\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P17\",\"name\":\"\u0e01\u0e33\u0e41\u0e1e\u0e07\u0e40\u0e2b\u0e25\u0e47\u0e01\",\"description\":\"\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19 7% \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P18\",\"name\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e17\u0e2d\u0e07\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 12% \u0e43\u0e2b\u0e49\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e19\u0e17\u0e35\u0e48\u0e40\u0e1e\u0e34\u0e48\u0e07\u0e42\u0e08\u0e21\u0e15\u0e35\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\u0e2d\u0e35\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\"},\n  {\"id\":\"P19\",\"name\":\"\u0e0a\u0e30\u0e25\u0e2d\u0e28\u0e31\u0e15\u0e23\u0e39\",\"description\":\"\u0e25\u0e14\u0e04\u0e27\u0e32\u0e21\u0e40\u0e23\u0e47\u0e27\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27 10% \u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P20\",\"name\":\"\u0e2d\u0e48\u0e2d\u0e19\u0e41\u0e23\u0e07\",\"description\":\"\u0e25\u0e14\u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27 6% \u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P21\",\"name\":\"\u0e2a\u0e15\u0e31\u0e49\u0e19\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35\u0e2a\u0e15\u0e31\u0e49\u0e19 1 \u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P22\",\"name\":\"\u0e2a\u0e15\u0e31\u0e49\u0e19\u0e2b\u0e19\u0e31\u0e01\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 15% \u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35\u0e2a\u0e15\u0e31\u0e49\u0e19 2 \u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P23\",\"name\":\"\u0e1b\u0e34\u0e14 passive\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e1b\u0e34\u0e14 passive \u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35 2 \u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P24\",\"name\":\"\u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\",\"description\":\"\u0e40\u0e21\u0e37\u0e48\u0e2d\u0e08\u0e30\u0e16\u0e39\u0e01\u0e01\u0e33\u0e08\u0e31\u0e14 \u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27 250% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e1b\u0e01\u0e15\u0e34\u0e01\u0e48\u0e2d\u0e19\u0e2d\u0e2d\u0e01\u0e08\u0e32\u0e01\u0e2a\u0e19\u0e32\u0e21\"},\n  {\"id\":\"P25\",\"name\":\"\u0e42\u0e25\u0e48\u0e15\u0e49\u0e32\u0e19\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\",\"description\":\"\u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49 \u0e25\u0e14\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e02\u0e2d\u0e07\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\u0e25\u0e07 30 \u0e08\u0e38\u0e14 \u0e41\u0e25\u0e30\u0e25\u0e14\u0e04\u0e27\u0e32\u0e21\u0e41\u0e23\u0e07\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e02\u0e2d\u0e07\u0e28\u0e31\u0e15\u0e23\u0e39\u0e25\u0e07 40%\"},\n  {\"id\":\"P26\",\"name\":\"\u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e1b\u0e23\u0e32\u0e14\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e27\",\"description\":\"\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 12% \u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P27\",\"name\":\"\u0e1e\u0e34\u0e29\u0e01\u0e31\u0e14\u0e01\u0e23\u0e48\u0e2d\u0e19\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e17\u0e33\u0e43\u0e2b\u0e49\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22\u0e17\u0e35\u0e48\u0e42\u0e14\u0e19\u0e42\u0e08\u0e21\u0e15\u0e35\u0e15\u0e34\u0e14\u0e1e\u0e34\u0e29 \u0e44\u0e14\u0e49\u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08 8% \u0e02\u0e2d\u0e07 HP \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a \u0e40\u0e1b\u0e47\u0e19\u0e40\u0e27\u0e25\u0e32 3 \u0e23\u0e2d\u0e1a\"}\n];\n\n// \u0e40\u0e1c\u0e37\u0e48\u0e2d\u0e43\u0e0a\u0e49\u0e41\u0e1a\u0e1a module (Node/bundler) \u0e43\u0e19\u0e2d\u0e19\u0e32\u0e04\u0e15 \u0e44\u0e21\u0e48\u0e01\u0e23\u0e30\u0e17\u0e1a\u0e01\u0e32\u0e23\u0e43\u0e0a\u0e49\u0e41\u0e1a\u0e1a <script> \u0e1b\u0e01\u0e15\u0e34\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { PASSIVE_PARAMS, PASSIVES };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_equipment.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e19\u0e34\u0e22\u0e32\u0e21\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (\u0e2d\u0e32\u0e27\u0e38\u0e18 7 / \u0e40\u0e01\u0e23\u0e32\u0e30 4 / \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a 4) x 3 \u0e14\u0e32\u0e27\n// \u0e41\u0e15\u0e48\u0e25\u0e30\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e21\u0e35 kind: \"percent\" (%) \u0e2b\u0e23\u0e37\u0e2d \"flat\" (\u0e04\u0e48\u0e32\u0e04\u0e07\u0e17\u0e35\u0e48\u0e15\u0e23\u0e07\u0e46) \u2014 \u0e04\u0e25\u0e30\u0e01\u0e31\u0e19\u0e44\u0e1b\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e2b\u0e25\u0e32\u0e01\u0e2b\u0e25\u0e32\u0e22\n// stat_defs[star] = array \u0e02\u0e2d\u0e07 {stat, kind, min, max} \u2014 1 \u0e14\u0e32\u0e27/2 \u0e14\u0e32\u0e27 \u0e21\u0e35 1 \u0e15\u0e31\u0e27, 3 \u0e14\u0e32\u0e27 \u0e21\u0e35 2 \u0e15\u0e31\u0e27\n// ==========================================\n\nconst EQUIPMENT_TYPES = {\n  // ---------- \u0e2d\u0e32\u0e27\u0e38\u0e18 (7) ----------\n  sword: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e14\u0e32\u0e1a\u0e2a\u0e19\u0e34\u0e21\", 2: \"\u0e14\u0e32\u0e1a\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\", 3: \"\u0e14\u0e32\u0e1a\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"percent\", min: 6.2, max: 10 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }, { stat: \"def\", kind: \"flat\", min: 16, max: 28 }]\n    }\n  },\n  axe: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e02\u0e27\u0e32\u0e19\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e02\u0e27\u0e32\u0e19\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e2b\u0e19\u0e31\u0e01\", 3: \"\u0e02\u0e27\u0e32\u0e19\u0e1b\u0e23\u0e30\u0e2b\u0e32\u0e23\u0e40\u0e25\u0e37\u0e2d\u0e14\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }],\n      2: [{ stat: \"atk\", kind: \"flat\", min: 12, max: 20 }],\n      3: [{ stat: \"atk\", kind: \"flat\", min: 12, max: 20 }, { stat: \"hp\", kind: \"percent\", min: 10, max: 16 }]\n    }\n  },\n  spear: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e2b\u0e2d\u0e01\u0e44\u0e21\u0e49\u0e1c\u0e38\", 2: \"\u0e2b\u0e2d\u0e01\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e41\u0e2b\u0e25\u0e21\", 3: \"\u0e2b\u0e2d\u0e01\u0e08\u0e2d\u0e21\u0e2a\u0e21\u0e38\u0e17\u0e23\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"percent\", min: 6.2, max: 10 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }, { stat: \"spd\", kind: \"percent\", min: 16, max: 24 }]\n    }\n  },\n  hammer: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e04\u0e49\u0e2d\u0e19\u0e2b\u0e34\u0e19\", 2: \"\u0e04\u0e49\u0e2d\u0e19\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e2b\u0e19\u0e32\", 3: \"\u0e04\u0e49\u0e2d\u0e19\u0e28\u0e36\u0e01\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }],\n      2: [{ stat: \"atk\", kind: \"flat\", min: 12, max: 20 }],\n      3: [{ stat: \"atk\", kind: \"flat\", min: 12, max: 20 }, { stat: \"def\", kind: \"percent\", min: 16, max: 24 }]\n    }\n  },\n  bow: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e18\u0e19\u0e39\u0e44\u0e21\u0e49\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e18\u0e19\u0e39\u0e2a\u0e32\u0e22\u0e40\u0e2b\u0e25\u0e47\u0e01\", 3: \"\u0e18\u0e19\u0e39\u0e2a\u0e32\u0e22\u0e25\u0e21\u0e17\u0e30\u0e40\u0e25\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"percent\", min: 6.2, max: 10 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }, { stat: \"crit_rate\", kind: \"percent\", min: 5, max: 8 }]\n    }\n  },\n  dagger: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e21\u0e35\u0e14\u0e2a\u0e19\u0e34\u0e21\", 2: \"\u0e21\u0e35\u0e14\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e04\u0e21\", 3: \"\u0e21\u0e35\u0e14\u0e04\u0e39\u0e48\u0e40\u0e07\u0e32\u0e23\u0e32\u0e15\u0e23\u0e35\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }],\n      2: [{ stat: \"atk\", kind: \"flat\", min: 12, max: 20 }],\n      3: [{ stat: \"atk\", kind: \"flat\", min: 12, max: 20 }, { stat: \"evasion\", kind: \"percent\", min: 5, max: 8 }]\n    }\n  },\n  staff: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e04\u0e17\u0e32\u0e44\u0e21\u0e49\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e04\u0e17\u0e32\u0e41\u0e01\u0e30\u0e2a\u0e25\u0e31\u0e01\", 3: \"\u0e04\u0e17\u0e32\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e17\u0e30\u0e40\u0e25\u0e25\u0e36\u0e01\" },\n    // \u0e2a\u0e32\u0e22 support \u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49\u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e44\u0e14\u0e49\u0e15\u0e31\u0e27\u0e21\u0e32\u0e41\u0e25\u0e49\u0e27 (\u0e44\u0e21\u0e48\u0e1c\u0e39\u0e01\u0e01\u0e31\u0e1a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e0a\u0e34\u0e49\u0e19\u0e19\u0e35\u0e49\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b) - \u0e40\u0e01\u0e47\u0e1a\u0e04\u0e48\u0e32 ATK%/HP \u0e40\u0e14\u0e34\u0e21\u0e44\u0e27\u0e49\u0e17\u0e38\u0e01\u0e14\u0e32\u0e27 \u0e44\u0e21\u0e48\u0e41\u0e01\u0e49\u0e15\u0e31\u0e27\u0e40\u0e25\u0e02\n    stat_defs: {\n      1: [{ stat: \"def\", kind: \"percent\", min: 10, max: 16 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 10, max: 16 }, { stat: \"hp\", kind: \"flat\", min: 60, max: 100 }]\n    }\n  },\n\n  // ---------- \u0e40\u0e01\u0e23\u0e32\u0e30 (4) ----------\n  armor_body: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e1c\u0e49\u0e32\u0e43\u0e1a\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e40\u0e01\u0e23\u0e32\u0e30\u0e2b\u0e19\u0e31\u0e07\", 3: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e40\u0e01\u0e23\u0e32\u0e30\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\" },\n    stat_defs: {\n      1: [{ stat: \"def\", kind: \"percent\", min: 10, max: 16 }],\n      2: [{ stat: \"def\", kind: \"percent\", min: 16, max: 24 }],\n      3: [{ stat: \"def\", kind: \"percent\", min: 16, max: 24 }, { stat: \"hp\", kind: \"percent\", min: 10, max: 16 }]\n    }\n  },\n  shield: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e42\u0e25\u0e48\u0e44\u0e21\u0e49\u0e1c\u0e38\", 2: \"\u0e42\u0e25\u0e48\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e2b\u0e19\u0e32\", 3: \"\u0e42\u0e25\u0e48\u0e21\u0e31\u0e07\u0e01\u0e23\u0e17\u0e30\u0e40\u0e25\" },\n    stat_defs: {\n      1: [{ stat: \"def\", kind: \"flat\", min: 8, max: 14 }],\n      2: [{ stat: \"def\", kind: \"flat\", min: 16, max: 28 }],\n      3: [{ stat: \"def\", kind: \"flat\", min: 16, max: 28 }, { stat: \"atk\", kind: \"percent\", min: 10, max: 16 }]\n    }\n  },\n  boots: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e23\u0e2d\u0e07\u0e40\u0e17\u0e49\u0e32\u0e1c\u0e49\u0e32\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e23\u0e2d\u0e07\u0e40\u0e17\u0e49\u0e32\u0e2b\u0e19\u0e31\u0e07\u0e2b\u0e19\u0e32\", 3: \"\u0e23\u0e2d\u0e07\u0e40\u0e17\u0e49\u0e32\u0e1a\u0e39\u0e4a\u0e15\u0e19\u0e31\u0e01\u0e40\u0e14\u0e34\u0e19\u0e40\u0e23\u0e37\u0e2d\" },\n    stat_defs: {\n      1: [{ stat: \"spd\", kind: \"percent\", min: 10, max: 16 }],\n      2: [{ stat: \"spd\", kind: \"percent\", min: 16, max: 24 }],\n      3: [{ stat: \"spd\", kind: \"percent\", min: 16, max: 24 }, { stat: \"def\", kind: \"flat\", min: 16, max: 28 }]\n    }\n  },\n  bone_armor: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e1b\u0e25\u0e32\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e40\u0e01\u0e23\u0e32\u0e30\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e41\u0e02\u0e47\u0e07\", 3: \"\u0e40\u0e01\u0e23\u0e32\u0e30\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e1b\u0e25\u0e32\u0e27\u0e32\u0e2c\" },\n    stat_defs: {\n      1: [{ stat: \"hp\", kind: \"percent\", min: 6.2, max: 10 }],\n      2: [{ stat: \"hp\", kind: \"percent\", min: 10, max: 16 }],\n      3: [{ stat: \"hp\", kind: \"percent\", min: 10, max: 16 }, { stat: \"resist\", kind: \"percent\", min: 6.2, max: 10 }]\n    }\n  },\n\n  // ---------- \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a (4) ----------\n  ring: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e41\u0e2b\u0e27\u0e19\u0e17\u0e2d\u0e07\u0e41\u0e14\u0e07\", 2: \"\u0e41\u0e2b\u0e27\u0e19\u0e40\u0e07\u0e34\u0e19\u0e2a\u0e25\u0e31\u0e01\", 3: \"\u0e41\u0e2b\u0e27\u0e19\u0e44\u0e02\u0e48\u0e21\u0e38\u0e01\u0e14\u0e33\" },\n    stat_defs: {\n      1: [{ stat: \"crit_rate\", kind: \"percent\", min: 3.2, max: 5 }],\n      2: [{ stat: \"crit_rate\", kind: \"percent\", min: 5, max: 8 }],\n      3: [{ stat: \"crit_rate\", kind: \"percent\", min: 5, max: 8 }, { stat: \"atk\", kind: \"percent\", min: 10, max: 16 }]\n    }\n  },\n  necklace: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e2a\u0e23\u0e49\u0e2d\u0e22\u0e40\u0e0a\u0e37\u0e2d\u0e01\u0e2b\u0e19\u0e31\u0e07\", 2: \"\u0e2a\u0e23\u0e49\u0e2d\u0e22\u0e40\u0e07\u0e34\u0e19\", 3: \"\u0e2a\u0e23\u0e49\u0e2d\u0e22\u0e01\u0e30\u0e42\u0e2b\u0e25\u0e01\u0e17\u0e2d\u0e07\" },\n    stat_defs: {\n      1: [{ stat: \"crit_damage\", kind: \"percent\", min: 3.2, max: 5 }],\n      2: [{ stat: \"crit_damage\", kind: \"percent\", min: 5, max: 8 }],\n      3: [{ stat: \"crit_damage\", kind: \"percent\", min: 5, max: 8 }, { stat: \"atk\", kind: \"flat\", min: 12, max: 20 }]\n    }\n  },\n  brooch: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e40\u0e02\u0e47\u0e21\u0e01\u0e25\u0e31\u0e14\u0e17\u0e2d\u0e07\u0e41\u0e14\u0e07\", 2: \"\u0e40\u0e02\u0e47\u0e21\u0e01\u0e25\u0e31\u0e14\u0e40\u0e07\u0e34\u0e19\", 3: \"\u0e40\u0e02\u0e47\u0e21\u0e01\u0e25\u0e31\u0e14\u0e40\u0e02\u0e47\u0e21\u0e17\u0e34\u0e28\u0e17\u0e2d\u0e07\" },\n    stat_defs: {\n      1: [{ stat: \"spd\", kind: \"percent\", min: 10, max: 16 }],\n      2: [{ stat: \"spd\", kind: \"percent\", min: 16, max: 24 }],\n      3: [{ stat: \"spd\", kind: \"percent\", min: 16, max: 24 }, { stat: \"evasion\", kind: \"percent\", min: 5, max: 8 }]\n    }\n  },\n  bracelet: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e01\u0e33\u0e44\u0e25\u0e40\u0e0a\u0e37\u0e2d\u0e01\", 2: \"\u0e01\u0e33\u0e44\u0e25\u0e40\u0e07\u0e34\u0e19\", 3: \"\u0e01\u0e33\u0e44\u0e25\u0e42\u0e0b\u0e48\u0e40\u0e07\u0e34\u0e19\" },\n    stat_defs: {\n      1: [{ stat: \"hp\", kind: \"flat\", min: 30, max: 50 }],\n      2: [{ stat: \"hp\", kind: \"flat\", min: 60, max: 100 }],\n      3: [{ stat: \"hp\", kind: \"flat\", min: 60, max: 100 }, { stat: \"spd\", kind: \"percent\", min: 16, max: 24 }]\n    }\n  }\n};\n\n// \u0e23\u0e30\u0e14\u0e31\u0e1a Level (\u0e1b\u0e49\u0e2d\u0e19\u0e02\u0e2d\u0e07\u0e0b\u0e49\u0e33\u0e14\u0e32\u0e27+\u0e0a\u0e19\u0e34\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19) \u2014 \u0e04\u0e48\u0e32\u0e1e\u0e25\u0e31\u0e07\u0e04\u0e39\u0e13\u0e40\u0e02\u0e49\u0e32\u0e01\u0e31\u0e1a\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49\nconst EQUIPMENT_LEVELS = [\n  { level: 1, multiplier: 1.00, dupes_needed: 0 },\n  { level: 2, multiplier: 1.25, dupes_needed: 1 },\n  { level: 3, multiplier: 1.50, dupes_needed: 2 },\n  { level: 4, multiplier: 1.75, dupes_needed: 3 },\n  { level: 5, multiplier: 2.00, dupes_needed: 5 }\n];\n\n// \u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 \u2014 \u0e22\u0e49\u0e32\u0e22\u0e44\u0e1b\u0e19\u0e34\u0e22\u0e32\u0e21\u0e14\u0e49\u0e32\u0e19\u0e25\u0e48\u0e32\u0e07 (EQUIPMENT_UPGRADE_RECIPES) \u0e41\u0e25\u0e49\u0e27\n// \u0e40\u0e14\u0e34\u0e21\u0e21\u0e35\u0e41\u0e04\u0e48 2 \u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a\u0e43\u0e0a\u0e49\u0e23\u0e48\u0e27\u0e21\u0e01\u0e31\u0e19\u0e2b\u0e21\u0e14\u0e17\u0e38\u0e01\u0e0a\u0e34\u0e49\u0e19 \u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49\u0e40\u0e1b\u0e25\u0e35\u0e48\u0e22\u0e19\u0e40\u0e1b\u0e47\u0e19\u0e2a\u0e39\u0e15\u0e23\u0e40\u0e09\u0e1e\u0e32\u0e30\u0e15\u0e48\u0e2d\u0e0a\u0e19\u0e34\u0e14\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c (11 \u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a)\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { EQUIPMENT_TYPES, EQUIPMENT_LEVELS };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_equipment_materials.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e19\u0e34\u0e22\u0e32\u0e21\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a\u0e04\u0e23\u0e32\u0e1f\u0e17\u0e4c/\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e31\u0e49\u0e07 11 \u0e0a\u0e19\u0e34\u0e14 (\u0e41\u0e1a\u0e48\u0e07\u0e15\u0e32\u0e21\u0e2b\u0e21\u0e27\u0e14\u0e27\u0e31\u0e2a\u0e14\u0e38 + \u0e14\u0e32\u0e27)\n// \u0e41\u0e25\u0e30\u0e2a\u0e39\u0e15\u0e23\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 (1 \u0e14\u0e32\u0e27->2 \u0e14\u0e32\u0e27, 2 \u0e14\u0e32\u0e27->3 \u0e14\u0e32\u0e27) \u0e02\u0e2d\u0e07\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e31\u0e49\u0e07 15 \u0e0a\u0e19\u0e34\u0e14\n// ==========================================\n\nconst EQUIPMENT_MATERIALS = {\n  mat_iron_ore:        { name: \"\u0e41\u0e23\u0e48\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e14\u0e34\u0e1a\",        star: 1, category: \"metal\" },\n  mat_pure_steel:       { name: \"\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\u0e1a\u0e23\u0e34\u0e2a\u0e38\u0e17\u0e18\u0e34\u0e4c\",  star: 2, category: \"metal\" },\n  mat_softwood:         { name: \"\u0e44\u0e21\u0e49\u0e40\u0e19\u0e37\u0e49\u0e2d\u0e2d\u0e48\u0e2d\u0e19\",        star: 1, category: \"wood\" },\n  mat_spirit_hardwood:  { name: \"\u0e44\u0e21\u0e49\u0e40\u0e19\u0e37\u0e49\u0e2d\u0e41\u0e02\u0e47\u0e07\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\",  star: 2, category: \"wood\" },\n  mat_common_leather:   { name: \"\u0e2b\u0e19\u0e31\u0e07\u0e2a\u0e31\u0e15\u0e27\u0e4c\u0e18\u0e23\u0e23\u0e21\u0e14\u0e32\",     star: 1, category: \"leather\" },\n  mat_sea_leather:      { name: \"\u0e2b\u0e19\u0e31\u0e07\u0e2d\u0e2a\u0e39\u0e23\u0e17\u0e30\u0e40\u0e25\",        star: 2, category: \"leather\" },\n  mat_strong_thread:    { name: \"\u0e14\u0e49\u0e32\u0e22\u0e40\u0e2b\u0e19\u0e35\u0e22\u0e27\u0e1e\u0e34\u0e40\u0e28\u0e29\",     star: 1, category: \"thread\" },\n  mat_animal_bone:      { name: \"\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e2a\u0e31\u0e15\u0e27\u0e4c\u0e17\u0e31\u0e48\u0e27\u0e44\u0e1b\",   star: 1, category: \"bone\" },\n  mat_monster_bone:     { name: \"\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e2a\u0e31\u0e15\u0e27\u0e4c\u0e1b\u0e23\u0e30\u0e2b\u0e25\u0e32\u0e14\",  star: 2, category: \"bone\" },\n  mat_crystal_shard:    { name: \"\u0e40\u0e28\u0e29\u0e04\u0e23\u0e34\u0e2a\u0e15\u0e31\u0e25\",         star: 1, category: \"crystal\" },\n  mat_deep_pearl:        { name: \"\u0e44\u0e02\u0e48\u0e21\u0e38\u0e01\u0e17\u0e30\u0e40\u0e25\u0e25\u0e36\u0e01\",       star: 2, category: \"crystal\" }\n};\n\nconst EQUIPMENT_MATERIAL_FAMILIES = {\n  metal:   { 1: \"mat_iron_ore\",      2: \"mat_pure_steel\" },\n  wood:    { 1: \"mat_softwood\",      2: \"mat_spirit_hardwood\" },\n  leather: { 1: \"mat_common_leather\", 2: \"mat_sea_leather\" },\n  thread:  { 1: \"mat_strong_thread\" }, // \u0e21\u0e35\u0e41\u0e04\u0e48\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e14\u0e32\u0e27 1 \u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19 (\u0e2a\u0e39\u0e15\u0e23\u0e2d\u0e31\u0e1e\u0e40\u0e01\u0e23\u0e14\u0e17\u0e38\u0e01\u0e2d\u0e31\u0e19\u0e17\u0e35\u0e48\u0e43\u0e0a\u0e49\u0e14\u0e49\u0e32\u0e22\u0e40\u0e2b\u0e19\u0e35\u0e22\u0e27\u0e43\u0e0a\u0e49\u0e15\u0e31\u0e27\u0e19\u0e35\u0e49\u0e15\u0e31\u0e27\u0e40\u0e14\u0e35\u0e22\u0e27\u0e17\u0e31\u0e49\u0e07\u0e02\u0e31\u0e49\u0e19 2 \u0e14\u0e32\u0e27 \u0e41\u0e25\u0e30 3 \u0e14\u0e32\u0e27 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e14\u0e49\u0e32\u0e22\u0e40\u0e01\u0e23\u0e14\u0e2a\u0e39\u0e07\u0e01\u0e27\u0e48\u0e32)\n  bone:    { 1: \"mat_animal_bone\",   2: \"mat_monster_bone\" },\n  crystal: { 1: \"mat_crystal_shard\", 2: \"mat_deep_pearl\" }\n};\nconst EQUIPMENT_MATERIAL_FAMILY_ORDER = [\"metal\", \"wood\", \"leather\", \"thread\", \"bone\", \"crystal\"];\n\nconst EQUIPMENT_UPGRADE_RECIPES = {\n  sword:  { 2: [{ item_id: \"mat_iron_ore\", qty: 4 }], 3: [{ item_id: \"mat_pure_steel\", qty: 2 }, { item_id: \"mat_iron_ore\", qty: 3 }] },\n  dagger: { 2: [{ item_id: \"mat_iron_ore\", qty: 4 }], 3: [{ item_id: \"mat_pure_steel\", qty: 2 }, { item_id: \"mat_iron_ore\", qty: 3 }] },\n  axe:    { 2: [{ item_id: \"mat_iron_ore\", qty: 4 }], 3: [{ item_id: \"mat_pure_steel\", qty: 2 }, { item_id: \"mat_iron_ore\", qty: 3 }] },\n\n  spear:  { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_softwood\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_iron_ore\", qty: 2 }] },\n  hammer: { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_softwood\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_iron_ore\", qty: 2 }] },\n  shield: { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_softwood\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_iron_ore\", qty: 2 }] },\n\n  bow: { 2: [{ item_id: \"mat_softwood\", qty: 3 }, { item_id: \"mat_strong_thread\", qty: 2 }], 3: [{ item_id: \"mat_spirit_hardwood\", qty: 2 }, { item_id: \"mat_strong_thread\", qty: 4 }] },\n\n  staff: { 2: [{ item_id: \"mat_softwood\", qty: 3 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_crystal_shard\", qty: 3 }] },\n\n  armor_body: { 2: [{ item_id: \"mat_common_leather\", qty: 4 }, { item_id: \"mat_strong_thread\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 2 }, { item_id: \"mat_common_leather\", qty: 3 }] },\n  boots:      { 2: [{ item_id: \"mat_common_leather\", qty: 4 }, { item_id: \"mat_strong_thread\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 2 }, { item_id: \"mat_common_leather\", qty: 3 }] },\n\n  bone_armor: { 2: [{ item_id: \"mat_animal_bone\", qty: 4 }, { item_id: \"mat_strong_thread\", qty: 1 }], 3: [{ item_id: \"mat_monster_bone\", qty: 2 }, { item_id: \"mat_animal_bone\", qty: 3 }] },\n\n  ring:     { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_crystal_shard\", qty: 2 }] },\n  necklace: { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_crystal_shard\", qty: 2 }] },\n\n  brooch:   { 2: [{ item_id: \"mat_common_leather\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_strong_thread\", qty: 3 }] },\n  bracelet: { 2: [{ item_id: \"mat_common_leather\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_strong_thread\", qty: 3 }] }\n};\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { EQUIPMENT_MATERIALS, EQUIPMENT_MATERIAL_FAMILIES, EQUIPMENT_MATERIAL_FAMILY_ORDER, EQUIPMENT_UPGRADE_RECIPES };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_combat_power.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e04\u0e48\u0e32\u0e04\u0e07\u0e17\u0e35\u0e48\u0e02\u0e2d\u0e07\u0e23\u0e30\u0e1a\u0e1a \"\u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\" (Combat Power) \u2014 \u0e2a\u0e40\u0e1b\u0e04\u0e17\u0e35\u0e48 2 \u0e08\u0e32\u0e01 roadmap\n// \u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e15\u0e48\u0e2d\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 = (\u0e1c\u0e25\u0e23\u0e27\u0e21\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e16\u0e48\u0e27\u0e07\u0e19\u0e49\u0e33\u0e2b\u0e19\u0e31\u0e01) x \u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e15\u0e32\u0e21\u0e2a\u0e32\u0e22 (role)\n// \u0e2a\u0e32\u0e22 Fighter \u0e43\u0e2b\u0e49\u0e04\u0e48\u0e32\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14, Ranger \u0e15\u0e48\u0e33\u0e2a\u0e38\u0e14 \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e01\u0e33\u0e2b\u0e19\u0e14 \u0e2a\u0e48\u0e27\u0e19\u0e2a\u0e32\u0e22\u0e2d\u0e37\u0e48\u0e19\u0e40\u0e23\u0e35\u0e22\u0e07\u0e15\u0e32\u0e21\u0e04\u0e27\u0e32\u0e21\u0e40\u0e2b\u0e21\u0e32\u0e30\u0e2a\u0e21\n// ==========================================\n\n// \u0e19\u0e49\u0e33\u0e2b\u0e19\u0e31\u0e01\u0e02\u0e2d\u0e07\u0e41\u0e15\u0e48\u0e25\u0e30\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a \u0e15\u0e2d\u0e19\u0e23\u0e27\u0e21\u0e40\u0e1b\u0e47\u0e19\u0e04\u0e48\u0e32\u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e14\u0e34\u0e1a (\u0e01\u0e48\u0e2d\u0e19\u0e04\u0e39\u0e13\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e2a\u0e32\u0e22)\n// \u0e40\u0e19\u0e49\u0e19 HP \u0e01\u0e31\u0e1a ATK \u0e40\u0e1b\u0e47\u0e19\u0e2b\u0e25\u0e31\u0e01\u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e01\u0e33\u0e2b\u0e19\u0e14 \u0e41\u0e15\u0e48\u0e43\u0e2a\u0e48 DEF/SPD \u0e44\u0e27\u0e49\u0e40\u0e25\u0e47\u0e01\u0e19\u0e49\u0e2d\u0e22\u0e43\u0e2b\u0e49\u0e04\u0e23\u0e1a\u0e17\u0e38\u0e01\u0e21\u0e34\u0e15\u0e34\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\nconst COMBAT_POWER_STAT_WEIGHTS = {\n  hp: 0.3,\n  attack: 4,\n  defense_flat: 3,\n  speed: 2\n};\n\n// \u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e15\u0e32\u0e21\u0e2a\u0e32\u0e22 (role) \u2014 Fighter \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14, Ranger \u0e15\u0e48\u0e33\u0e2a\u0e38\u0e14 \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e01\u0e33\u0e2b\u0e19\u0e14\nconst COMBAT_POWER_ROLE_MULTIPLIER = {\n  fighter: 1.25,\n  assassin: 1.15,\n  tank: 1.05,\n  support: 0.95,\n  ranger: 0.85\n};\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { COMBAT_POWER_STAT_WEIGHTS, COMBAT_POWER_ROLE_MULTIPLIER };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: crew_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e14\u0e39\u0e41\u0e25\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e01\u0e32\u0e23\u0e08\u0e31\u0e14\u0e17\u0e35\u0e21 + \u0e14\u0e36\u0e07\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e08\u0e32\u0e01 id\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_characters.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d\n// ==========================================\n\nfunction crewGetBaseCharData(id) {\n  const found = CHARACTERS.find(c => c.id === id);\n  if (!found) {\n    throw new Error(`\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 id: ${id} \u0e43\u0e19 data_characters.js`);\n  }\n  // \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32\u0e2a\u0e33\u0e40\u0e19\u0e32 \u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19\u0e44\u0e21\u0e48\u0e43\u0e2b\u0e49 combat_engine \u0e44\u0e1b\u0e41\u0e01\u0e49\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a\u0e42\u0e14\u0e22\u0e44\u0e21\u0e48\u0e15\u0e31\u0e49\u0e07\u0e43\u0e08\n  return JSON.parse(JSON.stringify(found));\n}\n\n// \u0e40\u0e23\u0e35\u0e22\u0e07\u0e25\u0e33\u0e14\u0e31\u0e1a id \u0e25\u0e39\u0e01\u0e40\u0e23\u0e37\u0e2d: \u0e40\u0e01\u0e23\u0e14\u0e2a\u0e39\u0e07\u0e01\u0e48\u0e2d\u0e19 (S>A>B>C) \u0e41\u0e25\u0e49\u0e27\u0e16\u0e49\u0e32\u0e40\u0e01\u0e23\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e40\u0e25\u0e40\u0e27\u0e25\u0e2a\u0e39\u0e07\u0e01\u0e27\u0e48\u0e32\u0e2d\u0e22\u0e39\u0e48\u0e01\u0e48\u0e2d\u0e19\n// \u0e43\u0e0a\u0e49\u0e23\u0e48\u0e27\u0e21\u0e01\u0e31\u0e19\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e19\u0e49\u0e32\u0e04\u0e25\u0e31\u0e07\u0e25\u0e39\u0e01\u0e40\u0e23\u0e37\u0e2d\u0e41\u0e25\u0e30\u0e2b\u0e19\u0e49\u0e32\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e43\u0e2b\u0e49\u0e2d\u0e32\u0e2b\u0e32\u0e23\nfunction crewSortIdsByGradeLevel(ids) {\n  const gradeWeight = { S: 4, A: 3, B: 2, C: 1 };\n  return ids.slice().sort((a, b) => {\n    const gradeA = crewGetBaseCharData(a).grade;\n    const gradeB = crewGetBaseCharData(b).grade;\n    if (gradeWeight[gradeA] !== gradeWeight[gradeB]) return (gradeWeight[gradeB] || 0) - (gradeWeight[gradeA] || 0);\n    const lv = (playerState.crew[b].level || 1) - (playerState.crew[a].level || 1);\n    if (lv !== 0) return lv;\n    return crewGetBaseCharData(a).name.localeCompare(crewGetBaseCharData(b).name, 'th');\n  });\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { crewGetBaseCharData, crewSortIdsByGradeLevel };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: progression_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e04\u0e33\u0e19\u0e27\u0e13\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19 \u0e15\u0e32\u0e21 level / \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33 (dupes) / \u0e04\u0e25\u0e32\u0e2a (class)\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_characters.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d (\u0e43\u0e2b\u0e49\u0e15\u0e31\u0e27\u0e41\u0e1b\u0e23 CHARACTERS)\n// \u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e44\u0e21\u0e48\u0e21\u0e35\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e14\u0e34\u0e1a\u0e1d\u0e31\u0e07\u0e2d\u0e22\u0e39\u0e48 \u0e21\u0e35\u0e41\u0e15\u0e48\u0e2a\u0e39\u0e15\u0e23\u0e04\u0e33\u0e19\u0e27\u0e13\n// ==========================================\n\n// \u0e17\u0e38\u0e01\u0e40\u0e25\u0e40\u0e27\u0e25\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a 5% \u0e02\u0e2d\u0e07\u0e04\u0e48\u0e32\u0e40\u0e23\u0e34\u0e48\u0e21\u0e15\u0e49\u0e19 (level 1) \u0e41\u0e1a\u0e1a\u0e04\u0e07\u0e17\u0e35\u0e48 \u0e44\u0e21\u0e48\u0e17\u0e1a\u0e15\u0e49\u0e19\n// \u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a\u0e17\u0e38\u0e01\u0e04\u0e25\u0e32\u0e2a\u0e40\u0e2b\u0e21\u0e37\u0e2d\u0e19\u0e01\u0e31\u0e19\u0e2b\u0e21\u0e14 (class \u0e44\u0e21\u0e48\u0e21\u0e35\u0e1c\u0e25\u0e01\u0e31\u0e1a\u0e2a\u0e39\u0e15\u0e23\u0e1a\u0e27\u0e01 level \u0e19\u0e35\u0e49)\nconst LEVEL_STEP_PERCENT = 0.05;\n\n// \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e41\u0e15\u0e48\u0e25\u0e30 \"\u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48\u0e17\u0e33\u0e43\u0e2b\u0e49 max level \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e02\u0e36\u0e49\u0e19 1\" \u0e04\u0e39\u0e13\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e14\u0e49\u0e27\u0e22 1.10 \u0e41\u0e1a\u0e1a\u0e17\u0e1a\u0e15\u0e49\u0e19\u0e17\u0e1a\u0e14\u0e2d\u0e01\u0e15\u0e48\u0e2d\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07\u0e15\u0e25\u0e2d\u0e14\u0e0a\u0e35\u0e27\u0e34\u0e15\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\n// (\u0e44\u0e21\u0e48\u0e23\u0e35\u0e40\u0e0b\u0e47\u0e15\u0e15\u0e2d\u0e19\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a) \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e23\u0e30\u0e1a\u0e38\u0e44\u0e27\u0e49\u0e0a\u0e31\u0e14\u0e40\u0e08\u0e19: \u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48 1 \u00d71.1, \u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48 2 \u00d71.1 \u0e02\u0e2d\u0e07\u0e22\u0e2d\u0e14\u0e2a\u0e30\u0e2a\u0e21 (\u0e23\u0e27\u0e21\u0e40\u0e1b\u0e47\u0e19 \u00d71.21), \u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48 3 \u00d71.331 ...\nconst DUPE_LEVEL_COMPOUND_RATE = 1.10;\n\n// \u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48 \"\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a\" (\u0e08\u0e48\u0e32\u0e22\u0e40\u0e07\u0e34\u0e19\u0e40\u0e25\u0e37\u0e48\u0e2d\u0e19\u0e08\u0e32\u0e01 1\u21922 \u0e2b\u0e23\u0e37\u0e2d 2\u21923) \u0e04\u0e39\u0e13\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e14\u0e49\u0e27\u0e22 1.42 \u0e41\u0e1a\u0e1a\u0e44\u0e21\u0e48\u0e21\u0e35\u0e40\u0e07\u0e37\u0e48\u0e2d\u0e19\u0e44\u0e02\u0e17\u0e31\u0e19\u0e17\u0e35\n// \u0e41\u0e22\u0e01\u0e15\u0e48\u0e32\u0e07\u0e2b\u0e32\u0e01\u0e08\u0e32\u0e01\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e14\u0e49\u0e32\u0e19\u0e1a\u0e19\u0e42\u0e14\u0e22\u0e2a\u0e34\u0e49\u0e19\u0e40\u0e0a\u0e34\u0e07 (\u0e04\u0e39\u0e13\u0e0b\u0e49\u0e2d\u0e19\u0e01\u0e31\u0e19\u0e44\u0e1b\u0e40\u0e23\u0e37\u0e48\u0e2d\u0e22\u0e46 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e01\u0e31\u0e19)\nconst CLASS_UPGRADE_MULTIPLIER = 1.42;\n\n// \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a 1 (\u0e41\u0e15\u0e48\u0e25\u0e30\u0e15\u0e31\u0e27\u0e40\u0e1e\u0e34\u0e48\u0e21 max level 1 - \u0e23\u0e27\u0e21 5 \u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e1a\u0e15\u0e49\u0e19)\nconst CLASS1_MAX_DUPES = 5;\n\n// \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e15\u0e48\u0e2d \"1 \u0e01\u0e25\u0e38\u0e48\u0e21\" \u0e17\u0e35\u0e48\u0e43\u0e0a\u0e49\u0e40\u0e1e\u0e34\u0e48\u0e21 max level \u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a 2 (\u0e17\u0e38\u0e01 4 \u0e15\u0e31\u0e27 \u0e40\u0e1e\u0e34\u0e48\u0e21 1 level - \u0e1b\u0e23\u0e31\u0e1a\u0e40\u0e1b\u0e47\u0e19 4 \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e02\u0e2d \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e43\u0e2b\u0e49\u0e2d\u0e31\u0e1e\u0e22\u0e32\u0e01\u0e02\u0e36\u0e49\u0e19)\nconst CLASS2_DUPES_PER_LEVEL_GROUP = 3;\nconst CLASS2_MAX_GROUPS = 5; // 5 \u0e01\u0e25\u0e38\u0e48\u0e21 x 3 \u0e15\u0e31\u0e27 = 15 \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33 \u0e16\u0e36\u0e07\u0e08\u0e30\u0e41\u0e21\u0e47\u0e01\u0e04\u0e25\u0e32\u0e2a 2 (level 30)\n\n// ==========================================\n// 1) \u0e04\u0e33\u0e19\u0e27\u0e13\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e2b\u0e25\u0e31\u0e07\u0e1a\u0e27\u0e01 level (\u0e22\u0e31\u0e07\u0e44\u0e21\u0e48\u0e04\u0e39\u0e13\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33/\u0e04\u0e25\u0e32\u0e2a)\n// ==========================================\nfunction getLevelValue(baseStatAtLevel1, level) {\n  const lvl = Math.max(1, level);\n  return baseStatAtLevel1 + (baseStatAtLevel1 * LEVEL_STEP_PERCENT * (lvl - 1));\n}\n\n// ==========================================\n// 2) \u0e04\u0e33\u0e19\u0e27\u0e13\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e23\u0e27\u0e21\u0e08\u0e32\u0e01\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33 (\u0e17\u0e1a\u0e15\u0e49\u0e19\u0e15\u0e25\u0e2d\u0e14\u0e0a\u0e35\u0e27\u0e34\u0e15) + \u0e01\u0e32\u0e23\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e40\u0e07\u0e37\u0e48\u0e2d\u0e19\u0e44\u0e02 \u0e04\u0e39\u0e13\u0e0b\u0e49\u0e2d\u0e19\u0e01\u0e31\u0e19\u0e44\u0e1b\u0e40\u0e23\u0e37\u0e48\u0e2d\u0e22\u0e46)\n//    saveData \u0e15\u0e49\u0e2d\u0e07\u0e21\u0e35: class, dupes (\u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19), class1_dupes_final, class2_dupes_final (\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48 \"\u0e41\u0e0a\u0e48\u0e41\u0e02\u0e47\u0e07\" \u0e44\u0e27\u0e49\u0e15\u0e2d\u0e19\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a\u0e2d\u0e2d\u0e01\u0e08\u0e32\u0e01\u0e04\u0e25\u0e32\u0e2a\u0e19\u0e31\u0e49\u0e19)\n// ==========================================\nfunction getClassDupeMultiplier(saveData) {\n  const charClass = (saveData && saveData.class) || 1;\n  const currentDupes = Math.max(0, (saveData && saveData.dupes) || 0);\n\n  // \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e17\u0e35\u0e48 \"\u0e43\u0e0a\u0e49\u0e44\u0e1b\u0e08\u0e23\u0e34\u0e07\" \u0e43\u0e19\u0e04\u0e25\u0e32\u0e2a 1 \u0e15\u0e25\u0e2d\u0e14\u0e0a\u0e35\u0e27\u0e34\u0e15\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 - \u0e16\u0e49\u0e32\u0e40\u0e25\u0e22\u0e04\u0e25\u0e32\u0e2a 1 \u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27\u0e43\u0e0a\u0e49\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e41\u0e0a\u0e48\u0e41\u0e02\u0e47\u0e07\u0e44\u0e27\u0e49\u0e15\u0e2d\u0e19\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a \u0e16\u0e49\u0e32\u0e22\u0e31\u0e07\u0e2d\u0e22\u0e39\u0e48\u0e04\u0e25\u0e32\u0e2a 1 \u0e43\u0e0a\u0e49\u0e04\u0e48\u0e32\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19\u0e40\u0e25\u0e22\n  const class1DupesUsed = charClass >= 2 ? Math.min((saveData && saveData.class1_dupes_final) || 0, CLASS1_MAX_DUPES) : Math.min(currentDupes, CLASS1_MAX_DUPES);\n  // \u0e01\u0e25\u0e38\u0e48\u0e21\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e17\u0e35\u0e48 \"\u0e43\u0e0a\u0e49\u0e44\u0e1b\u0e08\u0e23\u0e34\u0e07\" \u0e43\u0e19\u0e04\u0e25\u0e32\u0e2a 2 \u0e15\u0e25\u0e2d\u0e14\u0e0a\u0e35\u0e27\u0e34\u0e15\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 (\u0e2b\u0e25\u0e31\u0e01\u0e01\u0e32\u0e23\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19)\n  const class2GroupsUsed = charClass >= 3\n    ? Math.min(Math.floor(((saveData && saveData.class2_dupes_final) || 0) / CLASS2_DUPES_PER_LEVEL_GROUP), CLASS2_MAX_GROUPS)\n    : (charClass === 2 ? Math.min(Math.floor(currentDupes / CLASS2_DUPES_PER_LEVEL_GROUP), CLASS2_MAX_GROUPS) : 0);\n\n  const totalDupeLevelUps = class1DupesUsed + class2GroupsUsed;\n  const classUpgradesPerformed = charClass - 1; // class1=0 \u0e04\u0e23\u0e31\u0e49\u0e07, class2=1 \u0e04\u0e23\u0e31\u0e49\u0e07, class3=2 \u0e04\u0e23\u0e31\u0e49\u0e07\n\n  return Math.pow(DUPE_LEVEL_COMPOUND_RATE, totalDupeLevelUps) * Math.pow(CLASS_UPGRADE_MULTIPLIER, classUpgradesPerformed);\n}\n\n// ==========================================\n// 3) \u0e04\u0e33\u0e19\u0e27\u0e13 max level \u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 \u0e15\u0e32\u0e21\u0e04\u0e25\u0e32\u0e2a\u0e41\u0e25\u0e30\u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\n// ==========================================\nfunction getMaxLevel(charClass, dupes) {\n  const safeDupes = Math.max(0, dupes || 0);\n\n  if (charClass === 1) {\n    const d = Math.min(safeDupes, CLASS1_MAX_DUPES);\n    return 20 + d; // 20 \u0e16\u0e36\u0e07 25\n  }\n  if (charClass === 2) {\n    const groups = Math.min(Math.floor(safeDupes / CLASS2_DUPES_PER_LEVEL_GROUP), CLASS2_MAX_GROUPS);\n    return 25 + groups; // 25 \u0e16\u0e36\u0e07 30\n  }\n  if (charClass === 3) {\n    return 30; // \u0e04\u0e07\u0e17\u0e35\u0e48 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e23\u0e30\u0e1a\u0e1a\u0e40\u0e1e\u0e34\u0e48\u0e21 max level \u0e41\u0e25\u0e49\u0e27\n  }\n  return 20;\n}\n\n// ==========================================\n// 4) \u0e15\u0e32\u0e23\u0e32\u0e07 EXP \u0e15\u0e48\u0e2d\u0e40\u0e25\u0e40\u0e27\u0e25 (\u0e21\u0e32\u0e08\u0e32\u0e01 progression_system.json \u0e40\u0e14\u0e34\u0e21\u0e17\u0e35\u0e48\u0e21\u0e35\u0e15\u0e31\u0e27\u0e40\u0e25\u0e02\u0e08\u0e23\u0e34\u0e07\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27)\n//    base_exp_table = EXP \u0e17\u0e35\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49 \"\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e2d\u0e31\u0e1e\u0e08\u0e32\u0e01 level \u0e19\u0e31\u0e49\u0e19 \u0e44\u0e1b level \u0e16\u0e31\u0e14\u0e44\u0e1b\" (\u0e40\u0e01\u0e23\u0e14 C \u0e04\u0e37\u0e2d\u0e04\u0e48\u0e32\u0e10\u0e32\u0e19)\n// ==========================================\n// base_exp_table \u0e40\u0e14\u0e34\u0e21 (level 1-19) \u0e15\u0e48\u0e2d\u0e14\u0e49\u0e27\u0e22\u0e2a\u0e48\u0e27\u0e19\u0e02\u0e22\u0e32\u0e22 level 20-29 \u0e17\u0e35\u0e48\u0e04\u0e33\u0e19\u0e27\u0e13\u0e2a\u0e37\u0e1a\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07\u0e08\u0e32\u0e01\u0e23\u0e39\u0e1b\u0e41\u0e1a\u0e1a\u0e40\u0e14\u0e34\u0e21:\n// \u0e15\u0e32\u0e23\u0e32\u0e07\u0e40\u0e14\u0e34\u0e21\u0e40\u0e1b\u0e47\u0e19\u0e02\u0e31\u0e49\u0e19\u0e1a\u0e31\u0e19\u0e44\u0e14 \u0e42\u0e14\u0e22 \"\u0e1c\u0e25\u0e15\u0e48\u0e32\u0e07\u0e02\u0e2d\u0e07\u0e1c\u0e25\u0e15\u0e48\u0e32\u0e07\" (\u0394 \u0e02\u0e2d\u0e07 \u0394) \u0e04\u0e07\u0e17\u0e35\u0e48\u0e43\u0e19\u0e41\u0e15\u0e48\u0e25\u0e30\u0e0a\u0e48\u0e27\u0e07 \u0e41\u0e25\u0e49\u0e27\u0e02\u0e22\u0e31\u0e1a\u0e02\u0e36\u0e49\u0e19\u0e40\u0e1b\u0e47\u0e19\u0e0a\u0e48\u0e27\u0e07\u0e46\n// (level1-10: \u0394\u0394=20, level10-15: \u0394\u0394=100, level15-19: \u0394\u0394=200) \u0e2a\u0e48\u0e27\u0e19\u0e02\u0e22\u0e32\u0e22\u0e19\u0e35\u0e49\u0e2a\u0e37\u0e1a\u0e15\u0e48\u0e2d \u0394\u0394=200 \u0e0a\u0e48\u0e27\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e44\u0e1b\u0e40\u0e23\u0e37\u0e48\u0e2d\u0e22\u0e46\n// \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e43\u0e2b\u0e49\u0e40\u0e25\u0e40\u0e27\u0e25 20-30 (\u0e04\u0e25\u0e32\u0e2a 2-3 \u0e43\u0e2b\u0e21\u0e48) \u0e21\u0e35\u0e15\u0e32\u0e23\u0e32\u0e07 EXP \u0e17\u0e35\u0e48\u0e42\u0e15\u0e15\u0e48\u0e2d\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e18\u0e23\u0e23\u0e21\u0e0a\u0e32\u0e15\u0e34\u0e08\u0e32\u0e01\u0e02\u0e2d\u0e07\u0e40\u0e14\u0e34\u0e21 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e40\u0e25\u0e02\u0e17\u0e35\u0e48\u0e04\u0e34\u0e14\u0e02\u0e36\u0e49\u0e19\u0e43\u0e2b\u0e21\u0e48\u0e25\u0e2d\u0e22\u0e46\nconst BASE_EXP_TABLE = {\n  1: 100, 2: 220, 3: 360, 4: 520, 5: 700, 6: 900, 7: 1120,\n  8: 1360, 9: 1620, 10: 1900, 11: 2280, 12: 2760, 13: 3340,\n  14: 4020, 15: 4800, 16: 5780, 17: 6960, 18: 8340, 19: 9920,\n  20: 11700, 21: 13680, 22: 15860, 23: 18240, 24: 20820,\n  25: 23600, 26: 26580, 27: 29760, 28: 33140, 29: 36720\n};\n\nconst GRADE_EXP_MULTIPLIER = { C: 1.0, B: 1.6, A: 2.35, S: 3.4 };\n\n// \u0e04\u0e48\u0e32\u0e43\u0e0a\u0e49\u0e08\u0e48\u0e32\u0e22\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a (\u0e14\u0e31\u0e1a\u0e25\u0e39\u0e19) \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e23\u0e30\u0e1a\u0e38: \u0e40\u0e01\u0e23\u0e14 C \u0e04\u0e25\u0e32\u0e2a1\u21922 = 100,000 \u0e41\u0e25\u0e49\u0e27\u0e04\u0e39\u0e13 2.2 \u0e15\u0e48\u0e2d\u0e02\u0e31\u0e49\u0e19 (\u0e44\u0e21\u0e48\u0e27\u0e48\u0e32\u0e08\u0e30\u0e02\u0e49\u0e32\u0e21\u0e40\u0e01\u0e23\u0e14\u0e2b\u0e23\u0e37\u0e2d\u0e02\u0e49\u0e32\u0e21\u0e23\u0e2d\u0e1a\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a)\n// \u0e23\u0e32\u0e04\u0e32\u0e04\u0e25\u0e32\u0e2a 2\u21923 \u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e23\u0e30\u0e1a\u0e38\u0e44\u0e27\u0e49\u0e0a\u0e31\u0e14\u0e40\u0e08\u0e19 \u0e43\u0e0a\u0e49\u0e2a\u0e39\u0e15\u0e23\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e15\u0e48\u0e2d\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07 (\u00d72.2 \u0e2d\u0e35\u0e01\u0e02\u0e31\u0e49\u0e19) \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e40\u0e2a\u0e19\u0e2d\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27\u0e40\u0e02\u0e32\u0e1a\u0e2d\u0e01\u0e43\u0e2b\u0e49\u0e14\u0e33\u0e40\u0e19\u0e34\u0e19\u0e01\u0e32\u0e23\u0e40\u0e25\u0e22\nconst CLASS_UPGRADE_BASE_COST = 300000; // x3 \u0e08\u0e32\u0e01\u0e40\u0e14\u0e34\u0e21 (100,000) \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e02\u0e2d\nconst CLASS_UPGRADE_COST_MULTIPLIER = 2.2;\nconst CLASS_UPGRADE_GRADE_INDEX = { C: 0, B: 1, A: 2, S: 3 };\n\nfunction getClassUpgradeCost(grade, fromClass) {\n  const gradeIdx = CLASS_UPGRADE_GRADE_INDEX[grade] || 0;\n  const stepIdx = fromClass - 1; // 1\u21922 = step 0, 2\u21923 = step 1\n  return Math.round(CLASS_UPGRADE_BASE_COST * Math.pow(CLASS_UPGRADE_COST_MULTIPLIER, gradeIdx + stepIdx));\n}\n\n// \u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a (1\u21922 \u0e2b\u0e23\u0e37\u0e2d 2\u21923) \u0e08\u0e48\u0e32\u0e22\u0e14\u0e31\u0e1a\u0e25\u0e39\u0e19\u0e15\u0e32\u0e21\u0e40\u0e01\u0e23\u0e14+\u0e04\u0e25\u0e32\u0e2a\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19 - \"\u0e41\u0e0a\u0e48\u0e41\u0e02\u0e47\u0e07\" \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e17\u0e35\u0e48\u0e43\u0e0a\u0e49\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27\u0e43\u0e19\u0e04\u0e25\u0e32\u0e2a\u0e40\u0e14\u0e34\u0e21\u0e44\u0e27\u0e49\u0e16\u0e32\u0e27\u0e23\n// (\u0e44\u0e27\u0e49\u0e43\u0e2b\u0e49\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e17\u0e1a\u0e15\u0e49\u0e19\u0e04\u0e33\u0e19\u0e27\u0e13\u0e22\u0e49\u0e2d\u0e19\u0e44\u0e1b\u0e16\u0e36\u0e07\u0e44\u0e14\u0e49\u0e41\u0e21\u0e49\u0e08\u0e30\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27) \u0e41\u0e25\u0e49\u0e27\u0e23\u0e35\u0e40\u0e0b\u0e47\u0e15 dupes \u0e40\u0e1b\u0e47\u0e19 0 \u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e04\u0e25\u0e32\u0e2a\u0e43\u0e2b\u0e21\u0e48\n// \u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a\u0e44\u0e14\u0e49\u0e01\u0e47\u0e15\u0e48\u0e2d\u0e40\u0e21\u0e37\u0e48\u0e2d \"\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e40\u0e15\u0e47\u0e21\u0e42\u0e04\u0e27\u0e15\u0e49\u0e32\u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a\u0e19\u0e31\u0e49\u0e19\" \u0e41\u0e25\u0e30 \"\u0e40\u0e25\u0e40\u0e27\u0e25\u0e15\u0e31\u0e19\u0e17\u0e35\u0e48\u0e40\u0e25\u0e40\u0e27\u0e25\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a\u0e19\u0e31\u0e49\u0e19\u0e41\u0e25\u0e49\u0e27\" (\u0e04\u0e25\u0e32\u0e2a1 = Lv.25, \u0e04\u0e25\u0e32\u0e2a2 = Lv.30)\nfunction crewGetClassUpgradeRequirement(charData) {\n  if (!charData || charData.class >= 3) return { eligible: false, reason: \"\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e41\u0e25\u0e49\u0e27\" };\n  const needDupes = charData.class === 1 ? CLASS1_MAX_DUPES : CLASS2_DUPES_PER_LEVEL_GROUP * CLASS2_MAX_GROUPS;\n  const needLevel = charData.class === 1 ? 25 : 30;\n  if ((charData.dupes || 0) < needDupes) return { eligible: false, reason: `\u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e43\u0e2b\u0e49\u0e04\u0e23\u0e1a ${needDupes} \u0e15\u0e31\u0e27\u0e01\u0e48\u0e2d\u0e19 (\u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49 ${charData.dupes || 0})` };\n  if ((charData.level || 1) < needLevel) return { eligible: false, reason: `\u0e40\u0e25\u0e40\u0e27\u0e25\u0e15\u0e49\u0e2d\u0e07\u0e15\u0e31\u0e19\u0e17\u0e35\u0e48 Lv.${needLevel} \u0e01\u0e48\u0e2d\u0e19 (\u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49 Lv.${charData.level || 1})` };\n  return { eligible: true, reason: \"\" };\n}\n\nfunction crewUpgradeClass(charId) {\n  const charData = playerState.crew[charId];\n  if (!charData) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e19\u0e35\u0e49\u0e43\u0e19\u0e04\u0e25\u0e31\u0e07\" };\n  if (charData.class >= 3) return { success: false, message: \"\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e41\u0e25\u0e49\u0e27\" };\n  const classReq = crewGetClassUpgradeRequirement(charData);\n  if (!classReq.eligible) return { success: false, message: classReq.reason };\n\n  const baseChar = crewGetBaseCharData(charId);\n  const cost = getClassUpgradeCost(baseChar.grade, charData.class);\n  if (playerState.doubloons < cost) return { success: false, message: `\u0e14\u0e31\u0e1a\u0e25\u0e39\u0e19\u0e44\u0e21\u0e48\u0e1e\u0e2d (\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23 ${cost})` };\n\n  playerState.doubloons -= cost;\n  if (charData.class === 1) {\n    charData.class1_dupes_final = charData.dupes || 0;\n  } else if (charData.class === 2) {\n    charData.class2_dupes_final = charData.dupes || 0;\n  }\n  charData.class += 1;\n  charData.dupes = 0;\n  playerSave();\n  return { success: true, newClass: charData.class, cost };\n}\n\n// \u0e04\u0e33\u0e19\u0e27\u0e13 EXP \u0e17\u0e35\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49 \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e2d\u0e31\u0e1e\u0e08\u0e32\u0e01 (level - 1) \u0e44\u0e1b\u0e40\u0e1b\u0e47\u0e19 level \u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19 \u0e15\u0e32\u0e21\u0e40\u0e01\u0e23\u0e14\nfunction getExpRequired(level, grade) {\n  if (level <= 1) return 0;\n  const base = BASE_EXP_TABLE[level - 1];\n  if (base === undefined) return null; // \u0e40\u0e01\u0e34\u0e19\u0e15\u0e32\u0e23\u0e32\u0e07\u0e17\u0e35\u0e48\u0e21\u0e35 (\u0e40\u0e25\u0e40\u0e27\u0e25\u0e41\u0e21\u0e47\u0e01\u0e02\u0e2d\u0e07\u0e40\u0e01\u0e21)\n  const multi = GRADE_EXP_MULTIPLIER[grade] || 1.0;\n  return Math.round(base * multi);\n}\n\n// ==========================================\n// 5) \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e2b\u0e25\u0e31\u0e01: \u0e23\u0e27\u0e21\u0e17\u0e38\u0e01\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e40\u0e02\u0e49\u0e32\u0e14\u0e49\u0e27\u0e22\u0e01\u0e31\u0e19 \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\n//    baseChar = object \u0e08\u0e32\u0e01 CHARACTERS (\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48 level 1, dupes 0, class 1)\n//    saveData = { level, dupes, class } \u0e08\u0e32\u0e01 playerSave.crew[id]\n// ==========================================\nfunction calculateCharacterStats(baseChar, saveData) {\n  const level = (saveData && saveData.level) || 1;\n  const dupes = (saveData && saveData.dupes) || 0;\n  const charClass = (saveData && saveData.class) || 1;\n\n  const multiplier = getClassDupeMultiplier(saveData);\n  // \u0e2a\u0e20\u0e32\u0e1e\u0e23\u0e48\u0e32\u0e07\u0e01\u0e32\u0e22\u0e01\u0e23\u0e30\u0e17\u0e1a\u0e41\u0e04\u0e48\u0e1b\u0e23\u0e30\u0e2a\u0e34\u0e17\u0e18\u0e34\u0e20\u0e32\u0e1e\u0e01\u0e32\u0e23\u0e2a\u0e39\u0e49 (\u0e42\u0e08\u0e21\u0e15\u0e35/\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19/\u0e04\u0e27\u0e32\u0e21\u0e40\u0e23\u0e47\u0e27) \u0e44\u0e21\u0e48\u0e01\u0e23\u0e30\u0e17\u0e1a hp\n  // \u0e15\u0e31\u0e49\u0e07\u0e43\u0e08\u0e44\u0e21\u0e48\u0e43\u0e2b\u0e49\u0e01\u0e23\u0e30\u0e17\u0e1a hp \u0e40\u0e1e\u0e23\u0e32\u0e30\u0e08\u0e30\u0e22\u0e34\u0e48\u0e07\u0e17\u0e33\u0e43\u0e2b\u0e49\u0e15\u0e31\u0e27\u0e17\u0e35\u0e48\u0e2a\u0e20\u0e32\u0e1e\u0e41\u0e22\u0e48\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27\u0e15\u0e32\u0e22\u0e07\u0e48\u0e32\u0e22\u0e02\u0e36\u0e49\u0e19\u0e44\u0e1b\u0e2d\u0e35\u0e01 (death spiral)\n  const conditionMulti = (typeof getConditionMultiplier === 'function') ? getConditionMultiplier(saveData) : 1;\n  const statKeys = ['hp', 'attack', 'defense_flat', 'speed'];\n\n  const result = {};\n  statKeys.forEach((key) => {\n    const base1 = baseChar.stats[key];\n    const levelVal = getLevelValue(base1, level);\n    const statMulti = (key === 'hp') ? multiplier : (multiplier * conditionMulti);\n    result[key] = Math.round((levelVal * statMulti) * 100) / 100;\n  });\n\n  // \u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 (\u0e16\u0e49\u0e32\u0e21\u0e35\u0e23\u0e30\u0e1a\u0e1a\u0e42\u0e2b\u0e25\u0e14\u0e2d\u0e22\u0e39\u0e48) \u2014 % \u0e04\u0e34\u0e14\u0e08\u0e32\u0e01\u0e04\u0e48\u0e32\u0e10\u0e32\u0e19\u0e01\u0e48\u0e2d\u0e19\u0e43\u0e2a\u0e48\u0e02\u0e2d\u0e07, flat \u0e1a\u0e27\u0e01\u0e15\u0e23\u0e07\u0e46 \u0e17\u0e35\u0e2b\u0e25\u0e31\u0e07\n  // \u0e04\u0e48\u0e32\u0e1e\u0e37\u0e49\u0e19\u0e10\u0e32\u0e19\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25: \u0e17\u0e38\u0e01\u0e15\u0e31\u0e27 5% / \u0e41\u0e23\u0e07\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 200% \u0e22\u0e01\u0e40\u0e27\u0e49\u0e19\u0e15\u0e31\u0e27\u0e17\u0e35\u0e48\u0e21\u0e35 passive \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 (P07/P08) \u0e08\u0e30\u0e43\u0e0a\u0e49\u0e04\u0e48\u0e32\u0e02\u0e2d\u0e07 passive \u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e04\u0e48\u0e32\u0e40\u0e23\u0e34\u0e48\u0e21\u0e15\u0e49\u0e19\u0e19\u0e35\u0e49\u0e44\u0e1b\u0e40\u0e25\u0e22 (\u0e44\u0e21\u0e48\u0e1a\u0e27\u0e01\u0e0b\u0e49\u0e2d\u0e19\u0e01\u0e31\u0e19)\n  // \u0e41\u0e25\u0e49\u0e27\u0e02\u0e2d\u0e07\u0e17\u0e35\u0e48\u0e43\u0e2a\u0e48 (equipment) \u0e08\u0e30\u0e1a\u0e27\u0e01\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e08\u0e32\u0e01\u0e04\u0e48\u0e32\u0e1e\u0e37\u0e49\u0e19\u0e10\u0e32\u0e19\u0e19\u0e35\u0e49\u0e15\u0e23\u0e07\u0e46 \u0e40\u0e2a\u0e21\u0e2d\u0e44\u0e21\u0e48\u0e27\u0e48\u0e32\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e08\u0e30\u0e21\u0e35\u0e04\u0e48\u0e32\u0e1e\u0e37\u0e49\u0e19\u0e10\u0e32\u0e19\u0e40\u0e17\u0e48\u0e32\u0e44\u0e2b\u0e23\u0e48\u0e01\u0e47\u0e15\u0e32\u0e21\n  const CRIT_PASSIVE_BASE_OVERRIDE = {\n    P07: { rate: PASSIVE_PARAMS.P07.chance, damage: (PASSIVE_PARAMS.P07.multiplier - 1) * 100 },\n    P08: { rate: PASSIVE_PARAMS.P08.chance, damage: (PASSIVE_PARAMS.P08.multiplier - 1) * 100 }\n  };\n  const critBase = CRIT_PASSIVE_BASE_OVERRIDE[baseChar.passive] || { rate: 5, damage: 200 };\n\n  if (typeof equipmentGetCharacterBonuses === 'function' && baseChar.id) {\n    const eq = equipmentGetCharacterBonuses(baseChar.id);\n    result.hp = Math.round((result.hp * (1 + eq.hp_percent / 100) + eq.hp_flat) * 100) / 100;\n    result.attack = Math.round((result.attack * (1 + eq.atk_percent / 100) + eq.atk_flat) * 100) / 100;\n    result.defense_flat = Math.round((result.defense_flat * (1 + eq.def_percent / 100) + eq.def_flat) * 100) / 100;\n    result.speed = Math.round((result.speed * (1 + eq.spd_percent / 100) + eq.spd_flat) * 100) / 100;\n    result.resist = Math.round(eq.resist_percent * 10) / 10;\n    result.crit_rate = Math.round((critBase.rate + eq.crit_rate) * 10) / 10;\n    result.crit_damage = Math.round((critBase.damage + eq.crit_damage) * 10) / 10;\n    result.evasion = Math.round(eq.evasion * 10) / 10;\n  } else {\n    result.resist = 0; result.crit_rate = critBase.rate; result.crit_damage = critBase.damage; result.evasion = 0;\n  }\n  result.can_attack = true; // \u0e2a\u0e32\u0e22 support \u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49\u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e41\u0e23\u0e01\u0e40\u0e2a\u0e21\u0e2d\u0e41\u0e25\u0e49\u0e27 \u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b\n\n  return result;\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = {\n    LEVEL_STEP_PERCENT,\n    DUPE_LEVEL_COMPOUND_RATE,\n    CLASS_UPGRADE_MULTIPLIER,\n    getLevelValue,\n    getClassDupeMultiplier,\n    getMaxLevel,\n    BASE_EXP_TABLE,\n    GRADE_EXP_MULTIPLIER,\n    getExpRequired,\n    calculateCharacterStats,\n    getClassUpgradeCost,\n    crewUpgradeClass\n  };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: equipment_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e25\u0e2d\u0e08\u0e34\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 \u2014 \u0e2a\u0e38\u0e48\u0e21\u0e04\u0e48\u0e32, \u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48, \u0e2d\u0e31\u0e1e\u0e40\u0e25\u0e40\u0e27\u0e25 (\u0e1b\u0e49\u0e2d\u0e19\u0e02\u0e2d\u0e07\u0e0b\u0e49\u0e33), \u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 (\u0e43\u0e0a\u0e49\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a)\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_equipment.js, player_save_template.js, crew_system.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d\n// ==========================================\n\nfunction equipmentEnsureDefaults() {\n  if (!playerState.equipment_inventory) playerState.equipment_inventory = [];\n  Object.keys(playerState.crew).forEach(id => {\n    if (!playerState.crew[id].equipped) {\n      playerState.crew[id].equipped = { weapon: null, armor: null, accessory: null };\n    }\n  });\n}\n\nfunction equipmentGenId() {\n  return \"eq_\" + Date.now() + \"_\" + Math.floor(Math.random() * 100000);\n}\n\nfunction equipmentRollStat(statDef) {\n  const raw = statDef.min + Math.random() * (statDef.max - statDef.min);\n  return Math.round(raw * 10) / 10;\n}\n\n// \u0e2a\u0e23\u0e49\u0e32\u0e07\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e0a\u0e34\u0e49\u0e19\u0e43\u0e2b\u0e21\u0e48 (typeKey \u0e40\u0e0a\u0e48\u0e19 \"sword\", star 1-3) \u0e41\u0e25\u0e49\u0e27\u0e40\u0e01\u0e47\u0e1a\u0e40\u0e02\u0e49\u0e32\u0e04\u0e25\u0e31\u0e07 \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32 instance \u0e17\u0e35\u0e48\u0e2a\u0e23\u0e49\u0e32\u0e07\nfunction equipmentCreateNew(typeKey, star) {\n  equipmentEnsureDefaults();\n  const typeDef = EQUIPMENT_TYPES[typeKey];\n  if (!typeDef) return null;\n\n  const statDefs = typeDef.stat_defs[star];\n  const rolls = statDefs.map(sd => ({\n    stat: sd.stat,\n    kind: sd.kind,\n    value: equipmentRollStat(sd)\n  }));\n\n  const instance = {\n    id: equipmentGenId(),\n    type_key: typeKey,\n    star: star,\n    level: 1,\n    level_progress: 0,\n    rolls: rolls\n  };\n  playerState.equipment_inventory.push(instance);\n  playerSave();\n  return instance;\n}\n\nfunction equipmentGetInstance(instanceId) {\n  equipmentEnsureDefaults();\n  return playerState.equipment_inventory.find(e => e.id === instanceId) || null;\n}\n\nfunction equipmentGetName(instance) {\n  if (!instance) return \"\";\n  return EQUIPMENT_TYPES[instance.type_key].names[instance.star];\n}\n\nfunction equipmentGetLevelInfo(instance) {\n  return EQUIPMENT_LEVELS.find(l => l.level === instance.level) || EQUIPMENT_LEVELS[0];\n}\n\n// \u0e04\u0e48\u0e32\u0e08\u0e23\u0e34\u0e07\u0e02\u0e2d\u0e07\u0e41\u0e15\u0e48\u0e25\u0e30 roll \u0e2b\u0e25\u0e31\u0e07\u0e04\u0e39\u0e13 Level multiplier \u0e41\u0e25\u0e49\u0e27 (\u0e1b\u0e31\u0e14\u0e17\u0e28\u0e19\u0e34\u0e22\u0e21 1 \u0e15\u0e33\u0e41\u0e2b\u0e19\u0e48\u0e07)\nfunction equipmentGetEffectiveRolls(instance) {\n  const levelInfo = equipmentGetLevelInfo(instance);\n  return instance.rolls.map(r => ({\n    ...r,\n    effective_value: Math.round(r.value * levelInfo.multiplier * 10) / 10\n  }));\n}\n\n// ------------------------------------------\n// \u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 / \u0e16\u0e2d\u0e14\n// ------------------------------------------\n\nfunction equipmentEquip(charId, instanceId) {\n  equipmentEnsureDefaults();\n  const instance = equipmentGetInstance(instanceId);\n  if (!instance) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e0a\u0e34\u0e49\u0e19\u0e19\u0e35\u0e49\" };\n  const typeDef = EQUIPMENT_TYPES[instance.type_key];\n\n  if (typeDef.class_lock) {\n    const baseChar = crewGetBaseCharData(charId);\n    if (baseChar.role !== typeDef.class_lock) {\n      return { success: false, message: `\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e19\u0e35\u0e49\u0e43\u0e2a\u0e48\u0e44\u0e14\u0e49\u0e40\u0e09\u0e1e\u0e32\u0e30\u0e2a\u0e32\u0e22 ${typeDef.class_lock} \u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19` };\n    }\n  }\n  // \u0e01\u0e31\u0e19\u0e02\u0e2d\u0e07\u0e0a\u0e34\u0e49\u0e19\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e43\u0e2a\u0e48\u0e0b\u0e49\u0e33 2 \u0e15\u0e31\u0e27\n  const wornByOther = Object.keys(playerState.crew).find(id => {\n    const eq = playerState.crew[id].equipped;\n    return eq && (eq.weapon === instanceId || eq.armor === instanceId || eq.accessory === instanceId);\n  });\n  if (wornByOther) {\n    playerState.crew[wornByOther].equipped[typeDef.slot] = null;\n  }\n\n  if (!playerState.crew[charId].equipped) playerState.crew[charId].equipped = { weapon: null, armor: null, accessory: null };\n  playerState.crew[charId].equipped[typeDef.slot] = instanceId;\n  playerSave();\n  return { success: true, message: `\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 ${equipmentGetName(instance)} \u0e41\u0e25\u0e49\u0e27` };\n}\n\nfunction equipmentUnequip(charId, slot) {\n  equipmentEnsureDefaults();\n  if (!playerState.crew[charId] || !playerState.crew[charId].equipped) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e19\u0e35\u0e49\" };\n  playerState.crew[charId].equipped[slot] = null;\n  playerSave();\n  return { success: true, message: \"\u0e16\u0e2d\u0e14\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e41\u0e25\u0e49\u0e27\" };\n}\n\n// ------------------------------------------\n// \u0e2d\u0e31\u0e1e\u0e40\u0e25\u0e40\u0e27\u0e25 (\u0e1b\u0e49\u0e2d\u0e19\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2b\u0e21\u0e27\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e49\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a) \u2014 \u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e44\u0e14\u0e49\u0e15\u0e48\u0e2d\u0e0a\u0e34\u0e49\u0e19\u0e02\u0e36\u0e49\u0e19\u0e01\u0e31\u0e1a\u0e14\u0e32\u0e27\u0e02\u0e2d\u0e07\u0e02\u0e2d\u0e07\u0e17\u0e35\u0e48\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e17\u0e35\u0e22\u0e1a\u0e01\u0e31\u0e1a\u0e14\u0e32\u0e27\u0e02\u0e2d\u0e07\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22:\n// \u0e14\u0e32\u0e27\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19 = \u0e40\u0e15\u0e47\u0e21 1 \u0e40\u0e25\u0e40\u0e27\u0e25/\u0e0a\u0e34\u0e49\u0e19, \u0e1b\u0e49\u0e2d\u0e19\u0e02\u0e2d\u0e07\u0e14\u0e32\u0e27\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 1 \u0e02\u0e31\u0e49\u0e19 = \u0e04\u0e23\u0e36\u0e48\u0e07\u0e40\u0e14\u0e35\u0e22\u0e27 (50% \u0e15\u0e49\u0e2d\u0e07 2 \u0e0a\u0e34\u0e49\u0e19\u0e16\u0e36\u0e07\u0e08\u0e30\u0e44\u0e14\u0e49 1 \u0e40\u0e25\u0e40\u0e27\u0e25), \u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 2 \u0e02\u0e31\u0e49\u0e19 = 25% (\u0e15\u0e49\u0e2d\u0e07 4 \u0e0a\u0e34\u0e49\u0e19)\n// \u0e2a\u0e30\u0e2a\u0e21\u0e40\u0e1b\u0e47\u0e19 level_progress (0-1) \u0e01\u0e48\u0e2d\u0e19 \u0e1e\u0e2d\u0e04\u0e23\u0e1a 1 \u0e04\u0e48\u0e2d\u0e22\u0e41\u0e1b\u0e25\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e40\u0e25\u0e40\u0e27\u0e25\u0e08\u0e23\u0e34\u0e07 (\u0e1b\u0e49\u0e2d\u0e19\u0e02\u0e2d\u0e07\u0e14\u0e32\u0e27\u0e2a\u0e39\u0e07\u0e01\u0e27\u0e48\u0e32\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22 \u0e44\u0e14\u0e49\u0e41\u0e04\u0e48\u0e40\u0e15\u0e47\u0e21 1 \u0e40\u0e25\u0e40\u0e27\u0e25/\u0e0a\u0e34\u0e49\u0e19 \u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e40\u0e01\u0e34\u0e19)\n// ------------------------------------------\n\nfunction equipmentLevelUp(targetInstanceId, materialInstanceId) {\n  equipmentEnsureDefaults();\n  const target = equipmentGetInstance(targetInstanceId);\n  const material = equipmentGetInstance(materialInstanceId);\n  if (!target || !material) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\" };\n  if (target.id === material.id) return { success: false, message: \"\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e0a\u0e34\u0e49\u0e19\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\" };\n  // \u0e2d\u0e19\u0e38\u0e0d\u0e32\u0e15\u0e43\u0e2b\u0e49\u0e1b\u0e49\u0e2d\u0e19\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c \"\u0e2b\u0e21\u0e27\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\" (\u0e2d\u0e32\u0e27\u0e38\u0e18\u0e1b\u0e49\u0e2d\u0e19\u0e2d\u0e32\u0e27\u0e38\u0e18 / \u0e40\u0e01\u0e23\u0e32\u0e30\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e01\u0e23\u0e32\u0e30 / \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a)\n  // \u0e44\u0e21\u0e48\u0e08\u0e33\u0e40\u0e1b\u0e47\u0e19\u0e15\u0e49\u0e2d\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e0a\u0e19\u0e34\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e2b\u0e23\u0e37\u0e2d\u0e14\u0e32\u0e27\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b (\u0e40\u0e0a\u0e48\u0e19 \u0e40\u0e2d\u0e32\u0e02\u0e27\u0e32\u0e19\u0e44\u0e1b\u0e1b\u0e49\u0e2d\u0e19\u0e14\u0e32\u0e1a\u0e44\u0e14\u0e49 \u0e44\u0e21\u0e48\u0e27\u0e48\u0e32\u0e14\u0e32\u0e27\u0e08\u0e30\u0e15\u0e48\u0e32\u0e07\u0e01\u0e31\u0e19\u0e41\u0e04\u0e48\u0e44\u0e2b\u0e19)\n  const targetSlot = EQUIPMENT_TYPES[target.type_key].slot;\n  const materialSlot = EQUIPMENT_TYPES[material.type_key].slot;\n  if (targetSlot !== materialSlot) {\n    return { success: false, message: \"\u0e15\u0e49\u0e2d\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2b\u0e21\u0e27\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19 (\u0e2d\u0e32\u0e27\u0e38\u0e18\u0e1b\u0e49\u0e2d\u0e19\u0e2d\u0e32\u0e27\u0e38\u0e18 / \u0e40\u0e01\u0e23\u0e32\u0e30\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e01\u0e23\u0e32\u0e30 / \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a)\" };\n  }\n  if (target.level >= 5) return { success: false, message: \"\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e19\u0e35\u0e49 Level 5 MAX \u0e41\u0e25\u0e49\u0e27\" };\n  // \u0e40\u0e0a\u0e47\u0e04\u0e27\u0e48\u0e32\u0e02\u0e2d\u0e07\u0e17\u0e35\u0e48\u0e40\u0e2d\u0e32\u0e21\u0e32\u0e1b\u0e49\u0e2d\u0e19\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e16\u0e39\u0e01\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48\n  const wornBy = Object.keys(playerState.crew).find(id => {\n    const eq = playerState.crew[id].equipped;\n    return eq && (eq.weapon === materialInstanceId || eq.armor === materialInstanceId || eq.accessory === materialInstanceId);\n  });\n  if (wornBy) return { success: false, message: \"\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e08\u0e30\u0e1b\u0e49\u0e2d\u0e19\u0e01\u0e33\u0e25\u0e31\u0e07\u0e16\u0e39\u0e01\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48 \u0e16\u0e2d\u0e14\u0e2d\u0e2d\u0e01\u0e01\u0e48\u0e2d\u0e19\" };\n\n  // \u0e14\u0e32\u0e27\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22\u0e01\u0e35\u0e48\u0e02\u0e31\u0e49\u0e19 \u0e22\u0e34\u0e48\u0e07\u0e15\u0e48\u0e33\u0e22\u0e34\u0e48\u0e07\u0e44\u0e14\u0e49\u0e04\u0e48\u0e32\u0e19\u0e49\u0e2d\u0e22\u0e25\u0e07\u0e04\u0e23\u0e36\u0e48\u0e07\u0e2b\u0e19\u0e36\u0e48\u0e07\u0e15\u0e48\u0e2d\u0e02\u0e31\u0e49\u0e19 (\u0e14\u0e32\u0e27\u0e2a\u0e39\u0e07\u0e01\u0e27\u0e48\u0e32\u0e2b\u0e23\u0e37\u0e2d\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19 = \u0e40\u0e15\u0e47\u0e21 1 \u0e40\u0e25\u0e40\u0e27\u0e25\u0e40\u0e2a\u0e21\u0e2d \u0e44\u0e21\u0e48\u0e21\u0e35\u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e40\u0e01\u0e34\u0e19)\n  const starGap = target.star - material.star;\n  const fraction = Math.min(1, Math.pow(0.5, starGap));\n\n  if (typeof target.level_progress !== 'number') target.level_progress = 0;\n  target.level_progress += fraction;\n\n  let levelsGained = 0;\n  while (target.level_progress >= 1 && target.level < 5) {\n    target.level_progress -= 1;\n    target.level += 1;\n    levelsGained += 1;\n  }\n  if (target.level >= 5) target.level_progress = 0; // \u0e40\u0e15\u0e47\u0e21 MAX \u0e41\u0e25\u0e49\u0e27 \u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e2a\u0e30\u0e2a\u0e21\u0e15\u0e48\u0e2d\u0e43\u0e2b\u0e49\u0e14\u0e39\u0e23\u0e01\n\n  const idx = playerState.equipment_inventory.findIndex(e => e.id === materialInstanceId);\n  if (idx > -1) playerState.equipment_inventory.splice(idx, 1);\n\n  playerSave();\n\n  if (levelsGained > 0) {\n    return { success: true, message: `\u0e2d\u0e31\u0e1e\u0e40\u0e1b\u0e47\u0e19 Level ${target.level}${target.level === 5 ? ' MAX' : ''} \u0e41\u0e25\u0e49\u0e27`, levelsGained };\n  }\n  const pct = Math.round(target.level_progress * 100);\n  return { success: true, message: `\u0e2a\u0e30\u0e2a\u0e21\u0e04\u0e27\u0e32\u0e21\u0e04\u0e37\u0e1a\u0e2b\u0e19\u0e49\u0e32\u0e44\u0e1b\u0e22\u0e31\u0e07\u0e40\u0e25\u0e40\u0e27\u0e25\u0e16\u0e31\u0e14\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27 ${pct}% (\u0e02\u0e2d\u0e07\u0e14\u0e32\u0e27\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32\u0e43\u0e2b\u0e49\u0e04\u0e48\u0e32\u0e19\u0e49\u0e2d\u0e22\u0e01\u0e27\u0e48\u0e32 \u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e2d\u0e35\u0e01\u0e08\u0e30\u0e04\u0e23\u0e1a)`, levelsGained: 0 };\n}\n\n// ------------------------------------------\n// \u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 (\u0e15\u0e49\u0e2d\u0e07 Level 5 MAX \u0e01\u0e48\u0e2d\u0e19 \u0e43\u0e0a\u0e49\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a)\n// ------------------------------------------\n\nfunction equipmentUpgradeStar(instanceId) {\n  equipmentEnsureDefaults();\n  const instance = equipmentGetInstance(instanceId);\n  if (!instance) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\" };\n  if (instance.star >= 3) return { success: false, message: \"\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e19\u0e35\u0e49\u0e2d\u0e22\u0e39\u0e48\u0e14\u0e32\u0e27\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e41\u0e25\u0e49\u0e27\" };\n  if (instance.level < 5) return { success: false, message: \"\u0e15\u0e49\u0e2d\u0e07\u0e2d\u0e31\u0e1e\u0e40\u0e1b\u0e47\u0e19 Level 5 MAX \u0e01\u0e48\u0e2d\u0e19\u0e16\u0e36\u0e07\u0e08\u0e30\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27\u0e44\u0e14\u0e49\" };\n\n  const nextStar = instance.star + 1;\n  const recipe = EQUIPMENT_UPGRADE_RECIPES[instance.type_key][nextStar];\n  if (!playerState.inventory.equipment_materials) playerState.inventory.equipment_materials = {};\n\n  const missing = recipe.find(req => {\n    const have = playerState.inventory.equipment_materials[req.item_id] || 0;\n    return have < req.qty;\n  });\n  if (missing) {\n    const have = playerState.inventory.equipment_materials[missing.item_id] || 0;\n    return { success: false, message: `${EQUIPMENT_MATERIALS[missing.item_id].name}\u0e44\u0e21\u0e48\u0e1e\u0e2d (\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23 ${missing.qty} \u0e21\u0e35\u0e2d\u0e22\u0e39\u0e48 ${have})` };\n  }\n\n  recipe.forEach(req => {\n    playerState.inventory.equipment_materials[req.item_id] -= req.qty;\n  });\n\n  const typeDef = EQUIPMENT_TYPES[instance.type_key];\n  const statDefs = typeDef.stat_defs[nextStar];\n  instance.star = nextStar;\n  instance.level = 1;\n  instance.level_progress = 0;\n  instance.rolls = statDefs.map(sd => ({\n    stat: sd.stat,\n    kind: sd.kind,\n    value: equipmentRollStat(sd)\n  }));\n\n  playerSave();\n  return { success: true, message: `\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27\u0e40\u0e1b\u0e47\u0e19 ${nextStar} \u0e14\u0e32\u0e27 \u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08! (${equipmentGetName(instance)})` };\n}\n\n// ------------------------------------------\n// \u0e23\u0e27\u0e21\u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 (\u0e43\u0e0a\u0e49\u0e43\u0e19 progression_system.js)\n// ------------------------------------------\n\nfunction equipmentGetCharacterBonuses(charId) {\n  const bonuses = {\n    atk_percent: 0, atk_flat: 0,\n    def_percent: 0, def_flat: 0,\n    hp_percent: 0, hp_flat: 0,\n    spd_percent: 0, spd_flat: 0,\n    resist_percent: 0,\n    crit_rate: 0, crit_damage: 0, evasion: 0\n  };\n  const charData = playerState.crew[charId];\n  if (!charData || !charData.equipped) return bonuses;\n\n  ['weapon', 'armor', 'accessory'].forEach(slot => {\n    const instanceId = charData.equipped[slot];\n    if (!instanceId) return;\n    const instance = equipmentGetInstance(instanceId);\n    if (!instance) return;\n\n    equipmentGetEffectiveRolls(instance).forEach(r => {\n      const key = r.stat + (r.kind === \"percent\" ? \"_percent\" : \"_flat\");\n      if (bonuses[key] !== undefined) {\n        bonuses[key] += r.effective_value;\n      } else if (r.stat === \"resist\") {\n        bonuses.resist_percent += r.effective_value;\n      } else if ([\"crit_rate\", \"crit_damage\", \"evasion\"].includes(r.stat)) {\n        bonuses[r.stat] += r.effective_value;\n      }\n    });\n  });\n\n  return bonuses;\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = {\n    equipmentEnsureDefaults, equipmentCreateNew, equipmentGetInstance, equipmentGetName,\n    equipmentGetLevelInfo, equipmentGetEffectiveRolls, equipmentEquip, equipmentUnequip,\n    equipmentLevelUp, equipmentUpgradeStar, equipmentGetCharacterBonuses\n  };\n}\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: combat_power_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e04\u0e33\u0e19\u0e27\u0e13 \"\u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\" (Combat Power) \u2014 \u0e04\u0e33\u0e19\u0e27\u0e13\u0e2a\u0e14\u0e08\u0e32\u0e01\u0e17\u0e35\u0e21\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19\u0e40\u0e2a\u0e21\u0e2d \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e40\u0e01\u0e47\u0e1a\u0e04\u0e48\u0e32\u0e25\u0e07 save\n// (\u0e40\u0e1e\u0e23\u0e32\u0e30\u0e02\u0e36\u0e49\u0e19\u0e01\u0e31\u0e1a\u0e40\u0e25\u0e40\u0e27\u0e25/\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33/\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e40\u0e1b\u0e25\u0e35\u0e48\u0e22\u0e19\u0e44\u0e14\u0e49\u0e15\u0e25\u0e2d\u0e14 \u0e04\u0e33\u0e19\u0e27\u0e13\u0e2a\u0e14\u0e41\u0e21\u0e48\u0e19\u0e22\u0e33\u0e01\u0e27\u0e48\u0e32\u0e40\u0e01\u0e47\u0e1a\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e2d\u0e32\u0e08\u0e44\u0e21\u0e48\u0e2d\u0e31\u0e1e\u0e40\u0e14\u0e17)\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_combat_power.js, crew_system.js, progression_system.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d\n// ==========================================\n\n// \u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 1 \u0e15\u0e31\u0e27 \u0e15\u0e32\u0e21\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19 (\u0e23\u0e27\u0e21\u0e40\u0e25\u0e40\u0e27\u0e25/\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33/\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27)\nfunction calculateCharacterCombatPower(charId) {\n  const saveData = playerState.crew[charId];\n  if (!saveData) return 0;\n  const baseChar = crewGetBaseCharData(charId);\n  const realStats = calculateCharacterStats(baseChar, saveData);\n\n  const w = COMBAT_POWER_STAT_WEIGHTS;\n  const rawPower = (realStats.hp * w.hp) + (realStats.attack * w.attack) + (realStats.defense_flat * w.defense_flat) + (realStats.speed * w.speed);\n\n  const roleMulti = COMBAT_POWER_ROLE_MULTIPLIER[baseChar.role] || 1;\n  return Math.round(rawPower * roleMulti);\n}\n\n// \u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e23\u0e27\u0e21\u0e02\u0e2d\u0e07\u0e17\u0e35\u0e21 5 \u0e15\u0e33\u0e41\u0e2b\u0e19\u0e48\u0e07\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19 (\u0e0a\u0e48\u0e2d\u0e07\u0e27\u0e48\u0e32\u0e07\u0e19\u0e31\u0e1a\u0e40\u0e1b\u0e47\u0e19 0)\nfunction calculateSquadCombatPower() {\n  let total = 0;\n  for (let i = 0; i < 5; i++) {\n    const charId = playerState.squad[i];\n    if (charId && playerState.crew[charId]) {\n      total += calculateCharacterCombatPower(charId);\n    }\n  }\n  return total;\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { calculateCharacterCombatPower, calculateSquadCombatPower };\n}\n\n\n// ===== PVP / \u0e2a\u0e39\u0e49\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e19 (\u0e1d\u0e31\u0e48\u0e07\u0e40\u0e0b\u0e34\u0e23\u0e4c\u0e1f\u0e40\u0e27\u0e2d\u0e23\u0e4c) =====\nfunction runPvpCombat(attackerSquadData, defenderSquadData, attackerPlayerState, defenderPlayerState) {\n  // equipmentGetCharacterBonuses() (\u0e40\u0e23\u0e35\u0e22\u0e01\u0e08\u0e32\u0e01 calculateCharacterStats) \u0e2d\u0e48\u0e32\u0e19 global \"playerState\" \u0e15\u0e23\u0e07\u0e46\n  // \u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e08\u0e30\u0e23\u0e31\u0e1a saveData \u0e17\u0e35\u0e48\u0e2a\u0e48\u0e07\u0e40\u0e02\u0e49\u0e32\u0e21\u0e32 \u2014 \u0e40\u0e1b\u0e47\u0e19 dependency \u0e17\u0e35\u0e48\u0e0b\u0e48\u0e2d\u0e19\u0e2d\u0e22\u0e39\u0e48\u0e43\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e01\u0e21\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a (\u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e17\u0e35\u0e48\u0e19\u0e35\u0e48\u0e41\u0e01\u0e49\u0e43\u0e2b\u0e21\u0e48)\n  // \u0e40\u0e0b\u0e34\u0e23\u0e4c\u0e1f\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e1b\u0e23\u0e30\u0e21\u0e27\u0e25\u0e1c\u0e25\u0e44\u0e14\u0e49\u0e2b\u0e25\u0e32\u0e22\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e01\u0e31\u0e19 \u0e15\u0e31\u0e27\u0e41\u0e1b\u0e23 global \u0e40\u0e14\u0e35\u0e48\u0e22\u0e27\u0e46 \u0e43\u0e0a\u0e49\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e1b\u0e01\u0e15\u0e34 \u0e08\u0e36\u0e07\u0e15\u0e49\u0e2d\u0e07\u0e2a\u0e25\u0e31\u0e1a\u0e04\u0e48\u0e32\u0e15\u0e23\u0e07\u0e19\u0e35\u0e49\u0e40\u0e2d\u0e07\n  // \u0e01\u0e48\u0e2d\u0e19\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e22\u0e39\u0e19\u0e34\u0e15\u0e41\u0e15\u0e48\u0e25\u0e30\u0e1d\u0e31\u0e48\u0e07 (\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22\u0e40\u0e1e\u0e23\u0e32\u0e30 JS \u0e40\u0e1b\u0e47\u0e19 single-thread \u0e41\u0e25\u0e30\u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e19\u0e35\u0e49\u0e17\u0e33\u0e07\u0e32\u0e19\u0e08\u0e1a\u0e43\u0e19\u0e17\u0e35\u0e40\u0e14\u0e35\u0e22\u0e27\u0e44\u0e21\u0e48\u0e2a\u0e25\u0e31\u0e1a\u0e01\u0e25\u0e32\u0e07)\n  let allUnits = [];\n  let stats = {};\n  let logs = [];\n\n  function getTeamName(side) { return side === 'player' ? '\u0e40\u0e23\u0e32' : '\u0e28\u0e31\u0e15\u0e23\u0e39'; }\n  function log(msg) { logs.push(msg); }\n\n  // 1. Initialize Units\n  playerState = attackerPlayerState;\n  attackerSquadData.forEach((entry, index) => {\n    if (!entry) return;\n    const id = entry.id;\n    const saveData = entry.saveData;\n    if (!id) return;\n\n    const baseChar = crewGetBaseCharData(id);\n    const scaledStats = calculateCharacterStats(baseChar, saveData);\n    let u = {\n      side: 'player',\n      side_id: 'player_' + index,\n      name: baseChar.name,\n      role: baseChar.role,\n      passive: baseChar.passive,\n      max_hp: scaledStats.hp,\n      hp: scaledStats.hp,\n      base_atk: scaledStats.attack,\n      base_def: scaledStats.defense_flat,\n      base_spd: scaledStats.speed,\n      atk: scaledStats.attack,\n      def: scaledStats.defense_flat,\n      spd: scaledStats.speed,\n      crit_rate: scaledStats.crit_rate || 0,\n      crit_damage: scaledStats.crit_damage || 0,\n      evasion: scaledStats.evasion || 0,\n      base_evasion: scaledStats.evasion || 0,\n      accuracy: 0,\n      resist: scaledStats.resist || 0,\n      unlock_attack: !!scaledStats.unlock_attack,\n      _stun: 0,\n      _silenced: 0,\n      _poison: 0,\n      _poison_source: null,\n      _p16_owner_turns: 0,\n      _p16_active: false\n    };\n    allUnits.push(u);\n    stats[u.side_id] = { name: u.name, side: u.side, dmg_dealt: 0, dmg_taken: 0, heal_given: 0, stun_count: 0, silence_count: 0, dodge_count: 0, dmg_prevented: 0, heal_proc_count: 0, heal_proc_total: 0, extra_turn_count: 0, elim_round: null };\n  });\n\n  playerState = defenderPlayerState;\n  defenderSquadData.forEach((entry, index) => {\n    if (!entry) return;\n    const id = entry.id;\n    const saveData = entry.saveData;\n    if (!id) return;\n\n    const baseChar = crewGetBaseCharData(id);\n    const scaledStats = calculateCharacterStats(baseChar, saveData);\n    let u = {\n      side: 'enemy',\n      side_id: 'enemy_' + index,\n      name: baseChar.name,\n      role: baseChar.role,\n      passive: baseChar.passive,\n      max_hp: scaledStats.hp,\n      hp: scaledStats.hp,\n      base_atk: scaledStats.attack,\n      base_def: scaledStats.defense_flat,\n      base_spd: scaledStats.speed,\n      atk: scaledStats.attack,\n      def: scaledStats.defense_flat,\n      spd: scaledStats.speed,\n      crit_rate: scaledStats.crit_rate || 0,\n      crit_damage: scaledStats.crit_damage || 0,\n      evasion: scaledStats.evasion || 0,\n      base_evasion: scaledStats.evasion || 0,\n      accuracy: 0,\n      resist: scaledStats.resist || 0,\n      unlock_attack: !!scaledStats.unlock_attack,\n      _stun: 0,\n      _silenced: 0,\n      _poison: 0,\n      _poison_source: null,\n      _p16_owner_turns: 0,\n      _p16_active: false\n    };\n    allUnits.push(u);\n    stats[u.side_id] = { name: u.name, side: u.side, dmg_dealt: 0, dmg_taken: 0, heal_given: 0, stun_count: 0, silence_count: 0, dodge_count: 0, dmg_prevented: 0, heal_proc_count: 0, heal_proc_total: 0, extra_turn_count: 0, elim_round: null };\n  });\n\n  function updateStats(u) {\n    let atkMulti = 1, defMulti = 1, spdMulti = 1;\n    let hasP17 = allUnits.some(x => x.side === u.side && x.hp > 0 && x.passive === 'P17' && !x._silenced);\n    if (hasP17) defMulti += PASSIVE_PARAMS.P17.def_bonus / 100;\n\n    let hasP19Enemy = allUnits.some(x => x.side !== u.side && x.hp > 0 && x.passive === 'P19' && !x._silenced);\n    if (hasP19Enemy) spdMulti -= PASSIVE_PARAMS.P19.spd_reduce / 100;\n\n    let hasP20Enemy = allUnits.some(x => x.side !== u.side && x.hp > 0 && x.passive === 'P20' && !x._silenced);\n    if (hasP20Enemy) atkMulti -= PASSIVE_PARAMS.P20.atk_reduce / 100;\n\n    if (u._p16_active) atkMulti += PASSIVE_PARAMS.P16.atk_bonus / 100;\n    if (u.passive === 'P04' && !u._silenced && u.hp < u.max_hp * 0.5) atkMulti += PASSIVE_PARAMS.P04.atk_bonus / 100;\n\n    u.atk = Math.max(1, u.base_atk * atkMulti);\n    u.def = Math.max(0, u.base_def * defMulti);\n    u.spd = Math.max(1, u.base_spd * spdMulti);\n\n    // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e1b\u0e23\u0e32\u0e14\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e27 (P26) \u2014 \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 \u0e04\u0e33\u0e19\u0e27\u0e13\u0e08\u0e32\u0e01 base_evasion \u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e01\u0e31\u0e19\u0e1a\u0e27\u0e01\u0e0b\u0e49\u0e33\n    let hasP26 = allUnits.some(x => x.side === u.side && x.hp > 0 && x.passive === 'P26' && !x._silenced);\n    u.evasion = u.base_evasion + (hasP26 ? PASSIVE_PARAMS.P26.evasion_bonus : 0);\n  }\n\n  // \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32\u0e25\u0e33\u0e14\u0e31\u0e1a\u0e15\u0e33\u0e41\u0e2b\u0e19\u0e48\u0e07\u0e0a\u0e48\u0e2d\u0e07 (0 = \u0e0a\u0e48\u0e2d\u0e07 1) \u0e08\u0e32\u0e01 side_id \u0e40\u0e0a\u0e48\u0e19 'player_2' \u0e2b\u0e23\u0e37\u0e2d 'enemy_1'\n  function getSlotIndex(u) {\n    return parseInt(u.side_id.split('_')[1], 10);\n  }\n\n  function getTargets(attacker, count = 1) {\n    let e = allUnits.filter(u => u.side !== attacker.side && u.hp > 0);\n    if (e.length === 0) return [];\n    let rnd = (arr) => arr[Math.floor(Math.random() * arr.length)];\n    let mainTgt = null;\n\n    // PVP: \u0e17\u0e31\u0e49\u0e07\u0e2a\u0e2d\u0e07\u0e1d\u0e31\u0e48\u0e07\u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e40\u0e25\u0e47\u0e07\u0e40\u0e1b\u0e49\u0e32\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e40\u0e2a\u0e21\u0e2d (\u0e41\u0e1a\u0e1a\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e1b\u0e01\u0e15\u0e34 - \u0e40\u0e25\u0e47\u0e07\u0e15\u0e32\u0e21\u0e2a\u0e32\u0e22 tank/fighter \u0e01\u0e48\u0e2d\u0e19)\n    // \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e41\u0e1a\u0e1a\u0e28\u0e31\u0e15\u0e23\u0e39 NPC (\u0e40\u0e25\u0e47\u0e07\u0e15\u0e32\u0e21\u0e25\u0e33\u0e14\u0e31\u0e1a\u0e0a\u0e48\u0e2d\u0e07) \u0e17\u0e35\u0e48\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a\u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a side==='enemy' \u2014 \u0e01\u0e15\u0e34\u0e01\u0e32\u0e19\u0e31\u0e49\u0e19\u0e2d\u0e2d\u0e01\u0e41\u0e1a\u0e1a\u0e21\u0e32\n    // \u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e21\u0e2d\u0e19\u0e2a\u0e40\u0e15\u0e2d\u0e23\u0e4c\u0e43\u0e19\u0e14\u0e48\u0e32\u0e19\u0e40\u0e01\u0e32\u0e30 (\u0e44\u0e21\u0e48\u0e2a\u0e21\u0e21\u0e32\u0e15\u0e23\u0e01\u0e31\u0e1a\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e42\u0e14\u0e22\u0e15\u0e31\u0e49\u0e07\u0e43\u0e08) \u0e40\u0e2d\u0e32\u0e21\u0e32\u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a PVP (\u0e04\u0e19\u0e2a\u0e39\u0e49\u0e04\u0e19) \u0e15\u0e23\u0e07\u0e46 \u0e08\u0e30\u0e17\u0e33\u0e43\u0e2b\u0e49\n    // \u0e1d\u0e31\u0e48\u0e07\u0e17\u0e35\u0e48\u0e44\u0e14\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e35\u0e22\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e1a\u0e0a\u0e31\u0e14\u0e40\u0e08\u0e19\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e44\u0e21\u0e48\u0e40\u0e1b\u0e47\u0e19\u0e18\u0e23\u0e23\u0e21 (\u0e17\u0e14\u0e2a\u0e2d\u0e1a\u0e41\u0e25\u0e49\u0e27\u0e1e\u0e1a\u0e08\u0e23\u0e34\u0e07: \u0e41\u0e21\u0e17\u0e0a\u0e4c\u0e01\u0e23\u0e30\u0e08\u0e01\u0e40\u0e07\u0e32\u0e17\u0e35\u0e21\u0e40\u0e2b\u0e21\u0e37\u0e2d\u0e19\u0e01\u0e31\u0e19\u0e17\u0e38\u0e01\n    // \u0e1b\u0e23\u0e30\u0e01\u0e32\u0e23 \u0e1d\u0e31\u0e48\u0e07 attacker \u0e0a\u0e19\u0e30 ~75-85% \u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e08\u0e30\u0e43\u0e01\u0e25\u0e49 50% \u2014 \u0e40\u0e1b\u0e47\u0e19\u0e08\u0e38\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e17\u0e35\u0e48\u0e15\u0e23\u0e23\u0e01\u0e30 PVP \u0e15\u0e48\u0e32\u0e07\u0e08\u0e32\u0e01 combat_engine.js\n    // \u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a\u0e42\u0e14\u0e22\u0e15\u0e31\u0e49\u0e07\u0e43\u0e08 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e04\u0e27\u0e32\u0e21\u0e1c\u0e34\u0e14\u0e1e\u0e25\u0e32\u0e14\u0e08\u0e32\u0e01\u0e01\u0e32\u0e23\u0e04\u0e31\u0e14\u0e25\u0e2d\u0e01)\n    let pools = { tank: [], fighter: [], assassin: [], ranger: [], support: [] };\n    e.forEach(x => pools[x.role].push(x));\n\n    if (attacker.role === 'assassin') mainTgt = rnd(e);\n    else if (attacker.role === 'ranger') {\n      let p1 = [...pools.tank, ...pools.fighter, ...pools.assassin];\n      if (p1.length > 0) mainTgt = rnd(p1);\n      else if (pools.support.length > 0) mainTgt = rnd(pools.support);\n      else if (pools.ranger.length > 0) mainTgt = rnd(pools.ranger);\n      else mainTgt = rnd(e);\n    } else {\n      if (pools.tank.length > 0) mainTgt = rnd(pools.tank);\n      else if (pools.fighter.length > 0) mainTgt = rnd(pools.fighter);\n      else if (pools.assassin.length > 0) mainTgt = rnd(pools.assassin);\n      else if (pools.ranger.length > 0) mainTgt = rnd(pools.ranger);\n      else mainTgt = rnd(pools.support);\n    }\n\n    if (!mainTgt) return [];\n    let tgts = [mainTgt];\n    if (count > 1) {\n      let others = e.filter(u => u.side_id !== mainTgt.side_id).sort(() => Math.random() - 0.5);\n      tgts.push(...others.slice(0, count - 1));\n    }\n    return tgts;\n  }\n\n  function dealDamage(target, dmg, source, round) {\n    target.hp -= dmg;\n    stats[source.side_id].dmg_dealt += dmg;\n    stats[target.side_id].dmg_taken += dmg;\n\n    if (target.hp > 0 && target.hp < target.max_hp * 0.5 && target.hp + dmg >= target.max_hp * 0.5) {\n      log(`${getTeamName(target.side)}:[${target.name}] HP \u0e1a\u0e32\u0e14\u0e40\u0e08\u0e47\u0e1a\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 50%!`);\n    }\n\n    if (target.hp > 0 && target.hp < target.max_hp * 0.25 && target.hp + dmg >= target.max_hp * 0.25) {\n      log(`${getTeamName(target.side)}:[${target.name}] HP \u0e27\u0e34\u0e01\u0e24\u0e15\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 25%!`);\n    }\n\n    if (target.hp <= 0) {\n      target.hp = 0;\n      log(`${getTeamName(target.side)}:[${target.name}] \u0e16\u0e39\u0e01\u0e01\u0e33\u0e08\u0e31\u0e14\u0e42\u0e14\u0e22 ${source.name}`);\n      stats[target.side_id].elim_round = round;\n\n      if (target.passive === 'P24' && !target._silenced) {\n        log(`${getTeamName(target.side)}:[${target.name}] \u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14`);\n        let aoeDmg = target.base_atk * (PASSIVE_PARAMS.P24.dmg_pct / 100);\n        let enemies = allUnits.filter(x => x.side !== target.side && x.hp > 0);\n        for (let e of enemies) {\n          let eEffDef = getEffectiveDefense(target, e);\n          let edmg = Math.max(1, aoeDmg - eEffDef);\n          if (e.passive === 'P10' && !e._silenced) {\n            let beforeReduce = edmg;\n            edmg = Math.max(1, edmg * (1 - (PASSIVE_PARAMS.P10.reduce_pct / 100)));\n            stats[e.side_id].dmg_prevented += Math.floor(beforeReduce - edmg);\n          }\n          edmg = applyDamageVariance(edmg);\n          edmg = Math.max(1, Math.floor(edmg));\n          let eHpAfter = Math.max(0, e.hp - edmg);\n          e.hp -= edmg;\n          stats[target.side_id].dmg_dealt += edmg;\n          stats[e.side_id].dmg_taken += edmg;\n          log(`- \u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e27\u0e32\u0e21\u0e40\u0e2a\u0e35\u0e22\u0e2b\u0e32\u0e22\u0e43\u0e2b\u0e49 ${e.name} ${edmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${Math.floor((eHpAfter / e.max_hp) * 100)}%HP) (\u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22)`);\n          if (e.hp <= 0) {\n            e.hp = 0;\n            log(`${getTeamName(e.side)}:[${e.name}] \u0e16\u0e39\u0e01\u0e01\u0e33\u0e08\u0e31\u0e14\u0e42\u0e14\u0e22\u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e02\u0e2d\u0e07 ${target.name}`);\n            stats[e.side_id].elim_round = round;\n          }\n        }\n      }\n    }\n  }\n\n  function healUnit(source, target, amt, doLog = true) {\n    if (target.hp <= 0) return 0;\n    let actualHeal = Math.min(amt, target.max_hp - target.hp);\n    target.hp += actualHeal;\n    stats[source.side_id].heal_given += actualHeal;\n    if (doLog && actualHeal > 0) log(`${getTeamName(source.side)}:[${source.name}] \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49 ${target.name} ${actualHeal} \u0e2b\u0e19\u0e48\u0e27\u0e22`);\n    return actualHeal;\n  }\n\n  // \u0e23\u0e27\u0e21\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e01\u0e32\u0e23\u0e2e\u0e35\u0e25/\u0e1a\u0e31\u0e1f\u0e40\u0e25\u0e37\u0e2d\u0e14\u0e2b\u0e25\u0e32\u0e22\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22\u0e43\u0e2b\u0e49\u0e40\u0e1b\u0e47\u0e19\u0e1a\u0e23\u0e23\u0e17\u0e31\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27 \u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e1a\u0e2d\u0e01\u0e40\u0e1b\u0e2d\u0e23\u0e4c\u0e40\u0e0b\u0e47\u0e19\u0e15\u0e4c\u0e40\u0e25\u0e37\u0e2d\u0e14\u0e17\u0e35\u0e48\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e02\u0e2d\u0e07\u0e41\u0e15\u0e48\u0e25\u0e30\u0e04\u0e19\n  // \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e43\u0e2b\u0e49\u0e1c\u0e39\u0e49\u0e43\u0e0a\u0e49\u0e42\u0e1b\u0e23\u0e41\u0e01\u0e23\u0e21\u0e2d\u0e48\u0e32\u0e19\u0e2b\u0e19\u0e49\u0e32\u0e08\u0e2d\u0e1b\u0e31\u0e14\u0e1f\u0e31\u0e07\u0e04\u0e23\u0e31\u0e49\u0e07\u0e40\u0e14\u0e35\u0e22\u0e27\u0e44\u0e14\u0e49\u0e04\u0e23\u0e1a\n  function healGroupAndLog(source, targets, amt, actionLabel) {\n    let parts = [];\n    let totalHealed = 0;\n    targets.forEach(t => {\n      let healed = healUnit(source, t, amt, false);\n      if (healed > 0) {\n        let pct = Math.floor((t.hp / t.max_hp) * 100);\n        parts.push(`${t.name} +${healed} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${pct}%HP)`);\n        totalHealed += healed;\n      }\n    });\n    if (parts.length > 0) {\n      log(`${getTeamName(source.side)}:[${source.name}] ${actionLabel} \u2014 ${parts.join(', ')}`);\n      stats[source.side_id].heal_proc_count++;\n      stats[source.side_id].heal_proc_total += totalHealed;\n    }\n  }\n\n  // \u0e2a\u0e38\u0e48\u0e21\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e14\u0e32\u0e40\u0e21\u0e08\u0e41\u0e1b\u0e23\u0e1c\u0e31\u0e19 \u0e1a\u0e27\u0e01\u0e25\u0e1a 15% \u0e08\u0e32\u0e01\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e04\u0e33\u0e19\u0e27\u0e13\u0e44\u0e14\u0e49 \u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e38\u0e01\u0e1b\u0e23\u0e30\u0e40\u0e20\u0e17\u0e44\u0e21\u0e48\u0e27\u0e48\u0e32\u0e08\u0e30\u0e21\u0e32\u0e08\u0e32\u0e01\u0e01\u0e32\u0e23\u0e42\u0e08\u0e21\u0e15\u0e35\u0e1b\u0e01\u0e15\u0e34\u0e2b\u0e23\u0e37\u0e2d passive \u0e43\u0e14\u0e01\u0e47\u0e15\u0e32\u0e21\n  function applyDamageVariance(dmg) {\n    const variance = 0.85 + Math.random() * 0.30; // \u0e2a\u0e38\u0e48\u0e21\u0e15\u0e48\u0e2d\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07\u0e23\u0e30\u0e2b\u0e27\u0e48\u0e32\u0e07 0.85 \u0e16\u0e36\u0e07 1.15\n    return dmg * variance;\n  }\n\n  // \u0e04\u0e33\u0e19\u0e27\u0e13\u0e04\u0e48\u0e32\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19\u0e17\u0e35\u0e48\u0e43\u0e0a\u0e49\u0e08\u0e23\u0e34\u0e07\u0e43\u0e19\u0e01\u0e32\u0e23\u0e2b\u0e31\u0e01\u0e14\u0e32\u0e40\u0e21\u0e08 \u0e01\u0e23\u0e13\u0e35\u0e44\u0e1f\u0e17\u0e4c\u0e40\u0e15\u0e2d\u0e23\u0e4c\u0e42\u0e08\u0e21\u0e15\u0e35\u0e41\u0e17\u0e07\u0e04\u0e4c \u0e43\u0e2b\u0e49\u0e17\u0e30\u0e25\u0e38\u0e40\u0e01\u0e23\u0e32\u0e30\u0e44\u0e1b 60% (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e04\u0e48\u0e32\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19\u0e41\u0e04\u0e48 40%)\n  function getEffectiveDefense(attackerUnit, targetUnit) {\n    if (attackerUnit.role === 'fighter' && targetUnit.role === 'tank') {\n      return targetUnit.def * 0.4;\n    }\n    return targetUnit.def;\n  }\n\n  function executeHit(attacker, initialTarget, isSilenced, dmgMultiplier, round) {\n    let actualTarget = initialTarget;\n    let tgtAllies = allUnits.filter(x => x.side === initialTarget.side && x.hp > 0 && x.passive === 'P12' && x.side_id !== initialTarget.side_id && !x._silenced);\n    if (tgtAllies.length > 0) {\n      let lowestAlly = [...tgtAllies].sort((a, b) => (a.hp / a.max_hp) - (b.hp / b.max_hp))[0];\n      if (Math.random() < PASSIVE_PARAMS.P12.chance / 100) {\n        log(`${getTeamName(lowestAlly.side)}:[${lowestAlly.name}] \u0e42\u0e25\u0e48\u0e21\u0e19\u0e38\u0e29\u0e22\u0e4c\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e41\u0e17\u0e19 ${initialTarget.name}`);\n        actualTarget = lowestAlly;\n        dmgMultiplier *= (PASSIVE_PARAMS.P12.receive_pct / 100);\n      }\n    }\n\n    if (actualTarget.passive === 'P11' && !actualTarget._silenced && Math.random() < PASSIVE_PARAMS.P11.chance / 100) {\n      stats[actualTarget.side_id].dodge_count++;\n      log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e01\u0e32\u0e23\u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49!`);\n      return;\n    }\n\n    // \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c (evasion \u0e02\u0e2d\u0e07\u0e1c\u0e39\u0e49\u0e42\u0e14\u0e19 - accuracy \u0e02\u0e2d\u0e07\u0e1c\u0e39\u0e49\u0e15\u0e35) \u2014 \u0e41\u0e22\u0e01\u0e08\u0e32\u0e01 P11 passive \u0e02\u0e49\u0e32\u0e07\u0e1a\u0e19 \u0e17\u0e33\u0e07\u0e32\u0e19\u0e04\u0e39\u0e48\u0e02\u0e19\u0e32\u0e19\n    const netEvasion = Math.max(0, (actualTarget.evasion || 0) - (attacker.accuracy || 0));\n    if (netEvasion > 0 && Math.random() * 100 < netEvasion) {\n      stats[actualTarget.side_id].dodge_count++;\n      log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e01\u0e32\u0e23\u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49!`);\n      return;\n    }\n\n    let isCrit = false, critMult = 1.0;\n    if (!isSilenced) {\n      // \u0e42\u0e25\u0e48\u0e15\u0e49\u0e32\u0e19\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 (P25) \u2014 \u0e16\u0e49\u0e32\u0e1d\u0e31\u0e48\u0e07\u0e15\u0e23\u0e07\u0e02\u0e49\u0e32\u0e21\u0e02\u0e2d\u0e07 attacker \u0e21\u0e35\u0e43\u0e04\u0e23\u0e16\u0e37\u0e2d P25 \u0e2d\u0e22\u0e39\u0e48 \u0e25\u0e14\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e41\u0e25\u0e30\u0e04\u0e27\u0e32\u0e21\u0e41\u0e23\u0e07\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e02\u0e2d\u0e07 attacker \u0e25\u0e07\n      let hasEnemyP25 = allUnits.some(x => x.side !== attacker.side && x.hp > 0 && x.passive === 'P25' && !x._silenced);\n      let critChanceReduce = hasEnemyP25 ? PASSIVE_PARAMS.P25.crit_chance_reduce : 0;\n      let critDmgReduce = hasEnemyP25 ? PASSIVE_PARAMS.P25.crit_dmg_reduce : 0;\n\n      // \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e23\u0e27\u0e21\u0e40\u0e1b\u0e47\u0e19\u0e04\u0e48\u0e32\u0e40\u0e14\u0e35\u0e22\u0e27 (\u0e1e\u0e37\u0e49\u0e19\u0e10\u0e32\u0e19/\u0e08\u0e32\u0e01 passive + \u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c) \u0e15\u0e23\u0e07\u0e01\u0e31\u0e1a\u0e15\u0e31\u0e27\u0e40\u0e01\u0e21\u0e2b\u0e25\u0e31\u0e01\n      if ((attacker.crit_rate || 0) > 0 && Math.random() * 100 < Math.max(0, attacker.crit_rate - critChanceReduce)) {\n        isCrit = true;\n        critMult = 1 + Math.max(0, (attacker.crit_damage || 0)) / 100 * (1 - critDmgReduce / 100);\n      }\n    }\n\n    let effDef = getEffectiveDefense(attacker, actualTarget);\n    // \u0e2a\u0e32\u0e22 support \u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49\u0e40\u0e2a\u0e21\u0e2d \u0e41\u0e15\u0e48\u0e14\u0e32\u0e40\u0e21\u0e08\u0e25\u0e14\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e15\u0e32\u0e21\u0e04\u0e48\u0e32 SUPPORT_ATTACK_DAMAGE_MULT (\u0e15\u0e23\u0e07\u0e01\u0e31\u0e1a\u0e15\u0e31\u0e27\u0e40\u0e01\u0e21\u0e2b\u0e25\u0e31\u0e01)\n    const roleDmgMult = attacker.role === 'support' ? SUPPORT_ATTACK_DAMAGE_MULT : 1;\n    let dmg = Math.max(1, (attacker.atk * critMult * dmgMultiplier * roleDmgMult) - effDef);\n    if (actualTarget.passive === 'P10' && !actualTarget._silenced) {\n      let beforeReduce = dmg;\n      dmg = Math.max(1, dmg * (1 - (PASSIVE_PARAMS.P10.reduce_pct / 100)));\n      stats[actualTarget.side_id].dmg_prevented += Math.floor(beforeReduce - dmg);\n    }\n    // \u0e15\u0e49\u0e32\u0e19\u0e17\u0e32\u0e19\u0e14\u0e32\u0e40\u0e21\u0e08\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c \u2014 \u0e41\u0e22\u0e01\u0e08\u0e32\u0e01 P10 passive \u0e02\u0e49\u0e32\u0e07\u0e1a\u0e19 \u0e17\u0e33\u0e07\u0e32\u0e19\u0e04\u0e39\u0e48\u0e02\u0e19\u0e32\u0e19\n    if ((actualTarget.resist || 0) > 0) {\n      let beforeResist = dmg;\n      dmg = Math.max(1, dmg * (1 - Math.min(90, actualTarget.resist) / 100));\n      stats[actualTarget.side_id].dmg_prevented += Math.floor(beforeResist - dmg);\n    }\n    dmg = applyDamageVariance(dmg);\n    dmg = Math.max(1, Math.floor(dmg));\n\n    let hpAfter = Math.max(0, actualTarget.hp - dmg);\n    let pctHP = Math.floor((hpAfter / actualTarget.max_hp) * 100);\n    let critText = isCrit ? ` \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25!` : ``;\n    log(`${getTeamName(attacker.side)}:[${attacker.name}] \u0e42\u0e08\u0e21\u0e15\u0e35 ${getTeamName(actualTarget.side)}:[${actualTarget.name}] ${dmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${pctHP}%HP)${critText}`);\n\n    dealDamage(actualTarget, dmg, attacker, round);\n\n    if (!isSilenced && attacker.passive === 'P06' && attacker.hp > 0) {\n      let h = Math.floor(dmg * (PASSIVE_PARAMS.P06.lifesteal_pct / 100));\n      if (h > 0) healUnit(attacker, attacker, h, false);\n    }\n\n    if (actualTarget.hp > 0 && !isSilenced) {\n      if (attacker.passive === 'P21' && Math.random() < PASSIVE_PARAMS.P21.chance / 100) {\n        actualTarget._stun = Math.max(actualTarget._stun, PASSIVE_PARAMS.P21.stun_duration);\n        stats[attacker.side_id].stun_count++;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e34\u0e14\u0e2a\u0e16\u0e32\u0e19\u0e30\u0e2a\u0e15\u0e31\u0e49\u0e19!`);\n      }\n      if (attacker.passive === 'P22' && Math.random() < PASSIVE_PARAMS.P22.chance / 100) {\n        actualTarget._stun = Math.max(actualTarget._stun, PASSIVE_PARAMS.P22.stun_duration);\n        stats[attacker.side_id].stun_count++;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e34\u0e14\u0e2a\u0e16\u0e32\u0e19\u0e30\u0e2a\u0e15\u0e31\u0e49\u0e19\u0e2b\u0e19\u0e31\u0e01!`);\n      }\n      if (attacker.passive === 'P23' && Math.random() < PASSIVE_PARAMS.P23.chance / 100) {\n        actualTarget._silenced = Math.max(actualTarget._silenced, PASSIVE_PARAMS.P23.silence_duration);\n        stats[attacker.side_id].silence_count++;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e16\u0e39\u0e01\u0e1b\u0e34\u0e14 passive!`);\n      }\n      if (attacker.passive === 'P27' && Math.random() < PASSIVE_PARAMS.P27.chance / 100) {\n        actualTarget._poison = Math.max(actualTarget._poison, PASSIVE_PARAMS.P27.duration);\n        actualTarget._poison_source = attacker;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e34\u0e14\u0e1e\u0e34\u0e29\u0e01\u0e31\u0e14\u0e01\u0e23\u0e48\u0e2d\u0e19!`);\n      }\n    }\n\n    if (actualTarget.hp > 0 && actualTarget.passive === 'P09' && !actualTarget._silenced && Math.random() < PASSIVE_PARAMS.P09.chance / 100) {\n      log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e35\u0e42\u0e15\u0e49\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e2a\u0e27\u0e19\u0e01\u0e25\u0e31\u0e1a ${attacker.name}`);\n      let cAtk = actualTarget.atk * (PASSIVE_PARAMS.P09.dmg_pct / 100);\n      let cEffDef = getEffectiveDefense(actualTarget, attacker);\n      let cDmg = Math.max(1, cAtk - cEffDef);\n      if (attacker.passive === 'P10' && !attacker._silenced) {\n        let beforeReduce = cDmg;\n        cDmg = Math.max(1, cDmg * (1 - (PASSIVE_PARAMS.P10.reduce_pct / 100)));\n        stats[attacker.side_id].dmg_prevented += Math.floor(beforeReduce - cDmg);\n      }\n      cDmg = applyDamageVariance(cDmg);\n      cDmg = Math.max(1, Math.floor(cDmg));\n      let cHpAfter = Math.max(0, attacker.hp - cDmg);\n      log(`- \u0e42\u0e08\u0e21\u0e15\u0e35 ${getTeamName(attacker.side)}:[${attacker.name}] ${cDmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${Math.floor((cHpAfter / attacker.max_hp) * 100)}%HP) [\u0e2a\u0e27\u0e19\u0e01\u0e25\u0e31\u0e1a]`);\n      dealDamage(attacker, cDmg, actualTarget, round);\n    }\n  }\n\n  function performAttackAction(attacker, isSilenced, forceSingle, round) {\n    if (attacker.hp <= 0) return;\n    let mainTgtArray = getTargets(attacker, 1);\n    if (mainTgtArray.length === 0) return;\n    let mainTarget = mainTgtArray[0];\n\n    let targets = [mainTarget];\n    let isAoE = false, aoeDmgPct = 1.0;\n\n    if (!isSilenced && !forceSingle) {\n      if (attacker.passive === 'P01') { isAoE = true; aoeDmgPct = PASSIVE_PARAMS.P01.dmg_pct / 100; targets = getTargets(attacker, PASSIVE_PARAMS.P01.targets); }\n      else if (attacker.passive === 'P02') { isAoE = true; aoeDmgPct = PASSIVE_PARAMS.P02.dmg_pct / 100; targets = getTargets(attacker, PASSIVE_PARAMS.P02.targets); }\n    }\n\n    targets.forEach(tgt => { if (attacker.hp > 0 && tgt.hp > 0) executeHit(attacker, tgt, isSilenced, isAoE ? aoeDmgPct : 1.0, round); });\n\n    if (!isSilenced && !forceSingle && attacker.passive === 'P03' && attacker.hp > 0 && mainTarget.hp > 0 && Math.random() < PASSIVE_PARAMS.P03.chance / 100) {\n      log(`${getTeamName(attacker.side)}:[${attacker.name}] \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\u0e17\u0e33\u0e07\u0e32\u0e19!`);\n      executeHit(attacker, mainTarget, isSilenced, PASSIVE_PARAMS.P03.dmg_pct / 100, round);\n    }\n  }\n\n  let isCombatActive = true;\n  let round = 1;\n\n  log(`\u0e40\u0e23\u0e34\u0e48\u0e21\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49!`);\n\n  while (isCombatActive && round <= 60) {\n    log(`--- \u0e23\u0e2d\u0e1a\u0e17\u0e35\u0e48 ${round} ---`);\n    allUnits.forEach(u => updateStats(u));\n    let turnOrder = [...allUnits].filter(u => u.hp > 0);\n    turnOrder.forEach(u => {\n      u._temp_spd = u.spd;\n      if (u.passive === 'P05' && !u._silenced && Math.random() < PASSIVE_PARAMS.P05.chance / 100) u._temp_spd += 1000;\n    });\n    turnOrder.sort((a, b) => {\n      if (b._temp_spd !== a._temp_spd) return b._temp_spd - a._temp_spd;\n      if (a.side === 'player' && b.side === 'enemy') return -1;\n      if (b.side === 'player' && a.side === 'enemy') return 1;\n      return 0;\n    });\n\n    for (let u of turnOrder) {\n      if (u.hp <= 0) continue;\n      if (!allUnits.some(x => x.side !== u.side && x.hp > 0)) { isCombatActive = false; break; }\n\n      if (u._stun > 0) {\n        u._stun--;\n        log(`${getTeamName(u.side)}:[${u.name}] \u0e15\u0e34\u0e14\u0e2a\u0e15\u0e31\u0e49\u0e19 \u0e02\u0e49\u0e32\u0e21\u0e15\u0e32\u0e42\u0e08\u0e21\u0e15\u0e35 (\u0e40\u0e2b\u0e25\u0e37\u0e2d ${u._stun} \u0e23\u0e2d\u0e1a)`);\n        continue;\n      }\n\n      if (u._poison > 0) {\n        let poisonDmg = Math.max(1, Math.floor(u.max_hp * (PASSIVE_PARAMS.P27.poison_pct / 100)));\n        let poisonSource = u._poison_source || u;\n        dealDamage(u, poisonDmg, poisonSource, round);\n        u._poison--;\n        log(`${getTeamName(u.side)}:[${u.name}] \u0e44\u0e14\u0e49\u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e1e\u0e34\u0e29 ${poisonDmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d ${u._poison} \u0e23\u0e2d\u0e1a)`);\n        if (u.hp <= 0) continue;\n      }\n\n      let isSilencedThisTurn = false;\n      if (u._silenced > 0) {\n        isSilencedThisTurn = true;\n        u._silenced--;\n        if (u._silenced > 0) log(`${getTeamName(u.side)}:[${u.name}] passive \u0e22\u0e31\u0e07\u0e16\u0e39\u0e01\u0e1b\u0e34\u0e14\u0e2d\u0e22\u0e39\u0e48 \u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e2d\u0e35\u0e01 ${u._silenced} \u0e23\u0e2d\u0e1a`);\n        else log(`${getTeamName(u.side)}:[${u.name}] passive \u0e16\u0e39\u0e01\u0e1b\u0e34\u0e14\u0e23\u0e2d\u0e1a\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22`);\n      }\n\n      if (u.passive === 'P16') {\n        if (u._p16_owner_turns > 0) {\n          u._p16_owner_turns--;\n          if (u._p16_owner_turns === 0) {\n            allUnits.filter(x => x.side === u.side).forEach(x => x._p16_active = false);\n            log(`${getTeamName(u.side)}:[${u.name}] \u0e1a\u0e31\u0e1f\u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a\u0e2b\u0e21\u0e14\u0e24\u0e17\u0e18\u0e34\u0e4c`);\n          }\n        }\n      }\n\n      if (!isSilencedThisTurn) {\n        if (u.passive === 'P13') {\n          let h = Math.floor(u.max_hp * (PASSIVE_PARAMS.P13.heal_pct / 100));\n          healGroupAndLog(u, [u], h, '\u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49\u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07');\n        }\n        else if (u.passive === 'P14') {\n          let h = Math.floor(u.max_hp * (PASSIVE_PARAMS.P14.heal_pct / 100));\n          let allies = allUnits.filter(x => x.side === u.side && x.hp > 0);\n          healGroupAndLog(u, allies, h, '\u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21');\n        } else if (u.passive === 'P15' && Math.random() < PASSIVE_PARAMS.P15.chance / 100) {\n          let h = Math.floor(u.max_hp * (PASSIVE_PARAMS.P15.heal_pct / 100));\n          let allies = allUnits.filter(x => x.side === u.side && x.hp > 0);\n          healGroupAndLog(u, allies, h, '\u0e23\u0e31\u0e01\u0e29\u0e32\u0e09\u0e38\u0e01\u0e40\u0e09\u0e34\u0e19\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21');\n        } else if (u.passive === 'P16' && u._p16_owner_turns === 0 && Math.random() < PASSIVE_PARAMS.P16.chance / 100) {\n          log(`${getTeamName(u.side)}:[${u.name}] \u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e08\u0e21\u0e15\u0e35\u0e17\u0e35\u0e21 25%`);\n          u._p16_owner_turns = PASSIVE_PARAMS.P16.duration;\n          allUnits.filter(x => x.side === u.side && x.hp > 0).forEach(ally => ally._p16_active = true);\n        }\n      }\n\n      allUnits.forEach(x => updateStats(x));\n\n      {\n        performAttackAction(u, isSilencedThisTurn, false, round);\n        let alliesWithP18 = allUnits.filter(x => x.side === u.side && x.hp > 0 && x.passive === 'P18' && !x._silenced);\n        for (let allyP18 of alliesWithP18) {\n          if (Math.random() < PASSIVE_PARAMS.P18.chance / 100) {\n            stats[allyP18.side_id].extra_turn_count++;\n            log(`${getTeamName(allyP18.side)}:[${allyP18.name}] \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e17\u0e2d\u0e07\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e2a\u0e31\u0e48\u0e07 ${u.name} \u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33`);\n            performAttackAction(u, isSilencedThisTurn, true, round);\n          }\n        }\n      }\n    }\n    if (isCombatActive) round++;\n  }\n\n  let attackerAlive = allUnits.some(u => u.side === 'player' && u.hp > 0);\n  let defenderAlive = allUnits.some(u => u.side === 'enemy' && u.hp > 0);\n  let isAttackerWin = attackerAlive && !defenderAlive;\n\n  return { isAttackerWin: isAttackerWin, logs: logs, stats: stats, totalRounds: round };\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { runPvpCombat };\n}\n\n";

const GAME_ENGINE_EXTRA_SOURCE = "// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_gacha_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e40\u0e01\u0e47\u0e1a\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25/\u0e04\u0e48\u0e32\u0e01\u0e15\u0e34\u0e01\u0e32\u0e02\u0e2d\u0e07\u0e23\u0e30\u0e1a\u0e1a\u0e01\u0e32\u0e0a\u0e32\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e04\u0e33\u0e19\u0e27\u0e13)\n// \u0e41\u0e1b\u0e25\u0e07\u0e15\u0e23\u0e07\u0e08\u0e32\u0e01\u0e44\u0e1f\u0e25\u0e4c\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a: gacha_system.json (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e41\u0e01\u0e49\u0e44\u0e02/\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e40\u0e15\u0e34\u0e21\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e43\u0e14\u0e46)\n// \u0e2b\u0e21\u0e32\u0e22\u0e40\u0e2b\u0e15\u0e38: \u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e1b\u0e47\u0e19 \u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25/\u0e2a\u0e40\u0e1b\u0e01 \u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19 \u0e22\u0e31\u0e07\u0e44\u0e21\u0e48\u0e21\u0e35\u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e2a\u0e38\u0e48\u0e21\u0e08\u0e23\u0e34\u0e07 (drawGacha \u0e2f\u0e25\u0e2f)\n// \u0e40\u0e21\u0e37\u0e48\u0e2d\u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e40\u0e02\u0e35\u0e22\u0e19\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e23\u0e30\u0e1a\u0e1a\u0e01\u0e32\u0e0a\u0e32\u0e08\u0e23\u0e34\u0e07 \u0e08\u0e30\u0e41\u0e22\u0e01\u0e40\u0e1b\u0e47\u0e19 gacha_system.js \u0e2d\u0e35\u0e01\u0e44\u0e1f\u0e25\u0e4c\u0e17\u0e35\u0e48\u0e21\u0e32\u0e2d\u0e48\u0e32\u0e19\u0e04\u0e48\u0e32\u0e08\u0e32\u0e01\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\n// ==========================================\n\n// \u0e42\u0e1a\u0e19\u0e31\u0e2a \"\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e43\u0e2b\u0e21\u0e48\" \u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e08\u0e23\u0e34\u0e07 4 \u0e04\u0e23\u0e31\u0e49\u0e07\u0e41\u0e23\u0e01 (\u0e44\u0e21\u0e48\u0e19\u0e31\u0e1a starter pull \u0e17\u0e35\u0e48\u0e25\u0e47\u0e2d\u0e01 role fighter \u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27):\n// - \u0e02\u0e31\u0e49\u0e19\u0e2a\u0e38\u0e48\u0e21\u0e40\u0e01\u0e23\u0e14 (step 1) \u0e43\u0e0a\u0e49\u0e2d\u0e31\u0e15\u0e23\u0e32\u0e19\u0e35\u0e49\u0e41\u0e17\u0e19\u0e2d\u0e31\u0e15\u0e23\u0e32\u0e1b\u0e01\u0e15\u0e34\u0e0a\u0e31\u0e48\u0e27\u0e04\u0e23\u0e32\u0e27 (\u0e40\u0e01\u0e23\u0e14\u0e14\u0e35\u0e2a\u0e38\u0e48\u0e21\u0e22\u0e32\u0e01\u0e25\u0e07\u0e01\u0e27\u0e48\u0e32\u0e1b\u0e01\u0e15\u0e34\u0e42\u0e14\u0e22\u0e15\u0e31\u0e49\u0e07\u0e43\u0e08 \u0e01\u0e31\u0e19\u0e23\u0e39\u0e49\u0e2a\u0e36\u0e01\u0e27\u0e48\u0e32\u0e44\u0e14\u0e49\u0e1f\u0e23\u0e35\u0e07\u0e48\u0e32\u0e22\u0e44\u0e1b)\n// - \u0e17\u0e38\u0e01\u0e40\u0e01\u0e23\u0e14\u0e2a\u0e38\u0e48\u0e21\u0e15\u0e34\u0e14\u0e0a\u0e31\u0e27\u0e23\u0e4c 100% \u0e40\u0e2a\u0e21\u0e2d\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27 (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e02\u0e31\u0e49\u0e19\u0e40\u0e0a\u0e34\u0e0d\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08/\u0e44\u0e21\u0e48\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b\u0e17\u0e31\u0e49\u0e07\u0e23\u0e30\u0e1a\u0e1a) \u0e0a\u0e48\u0e27\u0e07\u0e19\u0e35\u0e49\u0e08\u0e36\u0e07\u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e21\u0e35\u0e01\u0e32\u0e23\u0e1a\u0e31\u0e07\u0e04\u0e31\u0e1a\u0e1c\u0e48\u0e32\u0e19\u0e1e\u0e34\u0e40\u0e28\u0e29\u0e2d\u0e30\u0e44\u0e23\u0e2d\u0e35\u0e01 \u0e43\u0e0a\u0e49\u0e2d\u0e31\u0e15\u0e23\u0e32\u0e19\u0e35\u0e49\u0e15\u0e23\u0e07\u0e46 \u0e44\u0e14\u0e49\u0e40\u0e25\u0e22\nconst NEW_PLAYER_GACHA_BOOST = {\n  pull_count: 4,\n  boosted_grade_rates: { S: 0.3, A: 3, B: 12, C: 84.7 }\n};\n\nconst GACHA_SYSTEM = {\n  \"currency\": \"\u0e40\u0e1e\u0e0a\u0e23\",\n  \"pull_costs\": {\n    \"single_pull\": {\n      \"cost\": 10,\n      \"pulls_received\": 1\n    },\n    \"bundle_pull\": {\n      \"cost\": 50,\n      \"pulls_received\": 6,\n      \"note\": \"\u0e08\u0e48\u0e32\u0e22 50 \u0e40\u0e1e\u0e0a\u0e23 \u0e44\u0e14\u0e49\u0e2a\u0e38\u0e48\u0e21 5 \u0e04\u0e23\u0e31\u0e49\u0e07 \u0e1a\u0e27\u0e01\u0e1f\u0e23\u0e35\u0e2d\u0e35\u0e01 1 \u0e04\u0e23\u0e31\u0e49\u0e07 \u0e23\u0e27\u0e21 6 \u0e04\u0e23\u0e31\u0e49\u0e07 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e31\u0e19\u0e15\u0e35\u0e40\u0e01\u0e23\u0e14\u0e02\u0e31\u0e49\u0e19\u0e15\u0e48\u0e33\"\n    }\n  },\n  \"step_1_grade_roll\": {\n    \"description\": \"\u0e2a\u0e38\u0e48\u0e21\u0e27\u0e48\u0e32\u0e44\u0e14\u0e49\u0e40\u0e01\u0e23\u0e14\u0e2d\u0e30\u0e44\u0e23 (\u0e04\u0e33\u0e19\u0e27\u0e13\u0e23\u0e27\u0e21\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e40\u0e08\u0e2d\u00d7\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e40\u0e0a\u0e34\u0e0d\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08\u0e40\u0e09\u0e25\u0e35\u0e48\u0e22\u0e02\u0e2d\u0e07\u0e23\u0e30\u0e1a\u0e1a\u0e40\u0e14\u0e34\u0e21\u0e44\u0e27\u0e49\u0e41\u0e25\u0e49\u0e27 \u0e41\u0e25\u0e49\u0e27\u0e1b\u0e23\u0e31\u0e1a\u0e43\u0e2b\u0e49\u0e23\u0e27\u0e21\u0e40\u0e1b\u0e47\u0e19 100% \u0e1e\u0e2d\u0e14\u0e35 \u0e40\u0e1e\u0e23\u0e32\u0e30\u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49\u0e2a\u0e38\u0e48\u0e21\u0e15\u0e34\u0e14\u0e0a\u0e31\u0e27\u0e23\u0e4c 100% \u0e44\u0e21\u0e48\u0e21\u0e35\u0e02\u0e31\u0e49\u0e19\u0e40\u0e0a\u0e34\u0e0d\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08/\u0e44\u0e21\u0e48\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b) \u0e08\u0e32\u0e01\u0e19\u0e31\u0e49\u0e19\u0e2a\u0e38\u0e48\u0e21\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e20\u0e32\u0e22\u0e43\u0e19\u0e40\u0e01\u0e23\u0e14\u0e19\u0e31\u0e49\u0e19\u0e41\u0e1a\u0e1a\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\",\n    \"grade_rates\": {\n      \"S\": 0.605,\n      \"A\": 4.435,\n      \"B\": 20.565,\n      \"C\": 74.395\n    }\n  },\n  \"step_2_invite_success\": {\n    \"description\": \"[\u0e40\u0e25\u0e34\u0e01\u0e43\u0e0a\u0e49\u0e41\u0e25\u0e49\u0e27 - \u0e40\u0e01\u0e47\u0e1a\u0e44\u0e27\u0e49\u0e2d\u0e49\u0e32\u0e07\u0e2d\u0e34\u0e07\u0e40\u0e09\u0e22\u0e46] \u0e40\u0e14\u0e34\u0e21\u0e2b\u0e25\u0e31\u0e07\u0e23\u0e39\u0e49\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e17\u0e35\u0e48\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49 \u0e23\u0e30\u0e1a\u0e1a\u0e2a\u0e38\u0e48\u0e21\u0e15\u0e31\u0e27\u0e40\u0e25\u0e02\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08\u0e2b\u0e19\u0e36\u0e48\u0e07\u0e04\u0e48\u0e32\u0e43\u0e19\u0e0a\u0e48\u0e27\u0e07\u0e02\u0e2d\u0e07\u0e40\u0e01\u0e23\u0e14\u0e19\u0e31\u0e49\u0e19 \u0e41\u0e2a\u0e14\u0e07\u0e43\u0e2b\u0e49\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e40\u0e2b\u0e47\u0e19\u0e01\u0e48\u0e2d\u0e19 \u0e41\u0e25\u0e49\u0e27\u0e08\u0e36\u0e07\u0e2a\u0e38\u0e48\u0e21\u0e08\u0e23\u0e34\u0e07\u0e27\u0e48\u0e32\u0e1c\u0e48\u0e32\u0e19\u0e2b\u0e23\u0e37\u0e2d\u0e44\u0e21\u0e48\u0e1c\u0e48\u0e32\u0e19 \u2014 \u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49 gachaRollInviteSuccess() \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08 100% \u0e40\u0e2a\u0e21\u0e2d\u0e41\u0e25\u0e49\u0e27 \u0e04\u0e48\u0e32\u0e40\u0e09\u0e25\u0e35\u0e48\u0e22\u0e02\u0e2d\u0e07\u0e0a\u0e48\u0e27\u0e07\u0e41\u0e15\u0e48\u0e25\u0e30\u0e40\u0e01\u0e23\u0e14\u0e15\u0e23\u0e07\u0e19\u0e35\u0e49\u0e16\u0e39\u0e01\u0e40\u0e2d\u0e32\u0e44\u0e1b\u0e04\u0e39\u0e13\u0e01\u0e31\u0e1a step_1 (\u0e40\u0e01\u0e23\u0e14\u0e40\u0e14\u0e34\u0e21) \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e04\u0e33\u0e19\u0e27\u0e13 grade_rates \u0e43\u0e2b\u0e21\u0e48\u0e14\u0e49\u0e32\u0e19\u0e1a\u0e19\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27\",\n    \"success_chance_range_by_grade\": {\n      \"C\": {\n        \"min\": 60,\n        \"max\": 90\n      },\n      \"B\": {\n        \"min\": 40,\n        \"max\": 60\n      },\n      \"A\": {\n        \"min\": 20,\n        \"max\": 35\n      },\n      \"S\": {\n        \"min\": 10,\n        \"max\": 15\n      }\n    }\n  },\n  \"on_invite_failure\": {\n    \"behavior\": \"\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e2b\u0e32\u0e22\u0e44\u0e1b\u0e17\u0e31\u0e19\u0e17\u0e35 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e25\u0e2d\u0e07\u0e43\u0e2b\u0e21\u0e48 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e31\u0e19\u0e15\u0e35\u0e43\u0e14\u0e46 \u0e40\u0e1e\u0e0a\u0e23\u0e17\u0e35\u0e48\u0e08\u0e48\u0e32\u0e22\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27\u0e44\u0e21\u0e48\u0e04\u0e37\u0e19\",\n    \"retry_allowed\": false\n  },\n  \"result_display\": {\n    \"step_1_shows\": [\n      \"character_name\",\n      \"grade\",\n      \"role\",\n      \"stats\"\n    ],\n    \"step_2_shows\": [\n      \"invite_success_chance_rolled\",\n      \"invite_result\"\n    ]\n  },\n  \"starter_pull_rule\": {\n    \"trigger\": \"\u0e1a\u0e31\u0e0d\u0e0a\u0e35\u0e43\u0e2b\u0e21\u0e48 \u0e22\u0e31\u0e07\u0e44\u0e21\u0e48\u0e40\u0e04\u0e22\u0e2a\u0e38\u0e48\u0e21\u0e01\u0e32\u0e0a\u0e32\u0e40\u0e25\u0e22\",\n    \"starting_gems\": 10,\n    \"behavior\": \"\u0e1a\u0e31\u0e07\u0e04\u0e31\u0e1a\u0e2a\u0e38\u0e48\u0e21\u0e01\u0e32\u0e0a\u0e32 1 \u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e31\u0e19\u0e17\u0e35 \u0e43\u0e0a\u0e49\u0e40\u0e1e\u0e0a\u0e23 10 \u0e40\u0e21\u0e47\u0e14\u0e17\u0e35\u0e48\u0e41\u0e08\u0e01\u0e43\u0e2b\u0e49\u0e1e\u0e2d\u0e14\u0e35 (\u0e40\u0e2b\u0e25\u0e37\u0e2d 0 \u0e2b\u0e25\u0e31\u0e07\u0e08\u0e1a)\",\n    \"role_lock\": \"fighter\",\n    \"role_lock_note\": \"\u0e40\u0e01\u0e23\u0e14\u0e22\u0e31\u0e07\u0e2a\u0e38\u0e48\u0e21\u0e15\u0e32\u0e21\u0e2d\u0e31\u0e15\u0e23\u0e32\u0e1b\u0e01\u0e15\u0e34 (grade_rates) \u0e41\u0e15\u0e48\u0e15\u0e31\u0e14\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 role \u0e2d\u0e37\u0e48\u0e19\u0e2d\u0e2d\u0e01\u0e08\u0e32\u0e01 pool \u0e0a\u0e31\u0e48\u0e27\u0e04\u0e23\u0e32\u0e27\u0e40\u0e09\u0e1e\u0e32\u0e30\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e04\u0e23\u0e31\u0e49\u0e07\u0e19\u0e35\u0e49\u0e04\u0e23\u0e31\u0e49\u0e07\u0e40\u0e14\u0e35\u0e22\u0e27\",\n    \"invite_success_on_starter_pull\": \"\u0e01\u0e32\u0e23\u0e31\u0e19\u0e15\u0e35\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08 100% \u0e44\u0e21\u0e48\u0e21\u0e35\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e1e\u0e25\u0e32\u0e14 \u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e2a\u0e38\u0e48\u0e21 success_chance \u0e40\u0e25\u0e22\u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e04\u0e23\u0e31\u0e49\u0e07\u0e41\u0e23\u0e01\u0e19\u0e35\u0e49\"\n  },\n  \"level_milestone_rewards\": {\n    \"description\": \"\u0e23\u0e32\u0e07\u0e27\u0e31\u0e25\u0e40\u0e1e\u0e0a\u0e23\u0e15\u0e32\u0e21 milestone level \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e35\u0e48\u0e40\u0e04\u0e22\u0e17\u0e33\u0e44\u0e14\u0e49\u0e15\u0e48\u0e2d\u0e40\u0e01\u0e23\u0e14 (\u0e19\u0e31\u0e1a\u0e23\u0e27\u0e21\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e43\u0e19\u0e40\u0e01\u0e23\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e41\u0e22\u0e01\u0e15\u0e48\u0e2d\u0e15\u0e31\u0e27)\",\n    \"currency_rewarded\": \"\u0e40\u0e1e\u0e0a\u0e23\",\n    \"reward_per_level_by_grade\": {\n      \"C\": 4,\n      \"B\": 7,\n      \"A\": 11,\n      \"S\": 18\n    },\n    \"tracking_note\": \"player_save \u0e40\u0e01\u0e47\u0e1a grade_milestones \u0e15\u0e48\u0e2d\u0e40\u0e01\u0e23\u0e14 (level \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e35\u0e48\u0e40\u0e04\u0e22\u0e41\u0e15\u0e30) \u0e40\u0e21\u0e37\u0e48\u0e2d\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e15\u0e31\u0e27\u0e43\u0e14\u0e02\u0e2d\u0e07\u0e40\u0e01\u0e23\u0e14\u0e19\u0e31\u0e49\u0e19\u0e16\u0e36\u0e07 level \u0e43\u0e2b\u0e21\u0e48\u0e17\u0e35\u0e48\u0e2a\u0e39\u0e07\u0e01\u0e27\u0e48\u0e32\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e1a\u0e31\u0e19\u0e17\u0e36\u0e01\u0e44\u0e27\u0e49 \u0e44\u0e14\u0e49\u0e40\u0e1e\u0e0a\u0e23 = (level_\u0e43\u0e2b\u0e21\u0e48 - level_\u0e40\u0e14\u0e34\u0e21) x reward_per_level_by_grade[\u0e40\u0e01\u0e23\u0e14] \u0e41\u0e25\u0e49\u0e27\u0e2d\u0e31\u0e1b\u0e40\u0e14\u0e15\u0e04\u0e48\u0e32\u0e1a\u0e31\u0e19\u0e17\u0e36\u0e01\u0e17\u0e31\u0e19\u0e17\u0e35\",\n    \"duplicate_or_lower_level_claim\": \"\u0e16\u0e49\u0e32 level \u0e17\u0e35\u0e48\u0e17\u0e33\u0e44\u0e14\u0e49 <= milestone \u0e40\u0e14\u0e34\u0e21 \u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e23\u0e31\u0e1a\u0e23\u0e32\u0e07\u0e27\u0e31\u0e25\u0e0b\u0e49\u0e33\"\n  }\n};\n\n// ---------- \u0e01\u0e32\u0e0a\u0e32\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 (\u0e41\u0e22\u0e01\u0e08\u0e32\u0e01\u0e01\u0e32\u0e0a\u0e32\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e14\u0e49\u0e32\u0e19\u0e1a\u0e19 \u0e43\u0e0a\u0e49\u0e40\u0e1e\u0e0a\u0e23\u0e40\u0e2b\u0e21\u0e37\u0e2d\u0e19\u0e01\u0e31\u0e19\u0e41\u0e15\u0e48\u0e23\u0e32\u0e04\u0e32/\u0e2d\u0e31\u0e15\u0e23\u0e32\u0e04\u0e19\u0e25\u0e30\u0e0a\u0e38\u0e14) ----------\n// \u0e2a\u0e38\u0e48\u0e21\u0e40\u0e14\u0e35\u0e48\u0e22\u0e27 3 \u0e40\u0e1e\u0e0a\u0e23: \u0e44\u0e21\u0e48\u0e25\u0e47\u0e2d\u0e01\u0e2b\u0e21\u0e27\u0e14\u0e40\u0e25\u0e22 \u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49\u0e17\u0e38\u0e01\u0e0a\u0e19\u0e34\u0e14\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e1b\u0e19\u0e01\u0e31\u0e19\u0e40\u0e2a\u0e21\u0e2d \u0e44\u0e21\u0e48\u0e27\u0e48\u0e32\u0e08\u0e30\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e17\u0e47\u0e1a\u0e44\u0e2b\u0e19\n// \u0e2a\u0e38\u0e48\u0e21 5+1 (15 \u0e40\u0e1e\u0e0a\u0e23): \u0e25\u0e47\u0e2d\u0e01\u0e15\u0e32\u0e21\u0e41\u0e17\u0e47\u0e1a\u0e17\u0e35\u0e48\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e2d\u0e22\u0e39\u0e48 (\u0e2d\u0e32\u0e27\u0e38\u0e18/\u0e40\u0e01\u0e23\u0e32\u0e30/\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a) \u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19\nconst EQUIPMENT_GACHA = {\n  single_pull: { cost: 3, pulls: 1 },\n  bundle_pull: { cost: 15, pulls: 6 },\n  star_rates: { 1: 80, 2: 17, 3: 3 } // % \u0e15\u0e48\u0e2d\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21 1 \u0e04\u0e23\u0e31\u0e49\u0e07\n};\n\nif (typeof module !== 'undefined' && module.exports) {\n  module.exports = { GACHA_SYSTEM, EQUIPMENT_GACHA, NEW_PLAYER_GACHA_BOOST };\n}\n\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_pirate_spirit.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e04\u0e48\u0e32\u0e04\u0e07\u0e17\u0e35\u0e48\u0e02\u0e2d\u0e07 \"\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14\" (Pirate Spirit) \u2014 \u0e1c\u0e25\u0e25\u0e31\u0e1e\u0e18\u0e4c\u0e17\u0e32\u0e07\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e43\u0e2b\u0e21\u0e48\u0e02\u0e2d\u0e07\u0e01\u0e32\u0e0a\u0e32\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\n// \u0e40\u0e21\u0e37\u0e48\u0e2d\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49\u0e40\u0e01\u0e23\u0e14\u0e43\u0e14\u0e01\u0e47\u0e15\u0e32\u0e21 \u0e21\u0e35\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2a\u0e31\u0e14\u0e2a\u0e48\u0e27\u0e19\u0e2b\u0e19\u0e36\u0e48\u0e07 (PIRATE_SPIRIT_SUB_RATE) \u0e17\u0e35\u0e48\u0e08\u0e30\u0e44\u0e14\u0e49\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14\u0e40\u0e01\u0e23\u0e14\u0e19\u0e31\u0e49\u0e19\n// \u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e08\u0e30\u0e44\u0e14\u0e49\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e08\u0e23\u0e34\u0e07 \u2014 \u0e44\u0e21\u0e48\u0e17\u0e14\u0e41\u0e17\u0e19\u0e2d\u0e31\u0e15\u0e23\u0e32\u0e40\u0e01\u0e23\u0e14\u0e40\u0e14\u0e34\u0e21 \u0e41\u0e04\u0e48\u0e41\u0e1a\u0e48\u0e07\u0e2a\u0e31\u0e14\u0e2a\u0e48\u0e27\u0e19\u0e20\u0e32\u0e22\u0e43\u0e19\u0e40\u0e01\u0e23\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\n// \u0e15\u0e31\u0e27\u0e2d\u0e22\u0e48\u0e32\u0e07: \u0e40\u0e01\u0e23\u0e14 S \u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49 3% \u0e02\u0e2d\u0e07\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14, 15% \u0e02\u0e2d\u0e07 3% \u0e19\u0e31\u0e49\u0e19 (0.45% \u0e23\u0e27\u0e21) \u0e08\u0e30\u0e40\u0e1b\u0e47\u0e19\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14 S \u0e41\u0e17\u0e19\n// ==========================================\n\n// \u0e2a\u0e31\u0e14\u0e2a\u0e48\u0e27\u0e19\u0e20\u0e32\u0e22\u0e43\u0e19\u0e41\u0e15\u0e48\u0e25\u0e30\u0e40\u0e01\u0e23\u0e14\u0e17\u0e35\u0e48\u0e08\u0e30\u0e01\u0e25\u0e32\u0e22\u0e40\u0e1b\u0e47\u0e19\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14\u0e41\u0e17\u0e19\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e08\u0e23\u0e34\u0e07 \u2014 \u0e44\u0e21\u0e48\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19\u0e17\u0e38\u0e01\u0e40\u0e01\u0e23\u0e14\u0e41\u0e25\u0e49\u0e27\n// \u0e40\u0e01\u0e23\u0e14\u0e15\u0e48\u0e33 \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e40\u0e08\u0e2d\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e2a\u0e39\u0e07\u0e01\u0e27\u0e48\u0e32 \u0e40\u0e01\u0e23\u0e14\u0e2a\u0e39\u0e07 \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e40\u0e08\u0e2d\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 (\u0e01\u0e31\u0e19\u0e44\u0e21\u0e48\u0e43\u0e2b\u0e49\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49\u0e40\u0e01\u0e23\u0e14\u0e2a\u0e39\u0e07\u0e21\u0e35\u0e04\u0e48\u0e32\u0e25\u0e14\u0e25\u0e07)\nconst PIRATE_SPIRIT_SUB_RATE_BY_GRADE = {\n  C: 0.15,\n  B: 0.12,\n  A: 0.09,\n  S: 0.06\n};\n\n// \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e43\u0e0a\u0e49\u0e07\u0e32\u0e19\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14\u0e17\u0e35\u0e48\u0e41\u0e19\u0e48\u0e0a\u0e31\u0e14\u0e43\u0e19\u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49 (\u0e23\u0e2d\u0e23\u0e30\u0e1a\u0e1a\u0e2d\u0e31\u0e1e\u0e40\u0e01\u0e23\u0e14\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e43\u0e19\u0e2a\u0e40\u0e1b\u0e04\u0e16\u0e31\u0e14\u0e44\u0e1b)\n// \u0e40\u0e01\u0e47\u0e1a\u0e2a\u0e30\u0e2a\u0e21\u0e44\u0e27\u0e49\u0e43\u0e19\u0e04\u0e25\u0e31\u0e07\u0e01\u0e48\u0e2d\u0e19 (playerState.inventory.pirate_spirit)\nconst PIRATE_SPIRIT_ITEMS = {\n  C: { id: \"spirit_c\", name: \"\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14 (\u0e40\u0e01\u0e23\u0e14 C)\", grade: \"C\" },\n  B: { id: \"spirit_b\", name: \"\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14 (\u0e40\u0e01\u0e23\u0e14 B)\", grade: \"B\" },\n  A: { id: \"spirit_a\", name: \"\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14 (\u0e40\u0e01\u0e23\u0e14 A)\", grade: \"A\" },\n  S: { id: \"spirit_s\", name: \"\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14 (\u0e40\u0e01\u0e23\u0e14 S)\", grade: \"S\" }\n};\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { PIRATE_SPIRIT_SUB_RATE_BY_GRADE, PIRATE_SPIRIT_ITEMS };\n}\n\n\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: gacha_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e25\u0e2d\u0e08\u0e34\u0e01\u0e23\u0e30\u0e1a\u0e1a\u0e2a\u0e38\u0e48\u0e21 (\u0e01\u0e32\u0e0a\u0e32) \u0e08\u0e23\u0e34\u0e07 \u2014 \u0e41\u0e1b\u0e25\u0e07\u0e01\u0e15\u0e34\u0e01\u0e32\u0e17\u0e38\u0e01\u0e02\u0e49\u0e2d\u0e08\u0e32\u0e01 data_gacha_system.js\n// \u0e43\u0e2b\u0e49\u0e40\u0e1b\u0e47\u0e19\u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e17\u0e35\u0e48\u0e23\u0e31\u0e19\u0e44\u0e14\u0e49\u0e08\u0e23\u0e34\u0e07\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e2b\u0e25\u0e48\u0e32\u0e19\u0e35\u0e49\u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d:\n//   1) data_gacha_system.js  -> \u0e43\u0e2b\u0e49 GACHA_SYSTEM\n//   2) data_characters.js    -> \u0e43\u0e2b\u0e49 CHARACTERS\n//\n// playerSave \u0e17\u0e35\u0e48\u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e43\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e23\u0e31\u0e1a\u0e40\u0e02\u0e49\u0e32\u0e21\u0e32 \u0e15\u0e49\u0e2d\u0e07\u0e21\u0e35\u0e42\u0e04\u0e23\u0e07\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e15\u0e23\u0e07\u0e01\u0e31\u0e1a\n// player_save_template.json (field: gems, has_completed_starter_pull,\n// crew, grade_milestones \u0e2f\u0e25\u0e2f) \u2014 \u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49 \"\u0e41\u0e01\u0e49\u0e44\u0e02 object playerSave \u0e17\u0e35\u0e48\u0e2a\u0e48\u0e07\u0e40\u0e02\u0e49\u0e32\u0e21\u0e32\u0e42\u0e14\u0e22\u0e15\u0e23\u0e07\"\n// (mutate) \u0e41\u0e25\u0e49\u0e27 return \u0e1c\u0e25\u0e25\u0e31\u0e1e\u0e18\u0e4c\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e01\u0e25\u0e31\u0e1a\u0e44\u0e1b\u0e14\u0e49\u0e27\u0e22\n// ==========================================\n\n// ---------- \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e0a\u0e48\u0e27\u0e22\u0e2a\u0e38\u0e48\u0e21\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e25\u0e48\u0e32\u0e07 ----------\n\n// \u0e2a\u0e38\u0e48\u0e21\u0e40\u0e01\u0e23\u0e14\u0e15\u0e32\u0e21\u0e2d\u0e31\u0e15\u0e23\u0e32\u0e43\u0e19 step_1_grade_roll.grade_rates (\u0e2b\u0e19\u0e48\u0e27\u0e22\u0e40\u0e1b\u0e47\u0e19 %)\n// useBoostedRates: \u0e43\u0e0a\u0e49 NEW_PLAYER_GACHA_BOOST.boosted_grade_rates \u0e41\u0e17\u0e19 (\u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e43\u0e2b\u0e21\u0e48 4 \u0e04\u0e23\u0e31\u0e49\u0e07\u0e41\u0e23\u0e01) - \u0e44\u0e21\u0e48\u0e23\u0e30\u0e1a\u0e38 = \u0e2d\u0e31\u0e15\u0e23\u0e32\u0e1b\u0e01\u0e15\u0e34\u0e40\u0e2a\u0e21\u0e2d\nfunction gachaRollGrade(useBoostedRates) {\n  const rates = useBoostedRates ? NEW_PLAYER_GACHA_BOOST.boosted_grade_rates : GACHA_SYSTEM.step_1_grade_roll.grade_rates; // { S, A, B, C }\n  const roll = Math.random() * 100;\n  let cumulative = 0;\n  // \u0e25\u0e33\u0e14\u0e31\u0e1a\u0e17\u0e35\u0e48\u0e40\u0e0a\u0e47\u0e04\u0e44\u0e21\u0e48\u0e21\u0e35\u0e1c\u0e25\u0e15\u0e48\u0e2d\u0e1c\u0e25\u0e25\u0e31\u0e1e\u0e18\u0e4c\u0e17\u0e32\u0e07\u0e2a\u0e16\u0e34\u0e15\u0e34 \u0e41\u0e15\u0e48\u0e40\u0e23\u0e35\u0e22\u0e07\u0e08\u0e32\u0e01\u0e40\u0e01\u0e23\u0e14\u0e2a\u0e39\u0e07\u0e44\u0e1b\u0e15\u0e48\u0e33\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e2d\u0e48\u0e32\u0e19\u0e07\u0e48\u0e32\u0e22\n  const order = [\"S\", \"A\", \"B\", \"C\"];\n  for (const grade of order) {\n    cumulative += rates[grade];\n    if (roll < cumulative) return grade;\n  }\n  return \"C\"; // \u0e01\u0e31\u0e19\u0e1e\u0e25\u0e32\u0e14\u0e08\u0e32\u0e01 floating point\n}\n\n// \u0e2a\u0e38\u0e48\u0e21\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 1 \u0e15\u0e31\u0e27\u0e20\u0e32\u0e22\u0e43\u0e19\u0e40\u0e01\u0e23\u0e14\u0e17\u0e35\u0e48\u0e01\u0e33\u0e2b\u0e19\u0e14 \u0e41\u0e1a\u0e1a\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\n// roleFilter: \u0e16\u0e49\u0e32\u0e23\u0e30\u0e1a\u0e38 \u0e08\u0e30\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e40\u0e09\u0e1e\u0e32\u0e30\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e17\u0e35\u0e48 role \u0e15\u0e23\u0e07\u0e01\u0e31\u0e19 (\u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a starter_pull_rule)\nfunction gachaPickCharacterInGrade(grade, roleFilter) {\n  let pool = CHARACTERS.filter(c => c.grade === grade);\n  if (roleFilter) pool = pool.filter(c => c.role === roleFilter);\n  if (pool.length === 0) {\n    throw new Error(`\u0e44\u0e21\u0e48\u0e21\u0e35\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e43\u0e19\u0e40\u0e01\u0e23\u0e14 ${grade}${roleFilter ? \" role \" + roleFilter : \"\"} \u0e43\u0e2b\u0e49\u0e2a\u0e38\u0e48\u0e21`);\n  }\n  return pool[Math.floor(Math.random() * pool.length)];\n}\n\n// \u0e40\u0e14\u0e34\u0e21\u0e2a\u0e38\u0e48\u0e21\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08\u0e41\u0e25\u0e49\u0e27\u0e2d\u0e32\u0e08\u0e44\u0e21\u0e48\u0e1c\u0e48\u0e32\u0e19 \u2014 \u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49\u0e22\u0e01\u0e40\u0e25\u0e34\u0e01\u0e02\u0e31\u0e49\u0e19\u0e19\u0e35\u0e49\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e15\u0e01\u0e25\u0e07\u0e01\u0e31\u0e19: \u0e40\u0e0a\u0e34\u0e0d\u0e44\u0e14\u0e49 = \u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08\u0e40\u0e2a\u0e21\u0e2d 100% \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e1c\u0e48\u0e32\u0e19/\u0e44\u0e21\u0e48\u0e1c\u0e48\u0e32\u0e19\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b\n// (\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e40\u0e08\u0e2d\u0e40\u0e01\u0e23\u0e14\u0e15\u0e48\u0e32\u0e07\u0e46 \u0e16\u0e39\u0e01\u0e04\u0e33\u0e19\u0e27\u0e13\u0e23\u0e27\u0e21\u0e40\u0e2d\u0e32\u0e44\u0e27\u0e49\u0e43\u0e19 step_1_grade_roll.grade_rates \u0e41\u0e25\u0e49\u0e27\u0e41\u0e17\u0e19 \u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e04\u0e39\u0e13\u0e01\u0e31\u0e1a\u0e2d\u0e30\u0e44\u0e23\u0e15\u0e23\u0e07\u0e19\u0e35\u0e49\u0e2d\u0e35\u0e01)\nfunction gachaRollInviteSuccess(grade) {\n  return { chanceRolled: 100, passed: true };\n}\n\n// \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e40\u0e02\u0e49\u0e32 crew \u0e02\u0e2d\u0e07 playerSave (\u0e2b\u0e23\u0e37\u0e2d\u0e40\u0e1e\u0e34\u0e48\u0e21 pending_dupes \u0e16\u0e49\u0e32\u0e21\u0e35\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27)\n// \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e17\u0e35\u0e48\u0e44\u0e14\u0e49\u0e21\u0e32\u0e43\u0e2b\u0e21\u0e48\u0e08\u0e30\u0e44\u0e21\u0e48\u0e21\u0e35\u0e1c\u0e25\u0e01\u0e31\u0e1a\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e17\u0e31\u0e19\u0e17\u0e35 \u0e15\u0e49\u0e2d\u0e07\u0e44\u0e1b\u0e01\u0e14\u0e43\u0e0a\u0e49\u0e17\u0e35\u0e48\u0e2b\u0e19\u0e49\u0e32\u0e2d\u0e31\u0e1e\u0e40\u0e01\u0e23\u0e14 (upgrade_system.js) \u0e01\u0e48\u0e2d\u0e19\nfunction gachaAddCharacterToCrew(playerSave, character) {\n  const existing = playerSave.crew[character.id];\n  if (existing) {\n    existing.pending_dupes = (existing.pending_dupes || 0) + 1;\n    return { isNew: false };\n  } else {\n    playerSave.crew[character.id] = {\n      level: 1,\n      current_exp: 0,\n      dupes: 0,\n      pending_dupes: 0,\n      class: 1,\n      in_squad: false,\n      condition: 100\n    };\n    return { isNew: true };\n  }\n}\n\n// ---------- \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e2b\u0e25\u0e31\u0e01: \u0e2a\u0e38\u0e48\u0e21 1 \u0e04\u0e23\u0e31\u0e49\u0e07 ----------\n// \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32 pull result \u0e15\u0e32\u0e21\u0e42\u0e04\u0e23\u0e07\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e17\u0e35\u0e48 result_display \u0e23\u0e30\u0e1a\u0e38\u0e44\u0e27\u0e49:\n// step_1_shows: character_name, grade, role, stats\n// step_2_shows: invite_success_chance_rolled, invite_result\nfunction gachaPerformSinglePull(playerSave) {\n  const isStarterPull = !playerSave.has_completed_starter_pull;\n\n  // step 0: \u0e15\u0e23\u0e27\u0e08/\u0e2b\u0e31\u0e01\u0e40\u0e1e\u0e0a\u0e23 (starter pull \u0e43\u0e0a\u0e49\u0e40\u0e1e\u0e0a\u0e23\u0e40\u0e23\u0e34\u0e48\u0e21\u0e15\u0e49\u0e19 10 \u0e40\u0e21\u0e47\u0e14\u0e17\u0e35\u0e48\u0e41\u0e08\u0e01\u0e43\u0e2b\u0e49\u0e1e\u0e2d\u0e14\u0e35 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e2b\u0e31\u0e01\u0e0b\u0e49\u0e33)\n  const cost = GACHA_SYSTEM.pull_costs.single_pull.cost;\n  if (!isStarterPull) {\n    if (playerSave.gems < cost) {\n      throw new Error(\"\u0e40\u0e1e\u0e0a\u0e23\u0e44\u0e21\u0e48\u0e1e\u0e2d\u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e2a\u0e38\u0e48\u0e21 1 \u0e04\u0e23\u0e31\u0e49\u0e07\");\n    }\n    playerSave.gems -= cost;\n  } else {\n    // starter_pull_rule: starting_gems: 10, behavior: \u0e43\u0e0a\u0e49\u0e40\u0e1e\u0e0a\u0e23 10 \u0e40\u0e21\u0e47\u0e14\u0e17\u0e35\u0e48\u0e41\u0e08\u0e01\u0e43\u0e2b\u0e49\u0e1e\u0e2d\u0e14\u0e35 (\u0e40\u0e2b\u0e25\u0e37\u0e2d 0)\n    playerSave.gems = Math.max(0, playerSave.gems - cost);\n  }\n\n  // step 1: \u0e2a\u0e38\u0e48\u0e21\u0e40\u0e01\u0e23\u0e14 \u0e41\u0e25\u0e49\u0e27\u0e2a\u0e38\u0e48\u0e21\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e43\u0e19\u0e40\u0e01\u0e23\u0e14\u0e19\u0e31\u0e49\u0e19 (starter pull \u0e25\u0e47\u0e2d\u0e01 role = fighter)\n  const roleLock = isStarterPull ? GACHA_SYSTEM.starter_pull_rule.role_lock : null;\n  const grade = gachaRollGrade();\n\n  // \u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14: \u0e41\u0e15\u0e48\u0e25\u0e30\u0e40\u0e01\u0e23\u0e14\u0e21\u0e35\u0e2a\u0e31\u0e14\u0e2a\u0e48\u0e27\u0e19\u0e44\u0e21\u0e48\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19 (\u0e22\u0e01\u0e40\u0e27\u0e49\u0e19 starter pull) \u0e08\u0e30\u0e44\u0e14\u0e49\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a\u0e19\u0e35\u0e49\u0e41\u0e17\u0e19\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e08\u0e23\u0e34\u0e07\n  if (!isStarterPull && Math.random() < PIRATE_SPIRIT_SUB_RATE_BY_GRADE[grade]) {\n    const spiritItem = PIRATE_SPIRIT_ITEMS[grade];\n    if (!playerSave.inventory.pirate_spirit) playerSave.inventory.pirate_spirit = {};\n    playerSave.inventory.pirate_spirit[spiritItem.id] = (playerSave.inventory.pirate_spirit[spiritItem.id] || 0) + 1;\n    return { is_spirit: true, spirit_name: spiritItem.name, grade: grade };\n  }\n\n  const character = gachaPickCharacterInGrade(grade, roleLock);\n\n  // step 2: \u0e2a\u0e38\u0e48\u0e21\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08 (starter pull \u0e01\u0e32\u0e23\u0e31\u0e19\u0e15\u0e35\u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08 100% \u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e2a\u0e38\u0e48\u0e21)\n  let inviteResult;\n  if (isStarterPull) {\n    inviteResult = { chanceRolled: 100, passed: true };\n  } else {\n    inviteResult = gachaRollInviteSuccess(grade);\n  }\n\n  let gained = null;\n  if (inviteResult.passed) {\n    gained = gachaAddCharacterToCrew(playerSave, character);\n  }\n  // on_invite_failure: \u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e2b\u0e32\u0e22\u0e44\u0e1b\u0e17\u0e31\u0e19\u0e17\u0e35 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e25\u0e2d\u0e07\u0e43\u0e2b\u0e21\u0e48 \u0e40\u0e1e\u0e0a\u0e23\u0e17\u0e35\u0e48\u0e08\u0e48\u0e32\u0e22\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27\u0e44\u0e21\u0e48\u0e04\u0e37\u0e19 (\u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07 revert gems)\n\n  if (isStarterPull) playerSave.has_completed_starter_pull = true;\n\n  return {\n    character_name: character.name,\n    grade: character.grade,\n    role: character.role,\n    stats: character.stats,\n    invite_success_chance_rolled: inviteResult.chanceRolled,\n    invite_result: inviteResult.passed ? \"success\" : \"failure\",\n    is_new_character: gained ? gained.isNew : null\n  };\n}\n\n// ---------- \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e2b\u0e25\u0e31\u0e01: \u0e2a\u0e38\u0e48\u0e21\u0e41\u0e1a\u0e1a\u0e0a\u0e38\u0e14 (bundle) ----------\n// bundle_pull: \u0e08\u0e48\u0e32\u0e22 50 \u0e40\u0e1e\u0e0a\u0e23 \u0e44\u0e14\u0e49\u0e2a\u0e38\u0e48\u0e21 5 \u0e04\u0e23\u0e31\u0e49\u0e07 + \u0e1f\u0e23\u0e35 1 \u0e04\u0e23\u0e31\u0e49\u0e07 \u0e23\u0e27\u0e21 6 \u0e04\u0e23\u0e31\u0e49\u0e07 \u0e44\u0e21\u0e48\u0e01\u0e32\u0e23\u0e31\u0e19\u0e15\u0e35\u0e40\u0e01\u0e23\u0e14\u0e02\u0e31\u0e49\u0e19\u0e15\u0e48\u0e33\n// \u0e2b\u0e21\u0e32\u0e22\u0e40\u0e2b\u0e15\u0e38: \u0e40\u0e2d\u0e01\u0e2a\u0e32\u0e23\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e23\u0e30\u0e1a\u0e38\u0e27\u0e48\u0e32\u0e41\u0e15\u0e48\u0e25\u0e30\u0e04\u0e23\u0e31\u0e49\u0e07\u0e43\u0e19 bundle \u0e2a\u0e38\u0e48\u0e21\u0e40\u0e01\u0e23\u0e14/\u0e1c\u0e48\u0e32\u0e19\u0e44\u0e21\u0e48\u0e1c\u0e48\u0e32\u0e19\u0e2d\u0e34\u0e2a\u0e23\u0e30\u0e15\u0e48\u0e2d\u0e01\u0e31\u0e19\u0e2b\u0e23\u0e37\u0e2d\u0e44\u0e21\u0e48\n// \u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e15\u0e35\u0e04\u0e27\u0e32\u0e21\u0e27\u0e48\u0e32\u0e40\u0e1b\u0e47\u0e19\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e40\u0e14\u0e35\u0e48\u0e22\u0e27 6 \u0e04\u0e23\u0e31\u0e49\u0e07\u0e0b\u0e49\u0e33 \u0e2d\u0e34\u0e2a\u0e23\u0e30\u0e15\u0e48\u0e2d\u0e01\u0e31\u0e19\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (\u0e14\u0e39\u0e2a\u0e23\u0e38\u0e1b\u0e17\u0e49\u0e32\u0e22\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21)\nfunction gachaPerformBundlePull(playerSave) {\n  const cost = GACHA_SYSTEM.pull_costs.bundle_pull.cost;\n  const pullsReceived = GACHA_SYSTEM.pull_costs.bundle_pull.pulls_received;\n\n  if (playerSave.gems < cost) {\n    throw new Error(\"\u0e40\u0e1e\u0e0a\u0e23\u0e44\u0e21\u0e48\u0e1e\u0e2d\u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e2a\u0e38\u0e48\u0e21\u0e41\u0e1a\u0e1a\u0e0a\u0e38\u0e14\");\n  }\n  playerSave.gems -= cost;\n\n  const results = [];\n  for (let i = 0; i < pullsReceived; i++) {\n    // \u0e2a\u0e38\u0e48\u0e21\u0e41\u0e15\u0e48\u0e25\u0e30\u0e04\u0e23\u0e31\u0e49\u0e07\u0e41\u0e1a\u0e1a\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e1a single pull \u0e41\u0e15\u0e48\u0e44\u0e21\u0e48\u0e2b\u0e31\u0e01\u0e40\u0e1e\u0e0a\u0e23\u0e0b\u0e49\u0e33 (\u0e08\u0e48\u0e32\u0e22\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27\u0e01\u0e49\u0e2d\u0e19\u0e40\u0e14\u0e35\u0e22\u0e27\u0e15\u0e2d\u0e19\u0e15\u0e49\u0e19)\n    // \u0e41\u0e25\u0e30 bundle pull \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48 starter pull \u0e40\u0e2a\u0e21\u0e2d (\u0e15\u0e32\u0e21\u0e40\u0e2d\u0e01\u0e2a\u0e32\u0e23 starter_pull \u0e1c\u0e39\u0e01\u0e01\u0e31\u0e1a\u0e1a\u0e31\u0e0d\u0e0a\u0e35\u0e43\u0e2b\u0e21\u0e48\u0e04\u0e23\u0e31\u0e49\u0e07\u0e41\u0e23\u0e01\u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19)\n    const grade = gachaRollGrade();\n\n    if (Math.random() < PIRATE_SPIRIT_SUB_RATE_BY_GRADE[grade]) {\n      const spiritItem = PIRATE_SPIRIT_ITEMS[grade];\n      if (!playerSave.inventory.pirate_spirit) playerSave.inventory.pirate_spirit = {};\n      playerSave.inventory.pirate_spirit[spiritItem.id] = (playerSave.inventory.pirate_spirit[spiritItem.id] || 0) + 1;\n      results.push({ is_spirit: true, spirit_name: spiritItem.name, grade: grade });\n      continue;\n    }\n\n    const character = gachaPickCharacterInGrade(grade, null);\n    const inviteResult = gachaRollInviteSuccess(grade);\n\n    let gained = null;\n    if (inviteResult.passed) {\n      gained = gachaAddCharacterToCrew(playerSave, character);\n    }\n\n    results.push({\n      character_name: character.name,\n      grade: character.grade,\n      role: character.role,\n      stats: character.stats,\n      invite_success_chance_rolled: inviteResult.chanceRolled,\n      invite_result: inviteResult.passed ? \"success\" : \"failure\",\n      is_new_character: gained ? gained.isNew : null\n    });\n  }\n\n  if (!playerSave.has_completed_starter_pull) playerSave.has_completed_starter_pull = true;\n\n  return results;\n}\n\n// ---------- \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19: \u0e23\u0e32\u0e07\u0e27\u0e31\u0e25 milestone \u0e15\u0e32\u0e21\u0e40\u0e25\u0e40\u0e27\u0e25\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e15\u0e48\u0e2d\u0e40\u0e01\u0e23\u0e14 ----------\n// \u0e40\u0e23\u0e35\u0e22\u0e01\u0e15\u0e2d\u0e19\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e40\u0e25\u0e37\u0e48\u0e2d\u0e19\u0e40\u0e25\u0e40\u0e27\u0e25 \u0e2a\u0e48\u0e07 grade \u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e15\u0e31\u0e27\u0e19\u0e31\u0e49\u0e19 \u0e41\u0e25\u0e30 newLevel \u0e17\u0e35\u0e48\u0e17\u0e33\u0e44\u0e14\u0e49\nfunction gachaClaimGradeMilestone(playerSave, grade, newLevel) {\n  const rewardPerLevel = GACHA_SYSTEM.level_milestone_rewards.reward_per_level_by_grade[grade];\n  const currentMilestone = playerSave.grade_milestones[grade] || 0;\n\n  if (newLevel <= currentMilestone) {\n    return { gemsAwarded: 0, newMilestone: currentMilestone };\n  }\n\n  const levelsGained = newLevel - currentMilestone;\n  const gemsAwarded = levelsGained * rewardPerLevel;\n\n  playerSave.grade_milestones[grade] = newLevel;\n  playerSave.gems += gemsAwarded;\n\n  return { gemsAwarded, newMilestone: newLevel };\n}\n\n// ---------- \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19: \u0e01\u0e32\u0e0a\u0e32\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 ----------\n// slotFilter: null = \u0e44\u0e21\u0e48\u0e25\u0e47\u0e2d\u0e01\u0e2b\u0e21\u0e27\u0e14 (\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49\u0e17\u0e38\u0e01\u0e0a\u0e19\u0e34\u0e14) | \"weapon\"/\"armor\"/\"accessory\" = \u0e25\u0e47\u0e2d\u0e01\u0e40\u0e09\u0e1e\u0e32\u0e30\u0e2b\u0e21\u0e27\u0e14\u0e19\u0e31\u0e49\u0e19\nfunction equipGachaRollStar() {\n  const rates = EQUIPMENT_GACHA.star_rates; // { 1, 2, 3 } \u0e2b\u0e19\u0e48\u0e27\u0e22 %\n  const roll = Math.random() * 100;\n  if (roll < rates[3]) return 3;\n  if (roll < rates[3] + rates[2]) return 2;\n  return 1;\n}\n\nfunction equipGachaPickTypeKey(slotFilter) {\n  let keys = Object.keys(EQUIPMENT_TYPES);\n  if (slotFilter) keys = keys.filter(k => EQUIPMENT_TYPES[k].slot === slotFilter);\n  return keys[Math.floor(Math.random() * keys.length)];\n}\n\n// \u0e17\u0e33\u0e01\u0e32\u0e23\u0e2a\u0e38\u0e48\u0e21\u0e01\u0e32\u0e0a\u0e32\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c pullCount \u0e04\u0e23\u0e31\u0e49\u0e07 \u0e04\u0e37\u0e19 array \u0e02\u0e2d\u0e07 equipment instance \u0e17\u0e35\u0e48\u0e44\u0e14\u0e49\nfunction equipGachaPerformPulls(pullCount, slotFilter) {\n  const results = [];\n  for (let i = 0; i < pullCount; i++) {\n    const star = equipGachaRollStar();\n    const typeKey = equipGachaPickTypeKey(slotFilter);\n    const instance = equipmentCreateNew(typeKey, star);\n    results.push(instance);\n  }\n  return results;\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = {\n    gachaRollGrade,\n    gachaPickCharacterInGrade,\n    gachaRollInviteSuccess,\n    gachaAddCharacterToCrew,\n    gachaPerformSinglePull,\n    gachaPerformBundlePull,\n    gachaClaimGradeMilestone,\n    equipGachaRollStar, equipGachaPickTypeKey, equipGachaPerformPulls\n  };\n}\n\n\n\n// ==========================================\n// server_gacha.js \u2014 \u0e01\u0e32\u0e0a\u0e32\u0e17\u0e35\u0e48 \"\u0e40\u0e0b\u0e34\u0e23\u0e4c\u0e1f\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e40\u0e1b\u0e47\u0e19\u0e04\u0e19\u0e2a\u0e38\u0e48\u0e21\u0e41\u0e25\u0e30\u0e2b\u0e31\u0e01\u0e40\u0e1e\u0e0a\u0e23\" (\u0e01\u0e0e\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e1a gachaDoPull / gachaDoEquipPull \u0e43\u0e19\u0e40\u0e01\u0e21\u0e40\u0e1b\u0e4a\u0e30)\n// ==========================================\nfunction gachaServerEnsure(ps) {\n  if (!ps.crew) ps.crew = {};\n  if (!ps.inventory) ps.inventory = {};\n  if (!ps.grade_milestones) ps.grade_milestones = {};\n  if (!ps.progress) ps.progress = {};\n  if (!ps.equipment_inventory) ps.equipment_inventory = [];\n  if (typeof ps.gems !== 'number' || !isFinite(ps.gems)) ps.gems = 0;\n}\n\nfunction gachaServerCharPull(ps, times, isStarter) {\n  gachaServerEnsure(ps);\n  let roleLock = null;\n  let loopTimes = times;\n  if (isStarter) {\n    if (ps.has_completed_starter_pull) return { error: '\u0e2a\u0e38\u0e48\u0e21\u0e1c\u0e39\u0e49\u0e0a\u0e48\u0e27\u0e22\u0e04\u0e19\u0e41\u0e23\u0e01\u0e44\u0e1b\u0e41\u0e25\u0e49\u0e27' };\n    ps.gems = Math.max(0, ps.gems - GACHA_SYSTEM.pull_costs.single_pull.cost);\n    roleLock = GACHA_SYSTEM.starter_pull_rule.role_lock;\n    loopTimes = 1;\n  } else {\n    let cost = 0;\n    if (times === 1) cost = GACHA_SYSTEM.pull_costs.single_pull.cost;\n    else if (times === 6) cost = GACHA_SYSTEM.pull_costs.bundle_pull.cost;\n    else return { error: '\u0e08\u0e33\u0e19\u0e27\u0e19\u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e21\u0e48\u0e16\u0e39\u0e01\u0e15\u0e49\u0e2d\u0e07' };\n    if (ps.gems < cost) return { error: '\u0e40\u0e1e\u0e0a\u0e23\u0e44\u0e21\u0e48\u0e1e\u0e2d' };\n    ps.gems -= cost;\n  }\n  const queue = [];\n  for (let i = 0; i < loopTimes; i++) {\n    const grade = gachaRollGrade(false);\n    if (!isStarter && Math.random() < PIRATE_SPIRIT_SUB_RATE_BY_GRADE[grade]) {\n      const spiritItem = PIRATE_SPIRIT_ITEMS[grade];\n      if (!ps.inventory.pirate_spirit) ps.inventory.pirate_spirit = {};\n      ps.inventory.pirate_spirit[spiritItem.id] = (ps.inventory.pirate_spirit[spiritItem.id] || 0) + 1;\n      queue.push({ isSpirit: true, grade: grade, spiritName: spiritItem.name });\n      ps.gacha_pulls_completed = (ps.gacha_pulls_completed || 0) + 1;\n      continue;\n    }\n    const character = gachaPickCharacterInGrade(grade, roleLock);\n    gachaAddCharacterToCrew(ps, character);\n    if (isStarter) ps.has_completed_starter_pull = true;\n    if (!isStarter) ps.gacha_pulls_completed = (ps.gacha_pulls_completed || 0) + 1;\n    queue.push({ characterId: character.id, isStarter: !!isStarter });\n  }\n  return { queue: queue };\n}\n\nfunction gachaServerEquipPull(ps, times, slotFilterRaw) {\n  gachaServerEnsure(ps);\n  const unlocked = ((ps.progress.island_1 || {}).highest_stage_cleared || 0) >= 20;\n  if (!unlocked) return { error: '\u0e01\u0e32\u0e0a\u0e32\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e22\u0e31\u0e07\u0e44\u0e21\u0e48\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01' };\n  const slotFilter = (slotFilterRaw === 'weapon' || slotFilterRaw === 'armor' || slotFilterRaw === 'accessory') ? slotFilterRaw : null;\n  let cost = 0;\n  if (times === 1) cost = EQUIPMENT_GACHA.single_pull.cost;\n  else if (times === EQUIPMENT_GACHA.bundle_pull.pulls) cost = EQUIPMENT_GACHA.bundle_pull.cost;\n  else return { error: '\u0e08\u0e33\u0e19\u0e27\u0e19\u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e21\u0e48\u0e16\u0e39\u0e01\u0e15\u0e49\u0e2d\u0e07' };\n  if (ps.gems < cost) return { error: '\u0e40\u0e1e\u0e0a\u0e23\u0e44\u0e21\u0e48\u0e1e\u0e2d' };\n  ps.gems -= cost;\n  const results = equipGachaPerformPulls(times, slotFilter);\n  return { results: results };\n}\n\n// \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e02\u0e2d\u0e07\u0e1d\u0e31\u0e48\u0e07\u0e40\u0e01\u0e21\u0e17\u0e35\u0e48\u0e42\u0e04\u0e49\u0e14\u0e23\u0e48\u0e27\u0e21\u0e40\u0e23\u0e35\u0e22\u0e01\u0e43\u0e0a\u0e49 \u2014 \u0e1a\u0e19\u0e40\u0e0b\u0e34\u0e23\u0e4c\u0e1f\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e44\u0e21\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e17\u0e33\u0e2d\u0e30\u0e44\u0e23 (\u0e40\u0e0b\u0e34\u0e23\u0e4c\u0e1f\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e1a\u0e31\u0e19\u0e17\u0e36\u0e01\u0e40\u0e0b\u0e1f\u0e40\u0e2d\u0e07\u0e2b\u0e25\u0e31\u0e07\u0e2a\u0e38\u0e48\u0e21\u0e40\u0e2a\u0e23\u0e47\u0e08)\nfunction playerSave() {}\n";

function createGameEngine() {
  const exposeExports = `
this.CHARACTERS = CHARACTERS;
this.EQUIPMENT_TYPES = EQUIPMENT_TYPES;
this.runPvpCombat = runPvpCombat;
this.crewGetBaseCharData = crewGetBaseCharData;
this.calculateCharacterStats = calculateCharacterStats;
this.calculateSquadCombatPower = calculateSquadCombatPower;
this.PASSIVES = PASSIVES;
this.calculateCharacterCombatPower = calculateCharacterCombatPower;
this.getClassDupeMultiplier = getClassDupeMultiplier;
this.getLevelValue = getLevelValue;
this.getMaxLevel = getMaxLevel;
this.equipmentGetInstance = equipmentGetInstance;
this.equipmentGetName = equipmentGetName;
this.equipmentGetEffectiveRolls = equipmentGetEffectiveRolls;
this.gachaServerCharPull = gachaServerCharPull;
this.gachaServerEquipPull = gachaServerEquipPull;
this.__setPlayerState = function(save) { playerState = save; };
`;
  const context = {};
  vm.createContext(context);
  vm.runInContext('let playerState;\n' + GAME_ENGINE_SOURCE + '\n' + GAME_ENGINE_EXTRA_SOURCE + exposeExports, context, { filename: 'game-engine-bundle.js' });
  return context;
}


// ===== leaderboard_http.js =====
// leaderboard_http.js
// เส้นทาง API ของ leaderboard ทั้ง 4 แบบ — ต้องล็อกอินก่อนถึงจะดูได้ (เพื่อบอก "อันดับของฉัน" ได้ด้วย)


// จำนวน top ที่เลือกดูได้ (เขาอยากเลือกดู top 10/30/100 แทนที่จะบังคับ 50 เสมอ) — ?limit=10|30|100
const ALLOWED_LEADERBOARD_LIMITS = [10, 30, 100];
function parseLeaderboardLimit(limitParam) {
  const n = parseInt(limitParam, 10);
  return ALLOWED_LEADERBOARD_LIMITS.includes(n) ? n : 30; // ค่าเริ่มต้น 30 ถ้าไม่ได้ระบุ/ระบุผิด
}

async function handleLeaderboardRequest(req, res, path, method, userId, db, gameEngine, sendJson, limitParam) {
  const limit = parseLeaderboardLimit(limitParam);

  if (path === '/api/leaderboard/reputation' && method === 'GET') {
    const entries = await db.getAllSavesWithUsernames();
    const result = buildReputationLeaderboard(entries);
    sendJson(res, 200, { top: result.all.slice(0, limit), you: findMyEntry(result, userId), limit, total: result.all.length });
    return true;
  }

  if (path === '/api/leaderboard/wave-survival' && method === 'GET') {
    const entries = await db.getAllSavesWithUsernames();
    const result = buildWaveSurvivalLeaderboard(entries);
    sendJson(res, 200, { top: result.all.slice(0, limit), you: findMyEntry(result, userId), limit, total: result.all.length });
    return true;
  }

  if (path === '/api/leaderboard/combat-power' && method === 'GET') {
    const entries = await db.getAllSavesWithUsernames();
    const result = buildCombatPowerLeaderboard(entries, gameEngine, (save) => { gameEngine.__setPlayerState(save); });
    sendJson(res, 200, { top: result.all.slice(0, limit), you: findMyEntry(result, userId), limit, total: result.all.length });
    return true;
  }

  if (path === '/api/leaderboard/stage-progress' && method === 'GET') {
    const entries = await db.getAllSavesWithUsernames();
    const result = buildStageProgressLeaderboard(entries);
    sendJson(res, 200, { top: result.all.slice(0, limit), you: findMyEntry(result, userId), limit, total: result.all.length });
    return true;
  }

  if (path === '/api/leaderboard/pvp' && method === 'GET') {
    const seasonInfo = getSeasonInfo(new Date());
    if (!seasonInfo.isActive) {
      sendJson(res, 200, { top: [], you: null, seasonClosed: true, limit });
      return true;
    }
    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
    const profiles = await db.getAllPvpProfilesForSeason(seasonStartStr);
    const ranked = computeRanks(profiles.map(p => ({ id: p.user_id, points: p.points, matchesPlayed: p.matches_played })));

    const withNames = [];
    for (const r of ranked) {
      const username = await db.getDisplayName(r.id);
      withNames.push({ userId: r.id, username, value: r.points, position: r.position, rank: r.rank });
    }
    const you = withNames.find(e => e.userId === userId) || null;
    const shown = withNames.slice(0, limit);
    const lvMap = await db.getCaptainLevels(shown.map(e => e.userId).concat(you ? [you.userId] : []));
    shown.forEach(e => { e.level = lvMap[e.userId] || 1; });
    if (you) you.level = lvMap[you.userId] || 1;
    sendJson(res, 200, { top: shown, you, limit, total: withNames.filter(e => e.position).length });
    return true;
  }

  return false;
}

module.exports = { handleLeaderboardRequest };


// ===== payment_http.js =====
// payment_http.js
// เส้นทาง API ของระบบเติมเงิน — เติมด้วยมือทั้งหมด ไม่มีการตัดเงินอัตโนมัติผ่านบัตร/พร้อมเพย์ใดๆ
// ผู้เล่นโอนเงินจริงเอง แล้วกดแจ้งในเกม เจ้าของเกมเช็คสลิปเองแล้วกดอนุมัติ/ปฏิเสธผ่าน admin.html

function validateAmount(amountBaht) {
  if (typeof amountBaht !== 'number' || !Number.isFinite(amountBaht) || !Number.isInteger(amountBaht)) {
    return 'จำนวนเงินต้องเป็นตัวเลขจำนวนเต็ม';
  }
  if (amountBaht < PAYMENT_CONFIG.MIN_AMOUNT_BAHT) return `จำนวนเงินต้องอย่างน้อย ${PAYMENT_CONFIG.MIN_AMOUNT_BAHT} บาท`;
  if (amountBaht > PAYMENT_CONFIG.MAX_AMOUNT_BAHT) return `จำนวนเงินต้องไม่เกิน ${PAYMENT_CONFIG.MAX_AMOUNT_BAHT} บาท ต่อครั้ง`;
  return null;
}

async function handlePaymentRequest(req, res, path, method, body, userId, db, adminSecret, sendJson) {
  // ---------- GET /api/topup/info (ข้อมูลบัญชีธนาคาร + อัตราแลกเปลี่ยน ให้เกมแสดงผล) ----------
  if (path === '/api/topup/info' && method === 'GET') {
    sendJson(res, 200, {
      bankName: PAYMENT_CONFIG.BANK_NAME,
      bankAccountNumber: PAYMENT_CONFIG.BANK_ACCOUNT_NUMBER,
      bankAccountName: PAYMENT_CONFIG.BANK_ACCOUNT_NAME,
      gemsPerBaht: PAYMENT_CONFIG.GEMS_PER_BAHT,
      minAmountBaht: PAYMENT_CONFIG.MIN_AMOUNT_BAHT,
      maxAmountBaht: PAYMENT_CONFIG.MAX_AMOUNT_BAHT
    });
    return true;
  }

  // ---------- POST /api/topup/request (แจ้งว่าโอนเงินแล้ว รอตรวจสอบ) ----------
  if (path === '/api/topup/request' && method === 'POST') {
    const amountError = validateAmount(body.amountBaht);
    if (amountError) { sendJson(res, 400, { error: amountError }); return true; }

    const username = await db.getUsername(userId);
    const gemAmount = Math.floor(body.amountBaht * PAYMENT_CONFIG.GEMS_PER_BAHT);
    const note = typeof body.note === 'string' ? body.note.slice(0, 200) : null;

    const request = await db.createTopupRequest(userId, username, body.amountBaht, gemAmount, note);
    sendJson(res, 201, { request });
    return true;
  }

  // ---------- GET /api/topup/my-requests (ดูสถานะรายการของตัวเอง) ----------
  if (path === '/api/topup/my-requests' && method === 'GET') {
    const requests = await db.getTopupRequestsForUser(userId);
    sendJson(res, 200, { requests });
    return true;
  }

  // ---------- GET /api/topup/admin/pending (แอดมินดูรายการที่รอตรวจสอบทั้งหมด) ----------
  if (path === '/api/topup/admin/pending' && method === 'GET') {
    const providedSecret = req.headers['x-admin-secret'];
    if (!adminSecret || providedSecret !== adminSecret) { sendJson(res, 403, { error: 'ไม่มีสิทธิ์เรียกใช้งานจุดนี้' }); return true; }
    const requests = await db.getPendingTopupRequests();
    sendJson(res, 200, { requests });
    return true;
  }

  // ---------- POST /api/topup/admin/resolve (แอดมินอนุมัติ/ปฏิเสธ) ----------
  if (path === '/api/topup/admin/resolve' && method === 'POST') {
    const providedSecret = req.headers['x-admin-secret'];
    if (!adminSecret || providedSecret !== adminSecret) { sendJson(res, 403, { error: 'ไม่มีสิทธิ์เรียกใช้งานจุดนี้' }); return true; }

    const requestId = body.requestId;
    const action = body.action; // 'approve' | 'reject'
    if (!['approve', 'reject'].includes(action)) { sendJson(res, 400, { error: 'action ต้องเป็น approve หรือ reject' }); return true; }

    const topupRequest = await db.getTopupRequestById(requestId);
    if (!topupRequest) { sendJson(res, 404, { error: 'ไม่พบรายการนี้' }); return true; }
    if (topupRequest.status !== 'pending') { sendJson(res, 400, { error: 'รายการนี้ถูกดำเนินการไปแล้ว' }); return true; }

    if (action === 'approve') {
      await db.createGrant(topupRequest.user_id, { source: 'topup', gems: topupRequest.gem_amount, note: `เติมเงิน ${topupRequest.amount_baht} บาท` });
      await db.resolveTopupRequest(requestId, 'approved');
      sendJson(res, 200, { success: true, creditedGems: topupRequest.gem_amount });
    } else {
      await db.resolveTopupRequest(requestId, 'rejected');
      sendJson(res, 200, { success: true });
    }
    return true;
  }

  return false;
}

module.exports = { handlePaymentRequest, validateAmount };


// ===== pvp_http.js =====
// pvp_http.js
// เส้นทาง API ของระบบ PVP ทั้งหมด — แยกไฟล์จาก app.js เพื่อไม่ให้ไฟล์หลักยาวเกินไป
// app.js จะเรียก handlePvpRequest() ต่อเมื่อ path ขึ้นต้นด้วย /api/pvp/



function isValidTeamArray(team) {
  if (!Array.isArray(team) || team.length > 5) return false;
  return team.every(id => id === null || typeof id === 'string');
}

// เช็คว่าตัวละครทุกตัวที่เลือกเป็นตัวที่ผู้เล่นมีอยู่จริงในเซฟ (กันส่ง id มั่วๆ มา)
function allCharactersOwned(team, saveData) {
  if (!saveData || !saveData.crew) return team.every(id => id === null);
  return team.every(id => id === null || !!saveData.crew[id]);
}

// สร้างข้อมูลทีมของผู้เล่นคนหนึ่งให้คู่ต่อสู้ดู: พลังสู้รบ + ค่าพลังรายตัว + ที่มาของค่าพลัง + อุปกรณ์
// คำนวณฝั่งเซิร์ฟเวอร์ด้วย engine ตัวเดียวกับที่ใช้ตัดสินผลจริง ตัวเลขจึงตรงกับในการต่อสู้
function buildTeamView(gameEngine, save, teamIds) {
  gameEngine.__setPlayerState(save);
  const members = [];
  (teamIds || []).forEach((charId, idx) => {
    if (!charId || !save.crew || !save.crew[charId]) return;
    const saved = save.crew[charId];
    const base = gameEngine.crewGetBaseCharData(charId);
    const stats = gameEngine.calculateCharacterStats(base, saved);
    const level = saved.level || 1;
    const charClass = saved.class || 1;
    const dupes = saved.dupes || 0;
    const passive = (gameEngine.PASSIVES || []).find(p => p.id === base.passive) || null;

    const equipment = [];
    const equipped = saved.equipped || {};
    ['weapon', 'armor', 'accessory'].forEach(slot => {
      const inst = equipped[slot] ? gameEngine.equipmentGetInstance(equipped[slot]) : null;
      if (!inst) return;
      equipment.push({
        slot,
        name: gameEngine.equipmentGetName(inst),
        star: inst.star,
        level: inst.level,
        rolls: gameEngine.equipmentGetEffectiveRolls(inst).map(r => ({ stat: r.stat, kind: r.kind, value: r.effective_value }))
      });
    });

    members.push({
      slot: idx + 1,
      charId,
      name: base.name,
      grade: base.grade,
      role: base.role,
      level,
      maxLevel: gameEngine.getMaxLevel(charClass, dupes),
      charClass,
      dupes,
      levelMultiplier: gameEngine.getLevelValue(1, level),
      classMultiplier: gameEngine.getClassDupeMultiplier(charClass, dupes),
      baseStats: base.stats,
      stats,
      combatPower: gameEngine.calculateCharacterCombatPower(charId),
      passiveName: passive ? passive.name : null,
      passiveDescription: passive ? passive.description : null,
      equipment
    });
  });
  const teamPower = members.reduce((sum, m) => sum + m.combatPower, 0);
  return { members, teamPower };
}

async function handlePvpRequest(req, res, path, method, body, userId, db, gameEngine, adminSecret, sendJson) {
  const now = new Date();

  // ผู้เล่นต้องเคลียร์ด่านทั้งหมดของเกาะที่ 2 ก่อนถึงจะใช้ PVP ได้ (เส้นทางแอดมินไม่เกี่ยว)
  if (path.startsWith('/api/pvp/') && !path.startsWith('/api/pvp/admin/') && userId) {
    if ((await db.getQuarantine(userId)).active) { sendJson(res, 503, { error: 'ระบบไม่พร้อมให้บริการชั่วคราว ลองใหม่ภายหลัง' }); return true; }
    const mySave = await db.getSave(userId);
    if (!isPvpUnlockedSave(mySave)) { sendJson(res, 403, { error: 'PVP ปลดล็อกเมื่อเคลียร์ด่านทั้งหมดของเกาะที่สอง', locked: true }); return true; }
  }

  // ---------- GET /api/pvp/last-battle: บันทึกการต่อสู้ PVP ของเมื่อวาน (แมตช์ที่ตัดสินแล้วล่าสุดของเรา) ----------
  if (path === '/api/pvp/last-battle' && method === 'GET') {
    const seasonInfo = getSeasonInfo(now);
    if (!seasonInfo.isActive || seasonInfo.dayNumber <= 1) { sendJson(res, 200, { available: false, reason: 'ยังไม่มีแมตช์เมื่อวาน' }); return true; }
    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
    const m = await db.getMatchForUserOnDay(seasonStartStr, seasonInfo.dayNumber - 1, userId);
    if (!m || !m.resolved || m.is_bot || m.player_b === null) { sendJson(res, 200, { available: false, reason: 'เมื่อวานไม่มีการต่อสู้กับผู้เล่นให้ดูบันทึก' }); return true; }
    if (!m.battle_log) { sendJson(res, 200, { available: false, reason: 'แมตช์เมื่อวานไม่มีบันทึก (ตัดสินก่อนระบบบันทึกเริ่มทำงาน หรือมีฝ่ายไม่ได้จัดทีมจึงไม่ได้สู้จริง) บันทึกของวันต่อๆ ไปจะดูได้' }); return true; }
    let data;
    try { data = JSON.parse(m.battle_log); } catch (e) { sendJson(res, 200, { available: false, reason: 'อ่านบันทึกไม่ได้' }); return true; }
    const iAmAttacker = m.attacker_id === userId;
    const opponentId = m.player_a === userId ? m.player_b : m.player_a;
    sendJson(res, 200, {
      available: true,
      won: m.winner_id === userId,
      opponentName: await db.getDisplayName(opponentId),
      youWereAttacker: iAmAttacker,
      rounds: data.rounds,
      summary: (data.summary || []).map(s => Object.assign({}, s, { side: (s.side === 'attacker') === iAmAttacker ? 'me' : 'friend' })),
      logs: data.logs || []
    });
    return true;
  }

  // ---------- GET /api/pvp/opponent-team ----------
  // ดูทีมของคู่ต่อสู้ "วันนี้ของตัวเอง" เท่านั้น (ดูของคนอื่นที่ไม่ใช่คู่ไม่ได้) ถ้าเขาซ่อนทีมไว้จะไม่ส่งข้อมูลให้
  if (path === '/api/pvp/opponent-team' && method === 'GET') {
    const seasonInfo = getSeasonInfo(now);
    if (!seasonInfo.isActive) { sendJson(res, 200, { noOpponent: true }); return true; }
    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
    const match = await db.getMatchForUserOnDay(seasonStartStr, seasonInfo.dayNumber, userId);
    if (!match) { sendJson(res, 200, { noOpponent: true }); return true; }
    if (match.is_bot || match.player_b === null) { sendJson(res, 200, { isBot: true }); return true; }
    if (seasonInfo.dayNumber === 1) { sendJson(res, 200, { mystery: true }); return true; }

    const opponentId = match.player_a === userId ? match.player_b : match.player_a;
    const profiles = await db.getAllPvpProfilesForSeason(seasonStartStr);
    const oppProfile = profiles.find(p => p.user_id === opponentId);
    if (!oppProfile) { sendJson(res, 200, { noOpponent: true }); return true; }
    if (oppProfile.hide_today) { sendJson(res, 200, { hidden: true }); return true; }

    const oppSave = await db.getSave(opponentId);
    // ทีมที่จะใช้ต่อสู้จริง: ถ้าคู่แข่งเป็นฝ่ายรุกใช้ attack_team, ฝ่ายรับใช้ defense_team (ตรงกับตอนตัดสินผล)
    const teamIds = match.attacker_id === opponentId ? oppProfile.attack_team : oppProfile.defense_team;
    const view = oppSave ? buildTeamView(gameEngine, oppSave, teamIds) : { members: [], teamPower: 0 };
    sendJson(res, 200, { username: await db.getDisplayName(opponentId), captainLevel: captainLevelOfSave(oppSave), teamPower: view.teamPower, members: view.members });
    return true;
  }

  // ---------- POST /api/pvp/teams ----------
  // ทีมเดียว ใช้ทั้งบุกและตั้งรับ (รวมทีมโจมตี/ตั้งรับเป็นทีมเดียวตามสเปคใหม่)
  if (path === '/api/pvp/teams' && method === 'POST') {
    const team = body.team;
    if (!isValidTeamArray(team)) {
      sendJson(res, 400, { error: 'รูปแบบทีมไม่ถูกต้อง (ต้องเป็นรายการไม่เกิน 5 ช่อง)' }); return true;
    }
    const saveData = await db.getSave(userId);
    if (!allCharactersOwned(team, saveData)) {
      sendJson(res, 400, { error: 'มีตัวละครในทีมที่คุณไม่ได้เป็นเจ้าของ' }); return true;
    }
    const seasonInfo = getSeasonInfo(now);
    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
    await db.ensurePvpProfile(userId, seasonStartStr, PVP_CONFIG.STARTING_POINTS);
    await db.setPvpTeams(userId, team);
    sendJson(res, 200, { success: true }); return true;
  }

  // ---------- POST /api/pvp/hide-team ----------
  if (path === '/api/pvp/hide-team' && method === 'POST') {
    const saveData = await db.getSave(userId);
    if (!saveData || (saveData.gems || 0) < PVP_CONFIG.HIDE_TEAM_COST_GEMS) {
      sendJson(res, 400, { error: `เพชรไม่พอ (ต้องการ ${PVP_CONFIG.HIDE_TEAM_COST_GEMS})` }); return true;
    }
    const seasonInfo = getSeasonInfo(now);
    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
    await db.ensurePvpProfile(userId, seasonStartStr, PVP_CONFIG.STARTING_POINTS);

    saveData.gems -= PVP_CONFIG.HIDE_TEAM_COST_GEMS;
    await db.setSave(userId, saveData);
    await db.setPvpHidden(userId, true);
    sendJson(res, 200, { success: true, gemsRemaining: saveData.gems }); return true;
  }

  // ---------- GET /api/pvp/status ----------
  if (path === '/api/pvp/status' && method === 'GET') {
    const seasonInfo = getSeasonInfo(now);

    if (!seasonInfo.isActive) {
      sendJson(res, 200, {
        season: { isActive: false, isClosedGap: true, nextSeasonStart: seasonInfo.nextSeasonStart }
      }); return true;
    }

    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];

    // เผื่อไว้กรณีไม่มี cron ภายนอกมาเรียก /admin/run-daily-tick เลย (หรือยังไม่ทันถึงเวลา cron วันนี้):
    // ให้ผู้เล่นคนแรกที่เปิดหน้า PVP ของวันนั้นเป็นคนกระตุ้นให้จับคู่/ตัดสินผลของวันทำงานเองอัตโนมัติ
    // ปลอดภัยเรียกซ้ำได้เสมอ (runPvpDailyTick เช็คอยู่แล้วว่าวันนี้จับคู่ไปหรือยัง ไม่ทำงานซ้ำถ้าทำไปแล้ว)
    // ทำให้ระบบทำงานได้เองแม้ไม่ได้ตั้งค่า cron ภายนอกหรือ ADMIN_SECRET เลยก็ตาม
    try {
      await runPvpDailyTick(db, gameEngine, now);
    } catch (e) {
      console.error('เรียก runPvpDailyTick อัตโนมัติจาก /api/pvp/status ไม่สำเร็จ:', e);
    }

    const profile = await db.ensurePvpProfile(userId, seasonStartStr, PVP_CONFIG.STARTING_POINTS);
    const allProfiles = await db.getAllPvpProfilesForSeason(seasonStartStr);
    const ranked = computeRanks(allProfiles.map(p => ({ id: p.user_id, points: p.points, matchesPlayed: p.matches_played })));
    const myRankInfo = ranked.find(r => r.id === userId) || { rank: 'unranked', position: null };

    const todayMatch = await db.getMatchForUserOnDay(seasonStartStr, seasonInfo.dayNumber, userId);
    let todaysOpponent = null;
    if (todayMatch && todayMatch.is_bot) {
      todaysOpponent = { isBot: true };
    } else if (todayMatch && todayMatch.player_b !== null) {
      if (seasonInfo.dayNumber === 1) {
        todaysOpponent = { isMystery: true };
      } else {
        const opponentId = todayMatch.player_a === userId ? todayMatch.player_b : todayMatch.player_a;
        const opponentProfile = allProfiles.find(p => p.user_id === opponentId);
        const opponentHidden = opponentProfile && opponentProfile.hide_today;
        todaysOpponent = {
          isMystery: false,
          username: opponentHidden ? null : await db.getDisplayName(opponentId),
          captainLevel: opponentHidden ? null : ((await db.getCaptainLevels([opponentId]))[opponentId] || 1),
          isHidden: !!opponentHidden,
          youAreAttacker: todayMatch.attacker_id === userId
        };
      }
    }

    let yesterdaysResult = null;
    if (seasonInfo.dayNumber > 1) {
      const yMatch = await db.getMatchForUserOnDay(seasonStartStr, seasonInfo.dayNumber - 1, userId);
      if (yMatch && yMatch.is_bot) {
        yesterdaysResult = yMatch.resolved ? { won: true, vsBot: true, opponentUsername: null } : null;
      } else if (yMatch && yMatch.resolved) {
        const opponentId = yMatch.player_a === userId ? yMatch.player_b : yMatch.player_a;
        yesterdaysResult = {
          won: yMatch.winner_id === userId,
          opponentUsername: opponentId ? await db.getDisplayName(opponentId) : null
        };
      } else if (yMatch && yMatch.player_b === null) {
        yesterdaysResult = { won: null, wasBye: true };
      }
    }

    sendJson(res, 200, {
      season: { isActive: true, dayNumber: seasonInfo.dayNumber, seasonEnd: seasonInfo.seasonEnd },
      points: profile.points,
      rank: myRankInfo.rank,
      position: myRankInfo.position,
      totalPlayers: ranked.length,
      team: profile.attack_team,
      hiddenToday: profile.hide_today,
      todaysOpponent,
      yesterdaysResult
    }); return true;
  }

  // ---------- POST /api/pvp/admin/run-daily-tick (เรียกจาก cron ภายนอก ต้องมี secret ถูกต้อง) ----------
  if (path === '/api/pvp/admin/run-daily-tick' && method === 'POST') {
    const providedSecret = req.headers['x-admin-secret'];
    if (!adminSecret || providedSecret !== adminSecret) {
      sendJson(res, 403, { error: 'ไม่มีสิทธิ์เรียกใช้งานจุดนี้' }); return true;
    }
    const result = await runPvpDailyTick(db, gameEngine, now);
    sendJson(res, 200, result); return true;
  }

  return false; // ไม่ตรงเส้นทางใดใน PVP ให้ app.js ไปแสดง 404 เอง
}

module.exports = { handlePvpRequest };


// ===== app.js =====
// app.js
// ตัวจัดการ request ทั้งหมดของ API — เขียนด้วย Node.js built-in "http" ล้วนๆ ไม่ใช้ Express
// (ตัดสินใจไม่ใช้ Express เพื่อให้ dependency ภายนอกน้อยที่สุด ง่ายต่อการดูแลระยะยาว)
//
// รับ "db" เข้ามาจากข้างนอก (dependency injection) แทนที่จะต่อฐานข้อมูลตรงในไฟล์นี้
// ทำให้ทดสอบ logic ทั้งหมดได้โดยไม่ต้องมีฐานข้อมูลจริง (ดู test/app.test.js)
//
// db ต้องมีฟังก์ชัน (ทั้งหมดเป็น async):
//   getUserByUsername(username) -> {id, username, password_hash, password_salt} หรือ null
//   createUser(username, passwordHash, passwordSalt) -> {id, username} หรือโยน error ถ้าชื่อซ้ำ
//   getSave(userId) -> ข้อมูลเซฟ (object) หรือ null ถ้ายังไม่เคยเซฟ
//   setSave(userId, saveData) -> void





// ---------- กันสแปม/บรุตฟอร์ซแบบง่ายๆ (in-memory, ต่ออินสแตนซ์เดียว) ----------
// จำกัดจำนวนครั้งที่ยิง /api/register หรือ /api/login ได้ต่อ IP ต่อหน้าต่างเวลา
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 10;
const rateLimitMap = new Map(); // ip -> [timestamp, ...]

function isRateLimited(ip) {
  const now = Date.now();
  const attempts = (rateLimitMap.get(ip) || []).filter(t => now - t < RATE_LIMIT_WINDOW_MS);
  attempts.push(now);
  rateLimitMap.set(ip, attempts);
  return attempts.length > RATE_LIMIT_MAX_ATTEMPTS;
}

// ---------- ตัวช่วยอ่าน body เป็น JSON ----------
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooBig = false;
    req.on('data', chunk => {
      if (tooBig) return; // เกินขนาดแล้ว หยุดเก็บเพิ่ม แต่ยังปล่อยให้ request จบตามปกติ
      data += chunk;
      if (data.length > 3 * 1024 * 1024) { // กันส่ง body ใหญ่ผิดปกติ
        tooBig = true;
      }
    });
    req.on('end', () => {
      if (tooBig) return reject(new Error('body too large'));
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (e) {
        reject(new Error('invalid json'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, body) {
  const text = JSON.stringify(body);
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text) });
  res.end(text);
}

function getBearerToken(req) {
  const header = req.headers['authorization'] || '';
  const match = header.match(/^Bearer (.+)$/);
  return match ? match[1] : null;
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

// สร้างตัวจัดการ request หลัก (ใช้กับ http.createServer(handler) ได้ตรงๆ)
// ==========================================
// ระบบเพื่อน + จดหมาย + สู้กับเพื่อน + ลบบัญชีตัวเอง
// ==========================================
const MAX_FRIENDS = 50;
const MAX_FRIEND_REQUESTS_PER_HOUR = 10;
const MAX_MESSAGES_PER_HOUR = 20;
const MAX_MESSAGE_LENGTH = 200;

async function handleSocialRequest(req, res, path, method, searchParams, body, userId, db, gameEngine) {
  const parsePid = (v) => { const n = parseInt(v, 10); return Number.isInteger(n) && String(v).trim().length === 5 ? n : null; };
  const err = (code, msg) => { sendJson(res, code, { error: msg }); return true; };

  // ---- ค้นหาผู้เล่นจากรหัส 5 หลัก: บอกแค่ชื่อกับเลเวล (ไว้ยืนยันก่อนส่งคำเชิญ) ----
  if (path === '/api/players/lookup' && method === 'GET') {
    const target = await db.getUserByPublicId(parsePid(searchParams.get('publicId')));
    if (!target) return err(404, 'ไม่พบผู้เล่นรหัสนี้ ตรวจรหัสอีกครั้ง');
    const lv = await db.getCaptainLevels([target.id]);
    sendJson(res, 200, { username: (await db.getDisplayName(target.id)) || target.username, publicId: target.public_id, captainLevel: lv[target.id] || 1 });
    return true;
  }

  // ---- สรุปสำหรับแถบเมนูหลัก ----
  if (path === '/api/friends/summary' && method === 'GET') {
    db.touchLastSeen(userId).catch(() => {});
    sendJson(res, 200, { friendCount: await db.countFriends(userId), max: MAX_FRIENDS, unreadMail: await db.countUnreadMessages(userId), pendingRequests: await db.countPendingRequests(userId) });
    return true;
  }

  // ---- รายชื่อเพื่อน ----
  if (path === '/api/friends' && method === 'GET') {
    const friends = await db.listFriends(userId);
    const lvMap = await db.getCaptainLevels(friends.map(f => f.id));
    const out = [];
    for (const f of friends) {
      let teamPower = 0;
      try {
        const fs = await db.getSave(f.id);
        if (fs) { gameEngine.__setPlayerState(fs); teamPower = gameEngine.calculateSquadCombatPower(); }
      } catch (e) { teamPower = 0; }
      out.push({ publicId: f.public_id, username: f.username, captainLevel: lvMap[f.id] || 1, lastSeenAt: f.last_seen_at, since: f.since, teamPower });
    }
    sendJson(res, 200, { friends: out, max: MAX_FRIENDS });
    return true;
  }

  // ---- ส่งคำเชิญเป็นเพื่อน ----
  if (path === '/api/friends/request' && method === 'POST') {
    const pid = parsePid(body.publicId);
    if (!pid) return err(400, 'รหัสผู้เล่นต้องเป็นตัวเลข 5 หลัก');
    const target = await db.getUserByPublicId(pid);
    if (!target) return err(404, 'ไม่พบผู้เล่นรหัสนี้ ตรวจรหัสอีกครั้ง');
    if (target.id === userId) return err(400, 'เพิ่มตัวเองเป็นเพื่อนไม่ได้');
    if (await db.areFriends(userId, target.id)) return err(400, `${(await db.getDisplayName(target.id)) || target.username} เป็นเพื่อนของคุณอยู่แล้ว`);
    if (await db.findPendingRequest(userId, target.id)) return err(400, 'เคยส่งคำเชิญไปแล้ว รอเขาตอบรับ');
    if (await db.countRecentRequests(userId) >= MAX_FRIEND_REQUESTS_PER_HOUR) return err(429, 'ส่งคำเชิญบ่อยเกินไป รอสักครู่แล้วลองใหม่');
    if (await db.countFriends(userId) >= MAX_FRIENDS) return err(400, `มีเพื่อนครบ ${MAX_FRIENDS} คนแล้ว`);

    // เขาเชิญเรามาก่อนอยู่แล้ว = ตอบรับให้เลย
    const theirs = await db.findPendingRequest(target.id, userId);
    if (theirs) {
      if (await db.countFriends(target.id) >= MAX_FRIENDS) return err(400, 'เพื่อนของอีกฝ่ายเต็มแล้ว');
      await db.resolveFriendRequest(theirs.id, 'accepted');
      await db.addFriendship(userId, target.id);
      sendJson(res, 200, { success: true, autoAccepted: true, username: (await db.getDisplayName(target.id)) || target.username, publicId: target.public_id });
      return true;
    }
    await db.createFriendRequest(userId, target.id);
    sendJson(res, 200, { success: true, autoAccepted: false, username: (await db.getDisplayName(target.id)) || target.username, publicId: target.public_id });
    return true;
  }

  // ---- ตอบรับ/ปฏิเสธคำเชิญ ----
  if (path === '/api/friends/respond' && method === 'POST') {
    const reqRow = await db.getRequestForUser(parseInt(body.requestId, 10), userId);
    if (!reqRow) return err(404, 'ไม่พบคำเชิญนี้ (อาจถูกตอบไปแล้ว)');
    if (body.accept) {
      if (await db.countFriends(userId) >= MAX_FRIENDS) return err(400, `มีเพื่อนครบ ${MAX_FRIENDS} คนแล้ว`);
      if (await db.countFriends(reqRow.from_user) >= MAX_FRIENDS) return err(400, 'เพื่อนของอีกฝ่ายเต็มแล้ว');
      await db.resolveFriendRequest(reqRow.id, 'accepted');
      await db.addFriendship(userId, reqRow.from_user);
    } else {
      await db.resolveFriendRequest(reqRow.id, 'declined');
    }
    sendJson(res, 200, { success: true });
    return true;
  }

  // ---- ลบเพื่อน ----
  if (path === '/api/friends/remove' && method === 'POST') {
    const target = await db.getUserByPublicId(parsePid(body.publicId));
    if (!target) return err(404, 'ไม่พบผู้เล่นคนนี้');
    await db.removeFriendship(userId, target.id);
    sendJson(res, 200, { success: true });
    return true;
  }

  // ---- ดูทีมหลักของเพื่อน ----
  if (path === '/api/friends/team' && method === 'GET') {
    const target = await db.getUserByPublicId(parsePid(searchParams.get('publicId')));
    if (!target || !(await db.areFriends(userId, target.id))) return err(404, 'ไม่พบเพื่อนคนนี้');
    const save = await db.getSave(target.id);
    if (!save) return err(404, 'เพื่อนยังไม่มีข้อมูลเกม');
    const view = buildTeamView(gameEngine, save, Array.isArray(save.squad) ? save.squad : []);
    sendJson(res, 200, { username: displayNameOf(save, target.username), publicId: target.public_id, captainLevel: captainLevelOfSave(save), lastSeenAt: target.last_seen_at, teamPower: view.teamPower, members: view.members });
    return true;
  }

  // ---- สู้กับเพื่อน (ทีมหลักของทั้งสองฝ่าย ไม่ได้แต้ม ไม่มีรางวัล) ----
  if (path === '/api/friends/battle' && method === 'POST') {
    const target = await db.getUserByPublicId(parsePid(body.publicId));
    if (!target || !(await db.areFriends(userId, target.id))) return err(404, 'ไม่พบเพื่อนคนนี้');
    const mySave = await db.getSave(userId);
    const friendSave = await db.getSave(target.id);
    const mySquad = extractSquadData(mySave, mySave && mySave.squad);
    const friendSquad = extractSquadData(friendSave, friendSave && friendSave.squad);
    if (mySquad.length === 0) return err(400, 'คุณยังไม่ได้จัดทีมหลัก (หรือเซฟยังไม่ถูกส่งขึ้นเซิร์ฟเวอร์) ลองจัดทีมแล้วรอสักครู่');
    if (friendSquad.length === 0) return err(400, 'เพื่อนยังไม่ได้จัดทีมหลัก');
    const result = gameEngine.runPvpCombat(mySquad, friendSquad, extractPlayerStateForEngine(mySave), extractPlayerStateForEngine(friendSave));
    const summary = Object.keys(result.stats || {}).map(k => {
      const s = result.stats[k];
      return { side: s.side === 'player' ? 'me' : 'friend', name: s.name, dmgDealt: Math.round(s.dmg_dealt), dmgTaken: Math.round(s.dmg_taken), healGiven: Math.round(s.heal_given), stun: s.stun_count || 0, silence: s.silence_count || 0, dodge: s.dodge_count || 0, prevented: Math.round(s.dmg_prevented || 0), healProcCount: s.heal_proc_count || 0, healProcTotal: Math.round(s.heal_proc_total || 0), extraTurns: s.extra_turn_count || 0, eliminatedRound: s.elim_round };
    });
    sendJson(res, 200, { won: !!result.isAttackerWin, rounds: result.totalRounds, friendName: displayNameOf(friendSave, target.username), summary, logs: (result.logs || []).slice(0, 600) });
    return true;
  }

  // ---- กล่องจดหมาย ----
  if (path === '/api/mail' && method === 'GET') {
    const requests = await db.listPendingRequests(userId);
    const messages = await db.listMessages(userId);
    const reqLv = await db.getCaptainLevels(requests.map(r => r.from_user));
    sendJson(res, 200, {
      requests: requests.map(r => ({ id: r.id, fromPublicId: r.from_public_id, fromUsername: r.from_username, fromCaptainLevel: reqLv[r.from_user] || 1, createdAt: r.created_at })),
      messages: messages.map(m => ({ id: m.id, fromPublicId: m.from_public_id, fromUsername: m.from_username, body: m.body, createdAt: m.created_at, read: !!m.read_at }))
    });
    return true;
  }
  if (path === '/api/mail/read-all' && method === 'POST') { await db.markAllMessagesRead(userId); sendJson(res, 200, { success: true }); return true; }
  if (path === '/api/mail/delete' && method === 'POST') { await db.deleteMessage(parseInt(body.messageId, 10), userId); sendJson(res, 200, { success: true }); return true; }
  if (path === '/api/mail/send' && method === 'POST') {
    const target = await db.getUserByPublicId(parsePid(body.publicId));
    if (!target || !(await db.areFriends(userId, target.id))) return err(404, 'ส่งได้เฉพาะเพื่อนเท่านั้น');
    const text = typeof body.body === 'string' ? body.body.trim() : '';
    if (!text) return err(400, 'พิมพ์ข้อความก่อน');
    if (text.length > MAX_MESSAGE_LENGTH) return err(400, `ข้อความยาวเกิน ${MAX_MESSAGE_LENGTH} ตัวอักษร`);
    if (await db.countRecentMessages(userId) >= MAX_MESSAGES_PER_HOUR) return err(429, 'ส่งข้อความบ่อยเกินไป รอสักครู่แล้วลองใหม่');
    await db.createMessage(userId, target.id, text);
    sendJson(res, 200, { success: true });
    return true;
  }

  // ---- ลบบัญชีตัวเอง (ต้องยืนยันรหัสผ่านของตัวเอง) ----
  if (path === '/api/account/delete' && method === 'POST') {
    const me = await db.getUserById(userId);
    if (!me) return err(404, 'ไม่พบบัญชี');
    if (typeof body.password !== 'string' || !verifyPassword(body.password, me.password_salt, me.password_hash)) {
      return err(403, 'รหัสผ่านไม่ถูกต้อง');
    }
    await db.deleteUserCascade(userId);
    sendJson(res, 200, { success: true });
    return true;
  }

  return false;
}

function createRequestHandler(db, secret, gameEngine, adminSecret) {
  if (!secret) throw new Error('ต้องมี secret สำหรับเซ็น token (ห้าม hardcode ในโค้ด ใช้ environment variable)');

  return async function handler(req, res) {
    try {
      const url = new URL(req.url, 'http://localhost');
      const path = url.pathname;
      const ip = getClientIp(req);

      // CORS พื้นฐาน (เกมเรียกจาก origin อื่นได้ - ปรับ origin ให้เจาะจงโดเมนจริงตอน deploy จริง)
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
      }

      // ---------- POST /api/register ----------
      if (path === '/api/register' && req.method === 'POST') {
        if (isRateLimited(ip)) return sendJson(res, 429, { error: 'ลองบ่อยเกินไป รอสักครู่แล้วลองใหม่' });

        const body = await readJsonBody(req);
        const usernameError = validateUsername(body.username);
        if (usernameError) return sendJson(res, 400, { error: usernameError });
        const passwordError = validatePassword(body.password);
        if (passwordError) return sendJson(res, 400, { error: passwordError });

        const username = body.username.trim();
        const existing = await db.getUserByUsername(username);
        if (existing) return sendJson(res, 409, { error: 'มีชื่อผู้ใช้นี้แล้ว' });

        const { salt, hash } = hashPassword(body.password);
        const user = await db.createUser(username, hash, salt);
        const token = generateToken({ userId: user.id, username: user.username }, secret);
        return sendJson(res, 201, { token, username: user.username, publicId: user.public_id });
      }

      // ---------- POST /api/login ----------
      if (path === '/api/login' && req.method === 'POST') {
        if (isRateLimited(ip)) return sendJson(res, 429, { error: 'ลองบ่อยเกินไป รอสักครู่แล้วลองใหม่' });

        const body = await readJsonBody(req);
        if (typeof body.username !== 'string' || typeof body.password !== 'string') {
          return sendJson(res, 400, { error: 'กรอกชื่อผู้ใช้และรหัสผ่านให้ครบ' });
        }
        const user = await db.getUserByUsername(body.username.trim());
        if (!user || !verifyPassword(body.password, user.password_salt, user.password_hash)) {
          return sendJson(res, 401, { error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
        }
        const token = generateToken({ userId: user.id, username: user.username }, secret);
        if (!user.public_id) user.public_id = await db.assignPublicId(user.id);
        db.touchLastSeen(user.id).catch(() => {});
        return sendJson(res, 200, { token, username: user.username, publicId: user.public_id });
      }

      // ---------- ทุกเส้นทางถัดจากนี้ต้องยืนยันตัวตนก่อน ----------
      // ---------- โค้ดเติมเพชร/ให้เพชรผู้เล่นคนอื่น ที่ซ่อนอยู่ในหน้าข้อมูลกัปตันของตัวเกม ----------
      // ปลอดภัยเพราะเช็คฝั่งเซิร์ฟเวอร์ว่า username ของคนที่กำลังพิมพ์โค้ดอยู่ อยู่ใน ADMIN_USERNAMES หรือไม่
      // ผู้เล่นทั่วไปที่ไม่ได้อยู่ใน allow-list พิมพ์โค้ดอะไรก็ได้ "โค้ดไม่ถูกต้อง" เหมือนกันหมด แม้จะเจอช่องลับนี้ก็ตาม
      if (path === '/api/self-service/redeem-code' && req.method === 'POST') {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) { sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' }); return true; }

        const requesterUsername = await db.getUsername(payload.userId);
        if (!ADMIN_USERNAMES.includes(requesterUsername)) {
          // ข้อความเดียวกับตอนพิมพ์โค้ดผิด เพื่อไม่ให้คนทั่วไปรู้ว่ามี allow-list ซ่อนอยู่
          sendJson(res, 400, { error: 'โค้ดไม่ถูกต้อง' }); return true;
        }

        const body = await readJsonBody(req);
        const code = typeof body.code === 'string' ? body.code.trim() : '';
        const match = /^j(\d+)$/i.exec(code);
        if (!match) { sendJson(res, 400, { error: 'โค้ดไม่ถูกต้อง' }); return true; }
        const gemAmount = parseInt(match[1], 10);
        if (!gemAmount || gemAmount <= 0) { sendJson(res, 400, { error: 'โค้ดไม่ถูกต้อง' }); return true; }

        const targetUsername = typeof body.targetUsername === 'string' && body.targetUsername.trim()
          ? body.targetUsername.trim() : requesterUsername;
        const targetUser = await db.getUserByUsername(targetUsername);
        if (!targetUser) { sendJson(res, 404, { error: 'ไม่พบผู้เล่นชื่อนี้' }); return true; }

        await db.createGrant(targetUser.id, { source: 'gm', gems: gemAmount, note: `โค้ด GM โดย ${requesterUsername}` });
        sendJson(res, 200, { success: true, targetUsername: targetUser.username, gemsGranted: gemAmount, queued: true });
        return true;
      }

      // ---------- เพื่อน / จดหมาย / ลบบัญชีตัวเอง ----------
      if (path.startsWith('/api/friends') || path.startsWith('/api/mail') || path.startsWith('/api/players/') || path === '/api/account/delete') {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
        const body = req.method === 'POST' ? await readJsonBody(req) : {};
        const handled = await handleSocialRequest(req, res, path, req.method, url.searchParams, body, payload.userId, db, gameEngine);
        if (handled) return;
      }

      // ---------- กล่องรับของ: ตัวเกมมาถามว่ามีอะไรค้างส่งไหม แล้วบวกเองและกดยืนยันกลับ ----------
      if (path === '/api/inbox' && req.method === 'GET') {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
        db.touchLastSeen(payload.userId).catch(() => {});
        const grants = await db.getPendingGrants(payload.userId);
        return sendJson(res, 200, { grants });
      }
      if (path === '/api/inbox/ack' && req.method === 'POST') {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
        const body = await readJsonBody(req);
        const acks = Array.isArray(body.acks) ? body.acks.filter(a => a && Number.isInteger(a.id)).slice(0, 50) : [];
        const acked = await db.ackGrants(payload.userId, acks);
        return sendJson(res, 200, { success: true, acked });
      }

      // ---------- ดูทีมหลัก (ทีมที่จัดไว้เล่นด่าน ไม่ใช่ทีม PVP) ของผู้เล่นในอันดับ ----------
      if (path === '/api/leaderboard/squad' && req.method === 'GET') {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
        const targetId = parseInt(url.searchParams.get('user'), 10);
        if (!Number.isInteger(targetId)) return sendJson(res, 400, { error: 'ระบุผู้เล่นไม่ถูกต้อง' });
        const targetSave = await db.getSave(targetId);
        if (!targetSave) return sendJson(res, 404, { error: 'ไม่พบข้อมูลผู้เล่นคนนี้' });
        const view = buildTeamView(gameEngine, targetSave, Array.isArray(targetSave.squad) ? targetSave.squad : []);
        return sendJson(res, 200, { username: displayNameOf(targetSave, await db.getUsername(targetId)), captainLevel: captainLevelOfSave(targetSave), teamPower: view.teamPower, members: view.members });
      }

      // ---------- กาชา: เซิร์ฟเวอร์สุ่มเอง หักเพชรเอง จดสมุดบัญชี แล้วส่งผลกลับให้เกมแสดง ----------
      if (path === '/api/gacha/pull' && req.method === 'POST') {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
        const body = await readJsonBody(req);
        const times = parseInt(body.times, 10);
        const release = await acquireUserLock(payload.userId);
        try {
          if ((await db.getQuarantine(payload.userId)).active) return sendJson(res, 503, { error: 'ระบบไม่พร้อมให้บริการชั่วคราว ลองใหม่ภายหลัง' });
          const save = await db.getSave(payload.userId);
          if (!save) return sendJson(res, 400, { error: 'เซิร์ฟเวอร์ยังไม่มีเซฟของคุณ ลองใหม่อีกครั้ง' });
          const gemsBefore = Number(save.gems) || 0;
          try { if (await db.getStarterDone(payload.userId)) save.has_completed_starter_pull = true; } catch (e) { /* ข้าม */ }
          gameEngine.__setPlayerState(save);
          const isEquip = body.kind === 'equip';
          const out = isEquip ? gameEngine.gachaServerEquipPull(save, times, body.slotFilter) : gameEngine.gachaServerCharPull(save, times, !!body.starter);
          if (out.error) return sendJson(res, 400, { error: out.error });
          await db.setSave(payload.userId, save);
          if (save.has_completed_starter_pull) { try { await db.setStarterDone(payload.userId); } catch (e) { /* ข้าม */ } }
          const gemsAfter = Number(save.gems) || 0;
          if (gemsAfter !== gemsBefore) {
            try { await db.addLedger(payload.userId, gemsAfter - gemsBefore, gemsAfter, 'gacha_spend', { kind: isEquip ? 'equip' : 'char', times: body.starter ? 1 : times, starter: !!body.starter }); } catch (e) { /* ข้าม */ }
          }
          const patch = { gems: save.gems, has_completed_starter_pull: !!save.has_completed_starter_pull, gacha_pulls_completed: save.gacha_pulls_completed || 0 };
          if (isEquip) patch.equipment_inventory = save.equipment_inventory;
          else { patch.crew = save.crew; patch.pirate_spirit = (save.inventory && save.inventory.pirate_spirit) || {}; }
          return sendJson(res, 200, { success: true, queue: out.queue || null, results: out.results || null, patch });
        } finally { release(); }
      }

      if (path === '/api/captain-name' && req.method === 'POST') {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
        const body = await readJsonBody(req);
        const release = await acquireUserLock(payload.userId);
        try {
          const existing = await db.getCaptainName(payload.userId);
          if (existing) {
            if (captainNameKey(existing) === captainNameKey(body.name)) return sendJson(res, 200, { success: true, name: existing });
            return sendJson(res, 400, { error: 'เปลี่ยนชื่อกัปตันไม่ได้', code: 'name_locked' });
          }
          const r = await tryClaimCaptainName(db, payload.userId, body.name);
          if (!r.ok) return sendJson(res, 409, { error: r.error, code: 'name_taken' });
          return sendJson(res, 200, { success: true, name: r.name });
        } finally { release(); }
      }

      if (path === '/api/save' && (req.method === 'GET' || req.method === 'POST')) {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });

        if (req.method === 'GET') {
          const save = await db.getSave(payload.userId);
          db.touchLastSeen(payload.userId).catch(() => {});
          return sendJson(res, 200, { save: save || null, publicId: await db.getPublicId(payload.userId) });
        }

        // POST /api/save
        const body = await readJsonBody(req);
        const releaseLock = await acquireUserLock(payload.userId);
        try {
        const saveError = validateSavePayload(body.save);
        if (saveError) return sendJson(res, 400, { error: saveError });
        // ตรวจเทียบกับเซฟเดิมบนเซิร์ฟเวอร์ (กันแก้เพชร/ตัวละครผ่านเซฟที่ส่งขึ้นมา)
        const prevSave = await db.getSave(payload.userId);
        const guardState = await db.getGuardState(payload.userId);
        const quarantine = await db.getQuarantine(payload.userId);
        const num = v => (v !== null && v !== undefined ? Number(v) : undefined);
        const verdict = checkSaveAgainstPrevious(prevSave, body.save, {
          budget: guardState ? num(guardState.budget) : undefined,
          crewBudget: guardState ? num(guardState.crewBudget) : undefined,
          dupeBudget: guardState ? num(guardState.dupeBudget) : undefined,
          spiritBudget: guardState ? num(guardState.spiritBudget) : undefined,
          hoursSince: guardState && guardState.at ? (Date.now() - new Date(guardState.at).getTime()) / 3600000 : 0,
          grantGems: await db.getRecentGrantGems(payload.userId),
          quarantined: quarantine.active
        });
        // ความเสี่ยงอัตโนมัติ: บวกคะแนนตามเหตุการณ์ ถึงเกณฑ์ = จำกัดบัญชีเอง (ไม่ต้องให้ GM ตรวจ)
        if (verdict.risk > 0) {
          try {
            const rr = await db.addRisk(payload.userId, verdict.risk, QUARANTINE_SCORE, QUARANTINE_DAYS);
            if (rr.newlyQuarantined) await db.addFlag(payload.userId, 'auto_quarantine', { score: Math.round(rr.score), days: QUARANTINE_DAYS });
          } catch (e) { /* ข้าม */ }
        }
        for (const f of verdict.flags) { try { await db.addFlag(payload.userId, f.kind, f.detail); } catch (e) { /* รายงานพลาดไม่ควรทำให้เซฟพัง */ } }
        const prevGems = prevSave ? (Number(prevSave.gems) || 0) : 0;
        const newGems = Number(body.save && body.save.gems);
        const gemDelta = Number.isFinite(newGems) ? Math.trunc(newGems) - Math.trunc(prevGems) : 0;
        if (verdict.reject) {
          try { await db.addLedger(payload.userId, gemDelta, prevGems, 'rejected', { attemptedGems: Number.isFinite(newGems) ? newGems : null }); } catch (e) { /* ข้าม */ }
          return sendJson(res, 409, { error: 'ซิงค์ข้อมูลไม่สำเร็จ', code: 'save_rejected' });
        }
        // ชื่อกัปตัน: เซิร์ฟเวอร์ถือชื่อจริง เซฟที่ส่งมาแก้ชื่อเองไม่ได้ / ผู้เล่นเดิมที่มีชื่อแต่ยังไม่เคยจดจะจดชื่อให้ตอนนี้ (ซ้ำ = ต้องตั้งใหม่)
        try {
          const srvName = await db.getCaptainName(payload.userId);
          const incoming = body.save && typeof body.save.player_name === 'string' ? body.save.player_name : '';
          if (srvName) { body.save.player_name = srvName; }
          else if (incoming.trim()) {
            const cr = await tryClaimCaptainName(db, payload.userId, incoming);
            if (!cr.ok) return sendJson(res, 409, { error: cr.error, code: 'name_taken' });
            body.save.player_name = cr.name;
          }
        } catch (e) { /* ตรวจชื่อพลาด ไม่ให้เซฟพัง */ }
        // รางวัลครั้งเดียว: ห้ามขาดรายการที่เคยรับ / ห้ามรับขั้นชื่อเสียงที่ยังไม่ถึงเกณฑ์
        let onceKeysToStore = null;
        try {
          const storedKeys = await db.getOnceKeys(payload.userId);
          const oc = checkOnceClaims(storedKeys, body.save);
          if (oc.missing.length || oc.invalid.length) {
            const kind = oc.missing.length ? 'once_unclaim' : 'once_invalid';
            try {
              const rr = await db.addRisk(payload.userId, RISK_WEIGHTS[kind] + RISK_WEIGHTS.rejected_extra, QUARANTINE_SCORE, QUARANTINE_DAYS);
              if (rr.newlyQuarantined) await db.addFlag(payload.userId, 'auto_quarantine', { score: Math.round(rr.score), days: QUARANTINE_DAYS });
            } catch (e) { /* ข้าม */ }
            try { await db.addFlag(payload.userId, kind, { missing: oc.missing.slice(0, 10), invalid: oc.invalid.slice(0, 10) }); } catch (e) { /* ข้าม */ }
            try { await db.addLedger(payload.userId, gemDelta, prevGems, 'rejected', { attemptedGems: Number.isFinite(newGems) ? newGems : null, once: kind }); } catch (e) { /* ข้าม */ }
            return sendJson(res, 409, { error: 'ซิงค์ข้อมูลไม่สำเร็จ', code: 'save_rejected' });
          }
          onceKeysToStore = oc.keys;
        } catch (e) { /* ตรวจพลาด ไม่ให้เซฟพัง */ }
        // ผู้ช่วยคนแรกสุ่มได้ครั้งเดียวต่อบัญชี: เซิร์ฟเวอร์จำเอง ต่อให้เซฟที่ส่งมาแก้ธงเป็น "ยังไม่เคยสุ่ม" ก็ไม่เชื่อ
        try {
          if (body.save && body.save.has_completed_starter_pull) await db.setStarterDone(payload.userId);
          else if (body.save && await db.getStarterDone(payload.userId)) body.save.has_completed_starter_pull = true;
        } catch (e) { /* ข้าม */ }
        await db.setSave(payload.userId, body.save);
        if (onceKeysToStore) { try { await db.setOnceKeys(payload.userId, onceKeysToStore); } catch (e) { /* ข้าม */ } }
        try { await db.setGuardState(payload.userId, verdict.newBudgets || { gems: verdict.newBudget }); } catch (e) { /* ไม่ให้เซฟพังเพราะตัวตรวจโกง */ }
        if (gemDelta !== 0) {
          try { await db.addLedger(payload.userId, gemDelta, newGems, !prevSave ? 'first_upload' : (gemDelta > 0 ? 'game_gain' : 'game_spend'), gemDelta > 0 ? { earnedByGame: verdict.earnedByGame } : null); } catch (e) { /* ข้าม */ }
        }
        return sendJson(res, 200, { success: true });
        } finally { releaseLock(); }
      }

      // ---------- เส้นทาง PVP ทั้งหมด (/api/pvp/...) ----------
      if (path.startsWith('/api/pvp/')) {
        if (path === '/api/pvp/admin/run-daily-tick') {
          const body = req.method === 'POST' ? await readJsonBody(req) : {};
          const handled = await handlePvpRequest(req, res, path, req.method, body, null, db, gameEngine, adminSecret, sendJson);
          if (handled) return;
        } else {
          const token = getBearerToken(req);
          const payload = token ? verifyToken(token, secret) : null;
          if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
          const body = req.method === 'POST' ? await readJsonBody(req) : {};
          const handled = await handlePvpRequest(req, res, path, req.method, body, payload.userId, db, gameEngine, adminSecret, sendJson);
          if (handled) return;
        }
      }

      // ---------- เส้นทาง Leaderboard ทั้งหมด (/api/leaderboard/...) ----------
      if (path.startsWith('/api/leaderboard/')) {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
        const handled = await handleLeaderboardRequest(req, res, path, req.method, payload.userId, db, gameEngine, sendJson, url.searchParams.get('limit'));
        if (handled) return;
      }

      // ---------- เส้นทางเติมเงิน (/api/topup/...) ----------
      if (path.startsWith('/api/topup/')) {
        if (path === '/api/topup/info' || path.startsWith('/api/topup/admin/')) {
          // /info เป็นข้อมูลสาธารณะ (แค่บัญชีธนาคาร ไม่มีอะไรอ่อนไหว), /admin/* ใช้ adminSecret แทน user token
          const body = req.method === 'POST' ? await readJsonBody(req) : {};
          const handled = await handlePaymentRequest(req, res, path, req.method, body, null, db, adminSecret, sendJson);
          if (handled) return;
        } else {
          const token = getBearerToken(req);
          const payload = token ? verifyToken(token, secret) : null;
          if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });
          const body = req.method === 'POST' ? await readJsonBody(req) : {};
          const handled = await handlePaymentRequest(req, res, path, req.method, body, payload.userId, db, adminSecret, sendJson);
          if (handled) return;
        }
      }

      // ---------- GM (ทุกจุดข้างล่างต้องมี x-admin-secret) ----------
      if (path.startsWith('/api/admin/')) {
        // ผ่านได้ 2 ทาง: (1) ล็อกอินด้วยบัญชีใน ADMIN_USERNAMES (ส่ง token มาใน Authorization) หรือ (2) ส่ง x-admin-secret ที่ตรงกับ ADMIN_SECRET (ถ้าตั้งไว้)
        let isAdmin = false;
        const adminToken = getBearerToken(req);
        const adminPayload = adminToken ? verifyToken(adminToken, secret) : null;
        if (adminPayload) {
          const adminName = await db.getUsername(adminPayload.userId);
          isAdmin = ADMIN_USERNAMES.includes(adminName);
        }
        const providedSecret = req.headers['x-admin-secret'];
        if (!isAdmin && adminSecret && providedSecret === adminSecret) isAdmin = true;
        if (!isAdmin) { return sendJson(res, 403, { error: 'ไม่มีสิทธิ์เรียกใช้งานจุดนี้ (ต้องล็อกอินด้วยบัญชีแอดมิน)' }); }
        const body = req.method === 'POST' ? await readJsonBody(req) : {};

        // หาผู้เล่นจากรหัส 5 หลัก หรือชื่อผู้ใช้
        const findTarget = async () => {
          const pid = parseInt(body.publicId, 10);
          if (Number.isInteger(pid) && String(body.publicId).trim() !== '') return await db.getUserByPublicId(pid);
          const uname = typeof body.username === 'string' ? body.username.trim() : '';
          return uname ? await db.getUserByUsername(uname) : null;
        };

        // ---- เติมเงินตามแพ็กเกจ: เลือกราคา เพชรคิดจากตารางในเซิร์ฟเวอร์ (ไม่ต้องพิมพ์จำนวนเอง กันพิมพ์ผิด) ----
        if (path === '/api/admin/topup-packages' && req.method === 'POST') {
          return sendJson(res, 200, { packages: TOPUP_PACKAGES });
        }
        if (path === '/api/admin/topup' && req.method === 'POST') {
          const pkg = TOPUP_PACKAGES.find(p => p.baht === parseInt(body.baht, 10));
          if (!pkg) return sendJson(res, 400, { error: 'ไม่มีแพ็กเกจราคานี้' });
          const user = await findTarget();
          if (!user) return sendJson(res, 404, { error: 'ไม่พบผู้เล่นคนนี้ (ตรวจรหัส 5 หลัก)' });
          const g = await db.createGrant(user.id, { source: 'topup', gems: pkg.gems, note: `เติมเงิน ${pkg.baht} บาท` });
          return sendJson(res, 200, { success: true, grantId: g.id, username: user.username, publicId: user.public_id, baht: pkg.baht, gems: pkg.gems, lastSeenAt: user.last_seen_at || null });
        }

        // ---- โอนเพชร/ดับลูน: ลงกล่องรับของ ผู้เล่นได้รับตอนเกมเช็คกล่อง (ออนไลน์อยู่ = ภายในไม่กี่วินาที, ออฟไลน์ = ตอนเข้าเกมครั้งหน้า) ----
        if (path === '/api/admin/grant-resources' && req.method === 'POST') {
          const gemsDelta = Number.isFinite(body.gems) ? Math.trunc(body.gems) : 0;
          const doubloonsDelta = Number.isFinite(body.doubloons) ? Math.trunc(body.doubloons) : 0;
          if (!gemsDelta && !doubloonsDelta) return sendJson(res, 400, { error: 'ต้องระบุจำนวนเพชรหรือดับลูนอย่างน้อยหนึ่งอย่าง' });
          const user = await findTarget();
          if (!user) return sendJson(res, 404, { error: 'ไม่พบผู้เล่นคนนี้ (ตรวจรหัส 5 หลักหรือชื่อผู้ใช้)' });
          const g = await db.createGrant(user.id, { source: 'gm', gems: gemsDelta, doubloons: doubloonsDelta, note: typeof body.note === 'string' ? body.note.slice(0, 200) : null });
          return sendJson(res, 200, { success: true, grantId: g.id, username: user.username, publicId: user.public_id, queued: true, lastSeenAt: user.last_seen_at || null });
        }

        // ---- ประวัติการโอน + สถานะล่าสุดของผู้เล่นคนนี้ (เพชรในเซฟล่าสุดที่เซิร์ฟเวอร์รู้) ----
        if (path === '/api/admin/grant-history' && req.method === 'POST') {
          const user = await findTarget();
          if (!user) return sendJson(res, 404, { error: 'ไม่พบผู้เล่นคนนี้' });
          const save = await db.getSave(user.id);
          const history = await db.getGrantHistory(user.id, 30);
          return sendJson(res, 200, {
            username: user.username, publicId: user.public_id, lastSeenAt: user.last_seen_at || null,
            currentGems: save ? (save.gems || 0) : null, currentDoubloons: save ? (save.doubloons || 0) : null,
            history
          });
        }

        // ---- สมุดบัญชีเพชรของผู้เล่นคนหนึ่ง ----
        if (path === '/api/admin/gem-ledger' && req.method === 'POST') {
          const user = await findTarget();
          if (!user) return sendJson(res, 404, { error: 'ไม่พบผู้เล่นคนนี้' });
          const rows = await db.listLedger(user.id, 150);
          const save = await db.getSave(user.id);
          return sendJson(res, 200, { username: user.username, publicId: user.public_id, currentGems: save ? (save.gems || 0) : null, rows });
        }

        // ---- สำรองข้อมูล: ดาวน์โหลดเซฟของผู้เล่นทุกคน (ไม่รวมรหัสผ่าน) ----
        if (path === '/api/admin/export-saves' && req.method === 'POST') {
          const rows = await db.exportAllSaves();
          return sendJson(res, 200, { exportedAt: new Date().toISOString(), count: rows.length, players: rows.map(r => ({ publicId: r.public_id, username: r.username, updatedAt: r.updated_at, save: r.save_data })) });
        }

        // ---- กู้คืนเซฟผู้เล่นคนเดียวจากไฟล์สำรอง ----
        if (path === '/api/admin/restore-save' && req.method === 'POST') {
          const user = await findTarget();
          if (!user) return sendJson(res, 404, { error: 'ไม่พบผู้เล่นคนนี้' });
          const err = validateSavePayload(body.save);
          if (err) return sendJson(res, 400, { error: err });
          const before = await db.getSave(user.id);
          await db.setSave(user.id, body.save);
          try { await db.setOnceKeys(user.id, extractOnceKeys(body.save)); } catch (e) { /* ข้าม */ }
          try { await db.setGuardState(user.id, { gems: SAVE_GUARD.BUDGET_CAP, crew: SAVE_GUARD.CREW_CAP, dupes: SAVE_GUARD.DUPE_CAP, spirits: SAVE_GUARD.SPIRIT_CAP }); } catch (e) { /* ข้าม */ }
          try { await db.addLedger(user.id, (Number(body.save.gems) || 0) - (before ? Number(before.gems) || 0 : 0), Number(body.save.gems) || 0, 'admin_restore', null); } catch (e) { /* ข้าม */ }
          return sendJson(res, 200, { success: true, username: user.username, publicId: user.public_id });
        }

        // ---- ปลดจำกัดบัญชี (กรณีระบบอัตโนมัติจำกัดผิดคน) ----
        if (path === '/api/admin/clear-quarantine' && req.method === 'POST') {
          const user = await findTarget();
          if (!user) return sendJson(res, 404, { error: 'ไม่พบผู้เล่นคนนี้' });
          await db.clearQuarantine(user.id);
          return sendJson(res, 200, { success: true, username: user.username, publicId: user.public_id });
        }

        // ---- รายงานเซฟน่าสงสัย (ตรวจโกง) ----
        if (path === '/api/admin/flags' && req.method === 'POST') {
          const flags = await db.listFlags(50);
          return sendJson(res, 200, { flags });
        }

        // ---- รายชื่อผู้เล่นทั้งหมด ----
        if (path === '/api/admin/users' && req.method === 'POST') {
          const users = await db.getUsersOverview();
          return sendJson(res, 200, { users });
        }

        // ---- ลบบัญชี: ต้องใส่รหัสยืนยันด้วยทุกครั้ง ----
        if (path === '/api/admin/delete-user' && req.method === 'POST') {
          const user = await findTarget();
          if (!user) return sendJson(res, 404, { error: 'ไม่พบผู้เล่นคนนี้' });
          if (ADMIN_USERNAMES.includes(user.username)) return sendJson(res, 400, { error: 'ลบบัญชี GM ไม่ได้' });
          await db.deleteUserCascade(user.id);
          return sendJson(res, 200, { success: true, deleted: { username: user.username, publicId: user.public_id } });
        }

        return sendJson(res, 404, { error: 'ไม่พบเส้นทางนี้' });
      }

      // ---------- health check เผื่อ hosting ping เช็คว่าเซิร์ฟเวอร์ยังทำงานอยู่ ----------
      if (path === '/api/health' && req.method === 'GET') {
        return sendJson(res, 200, { status: 'ok' });
      }

      return sendJson(res, 404, { error: 'ไม่พบเส้นทางนี้' });
    } catch (err) {
      if (err.message === 'invalid json' || err.message === 'body too large') {
        return sendJson(res, 400, { error: 'ข้อมูลที่ส่งมาไม่ถูกต้อง' });
      }
      console.error('Unhandled server error:', err);
      return sendJson(res, 500, { error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' });
    }
  };
}

module.exports = { createRequestHandler };


// ===== index.js (entrypoint) =====
// index.js
// จุดเริ่มต้นเซิร์ฟเวอร์จริง — รันด้วยคำสั่ง: node index.js
// ต้องตั้งค่า environment variables ก่อนรัน (ดู .env.example):
//   DATABASE_URL  - connection string ของ Postgres (Render สร้างให้อัตโนมัติตอนสร้าง Postgres database)
//   AUTH_SECRET   - ข้อความลับสุ่มยาวๆ ใช้เซ็น token (ห้ามบอกใคร ห้าม commit ขึ้น git)
//   PORT          - พอร์ตที่จะรัน (Render ตั้งให้อัตโนมัติ ไม่ต้องกำหนดเอง)




const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const AUTH_SECRET = process.env.AUTH_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET; // ใช้เรียก /api/pvp/admin/run-daily-tick จาก cron ภายนอก

// ชื่อผู้ใช้ (username ตอนสมัคร ไม่ใช่ชื่อกัปตัน) ที่อนุญาตให้ใช้ "โค้ดเติมเพชร" ที่ซ่อนอยู่ในหน้าข้อมูลกัปตันของตัวเกมได้
// ต้องแก้เป็นชื่อ username จริงของบัญชีคุณ (และเพื่อนที่ไว้ใจ ถ้ามี) ก่อน deploy ไม่งั้นโค้ดนี้จะใช้งานไม่ได้เลย (ตั้งใจไว้แบบนั้น เพื่อไม่ให้เป็นช่องโหว่)
// คนอื่นที่ไม่อยู่ในลิสต์นี้ พิมพ์โค้ดถูกแค่ไหนก็จะได้แค่ข้อความ "โค้ดไม่ถูกต้อง" เหมือนกันหมด ไม่รู้เลยว่ามีระบบนี้อยู่
// บัญชีที่เป็นแอดมิน (ชื่อผู้ใช้ตัวพิมพ์เล็ก) — ล็อกอินด้วยบัญชีเหล่านี้ก็ใช้สิทธิ์ GM ได้ทันที ไม่ต้องตั้ง ADMIN_SECRET
// ⚠ ต้องสมัครบัญชีชื่อเหล่านี้ไว้เองก่อน ไม่งั้นคนอื่นสมัครชื่อนี้แล้วจะได้สิทธิ์แอดมินไปด้วย
// แพ็กเกจเติมเงิน (บาท → เพชร) ที่หน้า GM ใช้ — แก้ราคาที่นี่ที่เดียว (ตารางในเกมฝั่งผู้เล่น TOPUP_PACKAGES ต้องตรงกัน)
const TOPUP_PACKAGES = [
  { baht: 30, gems: 50 },
  { baht: 90, gems: 155 },
  { baht: 150, gems: 265 },
  { baht: 300, gems: 550 }
];

const ADMIN_USERNAMES = [
  "kevin",
  "monalisa"
];

if (!DATABASE_URL) {
  console.error('ขาด environment variable: DATABASE_URL');
  process.exit(1);
}
if (!AUTH_SECRET) {
  console.error('ขาด environment variable: AUTH_SECRET');
  process.exit(1);
}
if (!ADMIN_SECRET) {
  console.warn('ไม่ได้ตั้งค่า ADMIN_SECRET — จุดเรียก /api/pvp/admin/run-daily-tick ด้วยมือ/cron ภายนอกจะใช้ไม่ได้ (แต่ไม่กระทบการเล่นปกติ เพราะระบบจับคู่ PVP กระตุ้นตัวเองอัตโนมัติทุกครั้งที่มีคนเปิดหน้า PVP อยู่แล้ว)');
}

async function main() {
  const db = createDb(DATABASE_URL);
  await db.init();
  const gameEngine = createGameEngine();
  const handler = createRequestHandler(db, AUTH_SECRET, gameEngine, ADMIN_SECRET);
  http.createServer(handler).listen(PORT, () => {
    console.log(`เซิร์ฟเวอร์ทำงานที่พอร์ต ${PORT}`);
  });
}

main().catch(err => {
  console.error('เริ่มเซิร์ฟเวอร์ไม่สำเร็จ:', err);
  process.exit(1);
});
