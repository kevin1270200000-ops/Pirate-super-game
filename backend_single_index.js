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
          points INTEGER NOT NULL DEFAULT 1000,
          attack_team JSONB NOT NULL DEFAULT '[]',
          defense_team JSONB NOT NULL DEFAULT '[]',
          hide_today BOOLEAN NOT NULL DEFAULT false,
          season_start DATE NOT NULL,
          updated_at TIMESTAMPTZ DEFAULT now()
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
      return r.rows[0];
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

    async getUsername(userId) {
      const r = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
      return r.rows[0] ? r.rows[0].username : null;
    },

    // ดึงเซฟทุกคนพร้อมชื่อผู้ใช้ ใช้คำนวณ leaderboard (ชื่อเสียง/พลังสู้รบ/หมอกสุสาน)
    async getAllSavesWithUsernames() {
      const r = await pool.query('SELECT u.id AS user_id, u.username, ps.save_data FROM users u JOIN player_saves ps ON ps.user_id = u.id');
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
          `UPDATE pvp_profiles SET points = $2, attack_team = '[]', defense_team = '[]', hide_today = false, season_start = $3, updated_at = now()
           WHERE user_id = $1 RETURNING *`,
          [userId, startingPoints, currentSeasonStartDateStr]
        );
        return r.rows[0];
      }
      return row;
    },

    async setPvpTeams(userId, attackTeam, defenseTeam) {
      await pool.query(
        'UPDATE pvp_profiles SET attack_team = $2, defense_team = $3, updated_at = now() WHERE user_id = $1',
        [userId, JSON.stringify(attackTeam), JSON.stringify(defenseTeam)]
      );
    },

    async setPvpHidden(userId, hidden) {
      await pool.query('UPDATE pvp_profiles SET hide_today = $2, updated_at = now() WHERE user_id = $1', [userId, hidden]);
    },

    async updatePvpPoints(userId, newPoints) {
      await pool.query('UPDATE pvp_profiles SET points = $2, updated_at = now() WHERE user_id = $1', [userId, newPoints]);
    },

    async getAllPvpProfilesForSeason(currentSeasonStartDateStr) {
      const r = await pool.query('SELECT * FROM pvp_profiles WHERE season_start = $1', [currentSeasonStartDateStr]);
      return r.rows;
    },

    async hasMatchesForDay(seasonStartDateStr, dayNumber) {
      const r = await pool.query('SELECT 1 FROM pvp_matches WHERE season_start = $1 AND day_number = $2 LIMIT 1', [seasonStartDateStr, dayNumber]);
      return r.rows.length > 0;
    },

    async createMatches(rows) {
      for (const m of rows) {
        await pool.query(
          `INSERT INTO pvp_matches (season_start, day_number, player_a, player_b, attacker_id, defender_id)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [m.seasonStart, m.dayNumber, m.playerA, m.playerB, m.attackerId, m.defenderId]
        );
      }
    },

    async getUnresolvedMatchesForDay(seasonStartDateStr, dayNumber) {
      const r = await pool.query(
        'SELECT * FROM pvp_matches WHERE season_start = $1 AND day_number = $2 AND resolved = false AND player_b IS NOT NULL',
        [seasonStartDateStr, dayNumber]
      );
      return r.rows;
    },

    async resolveMatch(matchId, winnerId) {
      await pool.query('UPDATE pvp_matches SET winner_id = $2, resolved = true WHERE id = $1', [matchId, winnerId]);
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
  STARTING_POINTS: 1000,        // แต้มเริ่มต้นของทุกคนตอนซีซั่นใหม่เริ่ม (รีเซ็ตทุกคนเท่ากันหมด)
  POINTS_ON_WIN: 20,
  POINTS_ON_LOSS: 20,           // ลบเท่ากับที่ชนะได้ (ปรับได้ทีหลัง)
  HIDE_TEAM_COST_GEMS: 3,
  REWARD_INTERVAL_DAYS: 7,      // แจกรางวัลทุก 7 วัน (วันที่ 7, 14, 21, 28 ของซีซั่น)
};

// สัดส่วนแรงค์ทองแดง/เงิน/ทอง/เพชร ตามเปอร์เซ็นต์ของผู้เล่นที่ "แข่งอยู่จริง" ในซีซั่นนั้น
// (แชมป์เปี้ยนแยกคำนวณต่างหากด้วย CHAMPION_TIER_TABLE ด้านล่าง ไม่ใช้เปอร์เซ็นต์ตรงๆ)
const RANK_PERCENTILES = {
  diamond: 0.10, // 10% บนสุด (รองจากแชมป์เปี้ยน)
  gold: 0.15,
  silver: 0.30,
  bronze: 0.45   // ที่เหลือทั้งหมดด้านล่าง (40+5 ที่เคยพูดถึง ปัดรวมเป็น 45 หลังหักแชมป์เปี้ยน 5% ออกไปแล้ว)
};

// จำนวนที่นั่งแชมป์เปี้ยน (top) ตามจำนวนผู้เล่นที่แข่งอยู่จริงทั้งหมด — ขั้นบันไดตามที่กำหนด สูงสุด 50 คน
// ทำงานแบบ: หาแถวแรกที่ totalPlayers < maxPlayers แล้วใช้ count ของแถวนั้น
const CHAMPION_TIER_TABLE = [
  { maxPlayers: 60, count: 3 },
  { maxPlayers: 100, count: 5 },
  { maxPlayers: 200, count: 10 },
  { maxPlayers: 400, count: 20 },
  { maxPlayers: 600, count: 30 },
  { maxPlayers: Infinity, count: 50 }
];

module.exports = { PVP_CONFIG, RANK_PERCENTILES, CHAMPION_TIER_TABLE };


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
// ซีซั่นเริ่มวันที่ 1 ของเดือน 00:00 (เวลาไทย) วิ่ง 28 วันเป๊ะ แล้วปิดจนกว่าจะถึงวันที่ 1 เดือนถัดไป
function getSeasonInfo(now = new Date()) {
  const localNow = new Date(now.getTime() + TIMEZONE_OFFSET_HOURS * 60 * 60 * 1000);
  const year = localNow.getUTCFullYear();
  const month = localNow.getUTCMonth();

  const seasonStartLocal = Date.UTC(year, month, 1, 0, 0, 0);
  const seasonStart = new Date(seasonStartLocal - TIMEZONE_OFFSET_HOURS * 60 * 60 * 1000);
  const seasonEnd = new Date(seasonStart.getTime() + PVP_CONFIG.SEASON_LENGTH_DAYS * DAY_MS);

  const nextSeasonStartLocal = Date.UTC(year, month + 1, 1, 0, 0, 0);
  const nextSeasonStart = new Date(nextSeasonStartLocal - TIMEZONE_OFFSET_HOURS * 60 * 60 * 1000);

  const isActive = now >= seasonStart && now < seasonEnd;
  const dayNumber = isActive ? Math.floor((now.getTime() - seasonStart.getTime()) / DAY_MS) + 1 : null;

  return { seasonStart, seasonEnd, nextSeasonStart, isActive, dayNumber, isClosedGap: !isActive };
}

// วันที่ dayNumber (1-28) เป็นวันแจกรางวัลไหม (ทุก 7 วัน: 7, 14, 21, 28)
function isRewardDay(dayNumber) {
  return dayNumber !== null && dayNumber > 0 && dayNumber % PVP_CONFIG.REWARD_INTERVAL_DAYS === 0;
}

// ---------- แรงค์ ----------

// จำนวนที่นั่งแชมป์เปี้ยน ตามจำนวนผู้เล่นที่แข่งอยู่จริงทั้งหมด (ขั้นบันได ดู data_pvp.js)
function getChampionSlotCount(totalPlayers) {
  for (const tier of CHAMPION_TIER_TABLE) {
    if (totalPlayers < tier.maxPlayers) return tier.count;
  }
  return CHAMPION_TIER_TABLE[CHAMPION_TIER_TABLE.length - 1].count;
}

// รับ players = [{id, points}, ...] คืนรายชื่อพร้อมแรงค์และอันดับ เรียงจากแต้มมากไปน้อย
// แรงค์คำนวณจาก "สัดส่วน" ของคนที่แข่งอยู่จริงตอนนั้น ไม่ใช่แต้มตายตัว (ยืดหยุ่นตามจำนวนคนเล่นจริง)
function computeRanks(players) {
  const sorted = [...players].sort((a, b) => b.points - a.points);
  const n = sorted.length;
  if (n === 0) return [];

  const championCount = Math.min(getChampionSlotCount(n), n);
  const remaining = n - championCount;
  const diamondCount = Math.round(remaining * RANK_PERCENTILES.diamond);
  const goldCount = Math.round(remaining * RANK_PERCENTILES.gold);
  const silverCount = Math.round(remaining * RANK_PERCENTILES.silver);
  // bronze = ที่เหลือทั้งหมดหลังหักแชมป์เปี้ยน/เพชร/ทอง/เงินออก (กันเศษปัดตกหล่น)

  return sorted.map((p, index) => {
    let rank;
    if (index < championCount) rank = 'champion';
    else if (index < championCount + diamondCount) rank = 'diamond';
    else if (index < championCount + diamondCount + goldCount) rank = 'gold';
    else if (index < championCount + diamondCount + goldCount + silverCount) rank = 'silver';
    else rank = 'bronze';
    return { id: p.id, points: p.points, rank, position: index + 1 };
  });
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
  getSeasonInfo, isRewardDay, getChampionSlotCount, computeRanks,
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
  const attackerProfile = await db.ensurePvpProfile(match.attacker_id, seasonStartStr, PVP_CONFIG.STARTING_POINTS);
  const defenderProfile = await db.ensurePvpProfile(match.defender_id, seasonStartStr, PVP_CONFIG.STARTING_POINTS);

  const attackerSave = await db.getSave(match.attacker_id);
  const defenderSave = await db.getSave(match.defender_id);

  const attackerSquad = extractSquadData(attackerSave, attackerProfile.attack_team);
  const defenderSquad = extractSquadData(defenderSave, defenderProfile.defense_team);

  let isAttackerWin;
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
  }

  const winnerId = isAttackerWin ? match.attacker_id : match.defender_id;
  const loserId = isAttackerWin ? match.defender_id : match.attacker_id;
  const winnerProfile = isAttackerWin ? attackerProfile : defenderProfile;
  const loserProfile = isAttackerWin ? defenderProfile : attackerProfile;

  const pointsResult = applyMatchPoints(winnerProfile.points, loserProfile.points);

  await db.resolveMatch(match.id, winnerId);
  await db.updatePvpPoints(winnerId, pointsResult.winnerNewPoints);
  await db.updatePvpPoints(loserId, pointsResult.loserNewPoints);

  return { matchId: match.id, winnerId, loserId, isAttackerWin };
}

async function runPvpDailyTick(db, gameEngine, now = new Date()) {
  const seasonInfo = getSeasonInfo(now);
  if (!seasonInfo.isActive) {
    return { ranTick: false, reason: 'season_closed' };
  }
  const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
  const dayNumber = seasonInfo.dayNumber;

  // 1. ตัดสินผลแมตช์เมื่อวาน (ถ้ามีและยังไม่ตัดสิน)
  let resolvedMatches = [];
  if (dayNumber > 1) {
    const pending = await db.getUnresolvedMatchesForDay(seasonStartStr, dayNumber - 1);
    for (const match of pending) {
      const r = await resolveOneMatch(db, gameEngine, match, seasonStartStr);
      resolvedMatches.push(r);
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
      matchRows.push({ seasonStart: seasonStartStr, dayNumber, playerA: bye, playerB: null, attackerId: null, defenderId: null });
    }
    if (matchRows.length > 0) await db.createMatches(matchRows);
    pairedCount = matchRows.length;
  }

  return { ranTick: true, dayNumber, resolvedCount: resolvedMatches.length, resolvedMatches, pairedCount, alreadyPaired };
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
function buildReputationLeaderboard(entries) {
  const list = entries.map(e => ({ userId: e.userId, username: e.username, value: (e.save && e.save.reputation) || 0 }));
  return finalizeLeaderboard(list);
}

function buildWaveSurvivalLeaderboard(entries) {
  const list = entries.map(e => {
    const ws = e.save && e.save.wave_survival;
    return { userId: e.userId, username: e.username, value: (ws && ws.best_score) || 0 };
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
    return { userId: e.userId, username: e.username, value };
  });
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
  finalizeLeaderboard, findMyEntry
};



// ===== embedded game engine (characters/combat/etc, loaded in isolated vm context) =====
const GAME_ENGINE_SOURCE = "// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_characters.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e40\u0e01\u0e47\u0e1a\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e14\u0e34\u0e1a\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e04\u0e33\u0e19\u0e27\u0e13)\n// \u0e41\u0e1b\u0e25\u0e07\u0e15\u0e23\u0e07\u0e08\u0e32\u0e01\u0e44\u0e1f\u0e25\u0e4c\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a: characters.json (\u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e41\u0e01\u0e49\u0e44\u0e02/\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e40\u0e15\u0e34\u0e21\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e43\u0e14\u0e46)\n// \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14: 55 \u0e15\u0e31\u0e27\n// ==========================================\n\nconst CHARACTERS = [\n  {\n    \"id\": \"c001\",\n    \"name\": \"\u0e2d\u0e35\u0e18\u0e32\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P10\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 445.7,\n      \"attack\": 24.7,\n      \"defense_flat\": 19.3,\n      \"speed\": 12,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c008\",\n    \"name\": \"\u0e40\u0e04\u0e40\u0e25\u0e1a\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 226.5,\n      \"attack\": 57,\n      \"defense_flat\": 8.3,\n      \"speed\": 21.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c016\",\n    \"name\": \"\u0e42\u0e19\u0e2d\u0e32\u0e2b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P14\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 301.5,\n      \"attack\": 27.8,\n      \"defense_flat\": 11.6,\n      \"speed\": 32.4,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c023\",\n    \"name\": \"\u0e40\u0e08\u0e21\u0e2a\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 214.7,\n      \"attack\": 65.7,\n      \"defense_flat\": 7.5,\n      \"speed\": 23.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c030\",\n    \"name\": \"\u0e1f\u0e2d\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"assassin\",\n    \"passive\": \"P23\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 190.9,\n      \"attack\": 68.3,\n      \"defense_flat\": 5.9,\n      \"speed\": 29.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b001\",\n    \"name\": \"\u0e41\u0e08\u0e47\u0e04\",\n    \"grade\": \"B\",\n    \"role\": \"tank\",\n    \"passive\": \"P10\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 682.2,\n      \"attack\": 41.5,\n      \"defense_flat\": 24.9,\n      \"speed\": 18,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b011\",\n    \"name\": \"\u0e44\u0e23\u0e2d\u0e31\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 287.8,\n      \"attack\": 94.2,\n      \"defense_flat\": 11.6,\n      \"speed\": 38.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a001\",\n    \"name\": \"\u0e25\u0e39\u0e04\u0e31\u0e2a\",\n    \"grade\": \"A\",\n    \"role\": \"fighter\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 508.1,\n      \"attack\": 132.4,\n      \"defense_flat\": 21,\n      \"speed\": 45.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a002\",\n    \"name\": \"\u0e42\u0e25\u0e41\u0e01\u0e19\",\n    \"grade\": \"A\",\n    \"role\": \"support\",\n    \"passive\": \"P17\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 607.8,\n      \"attack\": 62.6,\n      \"defense_flat\": 25.4,\n      \"speed\": 65.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s001\",\n    \"name\": \"\u0e40\u0e08\u0e04\u0e2d\u0e1a\",\n    \"grade\": \"S\",\n    \"role\": \"tank\",\n    \"passive\": \"P10\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 1588.2,\n      \"attack\": 86.2,\n      \"defense_flat\": 63.9,\n      \"speed\": 36.3,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c002\",\n    \"name\": \"\u0e40\u0e21\u0e2a\u0e31\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P09\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 409.5,\n      \"attack\": 25.3,\n      \"defense_flat\": 16.6,\n      \"speed\": 10.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c003\",\n    \"name\": \"\u0e42\u0e19\u0e41\u0e25\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P13\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 458.6,\n      \"attack\": 26.6,\n      \"defense_flat\": 17.7,\n      \"speed\": 10.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c004\",\n    \"name\": \"\u0e40\u0e1a\u0e23\u0e15\u0e15\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P11\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 411.2,\n      \"attack\": 27.4,\n      \"defense_flat\": 18.3,\n      \"speed\": 10.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c005\",\n    \"name\": \"\u0e04\u0e32\u0e23\u0e4c\u0e25\u0e2d\u0e2a\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P12\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 432.7,\n      \"attack\": 24.3,\n      \"defense_flat\": 18.2,\n      \"speed\": 10.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c006\",\n    \"name\": \"\u0e14\u0e2d\u0e21\u0e34\u0e19\u0e34\u0e01\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P17\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 435.4,\n      \"attack\": 26.9,\n      \"defense_flat\": 18.1,\n      \"speed\": 11.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c007\",\n    \"name\": \"\u0e27\u0e32\u0e40\u0e25\u0e19\u0e15\u0e34\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P09\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 405.4,\n      \"attack\": 25.2,\n      \"defense_flat\": 18.7,\n      \"speed\": 11.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c009\",\n    \"name\": \"\u0e40\u0e25\u0e35\u0e22\u0e21\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 240.2,\n      \"attack\": 57.5,\n      \"defense_flat\": 9.3,\n      \"speed\": 19.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c010\",\n    \"name\": \"\u0e21\u0e32\u0e23\u0e4c\u0e04\u0e31\u0e2a\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P03\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 231.5,\n      \"attack\": 58.5,\n      \"defense_flat\": 8.2,\n      \"speed\": 21.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c011\",\n    \"name\": \"\u0e40\u0e14\u0e19\u0e40\u0e27\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P06\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 242.2,\n      \"attack\": 51.7,\n      \"defense_flat\": 9.5,\n      \"speed\": 20.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c012\",\n    \"name\": \"\u0e23\u0e34\u0e42\u0e2d\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 235.6,\n      \"attack\": 57.6,\n      \"defense_flat\": 9.1,\n      \"speed\": 20.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c013\",\n    \"name\": \"\u0e40\u0e0b\u0e35\u0e22\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 242.5,\n      \"attack\": 58.2,\n      \"defense_flat\": 8.1,\n      \"speed\": 22.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c014\",\n    \"name\": \"\u0e42\u0e04\u0e14\u0e35\u0e49\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P03\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 236,\n      \"attack\": 60.3,\n      \"defense_flat\": 9.1,\n      \"speed\": 19.3,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c015\",\n    \"name\": \"\u0e41\u0e21\u0e47\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"fighter\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 226.6,\n      \"attack\": 53.5,\n      \"defense_flat\": 8.1,\n      \"speed\": 20.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c017\",\n    \"name\": \"\u0e40\u0e2e\u0e19\u0e23\u0e35\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P16\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 280.8,\n      \"attack\": 27.4,\n      \"defense_flat\": 10.8,\n      \"speed\": 31.4,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c018\",\n    \"name\": \"\u0e2d\u0e2d\u0e2a\u0e01\u0e32\u0e23\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P18\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 259.6,\n      \"attack\": 29.9,\n      \"defense_flat\": 10.5,\n      \"speed\": 30.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c019\",\n    \"name\": \"\u0e1f\u0e34\u0e19\u0e19\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 275.5,\n      \"attack\": 29.3,\n      \"defense_flat\": 11.2,\n      \"speed\": 31,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c020\",\n    \"name\": \"\u0e2d\u0e40\u0e25\u0e47\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P20\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 300.8,\n      \"attack\": 28.2,\n      \"defense_flat\": 11.3,\n      \"speed\": 31.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c021\",\n    \"name\": \"\u0e41\u0e0b\u0e21\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P14\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 259,\n      \"attack\": 30.1,\n      \"defense_flat\": 10.7,\n      \"speed\": 33.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c022\",\n    \"name\": \"\u0e40\u0e08\u0e22\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P19\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 263.6,\n      \"attack\": 27.7,\n      \"defense_flat\": 11.8,\n      \"speed\": 31,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c024\",\n    \"name\": \"\u0e44\u0e17\u0e40\u0e25\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 189.8,\n      \"attack\": 62.7,\n      \"defense_flat\": 7.4,\n      \"speed\": 23.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c025\",\n    \"name\": \"\u0e40\u0e25\u0e19\u0e19\u0e47\u0e2d\u0e01\u0e0b\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P05\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 197.8,\n      \"attack\": 62.2,\n      \"defense_flat\": 6.8,\n      \"speed\": 25.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c026\",\n    \"name\": \"\u0e23\u0e47\u0e2d\u0e04\u0e01\u0e35\u0e49\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 204.4,\n      \"attack\": 60,\n      \"defense_flat\": 7.4,\n      \"speed\": 24.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c027\",\n    \"name\": \"\u0e44\u0e04\u0e25\u0e4c\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 190,\n      \"attack\": 66.6,\n      \"defense_flat\": 7,\n      \"speed\": 26,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c028\",\n    \"name\": \"\u0e40\u0e1a\u0e25\u0e04\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 186,\n      \"attack\": 57,\n      \"defense_flat\": 6.9,\n      \"speed\": 26.4,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c029\",\n    \"name\": \"\u0e44\u0e23\u0e14\u0e2d\u0e19\",\n    \"grade\": \"C\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 201.6,\n      \"attack\": 58.9,\n      \"defense_flat\": 6.9,\n      \"speed\": 24,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b002\",\n    \"name\": \"\u0e40\u0e2e\u0e04\u0e40\u0e15\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"B\",\n    \"role\": \"tank\",\n    \"passive\": \"P12\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 693.8,\n      \"attack\": 37.5,\n      \"defense_flat\": 25.1,\n      \"speed\": 16.6,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b003\",\n    \"name\": \"\u0e42\u0e23\u0e41\u0e21\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"tank\",\n    \"passive\": \"P13\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 675.9,\n      \"attack\": 40,\n      \"defense_flat\": 25,\n      \"speed\": 15.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b004\",\n    \"name\": \"\u0e41\u0e14\u0e40\u0e19\u0e35\u0e22\u0e25\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 363.7,\n      \"attack\": 90.3,\n      \"defense_flat\": 13,\n      \"speed\": 33.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b005\",\n    \"name\": \"\u0e27\u0e34\u0e01\u0e40\u0e15\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 342.5,\n      \"attack\": 78.8,\n      \"defense_flat\": 12.1,\n      \"speed\": 31.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b006\",\n    \"name\": \"\u0e40\u0e18\u0e42\u0e2d\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P06\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 354.8,\n      \"attack\": 82.8,\n      \"defense_flat\": 12.2,\n      \"speed\": 31.6,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b007\",\n    \"name\": \"\u0e40\u0e23\u0e21\u0e35\",\n    \"grade\": \"B\",\n    \"role\": \"fighter\",\n    \"passive\": \"P24\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 359.9,\n      \"attack\": 83,\n      \"defense_flat\": 13.9,\n      \"speed\": 32.7,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b008\",\n    \"name\": \"\u0e42\u0e2d\u0e25\u0e34\u0e40\u0e27\u0e2d\u0e23\u0e4c\",\n    \"grade\": \"B\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 441.6,\n      \"attack\": 39.3,\n      \"defense_flat\": 17.2,\n      \"speed\": 46.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b009\",\n    \"name\": \"\u0e40\u0e0b\u0e1a\u0e32\u0e2a\u0e40\u0e15\u0e35\u0e22\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"support\",\n    \"passive\": \"P18\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 403.2,\n      \"attack\": 40.9,\n      \"defense_flat\": 17.6,\n      \"speed\": 49.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b010\",\n    \"name\": \"\u0e21\u0e32\u0e23\u0e4c\u0e40\u0e0b\u0e25\",\n    \"grade\": \"B\",\n    \"role\": \"support\",\n    \"passive\": \"P16\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 392.3,\n      \"attack\": 41.4,\n      \"defense_flat\": 15.5,\n      \"speed\": 43.8,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b012\",\n    \"name\": \"\u0e2d\u0e35\u0e27\u0e32\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P05\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 278.1,\n      \"attack\": 100,\n      \"defense_flat\": 11.2,\n      \"speed\": 39.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b013\",\n    \"name\": \"\u0e40\u0e25\u0e42\u0e2d\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 296.2,\n      \"attack\": 91.8,\n      \"defense_flat\": 10.6,\n      \"speed\": 36,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b014\",\n    \"name\": \"\u0e2e\u0e32\u0e23\u0e4c\u0e14\u0e35\u0e49\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P07\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 307.6,\n      \"attack\": 87.1,\n      \"defense_flat\": 11.4,\n      \"speed\": 37.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b015\",\n    \"name\": \"\u0e40\u0e07\u0e32\",\n    \"grade\": \"B\",\n    \"role\": \"assassin\",\n    \"passive\": \"P22\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 282.9,\n      \"attack\": 104,\n      \"defense_flat\": 9,\n      \"speed\": 39.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a003\",\n    \"name\": \"\u0e40\u0e2d\u0e40\u0e14\u0e19\",\n    \"grade\": \"A\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 568.2,\n      \"attack\": 127,\n      \"defense_flat\": 18.7,\n      \"speed\": 49.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a004\",\n    \"name\": \"\u0e40\u0e0b\u0e23\u0e32\u0e1f\u0e34\u0e19\",\n    \"grade\": \"A\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 594.4,\n      \"attack\": 67.6,\n      \"defense_flat\": 23.3,\n      \"speed\": 68.3,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a005\",\n    \"name\": \"\u0e04\u0e2d\u0e19\u0e23\u0e32\u0e14\",\n    \"grade\": \"A\",\n    \"role\": \"tank\",\n    \"passive\": \"P12\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 945.1,\n      \"attack\": 56.9,\n      \"defense_flat\": 41.2,\n      \"speed\": 24.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a006\",\n    \"name\": \"\u0e42\u0e0b\u0e42\u0e25\",\n    \"grade\": \"A\",\n    \"role\": \"ranger\",\n    \"passive\": \"P02\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 434.7,\n      \"attack\": 144.2,\n      \"defense_flat\": 15.1,\n      \"speed\": 60.2,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a007\",\n    \"name\": \"\u0e14\u0e32\u0e23\u0e4c\u0e01\",\n    \"grade\": \"A\",\n    \"role\": \"assassin\",\n    \"passive\": \"P23\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 425.8,\n      \"attack\": 161,\n      \"defense_flat\": 12.5,\n      \"speed\": 57.1,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s002\",\n    \"name\": \"\u0e44\u0e17\u0e17\u0e31\u0e19\",\n    \"grade\": \"S\",\n    \"role\": \"fighter\",\n    \"passive\": \"P24\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 799.9,\n      \"attack\": 184.4,\n      \"defense_flat\": 31.8,\n      \"speed\": 72.9,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s003\",\n    \"name\": \"\u0e2d\u0e2d\u0e23\u0e32\u0e40\u0e04\u0e34\u0e25\",\n    \"grade\": \"S\",\n    \"role\": \"support\",\n    \"passive\": \"P15\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 986.6,\n      \"attack\": 90.7,\n      \"defense_flat\": 36.5,\n      \"speed\": 100.5,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s004\",\n    \"name\": \"\u0e40\u0e14\u0e27\u0e34\u0e14\",\n    \"grade\": \"S\",\n    \"role\": \"tank\",\n    \"passive\": \"P25\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 1550,\n      \"attack\": 95,\n      \"defense_flat\": 48,\n      \"speed\": 62,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s005\",\n    \"name\": \"\u0e23\u0e32\u0e1f\u0e32\u0e40\u0e2d\u0e25\",\n    \"grade\": \"S\",\n    \"role\": \"assassin\",\n    \"passive\": \"P08\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 850,\n      \"attack\": 180,\n      \"defense_flat\": 36,\n      \"speed\": 74,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"s006\",\n    \"name\": \"\u0e42\u0e0b\u0e40\u0e1f\u0e35\u0e22\",\n    \"grade\": \"S\",\n    \"role\": \"support\",\n    \"passive\": \"P26\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 1200,\n      \"attack\": 110,\n      \"defense_flat\": 42,\n      \"speed\": 68,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a008\",\n    \"name\": \"\u0e14\u0e34\u0e40\u0e2d\u0e42\u0e01\u0e49\",\n    \"grade\": \"A\",\n    \"role\": \"ranger\",\n    \"passive\": \"P27\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 520,\n      \"attack\": 145,\n      \"defense_flat\": 20,\n      \"speed\": 52,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"a009\",\n    \"name\": \"\u0e21\u0e31\u0e15\u0e40\u0e15\u0e42\u0e2d\",\n    \"grade\": \"A\",\n    \"role\": \"fighter\",\n    \"passive\": \"P04\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 780,\n      \"attack\": 130,\n      \"defense_flat\": 25,\n      \"speed\": 48,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b016\",\n    \"name\": \"\u0e19\u0e32\u0e15\u0e32\u0e40\u0e25\u0e35\u0e22\",\n    \"grade\": \"B\",\n    \"role\": \"assassin\",\n    \"passive\": \"P22\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 310,\n      \"attack\": 98,\n      \"defense_flat\": 12,\n      \"speed\": 40,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"b017\",\n    \"name\": \"\u0e40\u0e04\u0e25\u0e27\u0e34\u0e19\",\n    \"grade\": \"B\",\n    \"role\": \"ranger\",\n    \"passive\": \"P01\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 380,\n      \"attack\": 82,\n      \"defense_flat\": 16,\n      \"speed\": 28,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c031\",\n    \"name\": \"\u0e40\u0e2d\u0e19\u0e42\u0e0b\",\n    \"grade\": \"C\",\n    \"role\": \"tank\",\n    \"passive\": \"P05\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 440,\n      \"attack\": 32,\n      \"defense_flat\": 13,\n      \"speed\": 14,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  },\n  {\n    \"id\": \"c032\",\n    \"name\": \"\u0e14\u0e32\u0e19\u0e34\u0e42\u0e25\",\n    \"grade\": \"C\",\n    \"role\": \"support\",\n    \"passive\": \"P16\",\n    \"source\": \"gacha\",\n    \"stats\": {\n      \"hp\": 260,\n      \"attack\": 28,\n      \"defense_flat\": 8,\n      \"speed\": 22,\n      \"defense_percent\": 0,\n      \"crit_rate\": 0,\n      \"crit_damage\": 0,\n      \"evasion\": 0,\n      \"accuracy\": 0\n    },\n    \"skill\": null\n  }\n];\n\nif (typeof module !== 'undefined' && module.exports) {\n  module.exports = { CHARACTERS };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_passives.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e40\u0e01\u0e47\u0e1a \"\u0e15\u0e31\u0e27\u0e40\u0e25\u0e02\u0e1e\u0e32\u0e23\u0e32\u0e21\u0e34\u0e40\u0e15\u0e2d\u0e23\u0e4c\" \u0e02\u0e2d\u0e07 passive \u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19\n// \u0e2b\u0e49\u0e32\u0e21\u0e43\u0e2a\u0e48\u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e04\u0e33\u0e19\u0e27\u0e13/\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e43\u0e14\u0e46 \u0e43\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\n// \u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e40\u0e1e\u0e34\u0e48\u0e21/\u0e41\u0e01\u0e49\u0e04\u0e48\u0e32\u0e1e\u0e25\u0e31\u0e07\u0e02\u0e2d\u0e07 passive -> \u0e41\u0e01\u0e49\u0e17\u0e35\u0e48\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e14\u0e35\u0e22\u0e27\n// ==========================================\n\nconst PASSIVE_PARAMS = {\n  \"P01\": { targets: 2, dmg_pct: 80 },                          // \u0e42\u0e08\u0e21\u0e15\u0e35 AoE 2 \u0e40\u0e1b\u0e49\u0e32 (\u0e23\u0e27\u0e21 160%)\n  \"P02\": { targets: 3, dmg_pct: 60 },                          // \u0e42\u0e08\u0e21\u0e15\u0e35 AoE 3 \u0e40\u0e1b\u0e49\u0e32 (\u0e23\u0e27\u0e21 180%)\n  \"P03\": { chance: 35, dmg_pct: 100 },                         // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\n  \"P04\": { condition: \"hp_below_50\", atk_bonus: 70 },          // ATK \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e40\u0e21\u0e37\u0e48\u0e2d HP \u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 50%\n  \"P05\": { chance: 30 },                                       // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e44\u0e14\u0e49\u0e15\u0e32\u0e40\u0e23\u0e47\u0e27\u0e1e\u0e34\u0e40\u0e28\u0e29\n  \"P06\": { lifesteal_pct: 25 },                                // \u0e14\u0e39\u0e14\u0e40\u0e25\u0e37\u0e2d\u0e14\n  \"P07\": { chance: 20, multiplier: 3 },                        // \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 x3\n  \"P08\": { chance: 15, multiplier: 3.6 },                      // \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 x3.6\n  \"P09\": { chance: 20, dmg_pct: 40 },                          // \u0e15\u0e35\u0e42\u0e15\u0e49\n  \"P10\": { reduce_pct: 35 },                                   // \u0e25\u0e14\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e35\u0e48\u0e44\u0e14\u0e49\u0e23\u0e31\u0e1a\n  \"P11\": { chance: 25 },                                       // \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\n  \"P12\": { chance: 30, receive_pct: 60 },                      // \u0e42\u0e25\u0e48\u0e21\u0e19\u0e38\u0e29\u0e22\u0e4c\n  \"P13\": { heal_pct: 8 },                                      // \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39\u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07\n  \"P14\": { heal_pct: 3 },                                      // \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39\u0e17\u0e35\u0e21\u0e17\u0e38\u0e01\u0e15\u0e32\n  \"P15\": { chance: 10, heal_pct: 50 },                         // \u0e23\u0e31\u0e01\u0e29\u0e32\u0e09\u0e38\u0e01\u0e40\u0e09\u0e34\u0e19\n  \"P16\": { chance: 40, atk_bonus: 25, duration: 2 },           // \u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a (\u0e1a\u0e31\u0e1f\u0e17\u0e35\u0e21)\n  \"P17\": { def_bonus: 7 },                                     // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e40\u0e1e\u0e34\u0e48\u0e21 DEF \u0e17\u0e35\u0e21\n  \"P18\": { chance: 12 },                                       // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e17\u0e2d\u0e07 (\u0e2a\u0e31\u0e48\u0e07\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e19\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33)\n  \"P19\": { spd_reduce: 10 },                                   // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e25\u0e14 SPD \u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P20\": { atk_reduce: 6 },                                    // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e25\u0e14 ATK \u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P21\": { chance: 30, stun_duration: 1 },                     // \u0e2a\u0e15\u0e31\u0e49\u0e19\n  \"P22\": { chance: 15, stun_duration: 2 },                     // \u0e2a\u0e15\u0e31\u0e49\u0e19\u0e2b\u0e19\u0e31\u0e01\n  \"P23\": { chance: 30, silence_duration: 2 },                  // \u0e1b\u0e34\u0e14 passive \u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P24\": { dmg_pct: 250 },                                     // \u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e15\u0e2d\u0e19\u0e15\u0e32\u0e22\n  \"P25\": { crit_chance_reduce: 30, crit_dmg_reduce: 40 },      // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e15\u0e49\u0e32\u0e19\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e28\u0e31\u0e15\u0e23\u0e39\n  \"P26\": { evasion_bonus: 12 },                                // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e17\u0e35\u0e21\n  \"P27\": { chance: 30, poison_pct: 8, duration: 3 }            // \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e15\u0e34\u0e14\u0e1e\u0e34\u0e29\n};\n\nconst PASSIVES = [\n  {\"id\":\"P01\",\"name\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e23\u0e30\u0e08\u0e32\u0e22 2\",\"description\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39 2 \u0e15\u0e31\u0e27\u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e01\u0e31\u0e19 \u0e17\u0e31\u0e49\u0e07\u0e2a\u0e2d\u0e07\u0e23\u0e31\u0e1a 80% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e2b\u0e25\u0e31\u0e01 \u0e23\u0e27\u0e21 160%\"},\n  {\"id\":\"P02\",\"name\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e23\u0e30\u0e08\u0e32\u0e22 3\",\"description\":\"\u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39 3 \u0e15\u0e31\u0e27\u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e01\u0e31\u0e19 \u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\u0e23\u0e31\u0e1a 60% \u0e23\u0e27\u0e21 180%\"},\n  {\"id\":\"P03\",\"name\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 35% \u0e42\u0e08\u0e21\u0e15\u0e35\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22\u0e40\u0e14\u0e34\u0e21\u0e0b\u0e49\u0e33\u0e2d\u0e35\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e40\u0e15\u0e47\u0e21\"},\n  {\"id\":\"P04\",\"name\":\"\u0e40\u0e14\u0e37\u0e2d\u0e14\u0e14\u0e32\u0e25\",\"description\":\"\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e08\u0e21\u0e15\u0e35 70% \u0e40\u0e21\u0e37\u0e48\u0e2d HP \u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 50% \u0e40\u0e0a\u0e47\u0e04\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P05\",\"name\":\"\u0e2a\u0e32\u0e22\u0e1f\u0e49\u0e32\u0e41\u0e25\u0e1a\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e48\u0e2d\u0e19\u0e40\u0e2a\u0e21\u0e2d\u0e43\u0e19\u0e23\u0e2d\u0e1a\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P06\",\"name\":\"\u0e14\u0e39\u0e14\u0e40\u0e25\u0e37\u0e2d\u0e14\",\"description\":\"\u0e1f\u0e37\u0e49\u0e19 HP \u0e01\u0e25\u0e31\u0e1a 25% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e35\u0e48\u0e17\u0e33\u0e44\u0e14\u0e49\u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\"},\n  {\"id\":\"P07\",\"name\":\"\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 20% \u0e14\u0e32\u0e40\u0e21\u0e08\u0e04\u0e39\u0e13 3 \u0e40\u0e17\u0e48\u0e32 \u0e04\u0e48\u0e32\u0e40\u0e09\u0e25\u0e35\u0e48\u0e22\u0e14\u0e32\u0e40\u0e21\u0e08\u0e40\u0e1e\u0e34\u0e48\u0e21 40%\"},\n  {\"id\":\"P08\",\"name\":\"\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e2a\u0e39\u0e07\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 15% \u0e14\u0e32\u0e40\u0e21\u0e08\u0e04\u0e39\u0e13 3.6 \u0e40\u0e17\u0e48\u0e32 \u0e04\u0e48\u0e32\u0e40\u0e09\u0e25\u0e35\u0e48\u0e22\u0e14\u0e32\u0e40\u0e21\u0e08\u0e40\u0e1e\u0e34\u0e48\u0e21 39%\"},\n  {\"id\":\"P09\",\"name\":\"\u0e15\u0e35\u0e42\u0e15\u0e49\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 20% \u0e42\u0e08\u0e21\u0e15\u0e35\u0e01\u0e25\u0e31\u0e1a\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e31\u0e19\u0e17\u0e35\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35\u0e14\u0e49\u0e27\u0e22\u0e14\u0e32\u0e40\u0e21\u0e08 40%\"},\n  {\"id\":\"P10\",\"name\":\"\u0e40\u0e01\u0e23\u0e32\u0e30\u0e40\u0e2b\u0e25\u0e47\u0e01\",\"description\":\"\u0e25\u0e14\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e35\u0e48\u0e23\u0e31\u0e1a\u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07 35%\"},\n  {\"id\":\"P11\",\"name\":\"\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 25% \u0e2b\u0e25\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e44\u0e14\u0e49\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\"},\n  {\"id\":\"P12\",\"name\":\"\u0e42\u0e25\u0e48\u0e21\u0e19\u0e38\u0e29\u0e22\u0e4c\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e41\u0e17\u0e19\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e19\u0e17\u0e35\u0e48 HP \u0e19\u0e49\u0e2d\u0e22\u0e2a\u0e38\u0e14 \u0e41\u0e15\u0e48\u0e23\u0e31\u0e1a\u0e41\u0e04\u0e48 60% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P13\",\"name\":\"\u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39\u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07\",\"description\":\"\u0e1f\u0e37\u0e49\u0e19 HP \u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07 8% \u0e02\u0e2d\u0e07 HP \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P14\",\"name\":\"\u0e23\u0e31\u0e01\u0e29\u0e32\u0e17\u0e35\u0e21\",\"description\":\"\u0e1f\u0e37\u0e49\u0e19 HP \u0e25\u0e39\u0e01\u0e40\u0e23\u0e37\u0e2d\u0e17\u0e38\u0e01\u0e04\u0e19 3% \u0e02\u0e2d\u0e07 HP  \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P15\",\"name\":\"\u0e23\u0e31\u0e01\u0e29\u0e32\u0e09\u0e38\u0e01\u0e40\u0e09\u0e34\u0e19\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 10% \u0e1f\u0e37\u0e49\u0e19 HP \u0e17\u0e31\u0e49\u0e07\u0e17\u0e35\u0e21 50% \u0e43\u0e19\u0e23\u0e2d\u0e1a\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P16\",\"name\":\"\u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 40% \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e08\u0e21\u0e15\u0e35 25% \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e43\u0e19\u0e23\u0e2d\u0e1a\u0e19\u0e31\u0e49\u0e19\"},\n  {\"id\":\"P17\",\"name\":\"\u0e01\u0e33\u0e41\u0e1e\u0e07\u0e40\u0e2b\u0e25\u0e47\u0e01\",\"description\":\"\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19 7% \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P18\",\"name\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e17\u0e2d\u0e07\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 12% \u0e43\u0e2b\u0e49\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e19\u0e17\u0e35\u0e48\u0e40\u0e1e\u0e34\u0e48\u0e07\u0e42\u0e08\u0e21\u0e15\u0e35\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\u0e2d\u0e35\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\"},\n  {\"id\":\"P19\",\"name\":\"\u0e0a\u0e30\u0e25\u0e2d\u0e28\u0e31\u0e15\u0e23\u0e39\",\"description\":\"\u0e25\u0e14\u0e04\u0e27\u0e32\u0e21\u0e40\u0e23\u0e47\u0e27\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27 10% \u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P20\",\"name\":\"\u0e2d\u0e48\u0e2d\u0e19\u0e41\u0e23\u0e07\",\"description\":\"\u0e25\u0e14\u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27 6% \u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P21\",\"name\":\"\u0e2a\u0e15\u0e31\u0e49\u0e19\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35\u0e2a\u0e15\u0e31\u0e49\u0e19 1 \u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P22\",\"name\":\"\u0e2a\u0e15\u0e31\u0e49\u0e19\u0e2b\u0e19\u0e31\u0e01\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 15% \u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35\u0e2a\u0e15\u0e31\u0e49\u0e19 2 \u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P23\",\"name\":\"\u0e1b\u0e34\u0e14 passive\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e1b\u0e34\u0e14 passive \u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e35\u0e48\u0e16\u0e39\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35 2 \u0e23\u0e2d\u0e1a\"},\n  {\"id\":\"P24\",\"name\":\"\u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\",\"description\":\"\u0e40\u0e21\u0e37\u0e48\u0e2d\u0e08\u0e30\u0e16\u0e39\u0e01\u0e01\u0e33\u0e08\u0e31\u0e14 \u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27 250% \u0e02\u0e2d\u0e07\u0e14\u0e32\u0e40\u0e21\u0e08\u0e1b\u0e01\u0e15\u0e34\u0e01\u0e48\u0e2d\u0e19\u0e2d\u0e2d\u0e01\u0e08\u0e32\u0e01\u0e2a\u0e19\u0e32\u0e21\"},\n  {\"id\":\"P25\",\"name\":\"\u0e42\u0e25\u0e48\u0e15\u0e49\u0e32\u0e19\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\",\"description\":\"\u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49 \u0e25\u0e14\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e02\u0e2d\u0e07\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e38\u0e01\u0e15\u0e31\u0e27\u0e25\u0e07 30 \u0e08\u0e38\u0e14 \u0e41\u0e25\u0e30\u0e25\u0e14\u0e04\u0e27\u0e32\u0e21\u0e41\u0e23\u0e07\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e02\u0e2d\u0e07\u0e28\u0e31\u0e15\u0e23\u0e39\u0e25\u0e07 40%\"},\n  {\"id\":\"P26\",\"name\":\"\u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e1b\u0e23\u0e32\u0e14\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e27\",\"description\":\"\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 12% \u0e15\u0e31\u0e49\u0e07\u0e41\u0e15\u0e48\u0e15\u0e49\u0e19\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\"},\n  {\"id\":\"P27\",\"name\":\"\u0e1e\u0e34\u0e29\u0e01\u0e31\u0e14\u0e01\u0e23\u0e48\u0e2d\u0e19\",\"description\":\"\u0e42\u0e2d\u0e01\u0e32\u0e2a 30% \u0e17\u0e33\u0e43\u0e2b\u0e49\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22\u0e17\u0e35\u0e48\u0e42\u0e14\u0e19\u0e42\u0e08\u0e21\u0e15\u0e35\u0e15\u0e34\u0e14\u0e1e\u0e34\u0e29 \u0e44\u0e14\u0e49\u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08 8% \u0e02\u0e2d\u0e07 HP \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e38\u0e01\u0e23\u0e2d\u0e1a \u0e40\u0e1b\u0e47\u0e19\u0e40\u0e27\u0e25\u0e32 3 \u0e23\u0e2d\u0e1a\"}\n];\n\n// \u0e40\u0e1c\u0e37\u0e48\u0e2d\u0e43\u0e0a\u0e49\u0e41\u0e1a\u0e1a module (Node/bundler) \u0e43\u0e19\u0e2d\u0e19\u0e32\u0e04\u0e15 \u0e44\u0e21\u0e48\u0e01\u0e23\u0e30\u0e17\u0e1a\u0e01\u0e32\u0e23\u0e43\u0e0a\u0e49\u0e41\u0e1a\u0e1a <script> \u0e1b\u0e01\u0e15\u0e34\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { PASSIVE_PARAMS, PASSIVES };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_equipment.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e19\u0e34\u0e22\u0e32\u0e21\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (\u0e2d\u0e32\u0e27\u0e38\u0e18 7 / \u0e40\u0e01\u0e23\u0e32\u0e30 4 / \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a 4) x 3 \u0e14\u0e32\u0e27\n// \u0e41\u0e15\u0e48\u0e25\u0e30\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e21\u0e35 kind: \"percent\" (%) \u0e2b\u0e23\u0e37\u0e2d \"flat\" (\u0e04\u0e48\u0e32\u0e04\u0e07\u0e17\u0e35\u0e48\u0e15\u0e23\u0e07\u0e46) \u2014 \u0e04\u0e25\u0e30\u0e01\u0e31\u0e19\u0e44\u0e1b\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e2b\u0e25\u0e32\u0e01\u0e2b\u0e25\u0e32\u0e22\n// stat_defs[star] = array \u0e02\u0e2d\u0e07 {stat, kind, min, max} \u2014 1\u2605/2\u2605 \u0e21\u0e35 1 \u0e15\u0e31\u0e27, 3\u2605 \u0e21\u0e35 2 \u0e15\u0e31\u0e27\n// ==========================================\n\nconst EQUIPMENT_TYPES = {\n  // ---------- \u0e2d\u0e32\u0e27\u0e38\u0e18 (7) ----------\n  sword: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e14\u0e32\u0e1a\u0e2a\u0e19\u0e34\u0e21\", 2: \"\u0e14\u0e32\u0e1a\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\", 3: \"\u0e14\u0e32\u0e1a\u0e42\u0e08\u0e23\u0e2a\u0e25\u0e31\u0e14\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"percent\", min: 3.1, max: 5.0 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }, { stat: \"def\", kind: \"flat\", min: 8, max: 14 }]\n    }\n  },\n  axe: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e02\u0e27\u0e32\u0e19\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e02\u0e27\u0e32\u0e19\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e2b\u0e19\u0e31\u0e01\", 3: \"\u0e02\u0e27\u0e32\u0e19\u0e1b\u0e23\u0e30\u0e2b\u0e32\u0e23\u0e40\u0e25\u0e37\u0e2d\u0e14\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"flat\", min: 3, max: 5 }],\n      2: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }],\n      3: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }, { stat: \"hp\", kind: \"percent\", min: 5.0, max: 8.0 }]\n    }\n  },\n  spear: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e2b\u0e2d\u0e01\u0e44\u0e21\u0e49\u0e1c\u0e38\", 2: \"\u0e2b\u0e2d\u0e01\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e41\u0e2b\u0e25\u0e21\", 3: \"\u0e2b\u0e2d\u0e01\u0e08\u0e2d\u0e21\u0e2a\u0e21\u0e38\u0e17\u0e23\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"percent\", min: 3.1, max: 5.0 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }, { stat: \"spd\", kind: \"percent\", min: 8.0, max: 12.0 }]\n    }\n  },\n  hammer: {\n    slot: \"weapon\", class_lock: null,\n    names: { 1: \"\u0e04\u0e49\u0e2d\u0e19\u0e2b\u0e34\u0e19\", 2: \"\u0e04\u0e49\u0e2d\u0e19\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e2b\u0e19\u0e32\", 3: \"\u0e04\u0e49\u0e2d\u0e19\u0e28\u0e36\u0e01\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"flat\", min: 3, max: 5 }],\n      2: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }],\n      3: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }, { stat: \"def\", kind: \"percent\", min: 8.0, max: 12.0 }]\n    }\n  },\n  bow: {\n    slot: \"weapon\", class_lock: \"ranger\",\n    names: { 1: \"\u0e18\u0e19\u0e39\u0e44\u0e21\u0e49\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e18\u0e19\u0e39\u0e2a\u0e32\u0e22\u0e40\u0e2b\u0e25\u0e47\u0e01\", 3: \"\u0e18\u0e19\u0e39\u0e2a\u0e32\u0e22\u0e25\u0e21\u0e17\u0e30\u0e40\u0e25\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"percent\", min: 3.1, max: 5.0 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }, { stat: \"crit_rate\", kind: \"percent\", min: 2.5, max: 4.0 }]\n    }\n  },\n  dagger: {\n    slot: \"weapon\", class_lock: \"assassin\",\n    names: { 1: \"\u0e21\u0e35\u0e14\u0e2a\u0e19\u0e34\u0e21\", 2: \"\u0e21\u0e35\u0e14\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e04\u0e21\", 3: \"\u0e21\u0e35\u0e14\u0e04\u0e39\u0e48\u0e40\u0e07\u0e32\u0e23\u0e32\u0e15\u0e23\u0e35\" },\n    stat_defs: {\n      1: [{ stat: \"atk\", kind: \"flat\", min: 3, max: 5 }],\n      2: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }],\n      3: [{ stat: \"atk\", kind: \"flat\", min: 6, max: 10 }, { stat: \"evasion\", kind: \"percent\", min: 2.5, max: 4.0 }]\n    }\n  },\n  staff: {\n    slot: \"weapon\", class_lock: \"support\",\n    names: { 1: \"\u0e04\u0e17\u0e32\u0e44\u0e21\u0e49\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e04\u0e17\u0e32\u0e41\u0e01\u0e30\u0e2a\u0e25\u0e31\u0e01\", 3: \"\u0e04\u0e17\u0e32\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\u0e17\u0e30\u0e40\u0e25\u0e25\u0e36\u0e01\" },\n    // 1\u2605 \u0e44\u0e21\u0e48\u0e43\u0e2b\u0e49 ATK/\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35 \u0e40\u0e1e\u0e23\u0e32\u0e30 support \u0e22\u0e31\u0e07\u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e17\u0e35\u0e48\u0e14\u0e32\u0e27\u0e19\u0e35\u0e49 - \u0e43\u0e2b\u0e49 DEF% \u0e41\u0e17\u0e19 (\u0e40\u0e2d\u0e32\u0e15\u0e31\u0e27\u0e23\u0e2d\u0e14)\n    // 2\u2605/3\u2605 \u0e16\u0e36\u0e07\u0e08\u0e30\u0e1b\u0e25\u0e14\u0e25\u0e47\u0e2d\u0e01\u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49 (unlock_attack: true) \u0e1e\u0e23\u0e49\u0e2d\u0e21 ATK\n    stat_defs: {\n      1: [{ stat: \"def\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      2: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0, unlock_attack: true }],\n      3: [{ stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0, unlock_attack: true }, { stat: \"hp\", kind: \"flat\", min: 30, max: 50 }]\n    }\n  },\n\n  // ---------- \u0e40\u0e01\u0e23\u0e32\u0e30 (4) ----------\n  armor_body: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e1c\u0e49\u0e32\u0e43\u0e1a\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e40\u0e01\u0e23\u0e32\u0e30\u0e2b\u0e19\u0e31\u0e07\", 3: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e40\u0e01\u0e23\u0e32\u0e30\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\" },\n    stat_defs: {\n      1: [{ stat: \"def\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      2: [{ stat: \"def\", kind: \"percent\", min: 8.0, max: 12.0 }],\n      3: [{ stat: \"def\", kind: \"percent\", min: 8.0, max: 12.0 }, { stat: \"hp\", kind: \"percent\", min: 5.0, max: 8.0 }]\n    }\n  },\n  shield: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e42\u0e25\u0e48\u0e44\u0e21\u0e49\u0e1c\u0e38\", 2: \"\u0e42\u0e25\u0e48\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e2b\u0e19\u0e32\", 3: \"\u0e42\u0e25\u0e48\u0e21\u0e31\u0e07\u0e01\u0e23\u0e17\u0e30\u0e40\u0e25\" },\n    stat_defs: {\n      1: [{ stat: \"def\", kind: \"flat\", min: 4, max: 7 }],\n      2: [{ stat: \"def\", kind: \"flat\", min: 8, max: 14 }],\n      3: [{ stat: \"def\", kind: \"flat\", min: 8, max: 14 }, { stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }]\n    }\n  },\n  boots: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e23\u0e2d\u0e07\u0e40\u0e17\u0e49\u0e32\u0e1c\u0e49\u0e32\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e23\u0e2d\u0e07\u0e40\u0e17\u0e49\u0e32\u0e2b\u0e19\u0e31\u0e07\u0e2b\u0e19\u0e32\", 3: \"\u0e23\u0e2d\u0e07\u0e40\u0e17\u0e49\u0e32\u0e1a\u0e39\u0e4a\u0e15\u0e19\u0e31\u0e01\u0e40\u0e14\u0e34\u0e19\u0e40\u0e23\u0e37\u0e2d\" },\n    stat_defs: {\n      1: [{ stat: \"spd\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      2: [{ stat: \"spd\", kind: \"percent\", min: 8.0, max: 12.0 }],\n      3: [{ stat: \"spd\", kind: \"percent\", min: 8.0, max: 12.0 }, { stat: \"def\", kind: \"flat\", min: 8, max: 14 }]\n    }\n  },\n  bone_armor: {\n    slot: \"armor\", class_lock: null,\n    names: { 1: \"\u0e40\u0e2a\u0e37\u0e49\u0e2d\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e1b\u0e25\u0e32\u0e40\u0e01\u0e48\u0e32\", 2: \"\u0e40\u0e01\u0e23\u0e32\u0e30\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e41\u0e02\u0e47\u0e07\", 3: \"\u0e40\u0e01\u0e23\u0e32\u0e30\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e1b\u0e25\u0e32\u0e27\u0e32\u0e2c\" },\n    stat_defs: {\n      1: [{ stat: \"hp\", kind: \"percent\", min: 3.1, max: 5.0 }],\n      2: [{ stat: \"hp\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      3: [{ stat: \"hp\", kind: \"percent\", min: 5.0, max: 8.0 }, { stat: \"resist\", kind: \"percent\", min: 3.1, max: 5.0 }]\n    }\n  },\n\n  // ---------- \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a (4) ----------\n  ring: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e41\u0e2b\u0e27\u0e19\u0e17\u0e2d\u0e07\u0e41\u0e14\u0e07\", 2: \"\u0e41\u0e2b\u0e27\u0e19\u0e40\u0e07\u0e34\u0e19\u0e2a\u0e25\u0e31\u0e01\", 3: \"\u0e41\u0e2b\u0e27\u0e19\u0e44\u0e02\u0e48\u0e21\u0e38\u0e01\u0e14\u0e33\" },\n    stat_defs: {\n      1: [{ stat: \"crit_rate\", kind: \"percent\", min: 1.6, max: 2.5 }],\n      2: [{ stat: \"crit_rate\", kind: \"percent\", min: 2.5, max: 4.0 }],\n      3: [{ stat: \"crit_rate\", kind: \"percent\", min: 2.5, max: 4.0 }, { stat: \"atk\", kind: \"percent\", min: 5.0, max: 8.0 }]\n    }\n  },\n  necklace: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e2a\u0e23\u0e49\u0e2d\u0e22\u0e40\u0e0a\u0e37\u0e2d\u0e01\u0e2b\u0e19\u0e31\u0e07\", 2: \"\u0e2a\u0e23\u0e49\u0e2d\u0e22\u0e40\u0e07\u0e34\u0e19\", 3: \"\u0e2a\u0e23\u0e49\u0e2d\u0e22\u0e01\u0e30\u0e42\u0e2b\u0e25\u0e01\u0e17\u0e2d\u0e07\" },\n    stat_defs: {\n      1: [{ stat: \"crit_damage\", kind: \"percent\", min: 1.6, max: 2.5 }],\n      2: [{ stat: \"crit_damage\", kind: \"percent\", min: 2.5, max: 4.0 }],\n      3: [{ stat: \"crit_damage\", kind: \"percent\", min: 2.5, max: 4.0 }, { stat: \"atk\", kind: \"flat\", min: 6, max: 10 }]\n    }\n  },\n  brooch: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e40\u0e02\u0e47\u0e21\u0e01\u0e25\u0e31\u0e14\u0e17\u0e2d\u0e07\u0e41\u0e14\u0e07\", 2: \"\u0e40\u0e02\u0e47\u0e21\u0e01\u0e25\u0e31\u0e14\u0e40\u0e07\u0e34\u0e19\", 3: \"\u0e40\u0e02\u0e47\u0e21\u0e01\u0e25\u0e31\u0e14\u0e40\u0e02\u0e47\u0e21\u0e17\u0e34\u0e28\u0e17\u0e2d\u0e07\" },\n    stat_defs: {\n      1: [{ stat: \"spd\", kind: \"percent\", min: 5.0, max: 8.0 }],\n      2: [{ stat: \"spd\", kind: \"percent\", min: 8.0, max: 12.0 }],\n      3: [{ stat: \"spd\", kind: \"percent\", min: 8.0, max: 12.0 }, { stat: \"evasion\", kind: \"percent\", min: 2.5, max: 4.0 }]\n    }\n  },\n  bracelet: {\n    slot: \"accessory\", class_lock: null,\n    names: { 1: \"\u0e01\u0e33\u0e44\u0e25\u0e40\u0e0a\u0e37\u0e2d\u0e01\", 2: \"\u0e01\u0e33\u0e44\u0e25\u0e40\u0e07\u0e34\u0e19\", 3: \"\u0e01\u0e33\u0e44\u0e25\u0e42\u0e0b\u0e48\u0e40\u0e07\u0e34\u0e19\" },\n    stat_defs: {\n      1: [{ stat: \"hp\", kind: \"flat\", min: 15, max: 25 }],\n      2: [{ stat: \"hp\", kind: \"flat\", min: 30, max: 50 }],\n      3: [{ stat: \"hp\", kind: \"flat\", min: 30, max: 50 }, { stat: \"spd\", kind: \"percent\", min: 8.0, max: 12.0 }]\n    }\n  }\n};\n\n// \u0e23\u0e30\u0e14\u0e31\u0e1a Level (\u0e1b\u0e49\u0e2d\u0e19\u0e02\u0e2d\u0e07\u0e0b\u0e49\u0e33\u0e14\u0e32\u0e27+\u0e0a\u0e19\u0e34\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19) \u2014 \u0e04\u0e48\u0e32\u0e1e\u0e25\u0e31\u0e07\u0e04\u0e39\u0e13\u0e40\u0e02\u0e49\u0e32\u0e01\u0e31\u0e1a\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e2a\u0e38\u0e48\u0e21\u0e44\u0e14\u0e49\nconst EQUIPMENT_LEVELS = [\n  { level: 1, multiplier: 1.00, dupes_needed: 0 },\n  { level: 2, multiplier: 1.25, dupes_needed: 1 },\n  { level: 3, multiplier: 1.50, dupes_needed: 2 },\n  { level: 4, multiplier: 1.75, dupes_needed: 3 },\n  { level: 5, multiplier: 2.00, dupes_needed: 5 }\n];\n\n// \u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 \u2014 \u0e22\u0e49\u0e32\u0e22\u0e44\u0e1b\u0e19\u0e34\u0e22\u0e32\u0e21\u0e14\u0e49\u0e32\u0e19\u0e25\u0e48\u0e32\u0e07 (EQUIPMENT_UPGRADE_RECIPES) \u0e41\u0e25\u0e49\u0e27\n// \u0e40\u0e14\u0e34\u0e21\u0e21\u0e35\u0e41\u0e04\u0e48 2 \u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a\u0e43\u0e0a\u0e49\u0e23\u0e48\u0e27\u0e21\u0e01\u0e31\u0e19\u0e2b\u0e21\u0e14\u0e17\u0e38\u0e01\u0e0a\u0e34\u0e49\u0e19 \u0e15\u0e2d\u0e19\u0e19\u0e35\u0e49\u0e40\u0e1b\u0e25\u0e35\u0e48\u0e22\u0e19\u0e40\u0e1b\u0e47\u0e19\u0e2a\u0e39\u0e15\u0e23\u0e40\u0e09\u0e1e\u0e32\u0e30\u0e15\u0e48\u0e2d\u0e0a\u0e19\u0e34\u0e14\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c (11 \u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a)\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { EQUIPMENT_TYPES, EQUIPMENT_LEVELS };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_equipment_materials.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e19\u0e34\u0e22\u0e32\u0e21\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a\u0e04\u0e23\u0e32\u0e1f\u0e17\u0e4c/\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e31\u0e49\u0e07 11 \u0e0a\u0e19\u0e34\u0e14 (\u0e41\u0e1a\u0e48\u0e07\u0e15\u0e32\u0e21\u0e2b\u0e21\u0e27\u0e14\u0e27\u0e31\u0e2a\u0e14\u0e38 + \u0e14\u0e32\u0e27)\n// \u0e41\u0e25\u0e30\u0e2a\u0e39\u0e15\u0e23\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 (1\u2605->2\u2605, 2\u2605->3\u2605) \u0e02\u0e2d\u0e07\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e31\u0e49\u0e07 15 \u0e0a\u0e19\u0e34\u0e14\n// ==========================================\n\nconst EQUIPMENT_MATERIALS = {\n  mat_iron_ore:        { name: \"\u0e41\u0e23\u0e48\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e14\u0e34\u0e1a\",        star: 1, category: \"metal\" },\n  mat_pure_steel:       { name: \"\u0e40\u0e2b\u0e25\u0e47\u0e01\u0e01\u0e25\u0e49\u0e32\u0e1a\u0e23\u0e34\u0e2a\u0e38\u0e17\u0e18\u0e34\u0e4c\",  star: 2, category: \"metal\" },\n  mat_softwood:         { name: \"\u0e44\u0e21\u0e49\u0e40\u0e19\u0e37\u0e49\u0e2d\u0e2d\u0e48\u0e2d\u0e19\",        star: 1, category: \"wood\" },\n  mat_spirit_hardwood:  { name: \"\u0e44\u0e21\u0e49\u0e40\u0e19\u0e37\u0e49\u0e2d\u0e41\u0e02\u0e47\u0e07\u0e27\u0e34\u0e0d\u0e0d\u0e32\u0e13\",  star: 2, category: \"wood\" },\n  mat_common_leather:   { name: \"\u0e2b\u0e19\u0e31\u0e07\u0e2a\u0e31\u0e15\u0e27\u0e4c\u0e18\u0e23\u0e23\u0e21\u0e14\u0e32\",     star: 1, category: \"leather\" },\n  mat_sea_leather:      { name: \"\u0e2b\u0e19\u0e31\u0e07\u0e2d\u0e2a\u0e39\u0e23\u0e17\u0e30\u0e40\u0e25\",        star: 2, category: \"leather\" },\n  mat_strong_thread:    { name: \"\u0e14\u0e49\u0e32\u0e22\u0e40\u0e2b\u0e19\u0e35\u0e22\u0e27\u0e1e\u0e34\u0e40\u0e28\u0e29\",     star: 1, category: \"thread\" },\n  mat_animal_bone:      { name: \"\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e2a\u0e31\u0e15\u0e27\u0e4c\u0e17\u0e31\u0e48\u0e27\u0e44\u0e1b\",   star: 1, category: \"bone\" },\n  mat_monster_bone:     { name: \"\u0e01\u0e23\u0e30\u0e14\u0e39\u0e01\u0e2a\u0e31\u0e15\u0e27\u0e4c\u0e1b\u0e23\u0e30\u0e2b\u0e25\u0e32\u0e14\",  star: 2, category: \"bone\" },\n  mat_crystal_shard:    { name: \"\u0e40\u0e28\u0e29\u0e04\u0e23\u0e34\u0e2a\u0e15\u0e31\u0e25\",         star: 1, category: \"crystal\" },\n  mat_deep_pearl:        { name: \"\u0e44\u0e02\u0e48\u0e21\u0e38\u0e01\u0e17\u0e30\u0e40\u0e25\u0e25\u0e36\u0e01\",       star: 2, category: \"crystal\" }\n};\n\nconst EQUIPMENT_MATERIAL_FAMILIES = {\n  metal:   { 1: \"mat_iron_ore\",      2: \"mat_pure_steel\" },\n  wood:    { 1: \"mat_softwood\",      2: \"mat_spirit_hardwood\" },\n  leather: { 1: \"mat_common_leather\", 2: \"mat_sea_leather\" },\n  bone:    { 1: \"mat_animal_bone\",   2: \"mat_monster_bone\" },\n  crystal: { 1: \"mat_crystal_shard\", 2: \"mat_deep_pearl\" }\n};\nconst EQUIPMENT_MATERIAL_FAMILY_ORDER = [\"metal\", \"wood\", \"leather\", \"bone\", \"crystal\"];\n\nconst EQUIPMENT_UPGRADE_RECIPES = {\n  sword:  { 2: [{ item_id: \"mat_iron_ore\", qty: 4 }], 3: [{ item_id: \"mat_pure_steel\", qty: 2 }, { item_id: \"mat_iron_ore\", qty: 3 }] },\n  dagger: { 2: [{ item_id: \"mat_iron_ore\", qty: 4 }], 3: [{ item_id: \"mat_pure_steel\", qty: 2 }, { item_id: \"mat_iron_ore\", qty: 3 }] },\n  axe:    { 2: [{ item_id: \"mat_iron_ore\", qty: 4 }], 3: [{ item_id: \"mat_pure_steel\", qty: 2 }, { item_id: \"mat_iron_ore\", qty: 3 }] },\n\n  spear:  { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_softwood\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_iron_ore\", qty: 2 }] },\n  hammer: { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_softwood\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_iron_ore\", qty: 2 }] },\n  shield: { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_softwood\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_iron_ore\", qty: 2 }] },\n\n  bow: { 2: [{ item_id: \"mat_softwood\", qty: 3 }, { item_id: \"mat_strong_thread\", qty: 2 }], 3: [{ item_id: \"mat_spirit_hardwood\", qty: 2 }, { item_id: \"mat_strong_thread\", qty: 4 }] },\n\n  staff: { 2: [{ item_id: \"mat_softwood\", qty: 3 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_spirit_hardwood\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_crystal_shard\", qty: 3 }] },\n\n  armor_body: { 2: [{ item_id: \"mat_common_leather\", qty: 4 }, { item_id: \"mat_strong_thread\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 2 }, { item_id: \"mat_common_leather\", qty: 3 }] },\n  boots:      { 2: [{ item_id: \"mat_common_leather\", qty: 4 }, { item_id: \"mat_strong_thread\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 2 }, { item_id: \"mat_common_leather\", qty: 3 }] },\n\n  bone_armor: { 2: [{ item_id: \"mat_animal_bone\", qty: 4 }, { item_id: \"mat_strong_thread\", qty: 1 }], 3: [{ item_id: \"mat_monster_bone\", qty: 2 }, { item_id: \"mat_animal_bone\", qty: 3 }] },\n\n  ring:     { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_crystal_shard\", qty: 2 }] },\n  necklace: { 2: [{ item_id: \"mat_iron_ore\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_pure_steel\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_crystal_shard\", qty: 2 }] },\n\n  brooch:   { 2: [{ item_id: \"mat_common_leather\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_strong_thread\", qty: 3 }] },\n  bracelet: { 2: [{ item_id: \"mat_common_leather\", qty: 2 }, { item_id: \"mat_crystal_shard\", qty: 2 }], 3: [{ item_id: \"mat_sea_leather\", qty: 1 }, { item_id: \"mat_deep_pearl\", qty: 1 }, { item_id: \"mat_strong_thread\", qty: 3 }] }\n};\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { EQUIPMENT_MATERIALS, EQUIPMENT_MATERIAL_FAMILIES, EQUIPMENT_MATERIAL_FAMILY_ORDER, EQUIPMENT_UPGRADE_RECIPES };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: data_combat_power.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e04\u0e48\u0e32\u0e04\u0e07\u0e17\u0e35\u0e48\u0e02\u0e2d\u0e07\u0e23\u0e30\u0e1a\u0e1a \"\u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\" (Combat Power) \u2014 \u0e2a\u0e40\u0e1b\u0e04\u0e17\u0e35\u0e48 2 \u0e08\u0e32\u0e01 roadmap\n// \u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e15\u0e48\u0e2d\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 = (\u0e1c\u0e25\u0e23\u0e27\u0e21\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e16\u0e48\u0e27\u0e07\u0e19\u0e49\u0e33\u0e2b\u0e19\u0e31\u0e01) x \u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e15\u0e32\u0e21\u0e2a\u0e32\u0e22 (role)\n// \u0e2a\u0e32\u0e22 Fighter \u0e43\u0e2b\u0e49\u0e04\u0e48\u0e32\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14, Ranger \u0e15\u0e48\u0e33\u0e2a\u0e38\u0e14 \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e01\u0e33\u0e2b\u0e19\u0e14 \u0e2a\u0e48\u0e27\u0e19\u0e2a\u0e32\u0e22\u0e2d\u0e37\u0e48\u0e19\u0e40\u0e23\u0e35\u0e22\u0e07\u0e15\u0e32\u0e21\u0e04\u0e27\u0e32\u0e21\u0e40\u0e2b\u0e21\u0e32\u0e30\u0e2a\u0e21\n// ==========================================\n\n// \u0e19\u0e49\u0e33\u0e2b\u0e19\u0e31\u0e01\u0e02\u0e2d\u0e07\u0e41\u0e15\u0e48\u0e25\u0e30\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a \u0e15\u0e2d\u0e19\u0e23\u0e27\u0e21\u0e40\u0e1b\u0e47\u0e19\u0e04\u0e48\u0e32\u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e14\u0e34\u0e1a (\u0e01\u0e48\u0e2d\u0e19\u0e04\u0e39\u0e13\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e2a\u0e32\u0e22)\n// \u0e40\u0e19\u0e49\u0e19 HP \u0e01\u0e31\u0e1a ATK \u0e40\u0e1b\u0e47\u0e19\u0e2b\u0e25\u0e31\u0e01\u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e01\u0e33\u0e2b\u0e19\u0e14 \u0e41\u0e15\u0e48\u0e43\u0e2a\u0e48 DEF/SPD \u0e44\u0e27\u0e49\u0e40\u0e25\u0e47\u0e01\u0e19\u0e49\u0e2d\u0e22\u0e43\u0e2b\u0e49\u0e04\u0e23\u0e1a\u0e17\u0e38\u0e01\u0e21\u0e34\u0e15\u0e34\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\nconst COMBAT_POWER_STAT_WEIGHTS = {\n  hp: 0.3,\n  attack: 4,\n  defense_flat: 3,\n  speed: 2\n};\n\n// \u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e15\u0e32\u0e21\u0e2a\u0e32\u0e22 (role) \u2014 Fighter \u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14, Ranger \u0e15\u0e48\u0e33\u0e2a\u0e38\u0e14 \u0e15\u0e32\u0e21\u0e17\u0e35\u0e48\u0e01\u0e33\u0e2b\u0e19\u0e14\nconst COMBAT_POWER_ROLE_MULTIPLIER = {\n  fighter: 1.25,\n  assassin: 1.15,\n  tank: 1.05,\n  support: 0.95,\n  ranger: 0.85\n};\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { COMBAT_POWER_STAT_WEIGHTS, COMBAT_POWER_ROLE_MULTIPLIER };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: crew_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e14\u0e39\u0e41\u0e25\u0e25\u0e2d\u0e08\u0e34\u0e01\u0e01\u0e32\u0e23\u0e08\u0e31\u0e14\u0e17\u0e35\u0e21 + \u0e14\u0e36\u0e07\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e08\u0e32\u0e01 id\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_characters.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d\n// ==========================================\n\nfunction crewGetBaseCharData(id) {\n  const found = CHARACTERS.find(c => c.id === id);\n  if (!found) {\n    throw new Error(`\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 id: ${id} \u0e43\u0e19 data_characters.js`);\n  }\n  // \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32\u0e2a\u0e33\u0e40\u0e19\u0e32 \u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19\u0e44\u0e21\u0e48\u0e43\u0e2b\u0e49 combat_engine \u0e44\u0e1b\u0e41\u0e01\u0e49\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a\u0e42\u0e14\u0e22\u0e44\u0e21\u0e48\u0e15\u0e31\u0e49\u0e07\u0e43\u0e08\n  return JSON.parse(JSON.stringify(found));\n}\n\n// \u0e40\u0e23\u0e35\u0e22\u0e07\u0e25\u0e33\u0e14\u0e31\u0e1a id \u0e25\u0e39\u0e01\u0e40\u0e23\u0e37\u0e2d: \u0e40\u0e01\u0e23\u0e14\u0e2a\u0e39\u0e07\u0e01\u0e48\u0e2d\u0e19 (S>A>B>C) \u0e41\u0e25\u0e49\u0e27\u0e16\u0e49\u0e32\u0e40\u0e01\u0e23\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e40\u0e25\u0e40\u0e27\u0e25\u0e2a\u0e39\u0e07\u0e01\u0e27\u0e48\u0e32\u0e2d\u0e22\u0e39\u0e48\u0e01\u0e48\u0e2d\u0e19\n// \u0e43\u0e0a\u0e49\u0e23\u0e48\u0e27\u0e21\u0e01\u0e31\u0e19\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e19\u0e49\u0e32\u0e04\u0e25\u0e31\u0e07\u0e25\u0e39\u0e01\u0e40\u0e23\u0e37\u0e2d\u0e41\u0e25\u0e30\u0e2b\u0e19\u0e49\u0e32\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e43\u0e2b\u0e49\u0e2d\u0e32\u0e2b\u0e32\u0e23\nfunction crewSortIdsByGradeLevel(ids) {\n  const gradeWeight = { S: 4, A: 3, B: 2, C: 1 };\n  return ids.slice().sort((a, b) => {\n    const gradeA = crewGetBaseCharData(a).grade;\n    const gradeB = crewGetBaseCharData(b).grade;\n    if (gradeWeight[gradeA] !== gradeWeight[gradeB]) return (gradeWeight[gradeB] || 0) - (gradeWeight[gradeA] || 0);\n    return (playerState.crew[b].level || 1) - (playerState.crew[a].level || 1);\n  });\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { crewGetBaseCharData, crewSortIdsByGradeLevel };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: progression_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e04\u0e33\u0e19\u0e27\u0e13\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19 \u0e15\u0e32\u0e21 level / \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33 (dupes) / \u0e04\u0e25\u0e32\u0e2a (class)\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_characters.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d (\u0e43\u0e2b\u0e49\u0e15\u0e31\u0e27\u0e41\u0e1b\u0e23 CHARACTERS)\n// \u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e44\u0e21\u0e48\u0e21\u0e35\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e14\u0e34\u0e1a\u0e1d\u0e31\u0e07\u0e2d\u0e22\u0e39\u0e48 \u0e21\u0e35\u0e41\u0e15\u0e48\u0e2a\u0e39\u0e15\u0e23\u0e04\u0e33\u0e19\u0e27\u0e13\n// ==========================================\n\n// \u0e17\u0e38\u0e01\u0e40\u0e25\u0e40\u0e27\u0e25\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a 5% \u0e02\u0e2d\u0e07\u0e04\u0e48\u0e32\u0e40\u0e23\u0e34\u0e48\u0e21\u0e15\u0e49\u0e19 (level 1) \u0e41\u0e1a\u0e1a\u0e04\u0e07\u0e17\u0e35\u0e48 \u0e44\u0e21\u0e48\u0e17\u0e1a\u0e15\u0e49\u0e19\n// \u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a\u0e17\u0e38\u0e01\u0e04\u0e25\u0e32\u0e2a\u0e40\u0e2b\u0e21\u0e37\u0e2d\u0e19\u0e01\u0e31\u0e19\u0e2b\u0e21\u0e14 (class \u0e44\u0e21\u0e48\u0e21\u0e35\u0e1c\u0e25\u0e01\u0e31\u0e1a\u0e2a\u0e39\u0e15\u0e23\u0e1a\u0e27\u0e01 level \u0e19\u0e35\u0e49)\nconst LEVEL_STEP_PERCENT = 0.05;\n\n// \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33 1 \u0e15\u0e31\u0e27 \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a 10% \u0e08\u0e32\u0e01\u0e04\u0e48\u0e32\u0e10\u0e32\u0e19 (\u0e19\u0e31\u0e1a\u0e08\u0e32\u0e01\u0e10\u0e32\u0e19\u0e40\u0e2a\u0e21\u0e2d \u0e44\u0e21\u0e48\u0e17\u0e1a\u0e15\u0e49\u0e19\u0e15\u0e32\u0e21\u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33)\n// \u0e04\u0e19\u0e25\u0e30\u0e15\u0e31\u0e27\u0e01\u0e31\u0e1a LEVEL_STEP_PERCENT \u0e14\u0e49\u0e32\u0e19\u0e1a\u0e19 (\u0e19\u0e31\u0e48\u0e19\u0e04\u0e37\u0e2d\u0e04\u0e48\u0e32\u0e15\u0e48\u0e2d\u0e40\u0e25\u0e40\u0e27\u0e25 \u0e19\u0e35\u0e48\u0e04\u0e37\u0e2d\u0e04\u0e48\u0e32\u0e15\u0e48\u0e2d\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33)\nconst DUPE_BONUS_PERCENT = 0.10;\n\n// \u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e10\u0e32\u0e19\u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a 2 \u0e41\u0e25\u0e30\u0e04\u0e25\u0e32\u0e2a 3 (\u0e21\u0e32\u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e04\u0e48\u0e32\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e02\u0e2d\u0e07 dupes \u0e40\u0e14\u0e34\u0e21\u0e15\u0e2d\u0e19\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a)\nconst CLASS_BASE_MULTIPLIER = 1.42;\n\n// \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e15\u0e48\u0e2d \"1 \u0e01\u0e25\u0e38\u0e48\u0e21\" \u0e17\u0e35\u0e48\u0e43\u0e0a\u0e49\u0e40\u0e1e\u0e34\u0e48\u0e21 max level \u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a 2 (\u0e17\u0e38\u0e01 4 \u0e15\u0e31\u0e27 \u0e40\u0e1e\u0e34\u0e48\u0e21 1 level)\nconst CLASS2_DUPES_PER_LEVEL_GROUP = 4;\nconst CLASS2_MAX_GROUPS = 5; // 5 \u0e01\u0e25\u0e38\u0e48\u0e21 x 4 \u0e15\u0e31\u0e27 = 20 \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33 \u0e16\u0e36\u0e07\u0e08\u0e30\u0e41\u0e21\u0e47\u0e01\u0e04\u0e25\u0e32\u0e2a 2 (level 30)\n\n// \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a 1 (\u0e41\u0e15\u0e48\u0e25\u0e30\u0e15\u0e31\u0e27\u0e40\u0e1e\u0e34\u0e48\u0e21 1 level \u0e41\u0e25\u0e30\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13 10%)\nconst CLASS1_MAX_DUPES = 5;\n\n// ==========================================\n// 1) \u0e04\u0e33\u0e19\u0e27\u0e13\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e2b\u0e25\u0e31\u0e07\u0e1a\u0e27\u0e01 level (\u0e22\u0e31\u0e07\u0e44\u0e21\u0e48\u0e04\u0e39\u0e13\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33/\u0e04\u0e25\u0e32\u0e2a)\n// ==========================================\nfunction getLevelValue(baseStatAtLevel1, level) {\n  const lvl = Math.max(1, level);\n  return baseStatAtLevel1 + (baseStatAtLevel1 * LEVEL_STEP_PERCENT * (lvl - 1));\n}\n\n// ==========================================\n// 2) \u0e04\u0e33\u0e19\u0e27\u0e13\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e23\u0e27\u0e21\u0e08\u0e32\u0e01\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33 + \u0e04\u0e25\u0e32\u0e2a\n//    charClass: 1, 2, \u0e2b\u0e23\u0e37\u0e2d 3\n//    dupes: \u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e2a\u0e30\u0e2a\u0e21 \"\u0e20\u0e32\u0e22\u0e43\u0e19\u0e04\u0e25\u0e32\u0e2a\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19\" (\u0e19\u0e31\u0e1a\u0e43\u0e2b\u0e21\u0e48\u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e17\u0e35\u0e48\u0e2d\u0e31\u0e1e\u0e04\u0e25\u0e32\u0e2a)\n// ==========================================\nfunction getClassDupeMultiplier(charClass, dupes) {\n  const safeDupes = Math.max(0, dupes || 0);\n\n  if (charClass === 1) {\n    // \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e41\u0e15\u0e48\u0e25\u0e30\u0e15\u0e31\u0e27 (\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e14\u0e2d\u0e31\u0e1e\u0e40\u0e01\u0e23\u0e14\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e01\u0e48\u0e2d\u0e19\u0e16\u0e36\u0e07\u0e08\u0e30\u0e21\u0e35\u0e1c\u0e25) \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e17\u0e35\u0e25\u0e30 10% \u0e41\u0e1a\u0e1a\u0e1a\u0e27\u0e01\u0e2a\u0e30\u0e2a\u0e21\u0e08\u0e32\u0e01\u0e10\u0e32\u0e19 (\u0e44\u0e21\u0e48\u0e17\u0e1a\u0e15\u0e49\u0e19)\n    // 0 \u0e15\u0e31\u0e27 = 1.00, 1 \u0e15\u0e31\u0e27 = 1.10, ... 5 \u0e15\u0e31\u0e27 (\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14) = 1.50\n    const d = Math.min(safeDupes, CLASS1_MAX_DUPES);\n    return 1 + (d * DUPE_BONUS_PERCENT);\n  }\n\n  if (charClass === 2) {\n    // \u0e15\u0e2d\u0e19\u0e2d\u0e31\u0e1e\u0e08\u0e32\u0e01\u0e04\u0e25\u0e32\u0e2a 1 -> 2 : \u0e15\u0e31\u0e27\u0e04\u0e39\u0e13 1.50 \u0e40\u0e14\u0e34\u0e21 \"\u0e16\u0e39\u0e01\u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\" \u0e14\u0e49\u0e27\u0e22 1.42 \u0e17\u0e31\u0e19\u0e17\u0e35 (\u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e04\u0e39\u0e13\u0e01\u0e31\u0e19)\n    // \u0e08\u0e32\u0e01\u0e19\u0e31\u0e49\u0e19\u0e17\u0e38\u0e01\u0e46 \u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e04\u0e23\u0e1a 4 \u0e15\u0e31\u0e27 (1 \u0e01\u0e25\u0e38\u0e48\u0e21) \u0e04\u0e39\u0e13\u0e40\u0e1e\u0e34\u0e48\u0e21\u0e2d\u0e35\u0e01 10% \u0e02\u0e2d\u0e07\u0e10\u0e32\u0e19 1.42\n    const groups = Math.min(Math.floor(safeDupes / CLASS2_DUPES_PER_LEVEL_GROUP), CLASS2_MAX_GROUPS);\n    return CLASS_BASE_MULTIPLIER * (1 + (groups * DUPE_BONUS_PERCENT));\n  }\n\n  if (charClass === 3) {\n    // \u0e15\u0e2d\u0e19\u0e2d\u0e31\u0e1e\u0e08\u0e32\u0e01\u0e04\u0e25\u0e32\u0e2a 2 -> 3 : \u0e40\u0e2d\u0e32\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e02\u0e2d\u0e07\u0e04\u0e25\u0e32\u0e2a 2 (1.42 x 1.25) \u0e04\u0e39\u0e13\u0e2d\u0e35\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e14\u0e49\u0e27\u0e22 1.42\n    // \u0e04\u0e25\u0e32\u0e2a 3 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e23\u0e30\u0e1a\u0e1a\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\u0e40\u0e1e\u0e34\u0e48\u0e21 max level \u0e2d\u0e35\u0e01\u0e41\u0e25\u0e49\u0e27 \u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e08\u0e36\u0e07\u0e04\u0e07\u0e17\u0e35\u0e48\n    const class2MaxMultiplier = CLASS_BASE_MULTIPLIER * (1 + (CLASS2_MAX_GROUPS * DUPE_BONUS_PERCENT));\n    return class2MaxMultiplier * CLASS_BASE_MULTIPLIER;\n  }\n\n  return 1;\n}\n\n// ==========================================\n// 3) \u0e04\u0e33\u0e19\u0e27\u0e13 max level \u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 \u0e15\u0e32\u0e21\u0e04\u0e25\u0e32\u0e2a\u0e41\u0e25\u0e30\u0e08\u0e33\u0e19\u0e27\u0e19\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33\n// ==========================================\nfunction getMaxLevel(charClass, dupes) {\n  const safeDupes = Math.max(0, dupes || 0);\n\n  if (charClass === 1) {\n    const d = Math.min(safeDupes, CLASS1_MAX_DUPES);\n    return 20 + d; // 20 \u0e16\u0e36\u0e07 25\n  }\n  if (charClass === 2) {\n    const groups = Math.min(Math.floor(safeDupes / CLASS2_DUPES_PER_LEVEL_GROUP), CLASS2_MAX_GROUPS);\n    return 25 + groups; // 25 \u0e16\u0e36\u0e07 30\n  }\n  if (charClass === 3) {\n    return 30; // \u0e04\u0e07\u0e17\u0e35\u0e48 \u0e44\u0e21\u0e48\u0e21\u0e35\u0e23\u0e30\u0e1a\u0e1a\u0e40\u0e1e\u0e34\u0e48\u0e21 max level \u0e41\u0e25\u0e49\u0e27\n  }\n  return 20;\n}\n\n// ==========================================\n// 4) \u0e15\u0e32\u0e23\u0e32\u0e07 EXP \u0e15\u0e48\u0e2d\u0e40\u0e25\u0e40\u0e27\u0e25 (\u0e21\u0e32\u0e08\u0e32\u0e01 progression_system.json \u0e40\u0e14\u0e34\u0e21\u0e17\u0e35\u0e48\u0e21\u0e35\u0e15\u0e31\u0e27\u0e40\u0e25\u0e02\u0e08\u0e23\u0e34\u0e07\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27)\n//    base_exp_table = EXP \u0e17\u0e35\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49 \"\u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e2d\u0e31\u0e1e\u0e08\u0e32\u0e01 level \u0e19\u0e31\u0e49\u0e19 \u0e44\u0e1b level \u0e16\u0e31\u0e14\u0e44\u0e1b\" (\u0e40\u0e01\u0e23\u0e14 C \u0e04\u0e37\u0e2d\u0e04\u0e48\u0e32\u0e10\u0e32\u0e19)\n// ==========================================\n// base_exp_table \u0e40\u0e14\u0e34\u0e21 (level 1-19) \u0e15\u0e48\u0e2d\u0e14\u0e49\u0e27\u0e22\u0e2a\u0e48\u0e27\u0e19\u0e02\u0e22\u0e32\u0e22 level 20-29 \u0e17\u0e35\u0e48\u0e04\u0e33\u0e19\u0e27\u0e13\u0e2a\u0e37\u0e1a\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07\u0e08\u0e32\u0e01\u0e23\u0e39\u0e1b\u0e41\u0e1a\u0e1a\u0e40\u0e14\u0e34\u0e21:\n// \u0e15\u0e32\u0e23\u0e32\u0e07\u0e40\u0e14\u0e34\u0e21\u0e40\u0e1b\u0e47\u0e19\u0e02\u0e31\u0e49\u0e19\u0e1a\u0e31\u0e19\u0e44\u0e14 \u0e42\u0e14\u0e22 \"\u0e1c\u0e25\u0e15\u0e48\u0e32\u0e07\u0e02\u0e2d\u0e07\u0e1c\u0e25\u0e15\u0e48\u0e32\u0e07\" (\u0394 \u0e02\u0e2d\u0e07 \u0394) \u0e04\u0e07\u0e17\u0e35\u0e48\u0e43\u0e19\u0e41\u0e15\u0e48\u0e25\u0e30\u0e0a\u0e48\u0e27\u0e07 \u0e41\u0e25\u0e49\u0e27\u0e02\u0e22\u0e31\u0e1a\u0e02\u0e36\u0e49\u0e19\u0e40\u0e1b\u0e47\u0e19\u0e0a\u0e48\u0e27\u0e07\u0e46\n// (level1-10: \u0394\u0394=20, level10-15: \u0394\u0394=100, level15-19: \u0394\u0394=200) \u0e2a\u0e48\u0e27\u0e19\u0e02\u0e22\u0e32\u0e22\u0e19\u0e35\u0e49\u0e2a\u0e37\u0e1a\u0e15\u0e48\u0e2d \u0394\u0394=200 \u0e0a\u0e48\u0e27\u0e07\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e44\u0e1b\u0e40\u0e23\u0e37\u0e48\u0e2d\u0e22\u0e46\n// \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e43\u0e2b\u0e49\u0e40\u0e25\u0e40\u0e27\u0e25 20-30 (\u0e04\u0e25\u0e32\u0e2a 2-3 \u0e43\u0e2b\u0e21\u0e48) \u0e21\u0e35\u0e15\u0e32\u0e23\u0e32\u0e07 EXP \u0e17\u0e35\u0e48\u0e42\u0e15\u0e15\u0e48\u0e2d\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e18\u0e23\u0e23\u0e21\u0e0a\u0e32\u0e15\u0e34\u0e08\u0e32\u0e01\u0e02\u0e2d\u0e07\u0e40\u0e14\u0e34\u0e21 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e40\u0e25\u0e02\u0e17\u0e35\u0e48\u0e04\u0e34\u0e14\u0e02\u0e36\u0e49\u0e19\u0e43\u0e2b\u0e21\u0e48\u0e25\u0e2d\u0e22\u0e46\nconst BASE_EXP_TABLE = {\n  1: 100, 2: 220, 3: 360, 4: 520, 5: 700, 6: 900, 7: 1120,\n  8: 1360, 9: 1620, 10: 1900, 11: 2280, 12: 2760, 13: 3340,\n  14: 4020, 15: 4800, 16: 5780, 17: 6960, 18: 8340, 19: 9920,\n  20: 11700, 21: 13680, 22: 15860, 23: 18240, 24: 20820,\n  25: 23600, 26: 26580, 27: 29760, 28: 33140, 29: 36720\n};\n\nconst GRADE_EXP_MULTIPLIER = { C: 1.0, B: 1.6, A: 2.35, S: 3.4 };\n\n// \u0e04\u0e33\u0e19\u0e27\u0e13 EXP \u0e17\u0e35\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49 \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e2d\u0e31\u0e1e\u0e08\u0e32\u0e01 (level - 1) \u0e44\u0e1b\u0e40\u0e1b\u0e47\u0e19 level \u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19 \u0e15\u0e32\u0e21\u0e40\u0e01\u0e23\u0e14\nfunction getExpRequired(level, grade) {\n  if (level <= 1) return 0;\n  const base = BASE_EXP_TABLE[level - 1];\n  if (base === undefined) return null; // \u0e40\u0e01\u0e34\u0e19\u0e15\u0e32\u0e23\u0e32\u0e07\u0e17\u0e35\u0e48\u0e21\u0e35 (\u0e40\u0e25\u0e40\u0e27\u0e25\u0e41\u0e21\u0e47\u0e01\u0e02\u0e2d\u0e07\u0e40\u0e01\u0e21)\n  const multi = GRADE_EXP_MULTIPLIER[grade] || 1.0;\n  return Math.round(base * multi);\n}\n\n// ==========================================\n// 5) \u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e2b\u0e25\u0e31\u0e01: \u0e23\u0e27\u0e21\u0e17\u0e38\u0e01\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e40\u0e02\u0e49\u0e32\u0e14\u0e49\u0e27\u0e22\u0e01\u0e31\u0e19 \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\n//    baseChar = object \u0e08\u0e32\u0e01 CHARACTERS (\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48 level 1, dupes 0, class 1)\n//    saveData = { level, dupes, class } \u0e08\u0e32\u0e01 playerSave.crew[id]\n// ==========================================\nfunction calculateCharacterStats(baseChar, saveData) {\n  const level = (saveData && saveData.level) || 1;\n  const dupes = (saveData && saveData.dupes) || 0;\n  const charClass = (saveData && saveData.class) || 1;\n\n  const multiplier = getClassDupeMultiplier(charClass, dupes);\n  // \u0e2a\u0e20\u0e32\u0e1e\u0e23\u0e48\u0e32\u0e07\u0e01\u0e32\u0e22\u0e01\u0e23\u0e30\u0e17\u0e1a\u0e41\u0e04\u0e48\u0e1b\u0e23\u0e30\u0e2a\u0e34\u0e17\u0e18\u0e34\u0e20\u0e32\u0e1e\u0e01\u0e32\u0e23\u0e2a\u0e39\u0e49 (\u0e42\u0e08\u0e21\u0e15\u0e35/\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19/\u0e04\u0e27\u0e32\u0e21\u0e40\u0e23\u0e47\u0e27) \u0e44\u0e21\u0e48\u0e01\u0e23\u0e30\u0e17\u0e1a hp\n  // \u0e15\u0e31\u0e49\u0e07\u0e43\u0e08\u0e44\u0e21\u0e48\u0e43\u0e2b\u0e49\u0e01\u0e23\u0e30\u0e17\u0e1a hp \u0e40\u0e1e\u0e23\u0e32\u0e30\u0e08\u0e30\u0e22\u0e34\u0e48\u0e07\u0e17\u0e33\u0e43\u0e2b\u0e49\u0e15\u0e31\u0e27\u0e17\u0e35\u0e48\u0e2a\u0e20\u0e32\u0e1e\u0e41\u0e22\u0e48\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27\u0e15\u0e32\u0e22\u0e07\u0e48\u0e32\u0e22\u0e02\u0e36\u0e49\u0e19\u0e44\u0e1b\u0e2d\u0e35\u0e01 (death spiral)\n  const conditionMulti = (typeof getConditionMultiplier === 'function') ? getConditionMultiplier(saveData) : 1;\n  const statKeys = ['hp', 'attack', 'defense_flat', 'speed'];\n\n  const result = {};\n  statKeys.forEach((key) => {\n    const base1 = baseChar.stats[key];\n    const levelVal = getLevelValue(base1, level);\n    const statMulti = (key === 'hp') ? multiplier : (multiplier * conditionMulti);\n    result[key] = Math.round((levelVal * statMulti) * 100) / 100;\n  });\n\n  // \u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 (\u0e16\u0e49\u0e32\u0e21\u0e35\u0e23\u0e30\u0e1a\u0e1a\u0e42\u0e2b\u0e25\u0e14\u0e2d\u0e22\u0e39\u0e48) \u2014 % \u0e04\u0e34\u0e14\u0e08\u0e32\u0e01\u0e04\u0e48\u0e32\u0e10\u0e32\u0e19\u0e01\u0e48\u0e2d\u0e19\u0e43\u0e2a\u0e48\u0e02\u0e2d\u0e07, flat \u0e1a\u0e27\u0e01\u0e15\u0e23\u0e07\u0e46 \u0e17\u0e35\u0e2b\u0e25\u0e31\u0e07\n  if (typeof equipmentGetCharacterBonuses === 'function' && baseChar.id) {\n    const eq = equipmentGetCharacterBonuses(baseChar.id);\n    result.hp = Math.round((result.hp * (1 + eq.hp_percent / 100) + eq.hp_flat) * 100) / 100;\n    result.attack = Math.round((result.attack * (1 + eq.atk_percent / 100) + eq.atk_flat) * 100) / 100;\n    result.defense_flat = Math.round((result.defense_flat * (1 + eq.def_percent / 100) + eq.def_flat) * 100) / 100;\n    result.speed = Math.round((result.speed * (1 + eq.spd_percent / 100) + eq.spd_flat) * 100) / 100;\n    result.resist = Math.round(eq.resist_percent * 10) / 10;\n    result.crit_rate = Math.round(eq.crit_rate * 10) / 10;\n    result.crit_damage = Math.round(eq.crit_damage * 10) / 10;\n    result.evasion = Math.round(eq.evasion * 10) / 10;\n    result.unlock_attack = eq.unlock_attack;\n  } else {\n    result.resist = 0; result.crit_rate = 0; result.crit_damage = 0; result.evasion = 0; result.unlock_attack = false;\n  }\n\n  return result;\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = {\n    LEVEL_STEP_PERCENT,\n    DUPE_BONUS_PERCENT,\n    CLASS_BASE_MULTIPLIER,\n    getLevelValue,\n    getClassDupeMultiplier,\n    getMaxLevel,\n    BASE_EXP_TABLE,\n    GRADE_EXP_MULTIPLIER,\n    getExpRequired,\n    calculateCharacterStats\n  };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: equipment_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e25\u0e2d\u0e08\u0e34\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 \u2014 \u0e2a\u0e38\u0e48\u0e21\u0e04\u0e48\u0e32, \u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48, \u0e2d\u0e31\u0e1e\u0e40\u0e25\u0e40\u0e27\u0e25 (\u0e1b\u0e49\u0e2d\u0e19\u0e02\u0e2d\u0e07\u0e0b\u0e49\u0e33), \u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 (\u0e43\u0e0a\u0e49\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a)\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_equipment.js, player_save_template.js, crew_system.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d\n// ==========================================\n\nfunction equipmentEnsureDefaults() {\n  if (!playerState.equipment_inventory) playerState.equipment_inventory = [];\n  Object.keys(playerState.crew).forEach(id => {\n    if (!playerState.crew[id].equipped) {\n      playerState.crew[id].equipped = { weapon: null, armor: null, accessory: null };\n    }\n  });\n}\n\nfunction equipmentGenId() {\n  return \"eq_\" + Date.now() + \"_\" + Math.floor(Math.random() * 100000);\n}\n\nfunction equipmentRollStat(statDef) {\n  const raw = statDef.min + Math.random() * (statDef.max - statDef.min);\n  return Math.round(raw * 10) / 10;\n}\n\n// \u0e2a\u0e23\u0e49\u0e32\u0e07\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e0a\u0e34\u0e49\u0e19\u0e43\u0e2b\u0e21\u0e48 (typeKey \u0e40\u0e0a\u0e48\u0e19 \"sword\", star 1-3) \u0e41\u0e25\u0e49\u0e27\u0e40\u0e01\u0e47\u0e1a\u0e40\u0e02\u0e49\u0e32\u0e04\u0e25\u0e31\u0e07 \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32 instance \u0e17\u0e35\u0e48\u0e2a\u0e23\u0e49\u0e32\u0e07\nfunction equipmentCreateNew(typeKey, star) {\n  equipmentEnsureDefaults();\n  const typeDef = EQUIPMENT_TYPES[typeKey];\n  if (!typeDef) return null;\n\n  const statDefs = typeDef.stat_defs[star];\n  const rolls = statDefs.map(sd => ({\n    stat: sd.stat,\n    kind: sd.kind,\n    value: equipmentRollStat(sd),\n    unlock_attack: !!sd.unlock_attack\n  }));\n\n  const instance = {\n    id: equipmentGenId(),\n    type_key: typeKey,\n    star: star,\n    level: 1,\n    rolls: rolls\n  };\n  playerState.equipment_inventory.push(instance);\n  playerSave();\n  return instance;\n}\n\nfunction equipmentGetInstance(instanceId) {\n  equipmentEnsureDefaults();\n  return playerState.equipment_inventory.find(e => e.id === instanceId) || null;\n}\n\nfunction equipmentGetName(instance) {\n  if (!instance) return \"\";\n  return EQUIPMENT_TYPES[instance.type_key].names[instance.star];\n}\n\nfunction equipmentGetLevelInfo(instance) {\n  return EQUIPMENT_LEVELS.find(l => l.level === instance.level) || EQUIPMENT_LEVELS[0];\n}\n\n// \u0e04\u0e48\u0e32\u0e08\u0e23\u0e34\u0e07\u0e02\u0e2d\u0e07\u0e41\u0e15\u0e48\u0e25\u0e30 roll \u0e2b\u0e25\u0e31\u0e07\u0e04\u0e39\u0e13 Level multiplier \u0e41\u0e25\u0e49\u0e27 (\u0e1b\u0e31\u0e14\u0e17\u0e28\u0e19\u0e34\u0e22\u0e21 1 \u0e15\u0e33\u0e41\u0e2b\u0e19\u0e48\u0e07)\nfunction equipmentGetEffectiveRolls(instance) {\n  const levelInfo = equipmentGetLevelInfo(instance);\n  return instance.rolls.map(r => ({\n    ...r,\n    effective_value: Math.round(r.value * levelInfo.multiplier * 10) / 10\n  }));\n}\n\n// ------------------------------------------\n// \u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 / \u0e16\u0e2d\u0e14\n// ------------------------------------------\n\nfunction equipmentEquip(charId, instanceId) {\n  equipmentEnsureDefaults();\n  const instance = equipmentGetInstance(instanceId);\n  if (!instance) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e0a\u0e34\u0e49\u0e19\u0e19\u0e35\u0e49\" };\n  const typeDef = EQUIPMENT_TYPES[instance.type_key];\n\n  if (typeDef.class_lock) {\n    const baseChar = crewGetBaseCharData(charId);\n    if (baseChar.role !== typeDef.class_lock) {\n      return { success: false, message: `\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e19\u0e35\u0e49\u0e43\u0e2a\u0e48\u0e44\u0e14\u0e49\u0e40\u0e09\u0e1e\u0e32\u0e30\u0e2a\u0e32\u0e22 ${typeDef.class_lock} \u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19` };\n    }\n  }\n  // \u0e01\u0e31\u0e19\u0e02\u0e2d\u0e07\u0e0a\u0e34\u0e49\u0e19\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e43\u0e2a\u0e48\u0e0b\u0e49\u0e33 2 \u0e15\u0e31\u0e27\n  const wornByOther = Object.keys(playerState.crew).find(id => {\n    const eq = playerState.crew[id].equipped;\n    return eq && (eq.weapon === instanceId || eq.armor === instanceId || eq.accessory === instanceId);\n  });\n  if (wornByOther) {\n    playerState.crew[wornByOther].equipped[typeDef.slot] = null;\n  }\n\n  if (!playerState.crew[charId].equipped) playerState.crew[charId].equipped = { weapon: null, armor: null, accessory: null };\n  playerState.crew[charId].equipped[typeDef.slot] = instanceId;\n  playerSave();\n  return { success: true, message: `\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48 ${equipmentGetName(instance)} \u0e41\u0e25\u0e49\u0e27` };\n}\n\nfunction equipmentUnequip(charId, slot) {\n  equipmentEnsureDefaults();\n  if (!playerState.crew[charId] || !playerState.crew[charId].equipped) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e19\u0e35\u0e49\" };\n  playerState.crew[charId].equipped[slot] = null;\n  playerSave();\n  return { success: true, message: \"\u0e16\u0e2d\u0e14\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e41\u0e25\u0e49\u0e27\" };\n}\n\n// ------------------------------------------\n// \u0e2d\u0e31\u0e1e\u0e40\u0e25\u0e40\u0e27\u0e25 (\u0e1b\u0e49\u0e2d\u0e19\u0e02\u0e2d\u0e07\u0e0b\u0e49\u0e33 \u0e14\u0e32\u0e27+\u0e0a\u0e19\u0e34\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e49\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a)\n// ------------------------------------------\n\nfunction equipmentLevelUp(targetInstanceId, materialInstanceId) {\n  equipmentEnsureDefaults();\n  const target = equipmentGetInstance(targetInstanceId);\n  const material = equipmentGetInstance(materialInstanceId);\n  if (!target || !material) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\" };\n  if (target.id === material.id) return { success: false, message: \"\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e0a\u0e34\u0e49\u0e19\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\" };\n  // \u0e2d\u0e19\u0e38\u0e0d\u0e32\u0e15\u0e43\u0e2b\u0e49\u0e1b\u0e49\u0e2d\u0e19\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c \"\u0e2b\u0e21\u0e27\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\" (\u0e2d\u0e32\u0e27\u0e38\u0e18\u0e1b\u0e49\u0e2d\u0e19\u0e2d\u0e32\u0e27\u0e38\u0e18 / \u0e40\u0e01\u0e23\u0e32\u0e30\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e01\u0e23\u0e32\u0e30 / \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a)\n  // \u0e44\u0e21\u0e48\u0e08\u0e33\u0e40\u0e1b\u0e47\u0e19\u0e15\u0e49\u0e2d\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e0a\u0e19\u0e34\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e2b\u0e23\u0e37\u0e2d\u0e14\u0e32\u0e27\u0e40\u0e17\u0e48\u0e32\u0e01\u0e31\u0e19\u0e2d\u0e35\u0e01\u0e15\u0e48\u0e2d\u0e44\u0e1b (\u0e40\u0e0a\u0e48\u0e19 \u0e40\u0e2d\u0e32\u0e02\u0e27\u0e32\u0e19\u0e44\u0e1b\u0e1b\u0e49\u0e2d\u0e19\u0e14\u0e32\u0e1a\u0e44\u0e14\u0e49 \u0e44\u0e21\u0e48\u0e27\u0e48\u0e32\u0e14\u0e32\u0e27\u0e08\u0e30\u0e15\u0e48\u0e32\u0e07\u0e01\u0e31\u0e19\u0e41\u0e04\u0e48\u0e44\u0e2b\u0e19)\n  const targetSlot = EQUIPMENT_TYPES[target.type_key].slot;\n  const materialSlot = EQUIPMENT_TYPES[material.type_key].slot;\n  if (targetSlot !== materialSlot) {\n    return { success: false, message: \"\u0e15\u0e49\u0e2d\u0e07\u0e40\u0e1b\u0e47\u0e19\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e2b\u0e21\u0e27\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e40\u0e17\u0e48\u0e32\u0e19\u0e31\u0e49\u0e19 (\u0e2d\u0e32\u0e27\u0e38\u0e18\u0e1b\u0e49\u0e2d\u0e19\u0e2d\u0e32\u0e27\u0e38\u0e18 / \u0e40\u0e01\u0e23\u0e32\u0e30\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e01\u0e23\u0e32\u0e30 / \u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a\u0e1b\u0e49\u0e2d\u0e19\u0e40\u0e04\u0e23\u0e37\u0e48\u0e2d\u0e07\u0e1b\u0e23\u0e30\u0e14\u0e31\u0e1a)\" };\n  }\n  if (target.level >= 5) return { success: false, message: \"\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e19\u0e35\u0e49 Level 5 MAX \u0e41\u0e25\u0e49\u0e27\" };\n  // \u0e40\u0e0a\u0e47\u0e04\u0e27\u0e48\u0e32\u0e02\u0e2d\u0e07\u0e17\u0e35\u0e48\u0e40\u0e2d\u0e32\u0e21\u0e32\u0e1b\u0e49\u0e2d\u0e19\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e16\u0e39\u0e01\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48\n  const wornBy = Object.keys(playerState.crew).find(id => {\n    const eq = playerState.crew[id].equipped;\n    return eq && (eq.weapon === materialInstanceId || eq.armor === materialInstanceId || eq.accessory === materialInstanceId);\n  });\n  if (wornBy) return { success: false, message: \"\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e08\u0e30\u0e1b\u0e49\u0e2d\u0e19\u0e01\u0e33\u0e25\u0e31\u0e07\u0e16\u0e39\u0e01\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48 \u0e16\u0e2d\u0e14\u0e2d\u0e2d\u0e01\u0e01\u0e48\u0e2d\u0e19\" };\n\n  target.level += 1;\n  const idx = playerState.equipment_inventory.findIndex(e => e.id === materialInstanceId);\n  if (idx > -1) playerState.equipment_inventory.splice(idx, 1);\n\n  playerSave();\n  return { success: true, message: `\u0e2d\u0e31\u0e1e\u0e40\u0e1b\u0e47\u0e19 Level ${target.level}${target.level === 5 ? ' MAX' : ''} \u0e41\u0e25\u0e49\u0e27` };\n}\n\n// ------------------------------------------\n// \u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27 (\u0e15\u0e49\u0e2d\u0e07 Level 5 MAX \u0e01\u0e48\u0e2d\u0e19 \u0e43\u0e0a\u0e49\u0e27\u0e31\u0e15\u0e16\u0e38\u0e14\u0e34\u0e1a)\n// ------------------------------------------\n\nfunction equipmentUpgradeStar(instanceId) {\n  equipmentEnsureDefaults();\n  const instance = equipmentGetInstance(instanceId);\n  if (!instance) return { success: false, message: \"\u0e44\u0e21\u0e48\u0e1e\u0e1a\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\" };\n  if (instance.star >= 3) return { success: false, message: \"\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e19\u0e35\u0e49\u0e2d\u0e22\u0e39\u0e48\u0e14\u0e32\u0e27\u0e2a\u0e39\u0e07\u0e2a\u0e38\u0e14\u0e41\u0e25\u0e49\u0e27\" };\n  if (instance.level < 5) return { success: false, message: \"\u0e15\u0e49\u0e2d\u0e07\u0e2d\u0e31\u0e1e\u0e40\u0e1b\u0e47\u0e19 Level 5 MAX \u0e01\u0e48\u0e2d\u0e19\u0e16\u0e36\u0e07\u0e08\u0e30\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27\u0e44\u0e14\u0e49\" };\n\n  const nextStar = instance.star + 1;\n  const recipe = EQUIPMENT_UPGRADE_RECIPES[instance.type_key][nextStar];\n  if (!playerState.inventory.equipment_materials) playerState.inventory.equipment_materials = {};\n\n  const missing = recipe.find(req => {\n    const have = playerState.inventory.equipment_materials[req.item_id] || 0;\n    return have < req.qty;\n  });\n  if (missing) {\n    const have = playerState.inventory.equipment_materials[missing.item_id] || 0;\n    return { success: false, message: `${EQUIPMENT_MATERIALS[missing.item_id].name}\u0e44\u0e21\u0e48\u0e1e\u0e2d (\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23 ${missing.qty} \u0e21\u0e35\u0e2d\u0e22\u0e39\u0e48 ${have})` };\n  }\n\n  recipe.forEach(req => {\n    playerState.inventory.equipment_materials[req.item_id] -= req.qty;\n  });\n\n  const typeDef = EQUIPMENT_TYPES[instance.type_key];\n  const statDefs = typeDef.stat_defs[nextStar];\n  instance.star = nextStar;\n  instance.level = 1;\n  instance.rolls = statDefs.map(sd => ({\n    stat: sd.stat,\n    kind: sd.kind,\n    value: equipmentRollStat(sd),\n    unlock_attack: !!sd.unlock_attack\n  }));\n\n  playerSave();\n  return { success: true, message: `\u0e2d\u0e31\u0e1e\u0e14\u0e32\u0e27\u0e40\u0e1b\u0e47\u0e19 ${nextStar}\u2605 \u0e2a\u0e33\u0e40\u0e23\u0e47\u0e08! (${equipmentGetName(instance)})` };\n}\n\n// ------------------------------------------\n// \u0e23\u0e27\u0e21\u0e42\u0e1a\u0e19\u0e31\u0e2a\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e2a\u0e27\u0e21\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 (\u0e43\u0e0a\u0e49\u0e43\u0e19 progression_system.js)\n// ------------------------------------------\n\nfunction equipmentGetCharacterBonuses(charId) {\n  const bonuses = {\n    atk_percent: 0, atk_flat: 0,\n    def_percent: 0, def_flat: 0,\n    hp_percent: 0, hp_flat: 0,\n    spd_percent: 0, spd_flat: 0,\n    resist_percent: 0,\n    crit_rate: 0, crit_damage: 0, evasion: 0,\n    unlock_attack: false\n  };\n  const charData = playerState.crew[charId];\n  if (!charData || !charData.equipped) return bonuses;\n\n  ['weapon', 'armor', 'accessory'].forEach(slot => {\n    const instanceId = charData.equipped[slot];\n    if (!instanceId) return;\n    const instance = equipmentGetInstance(instanceId);\n    if (!instance) return;\n\n    equipmentGetEffectiveRolls(instance).forEach(r => {\n      if (r.unlock_attack) bonuses.unlock_attack = true;\n      const key = r.stat + (r.kind === \"percent\" ? \"_percent\" : \"_flat\");\n      if (bonuses[key] !== undefined) {\n        bonuses[key] += r.effective_value;\n      } else if (r.stat === \"resist\") {\n        bonuses.resist_percent += r.effective_value;\n      } else if ([\"crit_rate\", \"crit_damage\", \"evasion\"].includes(r.stat)) {\n        bonuses[r.stat] += r.effective_value;\n      }\n    });\n  });\n\n  return bonuses;\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = {\n    equipmentEnsureDefaults, equipmentCreateNew, equipmentGetInstance, equipmentGetName,\n    equipmentGetLevelInfo, equipmentGetEffectiveRolls, equipmentEquip, equipmentUnequip,\n    equipmentLevelUp, equipmentUpgradeStar, equipmentGetCharacterBonuses\n  };\n}\n\n;\n// ==========================================\n// \u0e44\u0e1f\u0e25\u0e4c: combat_power_system.js\n// \u0e2b\u0e19\u0e49\u0e32\u0e17\u0e35\u0e48: \u0e04\u0e33\u0e19\u0e27\u0e13 \"\u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\" (Combat Power) \u2014 \u0e04\u0e33\u0e19\u0e27\u0e13\u0e2a\u0e14\u0e08\u0e32\u0e01\u0e17\u0e35\u0e21\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19\u0e40\u0e2a\u0e21\u0e2d \u0e44\u0e21\u0e48\u0e21\u0e35\u0e01\u0e32\u0e23\u0e40\u0e01\u0e47\u0e1a\u0e04\u0e48\u0e32\u0e25\u0e07 save\n// (\u0e40\u0e1e\u0e23\u0e32\u0e30\u0e02\u0e36\u0e49\u0e19\u0e01\u0e31\u0e1a\u0e40\u0e25\u0e40\u0e27\u0e25/\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33/\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e40\u0e1b\u0e25\u0e35\u0e48\u0e22\u0e19\u0e44\u0e14\u0e49\u0e15\u0e25\u0e2d\u0e14 \u0e04\u0e33\u0e19\u0e27\u0e13\u0e2a\u0e14\u0e41\u0e21\u0e48\u0e19\u0e22\u0e33\u0e01\u0e27\u0e48\u0e32\u0e40\u0e01\u0e47\u0e1a\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e2d\u0e32\u0e08\u0e44\u0e21\u0e48\u0e2d\u0e31\u0e1e\u0e40\u0e14\u0e17)\n// \u0e15\u0e49\u0e2d\u0e07\u0e42\u0e2b\u0e25\u0e14 data_combat_power.js, crew_system.js, progression_system.js \u0e01\u0e48\u0e2d\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e21\u0e2d\n// ==========================================\n\n// \u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e02\u0e2d\u0e07\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23 1 \u0e15\u0e31\u0e27 \u0e15\u0e32\u0e21\u0e2a\u0e40\u0e15\u0e15\u0e31\u0e2a\u0e08\u0e23\u0e34\u0e07\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19 (\u0e23\u0e27\u0e21\u0e40\u0e25\u0e40\u0e27\u0e25/\u0e15\u0e31\u0e27\u0e0b\u0e49\u0e33/\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c\u0e17\u0e35\u0e48\u0e43\u0e2a\u0e48\u0e2d\u0e22\u0e39\u0e48\u0e41\u0e25\u0e49\u0e27)\nfunction calculateCharacterCombatPower(charId) {\n  const saveData = playerState.crew[charId];\n  if (!saveData) return 0;\n  const baseChar = crewGetBaseCharData(charId);\n  const realStats = calculateCharacterStats(baseChar, saveData);\n\n  const w = COMBAT_POWER_STAT_WEIGHTS;\n  const rawPower = (realStats.hp * w.hp) + (realStats.attack * w.attack) + (realStats.defense_flat * w.defense_flat) + (realStats.speed * w.speed);\n\n  const roleMulti = COMBAT_POWER_ROLE_MULTIPLIER[baseChar.role] || 1;\n  return Math.round(rawPower * roleMulti);\n}\n\n// \u0e1e\u0e25\u0e31\u0e07\u0e2a\u0e39\u0e49\u0e23\u0e1a\u0e23\u0e27\u0e21\u0e02\u0e2d\u0e07\u0e17\u0e35\u0e21 5 \u0e15\u0e33\u0e41\u0e2b\u0e19\u0e48\u0e07\u0e1b\u0e31\u0e08\u0e08\u0e38\u0e1a\u0e31\u0e19 (\u0e0a\u0e48\u0e2d\u0e07\u0e27\u0e48\u0e32\u0e07\u0e19\u0e31\u0e1a\u0e40\u0e1b\u0e47\u0e19 0)\nfunction calculateSquadCombatPower() {\n  let total = 0;\n  for (let i = 0; i < 5; i++) {\n    const charId = playerState.squad[i];\n    if (charId && playerState.crew[charId]) {\n      total += calculateCharacterCombatPower(charId);\n    }\n  }\n  return total;\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { calculateCharacterCombatPower, calculateSquadCombatPower };\n}\n\n;\n// combat_engine_pvp.js\n// \u0e41\u0e01\u0e19\u0e15\u0e31\u0e14\u0e2a\u0e34\u0e19\u0e1c\u0e25\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49 PVP (server-authoritative) \u2014 \u0e14\u0e31\u0e14\u0e41\u0e1b\u0e25\u0e07\u0e08\u0e32\u0e01 combat_engine.js \u0e15\u0e31\u0e27\u0e08\u0e23\u0e34\u0e07\u0e02\u0e2d\u0e07\u0e40\u0e01\u0e21\n// \u0e2a\u0e23\u0e49\u0e32\u0e07\u0e42\u0e14\u0e22\u0e01\u0e32\u0e23\u0e15\u0e31\u0e14\u0e15\u0e48\u0e2d\u0e44\u0e1f\u0e25\u0e4c\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a\u0e14\u0e49\u0e27\u0e22\u0e2a\u0e04\u0e23\u0e34\u0e1b\u0e15\u0e4c (\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e1e\u0e34\u0e21\u0e1e\u0e4c\u0e43\u0e2b\u0e21\u0e48\u0e08\u0e32\u0e01\u0e04\u0e27\u0e32\u0e21\u0e08\u0e33) \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e23\u0e31\u0e1a\u0e1b\u0e23\u0e30\u0e01\u0e31\u0e19\u0e27\u0e48\u0e32\u0e01\u0e15\u0e34\u0e01\u0e32\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\n// (\u0e2a\u0e39\u0e15\u0e23\u0e14\u0e32\u0e40\u0e21\u0e08, \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25, \u0e01\u0e32\u0e23\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01, passive \u0e17\u0e38\u0e01\u0e15\u0e31\u0e27, \u0e25\u0e33\u0e14\u0e31\u0e1a\u0e40\u0e17\u0e34\u0e23\u0e4c\u0e19) \u0e40\u0e2b\u0e21\u0e37\u0e2d\u0e19\u0e01\u0e31\u0e1a\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e01\u0e21\u0e08\u0e23\u0e34\u0e07\u0e40\u0e1b\u0e4a\u0e30\u0e17\u0e38\u0e01\u0e1a\u0e23\u0e23\u0e17\u0e31\u0e14\n// \u0e08\u0e38\u0e14\u0e17\u0e35\u0e48\u0e15\u0e48\u0e32\u0e07\u0e08\u0e32\u0e01\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a \u0e21\u0e35\u0e41\u0e04\u0e48: (1) \u0e17\u0e31\u0e49\u0e07\u0e2a\u0e2d\u0e07\u0e1d\u0e31\u0e48\u0e07\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e22\u0e39\u0e19\u0e34\u0e15\u0e08\u0e32\u0e01\u0e15\u0e31\u0e27\u0e25\u0e30\u0e04\u0e23\u0e08\u0e23\u0e34\u0e07 (calculateCharacterStats)\n// \u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e1d\u0e31\u0e48\u0e07\u0e2b\u0e19\u0e36\u0e48\u0e07\u0e08\u0e30\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e08\u0e32\u0e01\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e28\u0e31\u0e15\u0e23\u0e39 (2) \u0e44\u0e21\u0e48\u0e21\u0e35 playerHpOverrides (\u0e41\u0e15\u0e48\u0e25\u0e30\u0e41\u0e21\u0e15\u0e0a\u0e4c\u0e40\u0e23\u0e34\u0e48\u0e21\u0e40\u0e15\u0e47\u0e21 HP \u0e40\u0e2a\u0e21\u0e2d)\n//\n// \u0e1c\u0e25\u0e02\u0e49\u0e32\u0e07\u0e40\u0e04\u0e35\u0e22\u0e07\u0e17\u0e35\u0e48\u0e15\u0e32\u0e21\u0e21\u0e32\u0e08\u0e32\u0e01\u0e01\u0e32\u0e23\u0e43\u0e0a\u0e49\u0e42\u0e04\u0e23\u0e07\u0e40\u0e14\u0e34\u0e21: \u0e1d\u0e31\u0e48\u0e07 \"defender\" (side='enemy') \u0e22\u0e31\u0e07\u0e43\u0e0a\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e40\u0e25\u0e47\u0e07\u0e40\u0e1b\u0e49\u0e32\u0e41\u0e1a\u0e1a\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e1a\n// \u0e28\u0e31\u0e15\u0e23\u0e39 NPC \u0e43\u0e19\u0e40\u0e01\u0e21 (\u0e40\u0e25\u0e47\u0e07\u0e15\u0e32\u0e21\u0e25\u0e33\u0e14\u0e31\u0e1a\u0e0a\u0e48\u0e2d\u0e07/\u0e15\u0e33\u0e41\u0e2b\u0e19\u0e48\u0e07) \u0e2a\u0e48\u0e27\u0e19\u0e1d\u0e31\u0e48\u0e07 \"attacker\" (side='player') \u0e43\u0e0a\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e40\u0e25\u0e47\u0e07\u0e40\u0e1b\u0e49\u0e32\u0e41\u0e1a\u0e1a\n// \u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e1b\u0e01\u0e15\u0e34 (\u0e40\u0e25\u0e47\u0e07\u0e15\u0e32\u0e21\u0e2a\u0e32\u0e22 tank/fighter \u0e01\u0e48\u0e2d\u0e19) \u0e17\u0e33\u0e43\u0e2b\u0e49\u0e1a\u0e17\u0e1a\u0e32\u0e17\u0e23\u0e38\u0e01/\u0e23\u0e31\u0e1a\u0e44\u0e21\u0e48\u0e2a\u0e21\u0e21\u0e32\u0e15\u0e23\u0e01\u0e31\u0e19\u0e43\u0e19\u0e41\u0e07\u0e48\u0e01\u0e32\u0e23\u0e40\u0e25\u0e47\u0e07\u0e40\u0e1b\u0e49\u0e32\n// \u0e16\u0e49\u0e32\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e43\u0e2b\u0e49\u0e40\u0e25\u0e47\u0e07\u0e40\u0e1b\u0e49\u0e32\u0e41\u0e1a\u0e1a\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e17\u0e31\u0e49\u0e07\u0e2a\u0e2d\u0e07\u0e1d\u0e31\u0e48\u0e07 \u0e41\u0e08\u0e49\u0e07\u0e44\u0e14\u0e49 \u0e1b\u0e23\u0e31\u0e1a\u0e44\u0e14\u0e49\u0e44\u0e21\u0e48\u0e22\u0e32\u0e01\n//\n// \u26a0\ufe0f \u0e02\u0e49\u0e2d\u0e04\u0e27\u0e23\u0e23\u0e30\u0e27\u0e31\u0e07\u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e2d\u0e19\u0e32\u0e04\u0e15: \u0e16\u0e49\u0e32\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e01\u0e21 combat_engine.js \u0e21\u0e35\u0e01\u0e32\u0e23\u0e41\u0e01\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49\u0e17\u0e35\u0e2b\u0e25\u0e31\u0e07 (\u0e1b\u0e23\u0e31\u0e1a\u0e2a\u0e21\u0e14\u0e38\u0e25 passive \u0e2f\u0e25\u0e2f)\n// \u0e44\u0e1f\u0e25\u0e4c\u0e19\u0e35\u0e49\u0e08\u0e30\u0e44\u0e21\u0e48\u0e2d\u0e31\u0e1e\u0e40\u0e14\u0e17\u0e15\u0e32\u0e21\u0e2d\u0e31\u0e15\u0e42\u0e19\u0e21\u0e31\u0e15\u0e34 \u0e15\u0e49\u0e2d\u0e07\u0e40\u0e2d\u0e32\u0e01\u0e32\u0e23\u0e41\u0e01\u0e49\u0e44\u0e02\u0e21\u0e32\u0e1b\u0e23\u0e31\u0e1a\u0e17\u0e35\u0e48\u0e19\u0e35\u0e48\u0e14\u0e49\u0e27\u0e22\u0e21\u0e37\u0e2d\u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\n// (\u0e04\u0e27\u0e23\u0e23\u0e35\u0e41\u0e1f\u0e04\u0e40\u0e15\u0e2d\u0e23\u0e4c\u0e43\u0e2b\u0e49\u0e17\u0e31\u0e49\u0e07\u0e2a\u0e2d\u0e07\u0e44\u0e1f\u0e25\u0e4c\u0e41\u0e0a\u0e23\u0e4c core loop \u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e08\u0e23\u0e34\u0e07\u0e46 \u0e43\u0e19\u0e2d\u0e19\u0e32\u0e04\u0e15)\n\nfunction runPvpCombat(attackerSquadData, defenderSquadData, attackerPlayerState, defenderPlayerState) {\n  // equipmentGetCharacterBonuses() (\u0e40\u0e23\u0e35\u0e22\u0e01\u0e08\u0e32\u0e01 calculateCharacterStats) \u0e2d\u0e48\u0e32\u0e19 global \"playerState\" \u0e15\u0e23\u0e07\u0e46\n  // \u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e08\u0e30\u0e23\u0e31\u0e1a saveData \u0e17\u0e35\u0e48\u0e2a\u0e48\u0e07\u0e40\u0e02\u0e49\u0e32\u0e21\u0e32 \u2014 \u0e40\u0e1b\u0e47\u0e19 dependency \u0e17\u0e35\u0e48\u0e0b\u0e48\u0e2d\u0e19\u0e2d\u0e22\u0e39\u0e48\u0e43\u0e19\u0e44\u0e1f\u0e25\u0e4c\u0e40\u0e01\u0e21\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a (\u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e17\u0e35\u0e48\u0e19\u0e35\u0e48\u0e41\u0e01\u0e49\u0e43\u0e2b\u0e21\u0e48)\n  // \u0e40\u0e0b\u0e34\u0e23\u0e4c\u0e1f\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e1b\u0e23\u0e30\u0e21\u0e27\u0e25\u0e1c\u0e25\u0e44\u0e14\u0e49\u0e2b\u0e25\u0e32\u0e22\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e01\u0e31\u0e19 \u0e15\u0e31\u0e27\u0e41\u0e1b\u0e23 global \u0e40\u0e14\u0e35\u0e48\u0e22\u0e27\u0e46 \u0e43\u0e0a\u0e49\u0e44\u0e21\u0e48\u0e44\u0e14\u0e49\u0e1b\u0e01\u0e15\u0e34 \u0e08\u0e36\u0e07\u0e15\u0e49\u0e2d\u0e07\u0e2a\u0e25\u0e31\u0e1a\u0e04\u0e48\u0e32\u0e15\u0e23\u0e07\u0e19\u0e35\u0e49\u0e40\u0e2d\u0e07\n  // \u0e01\u0e48\u0e2d\u0e19\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e22\u0e39\u0e19\u0e34\u0e15\u0e41\u0e15\u0e48\u0e25\u0e30\u0e1d\u0e31\u0e48\u0e07 (\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22\u0e40\u0e1e\u0e23\u0e32\u0e30 JS \u0e40\u0e1b\u0e47\u0e19 single-thread \u0e41\u0e25\u0e30\u0e1f\u0e31\u0e07\u0e01\u0e4c\u0e0a\u0e31\u0e19\u0e19\u0e35\u0e49\u0e17\u0e33\u0e07\u0e32\u0e19\u0e08\u0e1a\u0e43\u0e19\u0e17\u0e35\u0e40\u0e14\u0e35\u0e22\u0e27\u0e44\u0e21\u0e48\u0e2a\u0e25\u0e31\u0e1a\u0e01\u0e25\u0e32\u0e07)\n  let allUnits = [];\n  let stats = {};\n  let logs = [];\n\n  function getTeamName(side) { return side === 'player' ? '\u0e40\u0e23\u0e32' : '\u0e28\u0e31\u0e15\u0e23\u0e39'; }\n  function log(msg) { logs.push(msg); }\n\n  // 1. Initialize Units\n  playerState = attackerPlayerState;\n  attackerSquadData.forEach((entry, index) => {\n    if (!entry) return;\n    const id = entry.id;\n    const saveData = entry.saveData;\n    if (!id) return;\n\n    const baseChar = crewGetBaseCharData(id);\n    const scaledStats = calculateCharacterStats(baseChar, saveData);\n    let u = {\n      side: 'player',\n      side_id: 'player_' + index,\n      name: baseChar.name,\n      role: baseChar.role,\n      passive: baseChar.passive,\n      max_hp: scaledStats.hp,\n      hp: scaledStats.hp,\n      base_atk: scaledStats.attack,\n      base_def: scaledStats.defense_flat,\n      base_spd: scaledStats.speed,\n      atk: scaledStats.attack,\n      def: scaledStats.defense_flat,\n      spd: scaledStats.speed,\n      crit_rate: scaledStats.crit_rate || 0,\n      crit_damage: scaledStats.crit_damage || 0,\n      evasion: scaledStats.evasion || 0,\n      base_evasion: scaledStats.evasion || 0,\n      accuracy: 0,\n      resist: scaledStats.resist || 0,\n      unlock_attack: !!scaledStats.unlock_attack,\n      _stun: 0,\n      _silenced: 0,\n      _poison: 0,\n      _poison_source: null,\n      _p16_owner_turns: 0,\n      _p16_active: false\n    };\n    allUnits.push(u);\n    stats[u.side_id] = { name: u.name, side: u.side, dmg_dealt: 0, dmg_taken: 0, heal_given: 0, stun_count: 0, silence_count: 0, dodge_count: 0, dmg_prevented: 0, heal_proc_count: 0, heal_proc_total: 0, extra_turn_count: 0, elim_round: null };\n  });\n\n  playerState = defenderPlayerState;\n  defenderSquadData.forEach((entry, index) => {\n    if (!entry) return;\n    const id = entry.id;\n    const saveData = entry.saveData;\n    if (!id) return;\n\n    const baseChar = crewGetBaseCharData(id);\n    const scaledStats = calculateCharacterStats(baseChar, saveData);\n    let u = {\n      side: 'enemy',\n      side_id: 'enemy_' + index,\n      name: baseChar.name,\n      role: baseChar.role,\n      passive: baseChar.passive,\n      max_hp: scaledStats.hp,\n      hp: scaledStats.hp,\n      base_atk: scaledStats.attack,\n      base_def: scaledStats.defense_flat,\n      base_spd: scaledStats.speed,\n      atk: scaledStats.attack,\n      def: scaledStats.defense_flat,\n      spd: scaledStats.speed,\n      crit_rate: scaledStats.crit_rate || 0,\n      crit_damage: scaledStats.crit_damage || 0,\n      evasion: scaledStats.evasion || 0,\n      base_evasion: scaledStats.evasion || 0,\n      accuracy: 0,\n      resist: scaledStats.resist || 0,\n      unlock_attack: !!scaledStats.unlock_attack,\n      _stun: 0,\n      _silenced: 0,\n      _poison: 0,\n      _poison_source: null,\n      _p16_owner_turns: 0,\n      _p16_active: false\n    };\n    allUnits.push(u);\n    stats[u.side_id] = { name: u.name, side: u.side, dmg_dealt: 0, dmg_taken: 0, heal_given: 0, stun_count: 0, silence_count: 0, dodge_count: 0, dmg_prevented: 0, heal_proc_count: 0, heal_proc_total: 0, extra_turn_count: 0, elim_round: null };\n  });\n\n  function updateStats(u) {\n    let atkMulti = 1, defMulti = 1, spdMulti = 1;\n    let hasP17 = allUnits.some(x => x.side === u.side && x.hp > 0 && x.passive === 'P17' && !x._silenced);\n    if (hasP17) defMulti += PASSIVE_PARAMS.P17.def_bonus / 100;\n\n    let hasP19Enemy = allUnits.some(x => x.side !== u.side && x.hp > 0 && x.passive === 'P19' && !x._silenced);\n    if (hasP19Enemy) spdMulti -= PASSIVE_PARAMS.P19.spd_reduce / 100;\n\n    let hasP20Enemy = allUnits.some(x => x.side !== u.side && x.hp > 0 && x.passive === 'P20' && !x._silenced);\n    if (hasP20Enemy) atkMulti -= PASSIVE_PARAMS.P20.atk_reduce / 100;\n\n    if (u._p16_active) atkMulti += PASSIVE_PARAMS.P16.atk_bonus / 100;\n    if (u.passive === 'P04' && !u._silenced && u.hp < u.max_hp * 0.5) atkMulti += PASSIVE_PARAMS.P04.atk_bonus / 100;\n\n    u.atk = Math.max(1, u.base_atk * atkMulti);\n    u.def = Math.max(0, u.base_def * defMulti);\n    u.spd = Math.max(1, u.base_spd * spdMulti);\n\n    // \u0e2d\u0e2d\u0e23\u0e48\u0e32\u0e1b\u0e23\u0e32\u0e14\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e27 (P26) \u2014 \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 \u0e04\u0e33\u0e19\u0e27\u0e13\u0e08\u0e32\u0e01 base_evasion \u0e17\u0e38\u0e01\u0e04\u0e23\u0e31\u0e49\u0e07\u0e01\u0e31\u0e19\u0e1a\u0e27\u0e01\u0e0b\u0e49\u0e33\n    let hasP26 = allUnits.some(x => x.side === u.side && x.hp > 0 && x.passive === 'P26' && !x._silenced);\n    u.evasion = u.base_evasion + (hasP26 ? PASSIVE_PARAMS.P26.evasion_bonus : 0);\n  }\n\n  // \u0e04\u0e37\u0e19\u0e04\u0e48\u0e32\u0e25\u0e33\u0e14\u0e31\u0e1a\u0e15\u0e33\u0e41\u0e2b\u0e19\u0e48\u0e07\u0e0a\u0e48\u0e2d\u0e07 (0 = \u0e0a\u0e48\u0e2d\u0e07 1) \u0e08\u0e32\u0e01 side_id \u0e40\u0e0a\u0e48\u0e19 'player_2' \u0e2b\u0e23\u0e37\u0e2d 'enemy_1'\n  function getSlotIndex(u) {\n    return parseInt(u.side_id.split('_')[1], 10);\n  }\n\n  function getTargets(attacker, count = 1) {\n    let e = allUnits.filter(u => u.side !== attacker.side && u.hp > 0);\n    if (e.length === 0) return [];\n    let rnd = (arr) => arr[Math.floor(Math.random() * arr.length)];\n    let mainTgt = null;\n\n    // PVP: \u0e17\u0e31\u0e49\u0e07\u0e2a\u0e2d\u0e07\u0e1d\u0e31\u0e48\u0e07\u0e15\u0e49\u0e2d\u0e07\u0e43\u0e0a\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e40\u0e25\u0e47\u0e07\u0e40\u0e1b\u0e49\u0e32\u0e40\u0e14\u0e35\u0e22\u0e27\u0e01\u0e31\u0e19\u0e40\u0e2a\u0e21\u0e2d (\u0e41\u0e1a\u0e1a\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e1b\u0e01\u0e15\u0e34 - \u0e40\u0e25\u0e47\u0e07\u0e15\u0e32\u0e21\u0e2a\u0e32\u0e22 tank/fighter \u0e01\u0e48\u0e2d\u0e19)\n    // \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e41\u0e1a\u0e1a\u0e28\u0e31\u0e15\u0e23\u0e39 NPC (\u0e40\u0e25\u0e47\u0e07\u0e15\u0e32\u0e21\u0e25\u0e33\u0e14\u0e31\u0e1a\u0e0a\u0e48\u0e2d\u0e07) \u0e17\u0e35\u0e48\u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a\u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a side==='enemy' \u2014 \u0e01\u0e15\u0e34\u0e01\u0e32\u0e19\u0e31\u0e49\u0e19\u0e2d\u0e2d\u0e01\u0e41\u0e1a\u0e1a\u0e21\u0e32\n    // \u0e2a\u0e33\u0e2b\u0e23\u0e31\u0e1a\u0e21\u0e2d\u0e19\u0e2a\u0e40\u0e15\u0e2d\u0e23\u0e4c\u0e43\u0e19\u0e14\u0e48\u0e32\u0e19\u0e40\u0e01\u0e32\u0e30 (\u0e44\u0e21\u0e48\u0e2a\u0e21\u0e21\u0e32\u0e15\u0e23\u0e01\u0e31\u0e1a\u0e1c\u0e39\u0e49\u0e40\u0e25\u0e48\u0e19\u0e42\u0e14\u0e22\u0e15\u0e31\u0e49\u0e07\u0e43\u0e08) \u0e40\u0e2d\u0e32\u0e21\u0e32\u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a PVP (\u0e04\u0e19\u0e2a\u0e39\u0e49\u0e04\u0e19) \u0e15\u0e23\u0e07\u0e46 \u0e08\u0e30\u0e17\u0e33\u0e43\u0e2b\u0e49\n    // \u0e1d\u0e31\u0e48\u0e07\u0e17\u0e35\u0e48\u0e44\u0e14\u0e49\u0e01\u0e15\u0e34\u0e01\u0e32\u0e19\u0e35\u0e49\u0e40\u0e2a\u0e35\u0e22\u0e40\u0e1b\u0e23\u0e35\u0e22\u0e1a\u0e0a\u0e31\u0e14\u0e40\u0e08\u0e19\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e44\u0e21\u0e48\u0e40\u0e1b\u0e47\u0e19\u0e18\u0e23\u0e23\u0e21 (\u0e17\u0e14\u0e2a\u0e2d\u0e1a\u0e41\u0e25\u0e49\u0e27\u0e1e\u0e1a\u0e08\u0e23\u0e34\u0e07: \u0e41\u0e21\u0e17\u0e0a\u0e4c\u0e01\u0e23\u0e30\u0e08\u0e01\u0e40\u0e07\u0e32\u0e17\u0e35\u0e21\u0e40\u0e2b\u0e21\u0e37\u0e2d\u0e19\u0e01\u0e31\u0e19\u0e17\u0e38\u0e01\n    // \u0e1b\u0e23\u0e30\u0e01\u0e32\u0e23 \u0e1d\u0e31\u0e48\u0e07 attacker \u0e0a\u0e19\u0e30 ~75-85% \u0e41\u0e17\u0e19\u0e17\u0e35\u0e48\u0e08\u0e30\u0e43\u0e01\u0e25\u0e49 50% \u2014 \u0e40\u0e1b\u0e47\u0e19\u0e08\u0e38\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27\u0e17\u0e35\u0e48\u0e15\u0e23\u0e23\u0e01\u0e30 PVP \u0e15\u0e48\u0e32\u0e07\u0e08\u0e32\u0e01 combat_engine.js\n    // \u0e15\u0e49\u0e19\u0e09\u0e1a\u0e31\u0e1a\u0e42\u0e14\u0e22\u0e15\u0e31\u0e49\u0e07\u0e43\u0e08 \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48\u0e04\u0e27\u0e32\u0e21\u0e1c\u0e34\u0e14\u0e1e\u0e25\u0e32\u0e14\u0e08\u0e32\u0e01\u0e01\u0e32\u0e23\u0e04\u0e31\u0e14\u0e25\u0e2d\u0e01)\n    let pools = { tank: [], fighter: [], assassin: [], ranger: [], support: [] };\n    e.forEach(x => pools[x.role].push(x));\n\n    if (attacker.role === 'assassin') mainTgt = rnd(e);\n    else if (attacker.role === 'ranger') {\n      let p1 = [...pools.tank, ...pools.fighter, ...pools.assassin];\n      if (p1.length > 0) mainTgt = rnd(p1);\n      else if (pools.support.length > 0) mainTgt = rnd(pools.support);\n      else if (pools.ranger.length > 0) mainTgt = rnd(pools.ranger);\n      else mainTgt = rnd(e);\n    } else {\n      if (pools.tank.length > 0) mainTgt = rnd(pools.tank);\n      else if (pools.fighter.length > 0) mainTgt = rnd(pools.fighter);\n      else if (pools.assassin.length > 0) mainTgt = rnd(pools.assassin);\n      else if (pools.ranger.length > 0) mainTgt = rnd(pools.ranger);\n      else mainTgt = rnd(pools.support);\n    }\n\n    if (!mainTgt) return [];\n    let tgts = [mainTgt];\n    if (count > 1) {\n      let others = e.filter(u => u.side_id !== mainTgt.side_id).sort(() => Math.random() - 0.5);\n      tgts.push(...others.slice(0, count - 1));\n    }\n    return tgts;\n  }\n\n  function dealDamage(target, dmg, source, round) {\n    target.hp -= dmg;\n    stats[source.side_id].dmg_dealt += dmg;\n    stats[target.side_id].dmg_taken += dmg;\n\n    if (target.hp > 0 && target.hp < target.max_hp * 0.5 && target.hp + dmg >= target.max_hp * 0.5) {\n      log(`${getTeamName(target.side)}:[${target.name}] HP \u0e1a\u0e32\u0e14\u0e40\u0e08\u0e47\u0e1a\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 50%!`);\n    }\n\n    if (target.hp > 0 && target.hp < target.max_hp * 0.25 && target.hp + dmg >= target.max_hp * 0.25) {\n      log(`${getTeamName(target.side)}:[${target.name}] HP \u0e27\u0e34\u0e01\u0e24\u0e15\u0e15\u0e48\u0e33\u0e01\u0e27\u0e48\u0e32 25%!`);\n    }\n\n    if (target.hp <= 0) {\n      target.hp = 0;\n      log(`${getTeamName(target.side)}:[${target.name}] \u0e16\u0e39\u0e01\u0e01\u0e33\u0e08\u0e31\u0e14\u0e42\u0e14\u0e22 ${source.name}`);\n      stats[target.side_id].elim_round = round;\n\n      if (target.passive === 'P24' && !target._silenced) {\n        log(`${getTeamName(target.side)}:[${target.name}] \u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e42\u0e08\u0e21\u0e15\u0e35\u0e28\u0e31\u0e15\u0e23\u0e39\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14`);\n        let aoeDmg = target.base_atk * (PASSIVE_PARAMS.P24.dmg_pct / 100);\n        let enemies = allUnits.filter(x => x.side !== target.side && x.hp > 0);\n        for (let e of enemies) {\n          let eEffDef = getEffectiveDefense(target, e);\n          let edmg = Math.max(1, aoeDmg - eEffDef);\n          if (e.passive === 'P10' && !e._silenced) {\n            let beforeReduce = edmg;\n            edmg = Math.max(1, edmg * (1 - (PASSIVE_PARAMS.P10.reduce_pct / 100)));\n            stats[e.side_id].dmg_prevented += Math.floor(beforeReduce - edmg);\n          }\n          edmg = applyDamageVariance(edmg);\n          edmg = Math.max(1, Math.floor(edmg));\n          let eHpAfter = Math.max(0, e.hp - edmg);\n          e.hp -= edmg;\n          stats[target.side_id].dmg_dealt += edmg;\n          stats[e.side_id].dmg_taken += edmg;\n          log(`- \u0e2a\u0e23\u0e49\u0e32\u0e07\u0e04\u0e27\u0e32\u0e21\u0e40\u0e2a\u0e35\u0e22\u0e2b\u0e32\u0e22\u0e43\u0e2b\u0e49 ${e.name} ${edmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${Math.floor((eHpAfter / e.max_hp) * 100)}%HP) (\u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22)`);\n          if (e.hp <= 0) {\n            e.hp = 0;\n            log(`${getTeamName(e.side)}:[${e.name}] \u0e16\u0e39\u0e01\u0e01\u0e33\u0e08\u0e31\u0e14\u0e42\u0e14\u0e22\u0e23\u0e30\u0e40\u0e1a\u0e34\u0e14\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22\u0e02\u0e2d\u0e07 ${target.name}`);\n            stats[e.side_id].elim_round = round;\n          }\n        }\n      }\n    }\n  }\n\n  function healUnit(source, target, amt, doLog = true) {\n    if (target.hp <= 0) return 0;\n    let actualHeal = Math.min(amt, target.max_hp - target.hp);\n    target.hp += actualHeal;\n    stats[source.side_id].heal_given += actualHeal;\n    if (doLog && actualHeal > 0) log(`${getTeamName(source.side)}:[${source.name}] \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49 ${target.name} ${actualHeal} \u0e2b\u0e19\u0e48\u0e27\u0e22`);\n    return actualHeal;\n  }\n\n  // \u0e23\u0e27\u0e21\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e01\u0e32\u0e23\u0e2e\u0e35\u0e25/\u0e1a\u0e31\u0e1f\u0e40\u0e25\u0e37\u0e2d\u0e14\u0e2b\u0e25\u0e32\u0e22\u0e40\u0e1b\u0e49\u0e32\u0e2b\u0e21\u0e32\u0e22\u0e43\u0e2b\u0e49\u0e40\u0e1b\u0e47\u0e19\u0e1a\u0e23\u0e23\u0e17\u0e31\u0e14\u0e40\u0e14\u0e35\u0e22\u0e27 \u0e1e\u0e23\u0e49\u0e2d\u0e21\u0e1a\u0e2d\u0e01\u0e40\u0e1b\u0e2d\u0e23\u0e4c\u0e40\u0e0b\u0e47\u0e19\u0e15\u0e4c\u0e40\u0e25\u0e37\u0e2d\u0e14\u0e17\u0e35\u0e48\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e02\u0e2d\u0e07\u0e41\u0e15\u0e48\u0e25\u0e30\u0e04\u0e19\n  // \u0e40\u0e1e\u0e37\u0e48\u0e2d\u0e43\u0e2b\u0e49\u0e1c\u0e39\u0e49\u0e43\u0e0a\u0e49\u0e42\u0e1b\u0e23\u0e41\u0e01\u0e23\u0e21\u0e2d\u0e48\u0e32\u0e19\u0e2b\u0e19\u0e49\u0e32\u0e08\u0e2d\u0e1b\u0e31\u0e14\u0e1f\u0e31\u0e07\u0e04\u0e23\u0e31\u0e49\u0e07\u0e40\u0e14\u0e35\u0e22\u0e27\u0e44\u0e14\u0e49\u0e04\u0e23\u0e1a\n  function healGroupAndLog(source, targets, amt, actionLabel) {\n    let parts = [];\n    let totalHealed = 0;\n    targets.forEach(t => {\n      let healed = healUnit(source, t, amt, false);\n      if (healed > 0) {\n        let pct = Math.floor((t.hp / t.max_hp) * 100);\n        parts.push(`${t.name} +${healed} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${pct}%HP)`);\n        totalHealed += healed;\n      }\n    });\n    if (parts.length > 0) {\n      log(`${getTeamName(source.side)}:[${source.name}] ${actionLabel} \u2014 ${parts.join(', ')}`);\n      stats[source.side_id].heal_proc_count++;\n      stats[source.side_id].heal_proc_total += totalHealed;\n    }\n  }\n\n  // \u0e2a\u0e38\u0e48\u0e21\u0e15\u0e31\u0e27\u0e04\u0e39\u0e13\u0e14\u0e32\u0e40\u0e21\u0e08\u0e41\u0e1b\u0e23\u0e1c\u0e31\u0e19 \u0e1a\u0e27\u0e01\u0e25\u0e1a 15% \u0e08\u0e32\u0e01\u0e04\u0e48\u0e32\u0e17\u0e35\u0e48\u0e04\u0e33\u0e19\u0e27\u0e13\u0e44\u0e14\u0e49 \u0e43\u0e0a\u0e49\u0e01\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e17\u0e38\u0e01\u0e1b\u0e23\u0e30\u0e40\u0e20\u0e17\u0e44\u0e21\u0e48\u0e27\u0e48\u0e32\u0e08\u0e30\u0e21\u0e32\u0e08\u0e32\u0e01\u0e01\u0e32\u0e23\u0e42\u0e08\u0e21\u0e15\u0e35\u0e1b\u0e01\u0e15\u0e34\u0e2b\u0e23\u0e37\u0e2d passive \u0e43\u0e14\u0e01\u0e47\u0e15\u0e32\u0e21\n  function applyDamageVariance(dmg) {\n    const variance = 0.85 + Math.random() * 0.30; // \u0e2a\u0e38\u0e48\u0e21\u0e15\u0e48\u0e2d\u0e40\u0e19\u0e37\u0e48\u0e2d\u0e07\u0e23\u0e30\u0e2b\u0e27\u0e48\u0e32\u0e07 0.85 \u0e16\u0e36\u0e07 1.15\n    return dmg * variance;\n  }\n\n  // \u0e04\u0e33\u0e19\u0e27\u0e13\u0e04\u0e48\u0e32\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19\u0e17\u0e35\u0e48\u0e43\u0e0a\u0e49\u0e08\u0e23\u0e34\u0e07\u0e43\u0e19\u0e01\u0e32\u0e23\u0e2b\u0e31\u0e01\u0e14\u0e32\u0e40\u0e21\u0e08 \u0e01\u0e23\u0e13\u0e35\u0e44\u0e1f\u0e17\u0e4c\u0e40\u0e15\u0e2d\u0e23\u0e4c\u0e42\u0e08\u0e21\u0e15\u0e35\u0e41\u0e17\u0e07\u0e04\u0e4c \u0e43\u0e2b\u0e49\u0e17\u0e30\u0e25\u0e38\u0e40\u0e01\u0e23\u0e32\u0e30\u0e44\u0e1b 60% (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e04\u0e48\u0e32\u0e1b\u0e49\u0e2d\u0e07\u0e01\u0e31\u0e19\u0e41\u0e04\u0e48 40%)\n  function getEffectiveDefense(attackerUnit, targetUnit) {\n    if (attackerUnit.role === 'fighter' && targetUnit.role === 'tank') {\n      return targetUnit.def * 0.4;\n    }\n    return targetUnit.def;\n  }\n\n  function executeHit(attacker, initialTarget, isSilenced, dmgMultiplier, round) {\n    let actualTarget = initialTarget;\n    let tgtAllies = allUnits.filter(x => x.side === initialTarget.side && x.hp > 0 && x.passive === 'P12' && x.side_id !== initialTarget.side_id && !x._silenced);\n    if (tgtAllies.length > 0) {\n      let lowestAlly = [...tgtAllies].sort((a, b) => (a.hp / a.max_hp) - (b.hp / b.max_hp))[0];\n      if (Math.random() < PASSIVE_PARAMS.P12.chance / 100) {\n        log(`${getTeamName(lowestAlly.side)}:[${lowestAlly.name}] \u0e42\u0e25\u0e48\u0e21\u0e19\u0e38\u0e29\u0e22\u0e4c\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e41\u0e17\u0e19 ${initialTarget.name}`);\n        actualTarget = lowestAlly;\n        dmgMultiplier *= (PASSIVE_PARAMS.P12.receive_pct / 100);\n      }\n    }\n\n    if (actualTarget.passive === 'P11' && !actualTarget._silenced && Math.random() < PASSIVE_PARAMS.P11.chance / 100) {\n      stats[actualTarget.side_id].dodge_count++;\n      log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e01\u0e32\u0e23\u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49!`);\n      return;\n    }\n\n    // \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c (evasion \u0e02\u0e2d\u0e07\u0e1c\u0e39\u0e49\u0e42\u0e14\u0e19 - accuracy \u0e02\u0e2d\u0e07\u0e1c\u0e39\u0e49\u0e15\u0e35) \u2014 \u0e41\u0e22\u0e01\u0e08\u0e32\u0e01 P11 passive \u0e02\u0e49\u0e32\u0e07\u0e1a\u0e19 \u0e17\u0e33\u0e07\u0e32\u0e19\u0e04\u0e39\u0e48\u0e02\u0e19\u0e32\u0e19\n    const netEvasion = Math.max(0, (actualTarget.evasion || 0) - (attacker.accuracy || 0));\n    if (netEvasion > 0 && Math.random() * 100 < netEvasion) {\n      stats[actualTarget.side_id].dodge_count++;\n      log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e2b\u0e25\u0e1a\u0e2b\u0e25\u0e35\u0e01\u0e01\u0e32\u0e23\u0e42\u0e08\u0e21\u0e15\u0e35\u0e44\u0e14\u0e49!`);\n      return;\n    }\n\n    let isCrit = false, critMult = 1.0;\n    if (!isSilenced) {\n      // \u0e42\u0e25\u0e48\u0e15\u0e49\u0e32\u0e19\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25 (P25) \u2014 \u0e16\u0e49\u0e32\u0e1d\u0e31\u0e48\u0e07\u0e15\u0e23\u0e07\u0e02\u0e49\u0e32\u0e21\u0e02\u0e2d\u0e07 attacker \u0e21\u0e35\u0e43\u0e04\u0e23\u0e16\u0e37\u0e2d P25 \u0e2d\u0e22\u0e39\u0e48 \u0e25\u0e14\u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e41\u0e25\u0e30\u0e04\u0e27\u0e32\u0e21\u0e41\u0e23\u0e07\u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25\u0e02\u0e2d\u0e07 attacker \u0e25\u0e07\n      let hasEnemyP25 = allUnits.some(x => x.side !== attacker.side && x.hp > 0 && x.passive === 'P25' && !x._silenced);\n      let critChanceReduce = hasEnemyP25 ? PASSIVE_PARAMS.P25.crit_chance_reduce : 0;\n      let critDmgReduce = hasEnemyP25 ? PASSIVE_PARAMS.P25.crit_dmg_reduce : 0;\n\n      if (attacker.passive === 'P07' && Math.random() * 100 < Math.max(0, PASSIVE_PARAMS.P07.chance - critChanceReduce)) {\n        isCrit = true;\n        critMult = 1 + (PASSIVE_PARAMS.P07.multiplier - 1) * (1 - critDmgReduce / 100);\n      }\n      else if (attacker.passive === 'P08' && Math.random() * 100 < Math.max(0, PASSIVE_PARAMS.P08.chance - critChanceReduce)) {\n        isCrit = true;\n        critMult = 1 + (PASSIVE_PARAMS.P08.multiplier - 1) * (1 - critDmgReduce / 100);\n      }\n      else if ((attacker.crit_rate || 0) > 0 && Math.random() * 100 < Math.max(0, attacker.crit_rate - critChanceReduce)) {\n        isCrit = true;\n        critMult = 1 + Math.max(0, (attacker.crit_damage || 0)) / 100 * (1 - critDmgReduce / 100);\n      }\n    }\n\n    let effDef = getEffectiveDefense(attacker, actualTarget);\n    let dmg = Math.max(1, (attacker.atk * critMult * dmgMultiplier) - effDef);\n    if (actualTarget.passive === 'P10' && !actualTarget._silenced) {\n      let beforeReduce = dmg;\n      dmg = Math.max(1, dmg * (1 - (PASSIVE_PARAMS.P10.reduce_pct / 100)));\n      stats[actualTarget.side_id].dmg_prevented += Math.floor(beforeReduce - dmg);\n    }\n    // \u0e15\u0e49\u0e32\u0e19\u0e17\u0e32\u0e19\u0e14\u0e32\u0e40\u0e21\u0e08\u0e08\u0e32\u0e01\u0e2d\u0e38\u0e1b\u0e01\u0e23\u0e13\u0e4c \u2014 \u0e41\u0e22\u0e01\u0e08\u0e32\u0e01 P10 passive \u0e02\u0e49\u0e32\u0e07\u0e1a\u0e19 \u0e17\u0e33\u0e07\u0e32\u0e19\u0e04\u0e39\u0e48\u0e02\u0e19\u0e32\u0e19\n    if ((actualTarget.resist || 0) > 0) {\n      let beforeResist = dmg;\n      dmg = Math.max(1, dmg * (1 - Math.min(90, actualTarget.resist) / 100));\n      stats[actualTarget.side_id].dmg_prevented += Math.floor(beforeResist - dmg);\n    }\n    dmg = applyDamageVariance(dmg);\n    dmg = Math.max(1, Math.floor(dmg));\n\n    let hpAfter = Math.max(0, actualTarget.hp - dmg);\n    let pctHP = Math.floor((hpAfter / actualTarget.max_hp) * 100);\n    let critText = isCrit ? ` \u0e04\u0e23\u0e34\u0e15\u0e34\u0e04\u0e2d\u0e25!` : ``;\n    log(`${getTeamName(attacker.side)}:[${attacker.name}] \u0e42\u0e08\u0e21\u0e15\u0e35 ${getTeamName(actualTarget.side)}:[${actualTarget.name}] ${dmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${pctHP}%HP)${critText}`);\n\n    dealDamage(actualTarget, dmg, attacker, round);\n\n    if (!isSilenced && attacker.passive === 'P06' && attacker.hp > 0) {\n      let h = Math.floor(dmg * (PASSIVE_PARAMS.P06.lifesteal_pct / 100));\n      if (h > 0) healUnit(attacker, attacker, h, false);\n    }\n\n    if (actualTarget.hp > 0 && !isSilenced) {\n      if (attacker.passive === 'P21' && Math.random() < PASSIVE_PARAMS.P21.chance / 100) {\n        actualTarget._stun = Math.max(actualTarget._stun, PASSIVE_PARAMS.P21.stun_duration);\n        stats[attacker.side_id].stun_count++;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e34\u0e14\u0e2a\u0e16\u0e32\u0e19\u0e30\u0e2a\u0e15\u0e31\u0e49\u0e19!`);\n      }\n      if (attacker.passive === 'P22' && Math.random() < PASSIVE_PARAMS.P22.chance / 100) {\n        actualTarget._stun = Math.max(actualTarget._stun, PASSIVE_PARAMS.P22.stun_duration);\n        stats[attacker.side_id].stun_count++;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e34\u0e14\u0e2a\u0e16\u0e32\u0e19\u0e30\u0e2a\u0e15\u0e31\u0e49\u0e19\u0e2b\u0e19\u0e31\u0e01!`);\n      }\n      if (attacker.passive === 'P23' && Math.random() < PASSIVE_PARAMS.P23.chance / 100) {\n        actualTarget._silenced = Math.max(actualTarget._silenced, PASSIVE_PARAMS.P23.silence_duration);\n        stats[attacker.side_id].silence_count++;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e16\u0e39\u0e01\u0e1b\u0e34\u0e14 passive!`);\n      }\n      if (attacker.passive === 'P27' && Math.random() < PASSIVE_PARAMS.P27.chance / 100) {\n        actualTarget._poison = Math.max(actualTarget._poison, PASSIVE_PARAMS.P27.duration);\n        actualTarget._poison_source = attacker;\n        log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e34\u0e14\u0e1e\u0e34\u0e29\u0e01\u0e31\u0e14\u0e01\u0e23\u0e48\u0e2d\u0e19!`);\n      }\n    }\n\n    if (actualTarget.hp > 0 && actualTarget.passive === 'P09' && !actualTarget._silenced && Math.random() < PASSIVE_PARAMS.P09.chance / 100) {\n      log(`${getTeamName(actualTarget.side)}:[${actualTarget.name}] \u0e15\u0e35\u0e42\u0e15\u0e49\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e2a\u0e27\u0e19\u0e01\u0e25\u0e31\u0e1a ${attacker.name}`);\n      let cAtk = actualTarget.atk * (PASSIVE_PARAMS.P09.dmg_pct / 100);\n      let cEffDef = getEffectiveDefense(actualTarget, attacker);\n      let cDmg = Math.max(1, cAtk - cEffDef);\n      if (attacker.passive === 'P10' && !attacker._silenced) {\n        let beforeReduce = cDmg;\n        cDmg = Math.max(1, cDmg * (1 - (PASSIVE_PARAMS.P10.reduce_pct / 100)));\n        stats[attacker.side_id].dmg_prevented += Math.floor(beforeReduce - cDmg);\n      }\n      cDmg = applyDamageVariance(cDmg);\n      cDmg = Math.max(1, Math.floor(cDmg));\n      let cHpAfter = Math.max(0, attacker.hp - cDmg);\n      log(`- \u0e42\u0e08\u0e21\u0e15\u0e35 ${getTeamName(attacker.side)}:[${attacker.name}] ${cDmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e14 ${Math.floor((cHpAfter / attacker.max_hp) * 100)}%HP) [\u0e2a\u0e27\u0e19\u0e01\u0e25\u0e31\u0e1a]`);\n      dealDamage(attacker, cDmg, actualTarget, round);\n    }\n  }\n\n  function performAttackAction(attacker, isSilenced, forceSingle, round) {\n    if (attacker.hp <= 0) return;\n    let mainTgtArray = getTargets(attacker, 1);\n    if (mainTgtArray.length === 0) return;\n    let mainTarget = mainTgtArray[0];\n\n    let targets = [mainTarget];\n    let isAoE = false, aoeDmgPct = 1.0;\n\n    if (!isSilenced && !forceSingle) {\n      if (attacker.passive === 'P01') { isAoE = true; aoeDmgPct = PASSIVE_PARAMS.P01.dmg_pct / 100; targets = getTargets(attacker, PASSIVE_PARAMS.P01.targets); }\n      else if (attacker.passive === 'P02') { isAoE = true; aoeDmgPct = PASSIVE_PARAMS.P02.dmg_pct / 100; targets = getTargets(attacker, PASSIVE_PARAMS.P02.targets); }\n    }\n\n    targets.forEach(tgt => { if (attacker.hp > 0 && tgt.hp > 0) executeHit(attacker, tgt, isSilenced, isAoE ? aoeDmgPct : 1.0, round); });\n\n    if (!isSilenced && !forceSingle && attacker.passive === 'P03' && attacker.hp > 0 && mainTarget.hp > 0 && Math.random() < PASSIVE_PARAMS.P03.chance / 100) {\n      log(`${getTeamName(attacker.side)}:[${attacker.name}] \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33\u0e17\u0e33\u0e07\u0e32\u0e19!`);\n      executeHit(attacker, mainTarget, isSilenced, PASSIVE_PARAMS.P03.dmg_pct / 100, round);\n    }\n  }\n\n  let isCombatActive = true;\n  let round = 1;\n\n  log(`\u0e40\u0e23\u0e34\u0e48\u0e21\u0e01\u0e32\u0e23\u0e15\u0e48\u0e2d\u0e2a\u0e39\u0e49!`);\n\n  while (isCombatActive && round <= 60) {\n    log(`--- \u0e23\u0e2d\u0e1a\u0e17\u0e35\u0e48 ${round} ---`);\n    allUnits.forEach(u => updateStats(u));\n    let turnOrder = [...allUnits].filter(u => u.hp > 0);\n    turnOrder.forEach(u => {\n      u._temp_spd = u.spd;\n      if (u.passive === 'P05' && !u._silenced && Math.random() < PASSIVE_PARAMS.P05.chance / 100) u._temp_spd += 1000;\n    });\n    turnOrder.sort((a, b) => {\n      if (b._temp_spd !== a._temp_spd) return b._temp_spd - a._temp_spd;\n      if (a.side === 'player' && b.side === 'enemy') return -1;\n      if (b.side === 'player' && a.side === 'enemy') return 1;\n      return 0;\n    });\n\n    for (let u of turnOrder) {\n      if (u.hp <= 0) continue;\n      if (!allUnits.some(x => x.side !== u.side && x.hp > 0)) { isCombatActive = false; break; }\n\n      if (u._stun > 0) {\n        u._stun--;\n        log(`${getTeamName(u.side)}:[${u.name}] \u0e15\u0e34\u0e14\u0e2a\u0e15\u0e31\u0e49\u0e19 \u0e02\u0e49\u0e32\u0e21\u0e15\u0e32\u0e42\u0e08\u0e21\u0e15\u0e35 (\u0e40\u0e2b\u0e25\u0e37\u0e2d ${u._stun} \u0e23\u0e2d\u0e1a)`);\n        continue;\n      }\n\n      if (u._poison > 0) {\n        let poisonDmg = Math.max(1, Math.floor(u.max_hp * (PASSIVE_PARAMS.P27.poison_pct / 100)));\n        let poisonSource = u._poison_source || u;\n        dealDamage(u, poisonDmg, poisonSource, round);\n        u._poison--;\n        log(`${getTeamName(u.side)}:[${u.name}] \u0e44\u0e14\u0e49\u0e23\u0e31\u0e1a\u0e14\u0e32\u0e40\u0e21\u0e08\u0e1e\u0e34\u0e29 ${poisonDmg} \u0e2b\u0e19\u0e48\u0e27\u0e22 (\u0e40\u0e2b\u0e25\u0e37\u0e2d ${u._poison} \u0e23\u0e2d\u0e1a)`);\n        if (u.hp <= 0) continue;\n      }\n\n      let isSilencedThisTurn = false;\n      if (u._silenced > 0) {\n        isSilencedThisTurn = true;\n        u._silenced--;\n        if (u._silenced > 0) log(`${getTeamName(u.side)}:[${u.name}] passive \u0e22\u0e31\u0e07\u0e16\u0e39\u0e01\u0e1b\u0e34\u0e14\u0e2d\u0e22\u0e39\u0e48 \u0e40\u0e2b\u0e25\u0e37\u0e2d\u0e2d\u0e35\u0e01 ${u._silenced} \u0e23\u0e2d\u0e1a`);\n        else log(`${getTeamName(u.side)}:[${u.name}] passive \u0e16\u0e39\u0e01\u0e1b\u0e34\u0e14\u0e23\u0e2d\u0e1a\u0e2a\u0e38\u0e14\u0e17\u0e49\u0e32\u0e22`);\n      }\n\n      if (u.passive === 'P16') {\n        if (u._p16_owner_turns > 0) {\n          u._p16_owner_turns--;\n          if (u._p16_owner_turns === 0) {\n            allUnits.filter(x => x.side === u.side).forEach(x => x._p16_active = false);\n            log(`${getTeamName(u.side)}:[${u.name}] \u0e1a\u0e31\u0e1f\u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a\u0e2b\u0e21\u0e14\u0e24\u0e17\u0e18\u0e34\u0e4c`);\n          }\n        }\n      }\n\n      if (!isSilencedThisTurn) {\n        if (u.passive === 'P13') {\n          let h = Math.floor(u.max_hp * (PASSIVE_PARAMS.P13.heal_pct / 100));\n          healGroupAndLog(u, [u], h, '\u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49\u0e15\u0e31\u0e27\u0e40\u0e2d\u0e07');\n        }\n        else if (u.passive === 'P14') {\n          let h = Math.floor(u.max_hp * (PASSIVE_PARAMS.P14.heal_pct / 100));\n          let allies = allUnits.filter(x => x.side === u.side && x.hp > 0);\n          healGroupAndLog(u, allies, h, '\u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21');\n        } else if (u.passive === 'P15' && Math.random() < PASSIVE_PARAMS.P15.chance / 100) {\n          let h = Math.floor(u.max_hp * (PASSIVE_PARAMS.P15.heal_pct / 100));\n          let allies = allUnits.filter(x => x.side === u.side && x.hp > 0);\n          healGroupAndLog(u, allies, h, '\u0e23\u0e31\u0e01\u0e29\u0e32\u0e09\u0e38\u0e01\u0e40\u0e09\u0e34\u0e19\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e1f\u0e37\u0e49\u0e19\u0e1f\u0e39 HP \u0e43\u0e2b\u0e49\u0e17\u0e35\u0e21');\n        } else if (u.passive === 'P16' && u._p16_owner_turns === 0 && Math.random() < PASSIVE_PARAMS.P16.chance / 100) {\n          log(`${getTeamName(u.side)}:[${u.name}] \u0e01\u0e23\u0e30\u0e15\u0e38\u0e49\u0e19\u0e19\u0e31\u0e01\u0e23\u0e1a\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e40\u0e1e\u0e34\u0e48\u0e21\u0e42\u0e08\u0e21\u0e15\u0e35\u0e17\u0e35\u0e21 25%`);\n          u._p16_owner_turns = PASSIVE_PARAMS.P16.duration;\n          allUnits.filter(x => x.side === u.side && x.hp > 0).forEach(ally => ally._p16_active = true);\n        }\n      }\n\n      allUnits.forEach(x => updateStats(x));\n\n      if (u.role !== 'support') {\n        performAttackAction(u, isSilencedThisTurn, false, round);\n        let alliesWithP18 = allUnits.filter(x => x.side === u.side && x.hp > 0 && x.passive === 'P18' && !x._silenced);\n        for (let allyP18 of alliesWithP18) {\n          if (Math.random() < PASSIVE_PARAMS.P18.chance / 100) {\n            stats[allyP18.side_id].extra_turn_count++;\n            log(`${getTeamName(allyP18.side)}:[${allyP18.name}] \u0e42\u0e2d\u0e01\u0e32\u0e2a\u0e17\u0e2d\u0e07\u0e17\u0e33\u0e07\u0e32\u0e19! \u0e2a\u0e31\u0e48\u0e07 ${u.name} \u0e42\u0e08\u0e21\u0e15\u0e35\u0e0b\u0e49\u0e33`);\n            performAttackAction(u, isSilencedThisTurn, true, round);\n          }\n        }\n      }\n    }\n    if (isCombatActive) round++;\n  }\n\n  let attackerAlive = allUnits.some(u => u.side === 'player' && u.hp > 0);\n  let defenderAlive = allUnits.some(u => u.side === 'enemy' && u.hp > 0);\n  let isAttackerWin = attackerAlive && !defenderAlive;\n\n  return { isAttackerWin: isAttackerWin, logs: logs, stats: stats, totalRounds: round };\n}\n\nif (typeof module !== \"undefined\" && module.exports) {\n  module.exports = { runPvpCombat };\n}\n\n";

function createGameEngine() {
  const exposeExports = `
this.CHARACTERS = CHARACTERS;
this.EQUIPMENT_TYPES = EQUIPMENT_TYPES;
this.runPvpCombat = runPvpCombat;
this.crewGetBaseCharData = crewGetBaseCharData;
this.calculateCharacterStats = calculateCharacterStats;
this.calculateSquadCombatPower = calculateSquadCombatPower;
this.__setPlayerState = function(save) { playerState = save; };
`;
  const context = {};
  vm.createContext(context);
  vm.runInContext('let playerState;\n' + GAME_ENGINE_SOURCE + exposeExports, context, { filename: 'game-engine-bundle.js' });
  return context;
}


// ===== leaderboard_http.js =====
// leaderboard_http.js
// เส้นทาง API ของ leaderboard ทั้ง 4 แบบ — ต้องล็อกอินก่อนถึงจะดูได้ (เพื่อบอก "อันดับของฉัน" ได้ด้วย)


async function handleLeaderboardRequest(req, res, path, method, userId, db, gameEngine, sendJson) {
  if (path === '/api/leaderboard/reputation' && method === 'GET') {
    const entries = await db.getAllSavesWithUsernames();
    const result = buildReputationLeaderboard(entries);
    sendJson(res, 200, { top: result.top, you: findMyEntry(result, userId) });
    return true;
  }

  if (path === '/api/leaderboard/wave-survival' && method === 'GET') {
    const entries = await db.getAllSavesWithUsernames();
    const result = buildWaveSurvivalLeaderboard(entries);
    sendJson(res, 200, { top: result.top, you: findMyEntry(result, userId) });
    return true;
  }

  if (path === '/api/leaderboard/combat-power' && method === 'GET') {
    const entries = await db.getAllSavesWithUsernames();
    const result = buildCombatPowerLeaderboard(entries, gameEngine, (save) => { gameEngine.__setPlayerState(save); });
    sendJson(res, 200, { top: result.top, you: findMyEntry(result, userId) });
    return true;
  }

  if (path === '/api/leaderboard/pvp' && method === 'GET') {
    const seasonInfo = getSeasonInfo(new Date());
    if (!seasonInfo.isActive) {
      sendJson(res, 200, { top: [], you: null, seasonClosed: true });
      return true;
    }
    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
    const profiles = await db.getAllPvpProfilesForSeason(seasonStartStr);
    const ranked = computeRanks(profiles.map(p => ({ id: p.user_id, points: p.points })));

    const withNames = [];
    for (const r of ranked) {
      const username = await db.getUsername(r.id);
      withNames.push({ userId: r.id, username, value: r.points, position: r.position, rank: r.rank });
    }
    const you = withNames.find(e => e.userId === userId) || null;
    sendJson(res, 200, { top: withNames.slice(0, 50), you });
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
      const save = await db.getSave(topupRequest.user_id);
      if (!save) { sendJson(res, 400, { error: 'ผู้เล่นคนนี้ยังไม่เคยมีเซฟ อนุมัติไม่ได้' }); return true; }
      save.gems = (save.gems || 0) + topupRequest.gem_amount;
      await db.setSave(topupRequest.user_id, save);
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

async function handlePvpRequest(req, res, path, method, body, userId, db, gameEngine, adminSecret, sendJson) {
  const now = new Date();

  // ---------- POST /api/pvp/teams ----------
  if (path === '/api/pvp/teams' && method === 'POST') {
    if (!isValidTeamArray(body.attackTeam) || !isValidTeamArray(body.defenseTeam)) {
      sendJson(res, 400, { error: 'รูปแบบทีมไม่ถูกต้อง (ต้องเป็นรายการไม่เกิน 5 ช่อง)' }); return true;
    }
    const saveData = await db.getSave(userId);
    if (!allCharactersOwned(body.attackTeam, saveData) || !allCharactersOwned(body.defenseTeam, saveData)) {
      sendJson(res, 400, { error: 'มีตัวละครในทีมที่คุณไม่ได้เป็นเจ้าของ' }); return true;
    }
    const seasonInfo = getSeasonInfo(now);
    const seasonStartStr = seasonInfo.seasonStart.toISOString().split('T')[0];
    await db.ensurePvpProfile(userId, seasonStartStr, PVP_CONFIG.STARTING_POINTS);
    await db.setPvpTeams(userId, body.attackTeam, body.defenseTeam);
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
    const profile = await db.ensurePvpProfile(userId, seasonStartStr, PVP_CONFIG.STARTING_POINTS);
    const allProfiles = await db.getAllPvpProfilesForSeason(seasonStartStr);
    const ranked = computeRanks(allProfiles.map(p => ({ id: p.user_id, points: p.points })));
    const myRankInfo = ranked.find(r => r.id === userId) || { rank: 'bronze', position: null };

    const todayMatch = await db.getMatchForUserOnDay(seasonStartStr, seasonInfo.dayNumber, userId);
    let todaysOpponent = null;
    if (todayMatch && todayMatch.player_b !== null) {
      if (seasonInfo.dayNumber === 1) {
        todaysOpponent = { isMystery: true };
      } else {
        const opponentId = todayMatch.player_a === userId ? todayMatch.player_b : todayMatch.player_a;
        const opponentProfile = allProfiles.find(p => p.user_id === opponentId);
        const opponentHidden = opponentProfile && opponentProfile.hide_today;
        todaysOpponent = {
          isMystery: false,
          username: opponentHidden ? null : await db.getUsername(opponentId),
          isHidden: !!opponentHidden,
          youAreAttacker: todayMatch.attacker_id === userId
        };
      }
    }

    let yesterdaysResult = null;
    if (seasonInfo.dayNumber > 1) {
      const yMatch = await db.getMatchForUserOnDay(seasonStartStr, seasonInfo.dayNumber - 1, userId);
      if (yMatch && yMatch.resolved) {
        const opponentId = yMatch.player_a === userId ? yMatch.player_b : yMatch.player_a;
        yesterdaysResult = {
          won: yMatch.winner_id === userId,
          opponentUsername: opponentId ? await db.getUsername(opponentId) : null
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
      attackTeam: profile.attack_team,
      defenseTeam: profile.defense_team,
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
        return sendJson(res, 201, { token, username: user.username });
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
        return sendJson(res, 200, { token, username: user.username });
      }

      // ---------- ทุกเส้นทางถัดจากนี้ต้องยืนยันตัวตนก่อน ----------
      if (path === '/api/save' && (req.method === 'GET' || req.method === 'POST')) {
        const token = getBearerToken(req);
        const payload = token ? verifyToken(token, secret) : null;
        if (!payload) return sendJson(res, 401, { error: 'กรุณาเข้าสู่ระบบใหม่' });

        if (req.method === 'GET') {
          const save = await db.getSave(payload.userId);
          return sendJson(res, 200, { save: save || null });
        }

        // POST /api/save
        const body = await readJsonBody(req);
        const saveError = validateSavePayload(body.save);
        if (saveError) return sendJson(res, 400, { error: saveError });
        await db.setSave(payload.userId, body.save);
        return sendJson(res, 200, { success: true });
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
        const handled = await handleLeaderboardRequest(req, res, path, req.method, payload.userId, db, gameEngine, sendJson);
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

if (!DATABASE_URL) {
  console.error('ขาด environment variable: DATABASE_URL');
  process.exit(1);
}
if (!AUTH_SECRET) {
  console.error('ขาด environment variable: AUTH_SECRET');
  process.exit(1);
}
if (!ADMIN_SECRET) {
  console.warn('ไม่ได้ตั้งค่า ADMIN_SECRET — งานประจำวันของ PVP (จับคู่/ตัดสินผล) จะเรียกใช้ไม่ได้จนกว่าจะตั้งค่านี้');
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
