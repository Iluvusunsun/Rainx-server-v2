const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const BOT_SECRET = process.env.BOT_SECRET || "rainx-bot-secret";
const SIGN_SECRET = process.env.SIGN_SECRET || "rainx-sign-secret-xyz";
const OWNER_SECRET = process.env.OWNER_SECRET || "owner-secret-123";
const MAKURO_SECRET = process.env.MAKURO_SECRET || "makuro-secret-123";
const DATA_FILE = path.join(__dirname, "data.json");

// ====== IN-MEMORY CACHE ======
let _keys = {};
let _config = {};
let _guildLicenses = {};
let _dirty = false;

function loadData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            fs.writeFileSync(DATA_FILE, JSON.stringify({ keys: {}, config: {}, guildLicenses: {} }));
        }
        const d = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
        _keys = d.keys || {};
        _config = d.config || {};
        _guildLicenses = d.guildLicenses || {};
    } catch {
        _keys = {};
        _config = {};
        _guildLicenses = {};
    }
}

function saveData() {
    _dirty = false;
    fs.writeFileSync(DATA_FILE, JSON.stringify({ keys: _keys, config: _config, guildLicenses: _guildLicenses }, null, 2));
}

setInterval(() => { if (_dirty) saveData(); }, 5000);
loadData();

const userIndex = new Map();
for (const [k, v] of Object.entries(_keys)) {
    if (v.usedBy) {
        const idxKey = `${v.usedBy}:${v.guildId || ""}:${v.file || ""}`;
        userIndex.set(idxKey, k);
    }
}

// ====== STORES ======
const sessions = new Map();
const usedSessions = new Set();
const rateLimitMap = new Map();
const activeTokens = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [id, val] of sessions.entries()) {
        if (now > val.expireAt) sessions.delete(id);
    }
    for (const [hwid, val] of rateLimitMap.entries()) {
        if (now > val.resetAt) rateLimitMap.delete(hwid);
    }
    for (const [hwid, val] of activeTokens.entries()) {
        if (now > val.expireAt) activeTokens.delete(hwid);
    }
}, 30000);

// ====== HELPERS ======
function nowSec() { return Math.floor(Date.now() / 1000); }

function isExpired(k) {
    if (k.duration === -1) return false;
    if (k.expired) return true;
    if (!k.redeemedAt || k.redeemedAt === 0) return false;
    return nowSec() >= (k.redeemedAt + k.duration);
}

function isGuildExpired(guildId) {
    const lic = _guildLicenses[guildId];
    if (!lic) return true;
    if (!lic.active) return true;
    if (lic.expiresAt === -1) return false;
    return nowSec() >= lic.expiresAt;
}

function encrypt(data, keyHex) {
    const key = Buffer.from(keyHex.slice(0, 64), "hex");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const json = JSON.stringify(data);
    let enc = cipher.update(json, "utf8", "base64");
    enc += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");
    return { d: enc, iv: iv.toString("base64"), t: tag };
}

function checkRate(hwid) {
    const now = Date.now();
    const e = rateLimitMap.get(hwid) || { count: 0, resetAt: now + 60000 };
    if (now > e.resetAt) { e.count = 0; e.resetAt = now + 60000; }
    e.count++;
    rateLimitMap.set(hwid, e);
    return e.count <= 8;
}

function botAuth(req, res, next) {
    if (req.headers["x-bot-secret"] !== BOT_SECRET)
        return res.status(403).json({ error: "forbidden" });
    next();
}

function ownerAuth(req, res, next) {
    if (req.headers["x-owner-secret"] !== OWNER_SECRET)
        return res.status(403).json({ error: "forbidden" });
    next();
}

function makuroAuth(req, res, next) {
    if (req.headers["x-makuro-secret"] !== MAKURO_SECRET)
        return res.status(403).json({ ok: false, error: "forbidden" });
    next();
}

function guard(req, res, next) {
    const { hwid } = req.body;
    if (!hwid) return res.json({ e: "bad" });
    if (!checkRate(hwid)) return res.json({ e: "rate" });
    next();
}

// ====== FAKE ENDPOINTS ======
app.post("/api/v1/auth", (req, res) => {
    res.json({ ok: true, token: crypto.randomBytes(32).toString("base64"), expires: nowSec() + 300 });
});
app.post("/api/v2/verify", (req, res) => {
    res.json({ ok: true, authorized: true });
});
app.post("/api/v3/check", (req, res) => {
    res.json({ d: crypto.randomBytes(64).toString("base64"), iv: crypto.randomBytes(12).toString("base64"), t: crypto.randomBytes(16).toString("base64"), ok: true });
});

// ====== REAL ENDPOINTS ======
app.post("/cdn-cgi/challenge", guard, (req, res) => {
    const { key, hwid, ts, nonce } = req.body;
    if (!key || !hwid || !ts || !nonce) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ e: "ts" });
    if (!/^[a-f0-9]{32}$/.test(nonce)) return res.json({ e: "bad" });
    // HWID ต้องมีความยาวสมเหตุสมผล
    if (typeof hwid !== "string" || hwid.length < 8 || hwid.length > 128) return res.json({ e: "bad" });

    const keyData = _keys[key];
    if (!keyData) return res.json({ e: "key" });
    if (isExpired(keyData)) {
        keyData.expired = true;
        _dirty = true;
        return res.json({ e: "exp" });
    }

    const sessionId = crypto.randomBytes(16).toString("hex");
    const sessionKey = crypto.randomBytes(32).toString("hex");
    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

    // Server hash HWID เอง ไม่เชื่อ fp จาก client
    const hashedHwid = crypto.createHash("sha256").update(hwid + SIGN_SECRET).digest("hex");

    // สร้าง server-side fp เอง จาก HWID + IP + nonce
    const serverFp = crypto.createHash("sha256").update(hwid + clientIp + nonce + SIGN_SECRET).digest("hex");

    sessions.set(sessionId, {
        sessionKey, key,
        hwid: hashedHwid,
        serverFp,
        nonce,
        ip: clientIp,
        expireAt: Date.now() + 15000
    });

    res.json({ s: sessionId, k: sessionKey });
});

app.post("/cdn-cgi/token", guard, (req, res) => {
    const { s, hwid, ts, nonce } = req.body;
    if (!s || !hwid || !ts || !nonce) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ e: "ts" });
    if (usedSessions.has(s)) return res.json({ e: "used" });

    const entry = sessions.get(s);
    if (!entry) return res.json({ e: "sess" });

    const reqIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

    // Server hash HWID เอง แล้วเทียบกับที่เก็บไว้ตอน challenge
    const hashedHwidToken = crypto.createHash("sha256").update(hwid + SIGN_SECRET).digest("hex");

    // เช็ค HWID hash, nonce, IP ต้องตรง — ไม่เชื่อ fp จาก client
    const expectedFp = crypto.createHash("sha256").update(hwid + reqIp + nonce + SIGN_SECRET).digest("hex");

    if (entry.hwid !== hashedHwidToken || entry.nonce !== nonce || entry.ip !== reqIp || entry.serverFp !== expectedFp)
        return res.json({ e: "bad" });

    usedSessions.add(s);
    sessions.delete(s);
    setTimeout(() => usedSessions.delete(s), 30000);

    const keyData = _keys[entry.key];
    if (!keyData) return res.json({ e: "key" });
    if (isExpired(keyData)) {
        keyData.expired = true;
        _dirty = true;
        return res.json({ e: "exp" });
    }

    if (keyData.hwid && keyData.hwid !== "" && keyData.hwid !== hashedHwidToken)
        return res.json({ e: "hwid" });

    if (!keyData.hwid || keyData.hwid === "") keyData.hwid = hashedHwidToken;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) keyData.redeemedAt = nowSec();
    keyData.active = true;
    keyData.expired = false;
    keyData.executionCount = (keyData.executionCount || 0) + 1;
    _dirty = true;

    const activeToken = crypto.randomBytes(32).toString("hex");
    activeTokens.set(hashedHwidToken, {
        token: activeToken,
        key: entry.key,
        hwid: hashedHwidToken,
        expireAt: Date.now() + 5 * 60 * 1000
    });

    const payload = { ok: true, activeToken, ts: nowSec() };
    res.json(encrypt(payload, entry.sessionKey));
});

app.post("/cdn-cgi/heartbeat", guard, (req, res) => {
    const { hwid, token, ts } = req.body;
    if (!hwid || !token || !ts) return res.json({ alive: false });
    if (Math.abs(nowSec() - ts) > 15) return res.json({ alive: false });
    // Server hash HWID เอง ไม่เชื่อ client
    const hashedHwid = crypto.createHash("sha256").update(hwid + SIGN_SECRET).digest("hex");
    const entry = activeTokens.get(hashedHwid);
    if (!entry || entry.token !== token || Date.now() > entry.expireAt)
        return res.json({ alive: false });
    entry.expireAt = Date.now() + 5 * 60 * 1000;
    res.json({ alive: true });
});

// ====== NEW: 2-round auth validate (Client เรียก) ======
app.post("/cdn-cgi/validate", (req, res) => {
    const { token, hwid, h1, h2, ts } = req.body;
    if (!token || !hwid || !h1 || !ts) return res.json({ ok: false });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ ok: false });

    // หา token จาก activeTokens
    const hashedHwid = crypto.createHash("sha256").update(hwid).digest("hex");
    const entry = activeTokens.get(hashedHwid);
    if (!entry || entry.token !== token || Date.now() > entry.expireAt)
        return res.json({ ok: false });

    // สร้าง seed แบบ random แล้วส่ง check กลับ
    const seed = crypto.randomBytes(4).readUInt32BE(0) % 99999;
    const h1Num = parseInt(h1) || 0;
    // check = customHash(h1 + seed) — ทำ simple version ฝั่ง JS
    const check = String(((h1Num + seed) * 31337 + 8410) % 99999999999);

    res.json({ ok: true, seed, check });
});

// ====== NEW: Makuro token validation ======
// Makuro server เรียก endpoint นี้เพื่อเช็คว่า token valid ไหมก่อนส่ง raw content
app.post("/cdn-cgi/validate-token", makuroAuth, (req, res) => {
    const { token } = req.body;
    if (!token) return res.json({ ok: false });

    // หา token จาก activeTokens ทั้งหมด
    for (const [hwid, entry] of activeTokens.entries()) {
        if (entry.token === token) {
            if (Date.now() > entry.expireAt) {
                activeTokens.delete(hwid);
                return res.json({ ok: false, reason: "expired" });
            }
            return res.json({ ok: true });
        }
    }
    return res.json({ ok: false, reason: "invalid" });
});

// ====== BOT ENDPOINTS ======
app.post("/keys/generate", botAuth, (req, res) => {
    const { duration, amount, file } = req.body;
    const keys = [];
    for (let i = 0; i < Math.min(amount || 1, 50); i++) {
        const key = crypto.randomBytes(16).toString("hex");
        _keys[key] = {
            active: false, expired: false, duration: duration ?? -1,
            executionCount: 0, hwid: "", guildId: "",
            file: file || null, // null = ใช้ได้ทุกไฟล์
            createdAt: nowSec(), redeemedAt: 0, lastHwidReset: 0
        };
        keys.push(key);
    }
    _dirty = true;
    res.json({ ok: true, keys });
});

app.delete("/keys/:key", botAuth, (req, res) => {
    if (!_keys[req.params.key]) return res.status(404).json({ ok: false });
    const kd = _keys[req.params.key];
    if (kd.usedBy) {
        userIndex.delete(`${kd.usedBy}:${kd.guildId || ""}:${kd.file || ""}`);
        userIndex.delete(`${kd.usedBy}:${kd.guildId || ""}:`);
        userIndex.delete(`${kd.usedBy}::`);
    }
    delete _keys[req.params.key];
    _dirty = true;
    res.json({ ok: true });
});

app.get("/keys/:key", botAuth, (req, res) => {
    const kd = _keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: req.params.key, data: kd });
});

app.get("/keys", botAuth, (req, res) => {
    res.json({ ok: true, keys: _keys });
});

app.post("/keys/:key/reset-hwid", botAuth, (req, res) => {
    const kd = _keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false });
    kd.hwid = "";
    kd.lastHwidReset = nowSec();
    _dirty = true;
    res.json({ ok: true });
});

app.get("/keys/user/:userId", botAuth, (req, res) => {
    const guildId = req.query.guildId || "";
    const file = req.query.file || "";
    const uid = req.params.userId;

    // ลอง fallback หลายชั้น
    const attempts = [
        `${uid}:${guildId}:${file}`,  // exact match
        `${uid}:${guildId}:`,          // same guild, no file lock
        `${uid}::${file}`,             // any guild, same file
        `${uid}::`,                    // any guild, no file lock
    ];

    let key = null;
    for (const attempt of attempts) {
        const k = userIndex.get(attempt);
        if (k && _keys[k]) { key = k; break; }
    }

    // ถ้ายังไม่เจอ scan ทั้งหมด (กรณี legacy data)
    if (!key) {
        for (const [k, v] of Object.entries(_keys)) {
            if (v.usedBy === uid && (!guildId || !v.guildId || v.guildId === guildId)) {
                key = k;
                break;
            }
        }
    }

    if (!key || !_keys[key]) return res.status(404).json({ ok: false });
    res.json({ ok: true, key, data: _keys[key] });
});

app.post("/keys/:key/redeem", botAuth, (req, res) => {
    const { userId, guildId } = req.body;
    const kd = _keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false, reason: "Key ไม่ถูกต้อง" });
    if (isExpired(kd)) {
        kd.expired = true; _dirty = true;
        return res.json({ ok: false, reason: "Key หมดอายุแล้ว" });
    }
    if (kd.usedBy && kd.usedBy !== "" && kd.usedBy !== userId)
        return res.json({ ok: false, reason: "Key used by someone else" });
    if (kd.usedBy === userId)
        return res.json({ ok: false, reason: "Already redeemed" });
    // เช็ค guild lock - ถ้า key ถูก redeem ใน guild อื่นแล้วห้ามใช้
    if (kd.guildId && kd.guildId !== "" && guildId && kd.guildId !== guildId)
        return res.json({ ok: false, reason: "Key used in another guild" });
    kd.usedBy = userId;
    kd.guildId = guildId || "";
    kd.active = true;
    if (!kd.redeemedAt || kd.redeemedAt === 0) kd.redeemedAt = nowSec();
    const idxKey = `${userId}:${guildId || ""}:${kd.file || ""}`;
    userIndex.set(idxKey, req.params.key);
    _dirty = true;
    res.json({ ok: true, duration: kd.duration, file: kd.file || null });
});

app.post("/config", botAuth, (req, res) => {
    _config = { ..._config, ...req.body };
    _dirty = true;
    res.json({ ok: true });
});

app.get("/config", botAuth, (req, res) => {
    res.json({ ok: true, config: _config });
});

// ====== GUILD LICENSE ENDPOINTS ======
app.get("/guild/check/:guildId", botAuth, (req, res) => {
    const guildId = req.params.guildId;
    const expired = isGuildExpired(guildId);
    const lic = _guildLicenses[guildId];
    res.json({
        ok: !expired,
        expired,
        expiresAt: lic?.expiresAt || null,
        note: lic?.note || ""
    });
});

app.post("/guild/license", ownerAuth, (req, res) => {
    const { guildId, days, note } = req.body;
    if (!guildId) return res.status(400).json({ ok: false, error: "no guildId" });
    const duration = days === 0 ? -1 : (days || 30) * 86400;
    const expiresAt = duration === -1 ? -1 : nowSec() + duration;
    _guildLicenses[guildId] = {
        guildId, expiresAt,
        note: note || "",
        active: true,
        createdAt: nowSec()
    };
    _dirty = true;
    res.json({ ok: true, guildId, expiresAt, days: days || 30 });
});

app.post("/guild/renew", ownerAuth, (req, res) => {
    const { guildId, days } = req.body;
    if (!guildId) return res.status(400).json({ ok: false, error: "no guildId" });
    const lic = _guildLicenses[guildId];
    if (!lic) return res.status(404).json({ ok: false, error: "not found" });
    const addSec = (days || 30) * 86400;
    const base = lic.expiresAt === -1 ? nowSec() : Math.max(lic.expiresAt, nowSec());
    lic.expiresAt = base + addSec;
    lic.active = true;
    _dirty = true;
    res.json({ ok: true, guildId, expiresAt: lic.expiresAt });
});

app.delete("/guild/license/:guildId", ownerAuth, (req, res) => {
    if (!_guildLicenses[req.params.guildId])
        return res.status(404).json({ ok: false });
    delete _guildLicenses[req.params.guildId];
    _dirty = true;
    res.json({ ok: true });
});

app.get("/guild/licenses", ownerAuth, (req, res) => {
    res.json({ ok: true, licenses: _guildLicenses });
});

app.get("/ping", (req, res) => res.send("pong"));
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
