const express = require("express");
const { PrismaClient } = require("@prisma/client");
const crypto = require("crypto");
const path = require("path");

const prisma = new PrismaClient();
const app = express();

const PORT = process.env.PORT || 3000;
const BOT_SECRET = process.env.BOT_SECRET || "rainx-bot-secret";
const SIGN_SECRET = process.env.SIGN_SECRET || "rainx-sign-secret-xyz";
const OWNER_SECRET = process.env.OWNER_SECRET || "owner-secret-123";
const MAKURO_SECRET = process.env.MAKURO_SECRET || "makuro-secret-123";

// ====== SECURITY HEADERS ======
app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    next();
});

// ====== REQUEST SIZE LIMIT ======
app.use(express.json({ limit: "16kb" }));

// ====== RATE LIMIT PER IP ======
const ipRateMap = new Map();
function checkIpRate(ip) {
    const now = Date.now();
    const e = ipRateMap.get(ip) || { count: 0, resetAt: now + 60000 };
    if (now > e.resetAt) { e.count = 0; e.resetAt = now + 60000; }
    e.count++;
    ipRateMap.set(ip, e);
    return e.count <= 30;
}
app.use((req, res, next) => {
    const ip = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;
    if (!checkIpRate(ip)) return res.status(429).json({ e: "rate_ip" });
    next();
});

// ====== STORES ======
const sessions = new Map();
const usedSessions = new Set();
const rateLimitMap = new Map();
const activeTokens = new Map();
const usedNonces = new Set();
const suspiciousLog = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [id, val] of sessions.entries()) if (now > val.expireAt) sessions.delete(id);
    for (const [hwid, val] of rateLimitMap.entries()) if (now > val.resetAt) rateLimitMap.delete(hwid);
    for (const [hwid, val] of activeTokens.entries()) if (now > val.expireAt) activeTokens.delete(hwid);
    for (const [ip, val] of ipRateMap.entries()) if (now > val.resetAt) ipRateMap.delete(ip);
}, 30000);

setInterval(() => { if (usedNonces.size > 10000) usedNonces.clear(); }, 300000);

// ====== KEY EXPIRY AUTO-CLEANUP ======
setInterval(async () => {
    try {
        const keys = await prisma.key.findMany({
            where: { expired: false, duration: { not: -1 }, redeemedAt: { not: 0 } }
        });
        for (const k of keys) {
            if (nowSec() >= k.redeemedAt + k.duration) {
                await prisma.key.update({ where: { key: k.key }, data: { expired: true } });
            }
        }
    } catch {}
}, 60000);

// ====== HELPERS ======
function nowSec() { return Math.floor(Date.now() / 1000); }

function hashHwid(hwid) {
    return crypto.createHash("sha256").update(hwid + SIGN_SECRET).digest("hex");
}
function serverFp(hwid, ip, nonce) {
    return crypto.createHash("sha256").update(hwid + ip + nonce + SIGN_SECRET).digest("hex");
}
function encrypt(data, keyHex) {
    const key = Buffer.from(keyHex.slice(0, 64), "hex");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    let enc = cipher.update(JSON.stringify(data), "utf8", "base64");
    enc += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");
    return { d: enc, iv: iv.toString("base64"), t: tag };
}
function verifyHmac(payload, signature, secret) {
    if (!payload || !signature) return false;
    const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
    try { return crypto.timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex")); }
    catch { return false; }
}
function checkRate(hwid) {
    const now = Date.now();
    const e = rateLimitMap.get(hwid) || { count: 0, resetAt: now + 60000 };
    if (now > e.resetAt) { e.count = 0; e.resetAt = now + 60000; }
    e.count++;
    rateLimitMap.set(hwid, e);
    return e.count <= 8;
}
function logSuspicious(ip, reason) {
    const entry = suspiciousLog.get(ip) || { count: 0, reasons: [], firstAt: Date.now() };
    entry.count++;
    entry.reasons.push(reason);
    suspiciousLog.set(ip, entry);
    if (entry.count >= 5) console.warn(`[SUSPICIOUS] IP: ${ip} | Count: ${entry.count} | Reasons: ${entry.reasons.slice(-3).join(", ")}`);
}

function isExpiredData(k) {
    if (k.duration === -1) return false;
    if (k.expired) return true;
    if (!k.redeemedAt || k.redeemedAt === 0) return false;
    return nowSec() >= (k.redeemedAt + k.duration);
}
function isGuildExpiredData(lic) {
    if (!lic || !lic.active) return true;
    if (lic.expiresAt === -1) return false;
    return nowSec() >= lic.expiresAt;
}

// ====== AUTH MIDDLEWARE ======
function botAuth(req, res, next) {
    if (req.headers["x-bot-secret"] !== BOT_SECRET) return res.status(403).json({ error: "forbidden" });
    next();
}
function ownerAuth(req, res, next) {
    if (req.headers["x-owner-secret"] !== OWNER_SECRET) return res.status(403).json({ error: "forbidden" });
    next();
}
function makuroAuth(req, res, next) {
    if (req.headers["x-makuro-secret"] !== MAKURO_SECRET) return res.status(403).json({ ok: false, error: "forbidden" });
    next();
}
function guard(req, res, next) {
    const { hwid } = req.body;
    if (!hwid) return res.json({ e: "bad" });
    if (!checkRate(hwid)) return res.json({ e: "rate" });
    next();
}

// ====== FAKE ENDPOINTS ======
app.post("/api/v1/auth", (req, res) => res.json({ ok: true, token: crypto.randomBytes(32).toString("base64"), expires: nowSec() + 300 }));
app.post("/api/v2/verify", (req, res) => res.json({ ok: true, authorized: true }));
app.post("/api/v3/check", (req, res) => res.json({ d: crypto.randomBytes(64).toString("base64"), iv: crypto.randomBytes(12).toString("base64"), t: crypto.randomBytes(16).toString("base64"), ok: true }));
app.post("/api/v4/session", (req, res) => res.json({ ok: true, session: crypto.randomBytes(16).toString("hex"), ts: nowSec() }));
app.post("/api/v5/ping", (req, res) => res.json({ pong: true, ts: nowSec() }));
app.get("/api/status", (req, res) => res.json({ status: "ok", uptime: process.uptime() }));

// ====== REAL ENDPOINTS ======
app.post("/cdn-cgi/challenge", guard, async (req, res) => {
    const { key, hwid, ts, nonce } = req.body;
    if (!key || !hwid || !ts || !nonce) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ e: "ts" });
    if (!/^[a-f0-9]{32}$/.test(nonce)) return res.json({ e: "bad" });
    if (typeof hwid !== "string" || hwid.length < 8 || hwid.length > 128) return res.json({ e: "bad" });

    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;

    if (usedNonces.has(nonce)) { logSuspicious(clientIp, "replay_nonce"); return res.json({ e: "replay" }); }
    usedNonces.add(nonce);

    const keyData = await prisma.key.findUnique({ where: { key } }).catch(() => null);
    if (!keyData) { logSuspicious(clientIp, "invalid_key"); return res.json({ e: "key" }); }
    if (isExpiredData(keyData)) {
        await prisma.key.update({ where: { key }, data: { expired: true } }).catch(() => {});
        return res.json({ e: "exp" });
    }

    const sessionId = crypto.randomBytes(16).toString("hex");
    const sessionKey = crypto.randomBytes(32).toString("hex");
    const hashedHwid = hashHwid(hwid);
    const fp = serverFp(hwid, clientIp, nonce);

    sessions.set(sessionId, { sessionKey, key, hwid: hashedHwid, serverFp: fp, nonce, ip: clientIp, expireAt: Date.now() + 15000 });

    const responsePayload = sessionId + ":" + sessionKey + ":" + nowSec();
    const responseSig = crypto.createHmac("sha256", SIGN_SECRET).update(responsePayload).digest("hex");
    res.json({ s: sessionId, k: sessionKey, sig: responseSig });
});

app.post("/cdn-cgi/token", guard, async (req, res) => {
    const { s, hwid, ts, nonce } = req.body;
    if (!s || !hwid || !ts || !nonce) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ e: "ts" });
    if (usedSessions.has(s)) return res.json({ e: "used" });

    const entry = sessions.get(s);
    if (!entry) return res.json({ e: "sess" });

    const reqIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;
    const hashedHwidToken = hashHwid(hwid);
    const expectedFp = serverFp(hwid, reqIp, nonce);

    if (entry.hwid !== hashedHwidToken || entry.nonce !== nonce || entry.ip !== reqIp || entry.serverFp !== expectedFp) {
        logSuspicious(reqIp, "fp_mismatch");
        return res.json({ e: "bad" });
    }

    usedSessions.add(s);
    sessions.delete(s);
    setTimeout(() => usedSessions.delete(s), 30000);

    const keyData = await prisma.key.findUnique({ where: { key: entry.key } }).catch(() => null);
    if (!keyData) return res.json({ e: "key" });
    if (isExpiredData(keyData)) {
        await prisma.key.update({ where: { key: entry.key }, data: { expired: true } }).catch(() => {});
        return res.json({ e: "exp" });
    }
    if (keyData.hwid && keyData.hwid !== "" && keyData.hwid !== hashedHwidToken) {
        logSuspicious(reqIp, "hwid_mismatch");
        return res.json({ e: "hwid" });
    }

    await prisma.key.update({
        where: { key: entry.key },
        data: {
            hwid: hashedHwidToken,
            redeemedAt: keyData.redeemedAt === 0 ? nowSec() : keyData.redeemedAt,
            active: true, expired: false,
            executionCount: { increment: 1 }
        }
    }).catch(() => {});

    const activeToken = crypto.randomBytes(32).toString("hex");
    activeTokens.set(hashedHwidToken, { token: activeToken, key: entry.key, hwid: hashedHwidToken, expireAt: Date.now() + 5 * 60 * 1000 });

    const payload = { ok: true, activeToken, ts: nowSec() };
    res.json(encrypt(payload, entry.sessionKey));
});

app.post("/cdn-cgi/heartbeat", guard, (req, res) => {
    const { hwid, token, ts, ping } = req.body;
    if (!hwid || !token || !ts) return res.json({ alive: false });
    if (Math.abs(nowSec() - ts) > 15) return res.json({ alive: false });

    const hashedHwid = hashHwid(hwid);
    const entry = activeTokens.get(hashedHwid);
    if (!entry || entry.token !== token || Date.now() > entry.expireAt) return res.json({ alive: false });

    entry.expireAt = Date.now() + 5 * 60 * 1000;
    const seed = Math.floor(Math.random() * 99999);
    const responseCheck = String(((parseInt(ping) || 0) + seed) * 31337 + 8410) % 99999999999;
    res.json({ alive: true, seed, check: String(responseCheck) });
});

app.post("/cdn-cgi/validate", (req, res) => {
    const { token, hwid, h1, ts } = req.body;
    if (!token || !hwid || !h1 || !ts) return res.json({ ok: false });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ ok: false });
    const hashedHwid = crypto.createHash("sha256").update(hwid).digest("hex");
    const entry = activeTokens.get(hashedHwid);
    if (!entry || entry.token !== token || Date.now() > entry.expireAt) return res.json({ ok: false });
    const seed = crypto.randomBytes(4).readUInt32BE(0) % 99999;
    const h1Num = parseInt(h1) || 0;
    const check = String(((h1Num + seed) * 31337 + 8410) % 99999999999);
    res.json({ ok: true, seed, check });
});

app.post("/cdn-cgi/validate-token", makuroAuth, (req, res) => {
    const { token } = req.body;
    if (!token) return res.json({ ok: false });
    for (const [hwid, entry] of activeTokens.entries()) {
        if (entry.token === token) {
            if (Date.now() > entry.expireAt) { activeTokens.delete(hwid); return res.json({ ok: false, reason: "expired" }); }
            return res.json({ ok: true });
        }
    }
    return res.json({ ok: false, reason: "invalid" });
});

// ====== BOT ENDPOINTS ======
app.post("/keys/generate", botAuth, async (req, res) => {
    const { duration, amount, file } = req.body;
    const keys = [];
    for (let i = 0; i < Math.min(amount || 1, 50); i++) {
        const key = crypto.randomBytes(16).toString("hex");
        await prisma.key.create({
            data: { key, active: false, expired: false, duration: duration ?? -1, executionCount: 0, hwid: "", guildId: "", file: file || null, createdAt: nowSec(), redeemedAt: 0, lastHwidReset: 0 }
        }).catch(() => {});
        keys.push(key);
    }
    res.json({ ok: true, keys });
});

app.delete("/keys/:key", botAuth, async (req, res) => {
    const deleted = await prisma.key.delete({ where: { key: req.params.key } }).catch(() => null);
    if (!deleted) return res.status(404).json({ ok: false });
    res.json({ ok: true });
});

app.get("/keys/:key", botAuth, async (req, res) => {
    const kd = await prisma.key.findUnique({ where: { key: req.params.key } }).catch(() => null);
    if (!kd) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: req.params.key, data: kd });
});

app.get("/keys", botAuth, async (req, res) => {
    const keys = await prisma.key.findMany().catch(() => []);
    const keysObj = {};
    keys.forEach(k => { keysObj[k.key] = k; });
    res.json({ ok: true, keys: keysObj });
});

app.post("/keys/:key/reset-hwid", botAuth, async (req, res) => {
    const updated = await prisma.key.update({ where: { key: req.params.key }, data: { hwid: "", lastHwidReset: nowSec() } }).catch(() => null);
    if (!updated) return res.status(404).json({ ok: false });
    res.json({ ok: true });
});

app.get("/keys/user/:userId", botAuth, async (req, res) => {
    const { guildId = "", file = "" } = req.query;
    const uid = req.params.userId;
    let kd = await prisma.key.findFirst({ where: { usedBy: uid, ...(guildId ? { guildId } : {}) } }).catch(() => null);
    if (!kd) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: kd.key, data: kd });
});

app.post("/keys/:key/redeem", botAuth, async (req, res) => {
    const { userId, guildId } = req.body;
    const kd = await prisma.key.findUnique({ where: { key: req.params.key } }).catch(() => null);
    if (!kd) return res.status(404).json({ ok: false, reason: "Key ไม่ถูกต้อง" });
    if (isExpiredData(kd)) {
        await prisma.key.update({ where: { key: req.params.key }, data: { expired: true } }).catch(() => {});
        return res.json({ ok: false, reason: "Key หมดอายุแล้ว" });
    }
    if (kd.usedBy && kd.usedBy !== "" && kd.usedBy !== userId) return res.json({ ok: false, reason: "Key used by someone else" });
    if (kd.usedBy === userId) return res.json({ ok: false, reason: "Already redeemed" });
    if (kd.guildId && kd.guildId !== "" && guildId && kd.guildId !== guildId) return res.json({ ok: false, reason: "Key used in another guild" });
    await prisma.key.update({
        where: { key: req.params.key },
        data: { usedBy: userId, guildId: guildId || "", active: true, redeemedAt: kd.redeemedAt === 0 ? nowSec() : kd.redeemedAt }
    }).catch(() => {});
    res.json({ ok: true, duration: kd.duration, file: kd.file || null });
});

app.post("/config", botAuth, async (req, res) => {
    const { key, ...rest } = req.body;
    for (const [k, v] of Object.entries(req.body)) {
        await prisma.config.upsert({
            where: { key: k },
            create: { key: k, value: JSON.stringify(v) },
            update: { value: JSON.stringify(v) }
        }).catch(() => {});
    }
    res.json({ ok: true });
});

app.get("/config", botAuth, async (req, res) => {
    const rows = await prisma.config.findMany().catch(() => []);
    const config = {};
    rows.forEach(r => { try { config[r.key] = JSON.parse(r.value); } catch { config[r.key] = r.value; } });
    res.json({ ok: true, config });
});

// ====== GUILD LICENSE ENDPOINTS ======
app.get("/guild/check/:guildId", botAuth, async (req, res) => {
    const lic = await prisma.guildLicense.findUnique({ where: { guildId: req.params.guildId } }).catch(() => null);
    const expired = isGuildExpiredData(lic);
    res.json({ ok: !expired, expired, expiresAt: lic?.expiresAt || null, note: lic?.note || "" });
});

app.post("/guild/license", ownerAuth, async (req, res) => {
    const { guildId, days, note } = req.body;
    if (!guildId) return res.status(400).json({ ok: false, error: "no guildId" });
    const duration = days === 0 ? -1 : (days || 30) * 86400;
    const expiresAt = duration === -1 ? -1 : nowSec() + duration;
    await prisma.guildLicense.upsert({
        where: { guildId },
        create: { guildId, expiresAt, note: note || "", active: true, createdAt: nowSec() },
        update: { expiresAt, note: note || "", active: true }
    }).catch(() => {});
    res.json({ ok: true, guildId, expiresAt, days: days || 30 });
});

app.post("/guild/renew", ownerAuth, async (req, res) => {
    const { guildId, days } = req.body;
    if (!guildId) return res.status(400).json({ ok: false, error: "no guildId" });
    const lic = await prisma.guildLicense.findUnique({ where: { guildId } }).catch(() => null);
    if (!lic) return res.status(404).json({ ok: false, error: "not found" });
    const addSec = (days || 30) * 86400;
    const base = lic.expiresAt === -1 ? nowSec() : Math.max(lic.expiresAt, nowSec());
    const expiresAt = base + addSec;
    await prisma.guildLicense.update({ where: { guildId }, data: { expiresAt, active: true } }).catch(() => {});
    res.json({ ok: true, guildId, expiresAt });
});

app.delete("/guild/license/:guildId", ownerAuth, async (req, res) => {
    const deleted = await prisma.guildLicense.delete({ where: { guildId: req.params.guildId } }).catch(() => null);
    if (!deleted) return res.status(404).json({ ok: false });
    res.json({ ok: true });
});

app.get("/guild/licenses", ownerAuth, async (req, res) => {
    const licenses = await prisma.guildLicense.findMany().catch(() => []);
    res.json({ ok: true, licenses });
});

app.get("/ping", (req, res) => res.send("pong"));
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
