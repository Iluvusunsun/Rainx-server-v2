const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const BOT_SECRET = process.env.BOT_SECRET || "rainx-bot-secret";
const SIGN_SECRET = process.env.SIGN_SECRET || "rainx-sign-secret-xyz";
const DATA_FILE = path.join(__dirname, "data.json");

// ====== STORES ======
const challenges = new Map();      // challengeId -> entry
const usedChallenges = new Set();  // used challengeIds
const rateLimitMap = new Map();    // hwid -> { count, resetAt }
const bannedHwids = new Set();     // banned hwids
const suspiciousMap = new Map();   // hwid -> strike count

const RATE_LIMIT = 10;             // max 10 requests per minute per hwid
const MAX_STRIKES = 3;             // โดน ban หลัง 3 strikes

// cleanup every 60s
setInterval(() => {
    const now = Date.now();
    for (const [id, val] of challenges.entries()) {
        if (now > val.expireAt) challenges.delete(id);
    }
    for (const [hwid, val] of rateLimitMap.entries()) {
        if (now > val.resetAt) rateLimitMap.delete(hwid);
    }
}, 60000);

// ====== HELPERS ======
function loadData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            fs.writeFileSync(DATA_FILE, JSON.stringify({ keys: {}, config: {}, bannedHwids: [] }));
        }
        const d = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
        // restore banned hwids
        if (d.bannedHwids) d.bannedHwids.forEach(h => bannedHwids.add(h));
        return d;
    } catch {
        return { keys: {}, config: {}, bannedHwids: [] };
    }
}

function saveData(data) {
    data.bannedHwids = [...bannedHwids];
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function nowSec() { return Math.floor(Date.now() / 1000); }

function isExpired(keyData) {
    if (keyData.duration === -1) return false;
    if (keyData.expired === true) return true;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) return false;
    return nowSec() >= (keyData.redeemedAt + keyData.duration);
}

function signPayload(payload) {
    return crypto.createHmac("sha256", SIGN_SECRET)
        .update(JSON.stringify(payload)).digest("hex");
}

function makeSignedResponse(data) {
    const payload = { ...data, ts: nowSec() };
    payload.sig = signPayload({ ...data, ts: payload.ts });
    return payload;
}

function addStrike(hwid) {
    const strikes = (suspiciousMap.get(hwid) || 0) + 1;
    suspiciousMap.set(hwid, strikes);
    if (strikes >= MAX_STRIKES) {
        bannedHwids.add(hwid);
        const data = loadData();
        saveData(data);
        console.log(`🔨 Banned HWID: ${hwid}`);
    }
    return strikes;
}

function checkRateLimit(hwid) {
    const now = Date.now();
    const entry = rateLimitMap.get(hwid) || { count: 0, resetAt: now + 60000 };
    if (now > entry.resetAt) {
        entry.count = 0;
        entry.resetAt = now + 60000;
    }
    entry.count++;
    rateLimitMap.set(hwid, entry);
    return entry.count <= RATE_LIMIT;
}

function botAuth(req, res, next) {
    if (req.headers["x-bot-secret"] !== BOT_SECRET)
        return res.status(403).json({ error: "forbidden" });
    next();
}

// ====== LUA MIDDLEWARE ======
function luaGuard(req, res, next) {
    const hwid = req.body?.hwid;
    if (!hwid) return res.json(makeSignedResponse({ ok: false, reason: "โง่:>" }));

    // banned check
    if (bannedHwids.has(hwid))
        return res.json(makeSignedResponse({ ok: false, reason: "โดน ban แล้วนะโง่:>" }));

    // rate limit
    if (!checkRateLimit(hwid)) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:> spam เหรอ" }));
    }

    // content-type check
    if (!req.headers["content-type"]?.includes("application/json")) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:>" }));
    }

    // ห้ามมี header แปลกๆ ที่ httpspy มักใส่มา
    const suspiciousHeaders = ["x-debug", "x-proxy", "x-forwarded-host", "via"];
    for (const h of suspiciousHeaders) {
        if (req.headers[h]) {
            addStrike(hwid);
            return res.json(makeSignedResponse({ ok: false, reason: "โง่:>" }));
        }
    }

    next();
}

// ====== STEP 1: challenge ======
app.post("/challenge", luaGuard, (req, res) => {
    const { key, hwid, ts, nonce } = req.body;
    if (!key || !hwid || !ts || !nonce)
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:>" }));

    // timestamp window 10 วินาที
    if (Math.abs(nowSec() - ts) > 10) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:> ช้าเกิน" }));
    }

    // nonce ต้องเป็น hex 32 chars
    if (!/^[a-f0-9]{32}$/.test(nonce)) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:>" }));
    }

    const data = loadData();
    const keyData = data.keys[key];
    if (!keyData) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:> key ผิด" }));
    }
    if (isExpired(keyData)) {
        keyData.expired = true;
        saveData(data);
        return res.json(makeSignedResponse({ ok: false, reason: "Key หมดอายุแล้ว" }));
    }

    const challengeId = crypto.randomBytes(16).toString("hex");
    const challenge = crypto.randomBytes(32).toString("hex");

    challenges.set(challengeId, {
        challenge, key, hwid, nonce,
        expireAt: Date.now() + 15000  // 15 วินาทีเท่านั้น
    });

    res.json(makeSignedResponse({ ok: true, challengeId, challenge }));
});

// ====== STEP 2: verify ======
app.post("/verify", luaGuard, (req, res) => {
    const { challengeId, hwid, ts, answer } = req.body;
    if (!challengeId || !hwid || !ts || !answer)
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:>" }));

    // timestamp window 10 วินาที
    if (Math.abs(nowSec() - ts) > 10) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:> ช้าเกิน" }));
    }

    if (usedChallenges.has(challengeId)) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:> replay" }));
    }

    const entry = challenges.get(challengeId);
    if (!entry) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:> challenge หมดแล้ว" }));
    }

    if (entry.hwid !== hwid) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:>" }));
    }

    // เช็ค answer = HMAC(challenge + nonce + hwid)
    const expectedAnswer = crypto.createHmac("sha256", entry.challenge)
        .update(`${entry.nonce}:${hwid}:${ts}`)
        .digest("hex");
    const expectedAnswerB64 = crypto.createHmac("sha256", entry.challenge)
        .update(`${entry.nonce}:${hwid}:${ts}`)
        .digest("base64");

    if (answer !== expectedAnswer && answer !== expectedAnswerB64) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "โง่:> answer ผิด" }));
    }

    usedChallenges.add(challengeId);
    challenges.delete(challengeId);
    setTimeout(() => usedChallenges.delete(challengeId), 30000);

    const data = loadData();
    const keyData = data.keys[entry.key];
    if (!keyData) return res.json(makeSignedResponse({ ok: false, reason: "โง่:> key หาย" }));
    if (isExpired(keyData)) {
        keyData.expired = true;
        saveData(data);
        return res.json(makeSignedResponse({ ok: false, reason: "Key หมดอายุแล้ว" }));
    }

    const hashedHwid = crypto.createHash("sha256").update(hwid).digest("hex");
    if (keyData.hwid && keyData.hwid !== "" && keyData.hwid !== hashedHwid) {
        addStrike(hwid);
        return res.json(makeSignedResponse({ ok: false, reason: "reset hwid ก่อนน่ะโง่:>" }));
    }

    if (!keyData.hwid || keyData.hwid === "") keyData.hwid = hashedHwid;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) keyData.redeemedAt = nowSec();
    keyData.active = true;
    keyData.expired = false;
    keyData.executionCount = (keyData.executionCount || 0) + 1;
    saveData(data);

    return res.json(makeSignedResponse({ ok: true, scriptUrl: data.config.scriptUrl || null }));
});

// ====== BOT ENDPOINTS ======
app.post("/keys/generate", botAuth, (req, res) => {
    const { duration, amount } = req.body;
    const data = loadData();
    const keys = [];
    for (let i = 0; i < (amount || 1); i++) {
        const key = crypto.randomBytes(16).toString("hex");
        data.keys[key] = {
            active: false, expired: false, duration: duration ?? -1,
            executionCount: 0, hwid: "", createdAt: nowSec(), redeemedAt: 0, lastHwidReset: 0
        };
        keys.push(key);
    }
    saveData(data);
    res.json({ ok: true, keys });
});

app.delete("/keys/:key", botAuth, (req, res) => {
    const data = loadData();
    if (!data.keys[req.params.key]) return res.status(404).json({ ok: false });
    delete data.keys[req.params.key];
    saveData(data);
    res.json({ ok: true });
});

app.get("/keys/:key", botAuth, (req, res) => {
    const data = loadData();
    const keyData = data.keys[req.params.key];
    if (!keyData) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: req.params.key, data: keyData });
});

app.get("/keys", botAuth, (req, res) => {
    const data = loadData();
    res.json({ ok: true, keys: data.keys });
});

app.post("/keys/:key/reset-hwid", botAuth, (req, res) => {
    const data = loadData();
    const keyData = data.keys[req.params.key];
    if (!keyData) return res.status(404).json({ ok: false });
    keyData.hwid = "";
    keyData.lastHwidReset = nowSec();
    saveData(data);
    res.json({ ok: true });
});

app.get("/keys/user/:userId", botAuth, (req, res) => {
    const data = loadData();
    const entry = Object.entries(data.keys).find(([, v]) => v.usedBy === req.params.userId);
    if (!entry) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: entry[0], data: entry[1] });
});

app.post("/keys/:key/redeem", botAuth, (req, res) => {
    const { userId } = req.body;
    const data = loadData();
    const keyData = data.keys[req.params.key];
    if (!keyData) return res.status(404).json({ ok: false, reason: "Key ไม่ถูกต้อง" });
    if (isExpired(keyData)) {
        keyData.expired = true;
        saveData(data);
        return res.json({ ok: false, reason: "Key หมดอายุแล้ว" });
    }
    if (keyData.usedBy && keyData.usedBy !== "" && keyData.usedBy !== userId)
        return res.json({ ok: false, reason: "Key used by someone else" });
    if (keyData.usedBy === userId)
        return res.json({ ok: false, reason: "Already redeemed" });
    keyData.usedBy = userId;
    keyData.active = true;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) keyData.redeemedAt = nowSec();
    saveData(data);
    res.json({ ok: true, duration: keyData.duration });
});

app.post("/config", botAuth, (req, res) => {
    const data = loadData();
    data.config = { ...data.config, ...req.body };
    saveData(data);
    res.json({ ok: true });
});

app.get("/config", botAuth, (req, res) => {
    const data = loadData();
    res.json({ ok: true, config: data.config });
});

// ban/unban hwid
app.post("/ban/:hwid", botAuth, (req, res) => {
    bannedHwids.add(req.params.hwid);
    const data = loadData();
    saveData(data);
    res.json({ ok: true });
});

app.delete("/ban/:hwid", botAuth, (req, res) => {
    bannedHwids.delete(req.params.hwid);
    suspiciousMap.delete(req.params.hwid);
    const data = loadData();
    saveData(data);
    res.json({ ok: true });
});

app.get("/ping", (req, res) => res.send("pong"));

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
