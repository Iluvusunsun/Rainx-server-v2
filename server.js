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
const sessions = new Map();       // sessionId -> entry
const usedSessions = new Set();   // used sessionIds
const rateLimitMap = new Map();   // hwid -> { count, resetAt }

const RATE_LIMIT = 8;
setInterval(() => {
    const now = Date.now();
    for (const [id, val] of sessions.entries()) {
        if (now > val.expireAt) sessions.delete(id);
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
        return d;
    } catch { return { keys: {}, config: {}, bannedHwids: [] }; }
}

function saveData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function nowSec() { return Math.floor(Date.now() / 1000); }

function isExpired(k) {
    if (k.duration === -1) return false;
    if (k.expired) return true;
    if (!k.redeemedAt || k.redeemedAt === 0) return false;
    return nowSec() >= (k.redeemedAt + k.duration);
}

// เข้ารหัส response ด้วย AES-256-GCM
function encryptResponse(data, sessionKey) {
    const key = Buffer.from(sessionKey, "hex");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const json = JSON.stringify(data);
    let enc = cipher.update(json, "utf8", "base64");
    enc += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");
    return {
        d: enc,
        iv: iv.toString("base64"),
        t: tag
    };
}

function checkRate(hwid) {
    const now = Date.now();
    const e = rateLimitMap.get(hwid) || { count: 0, resetAt: now + 60000 };
    if (now > e.resetAt) { e.count = 0; e.resetAt = now + 60000; }
    e.count++;
    rateLimitMap.set(hwid, e);
    return e.count <= RATE_LIMIT;
}

function botAuth(req, res, next) {
    if (req.headers["x-bot-secret"] !== BOT_SECRET)
        return res.status(403).json({ error: "forbidden" });
    next();
}

// ====== GUARD MIDDLEWARE ======
function guard(req, res, next) {
    const { hwid } = req.body;
    if (!hwid) return res.json({ e: "bad" });
    if (!checkRate(hwid)) {
        return res.json({ e: "rate" });
    }
    const suspicious = ["x-debug", "x-proxy", "via", "x-forwarded-host"];
    for (const h of suspicious) {
        if (req.headers[h]) {
            return res.json({ e: "bad" });
        }
    }
    next();
}

// ====== STEP 1: init session ======
// endpoint ชื่อแปลก ดูเหมือน Cloudflare
app.post("/cdn-cgi/challenge", guard, (req, res) => {
    const { key, hwid, ts, nonce } = req.body;
    if (!key || !hwid || !ts || !nonce) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) {
        return res.json({ e: "ts" });
    }
    if (!/^[a-f0-9]{32}$/.test(nonce)) {
        return res.json({ e: "bad" });
    }

    const data = loadData();
    const keyData = data.keys[key];
    if (!keyData) { addStrike(hwid); return res.json({ e: "key" }); }
    if (isExpired(keyData)) {
        keyData.expired = true;
        saveData(data);
        return res.json({ e: "exp" });
    }

    const sessionId = crypto.randomBytes(16).toString("hex");
    const sessionKey = crypto.randomBytes(32).toString("hex");
    const challenge = crypto.randomBytes(32).toString("hex");

    sessions.set(sessionId, {
        challenge, sessionKey, key, hwid, nonce,
        expireAt: Date.now() + 15000
    });

    // เข้ารหัส sessionKey ด้วย HMAC ของ hwid+nonce
    const encKey = crypto.createHmac("sha256", SIGN_SECRET)
        .update(`${hwid}:${nonce}:${ts}`)
        .digest("hex");

    res.json({
        s: sessionId,
        c: challenge,
        k: encKey  // client ใช้ decrypt response step 2
    });
});

// ====== STEP 2: verify ======
app.post("/cdn-cgi/token", guard, (req, res) => {
    const { s, hwid, ts, nonce } = req.body;
    if (!s || !hwid || !ts || !nonce) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) {
        return res.json({ e: "ts" });
    }
    if (usedSessions.has(s)) {
        return res.json({ e: "used" });
    }

    const entry = sessions.get(s);
    if (!entry) { addStrike(hwid); return res.json({ e: "sess" }); }
    if (entry.hwid !== hwid || entry.nonce !== nonce) {
        return res.json({ e: "bad" });
    }

    usedSessions.add(s);
    sessions.delete(s);
    setTimeout(() => usedSessions.delete(s), 30000);

    const data = loadData();
    const keyData = data.keys[entry.key];
    if (!keyData) return res.json({ e: "key" });
    if (isExpired(keyData)) {
        keyData.expired = true;
        saveData(data);
        return res.json({ e: "exp" });
    }

    const hashedHwid = crypto.createHash("sha256").update(hwid).digest("hex");
    if (keyData.hwid && keyData.hwid !== "" && keyData.hwid !== hashedHwid) {
        return res.json({ e: "hwid" });
    }

    if (!keyData.hwid || keyData.hwid === "") keyData.hwid = hashedHwid;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) keyData.redeemedAt = nowSec();
    keyData.active = true;
    keyData.expired = false;
    keyData.executionCount = (keyData.executionCount || 0) + 1;
    saveData(data);

    // เข้ารหัส response ด้วย sessionKey
    const payload = {
        ok: true,
        scriptUrl: data.config.scriptUrl || null,
        ts: nowSec()
    };
    const encrypted = encryptResponse(payload, entry.sessionKey);
    res.json(encrypted);
});

// ====== BOT ENDPOINTS ======
app.post("/keys/generate", botAuth, (req, res) => {
    const { duration, amount } = req.body;
    const data = loadData();
    const keys = [];
    for (let i = 0; i < Math.min(amount || 1, 50); i++) {
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
    const kd = data.keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: req.params.key, data: kd });
});

app.get("/keys", botAuth, (req, res) => {
    const data = loadData();
    res.json({ ok: true, keys: data.keys });
});

app.post("/keys/:key/reset-hwid", botAuth, (req, res) => {
    const data = loadData();
    const kd = data.keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false });
    kd.hwid = "";
    kd.lastHwidReset = nowSec();
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
    const kd = data.keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false, reason: "Key ไม่ถูกต้อง" });
    if (isExpired(kd)) {
        kd.expired = true; saveData(data);
        return res.json({ ok: false, reason: "Key หมดอายุแล้ว" });
    }
    if (kd.usedBy && kd.usedBy !== "" && kd.usedBy !== userId)
        return res.json({ ok: false, reason: "Key used by someone else" });
    if (kd.usedBy === userId)
        return res.json({ ok: false, reason: "Already redeemed" });
    kd.usedBy = userId;
    kd.active = true;
    if (!kd.redeemedAt || kd.redeemedAt === 0) kd.redeemedAt = nowSec();
    saveData(data);
    res.json({ ok: true, duration: kd.duration });
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


app.get("/ping", (req, res) => res.send("pong"));
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
