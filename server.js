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

const usedTokens = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [token, exp] of usedTokens.entries()) {
        if (now > exp) usedTokens.delete(token);
    }
}, 60000);

function loadData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            fs.writeFileSync(DATA_FILE, JSON.stringify({ keys: {}, config: {} }));
        }
        return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    } catch {
        return { keys: {}, config: {} };
    }
}

function saveData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function nowSec() {
    return Math.floor(Date.now() / 1000);
}

function isExpired(keyData) {
    if (keyData.duration === -1) return false;
    if (keyData.expired === true) return true;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) return false;
    return nowSec() >= (keyData.redeemedAt + keyData.duration);
}

function signPayload(payload) {
    return crypto
        .createHmac("sha256", SIGN_SECRET)
        .update(JSON.stringify(payload))
        .digest("hex");
}

function makeSignedResponse(data) {
    const payload = { ...data, ts: nowSec() };
    payload.sig = signPayload({ ...data, ts: payload.ts });
    return payload;
}

function botAuth(req, res, next) {
    const secret = req.headers["x-bot-secret"];
    if (secret !== BOT_SECRET) return res.status(403).json({ error: "forbidden" });
    next();
}

app.post("/verify", (req, res) => {
    const { key, hwid, token, ts } = req.body;
    if (!key || !hwid || !token || !ts)
        return res.json(makeSignedResponse({ ok: false, reason: "กากไอสัส" }));

    const now = nowSec();
    if (Math.abs(now - ts) > 15)
        return res.json(makeSignedResponse({ ok: false, reason: "กากไอสัส" }));

    if (usedTokens.has(token))
        return res.json(makeSignedResponse({ ok: false, reason: "กากไอสัส" }));

    const expectedToken = crypto
        .createHmac("sha256", SIGN_SECRET)
        .update(`${key}:${hwid}:${ts}`)
        .digest("hex");

    if (token !== expectedToken)
        return res.json(makeSignedResponse({ ok: false, reason: "กากไอสัส" }));

    usedTokens.set(token, Date.now() + 30000);

    const data = loadData();
    const keyData = data.keys[key];

    if (!keyData)
        return res.json(makeSignedResponse({ ok: false, reason: "Key ไม่ถูกต้องนะ" }));

    if (isExpired(keyData)) {
        keyData.expired = true;
        saveData(data);
        return res.json(makeSignedResponse({ ok: false, reason: "Key หมดอายุแล้ว" }));
    }

    const hashedHwid = crypto.createHash("sha256").update(hwid).digest("hex");
    if (keyData.hwid && keyData.hwid !== "" && keyData.hwid !== hashedHwid)
        return res.json(makeSignedResponse({ ok: false, reason: "reset hwid ก่อนน่ะ" }));

    if (!keyData.hwid || keyData.hwid === "") keyData.hwid = hashedHwid;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) keyData.redeemedAt = now;
    keyData.active = true;
    keyData.expired = false;
    keyData.executionCount = (keyData.executionCount || 0) + 1;
    saveData(data);

    return res.json(makeSignedResponse({ ok: true, scriptUrl: data.config.scriptUrl || null }));
});

app.post("/keys/generate", botAuth, (req, res) => {
    const { duration, amount } = req.body;
    const data = loadData();
    const keys = [];
    for (let i = 0; i < (amount || 1); i++) {
        const key = crypto.randomBytes(16).toString("hex");
        data.keys[key] = {
            active: false, expired: false,
            duration: duration ?? -1,
            executionCount: 0, hwid: "",
            createdAt: nowSec(), redeemedAt: 0, lastHwidReset: 0
        };
        keys.push(key);
    }
    saveData(data);
    res.json({ ok: true, keys });
});

app.delete("/keys/:key", botAuth, (req, res) => {
    const data = loadData();
    if (!data.keys[req.params.key]) return res.status(404).json({ ok: false, reason: "Key not found" });
    delete data.keys[req.params.key];
    saveData(data);
    res.json({ ok: true });
});

app.get("/keys/:key", botAuth, (req, res) => {
    const data = loadData();
    const keyData = data.keys[req.params.key];
    if (!keyData) return res.status(404).json({ ok: false, reason: "Key not found" });
    res.json({ ok: true, key: req.params.key, data: keyData });
});

app.get("/keys", botAuth, (req, res) => {
    const data = loadData();
    res.json({ ok: true, keys: data.keys });
});

app.post("/keys/:key/reset-hwid", botAuth, (req, res) => {
    const data = loadData();
    const keyData = data.keys[req.params.key];
    if (!keyData) return res.status(404).json({ ok: false, reason: "Key not found" });
    keyData.hwid = "";
    keyData.lastHwidReset = nowSec();
    saveData(data);
    res.json({ ok: true });
});

app.get("/keys/user/:userId", botAuth, (req, res) => {
    const data = loadData();
    const entry = Object.entries(data.keys).find(([, v]) => v.usedBy === req.params.userId);
    if (!entry) return res.status(404).json({ ok: false, reason: "Not found" });
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

app.get("/ping", (req, res) => res.send("pong"));

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
