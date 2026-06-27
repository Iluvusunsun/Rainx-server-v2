const {
    MessageFlags, Client, GatewayIntentBits, REST, Routes,
    SlashCommandBuilder, EmbedBuilder, ActionRowBuilder,
    ButtonBuilder, ButtonStyle,
    ModalBuilder, TextInputBuilder, TextInputStyle
} = require('discord.js');
const crypto = require('crypto');

const TOKEN = process.env.BOT_TOKEN;
const CLIENT_ID = "1513724173644730511";
const SERVER_URL = process.env.SERVER_URL || "https://rainx-server-v2-production.up.railway.app";
const BOT_SECRET = process.env.BOT_SECRET || "rainx-bot-secret";
const OWNER_SECRET = process.env.OWNER_SECRET || "owner-secret-123";
const BOT_OWNER_ID = process.env.BOT_OWNER_ID || "";

// ====== HTTP HELPERS ======
async function serverGet(path) {
    const res = await fetch(`${SERVER_URL}${path}`, { headers: { "x-bot-secret": BOT_SECRET } });
    return res.json();
}
async function serverPost(path, body) {
    const res = await fetch(`${SERVER_URL}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-bot-secret": BOT_SECRET },
        body: JSON.stringify(body)
    });
    return res.json();
}
async function serverDelete(path) {
    const res = await fetch(`${SERVER_URL}${path}`, { method: "DELETE", headers: { "x-bot-secret": BOT_SECRET } });
    return res.json();
}
async function ownerPost(path, body) {
    const res = await fetch(`${SERVER_URL}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-owner-secret": OWNER_SECRET },
        body: JSON.stringify(body)
    });
    return res.json();
}
async function ownerDelete(path) {
    const res = await fetch(`${SERVER_URL}${path}`, { method: "DELETE", headers: { "x-owner-secret": OWNER_SECRET } });
    return res.json();
}
async function ownerGet(path) {
    const res = await fetch(`${SERVER_URL}${path}`, { headers: { "x-owner-secret": OWNER_SECRET } });
    return res.json();
}

// ====== PER-GUILD CONFIG CACHE ======
const guildConfigCache = new Map();

async function getGuildCfg(guildId) {
    const cached = guildConfigCache.get(guildId);
    if (cached && Date.now() < cached.expireAt) return cached.data;
    const result = await serverGet(`/config/${guildId}`).catch(() => null);
    if (!result?.ok) return { projectName: "Hub", bgUrl: "", setupUser: "System", adminRoleId: "", hwidResetCooldownHours: null, scripts: {} };
    guildConfigCache.set(guildId, { data: result.config, expireAt: Date.now() + 30000 });
    return result.config;
}

async function updateGuildCfg(guildId, patch) {
    guildConfigCache.delete(guildId);
    return serverPost(`/config/${guildId}`, patch);
}

// ====== PER-USER KEY CACHE ======
const userKeyCache = new Map();
function getCachedKey(userId, guildId) {
    const k = `${userId}:${guildId}`;
    const c = userKeyCache.get(k);
    if (!c || Date.now() > c.expireAt) return null;
    return c;
}
function setCachedKey(userId, guildId, key, data) {
    userKeyCache.set(`${userId}:${guildId}`, { key, data, expireAt: Date.now() + 60000 });
}
function clearCachedKey(userId, guildId) {
    userKeyCache.delete(`${userId}:${guildId}`);
}

function isBotOwner(userId) { return BOT_OWNER_ID && userId === BOT_OWNER_ID; }

function tsToDate(ts) {
    if (!ts || ts === -1) return "ถาวร";
    return new Date(ts * 1000).toLocaleString("th-TH", { timeZone: "Asia/Bangkok" });
}
function timeLeft(expiresAt) {
    if (!expiresAt || expiresAt === -1) return "ถาวร";
    const r = expiresAt - Math.floor(Date.now() / 1000);
    if (r <= 0) return "หมดอายุแล้ว";
    return `${Math.floor(r/86400)}d ${Math.floor((r%86400)/3600)}h ${Math.floor((r%3600)/60)}m`;
}
function timeText(redeemedAt, duration) {
    if (duration === -1) return "ถาวร";
    if (!redeemedAt || redeemedAt === 0) return "ยังไม่ได้ใช้";
    const r = (redeemedAt + duration) - Math.floor(Date.now() / 1000);
    if (r <= 0) return "หมดอายุแล้ว";
    return `${Math.floor(r/86400)}d ${Math.floor((r%86400)/3600)}h ${Math.floor((r%3600)/60)}m`;
}

function isAdmin(member, adminRoleId) {
    return member.permissions.has("Administrator") || (adminRoleId && adminRoleId !== "" && member.roles.cache.has(adminRoleId));
}

function getMainControlRow() {
    return new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId("get_script").setLabel("Get Script").setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId("redeem_key").setLabel("Redeem Key").setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId("reset_hwid").setLabel("Reset HWID").setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId("key_state").setLabel("State").setStyle(ButtonStyle.Secondary)
    );
}

async function checkGuildLicense(guildId) {
    try {
        const res = await serverGet(`/guild/check/${guildId}`);
        return res.ok === true;
    } catch { return false; }
}

async function requireLicense(interaction) {
    const licensed = await checkGuildLicense(interaction.guildId);
    if (!licensed) {
        await interaction.editReply({
            embeds: [new EmbedBuilder()
                .setTitle("Server ไม่มี License")
                .setDescription("Server นี้ยังไม่ได้เช่าบอท หรือ License หมดอายุแล้ว\nติดต่อ Owner เพื่อต่ออายุ")
                .setColor(0xe74c3c)]
        });
        return false;
    }
    return true;
}

// ====== CLIENT LOADER ======
const ClientLoader = `
do
    local _P = game:GetService("Players").LocalPlayer
    local function _earlykick(m) _P:Kick("[RainX] " .. m) end
    local _ok1, _isC = pcall(iscclosure, gethwid)
    if _ok1 and not _isC then _earlykick("E1") return end
    local _ok2, _genv = pcall(getgenv)
    if _ok2 and _genv and _genv.gethwid then
        local _ok3, _isC2 = pcall(iscclosure, _genv.gethwid)
        if _ok3 and not _isC2 then _earlykick("E2") return end
        local _ok4, _hw1 = pcall(_genv.gethwid)
        local _ok5, _hw2 = pcall(gethwid)
        if _ok4 and _ok5 and _hw1 ~= _hw2 then _earlykick("E3") return end
    end
    local _ok6, _isC3 = pcall(iscclosure, request)
    if _ok6 and not _isC3 then _earlykick("E4") return end
end

local _S = "https://rainx-server-v2-production.up.railway.app"
local _HS = game:GetService("HttpService")
local _PS = game:GetService("Players")
local _CL = _PS.LocalPlayer
local _rr = request
local _rg = gethwid
local _or = clonefunction(_rr)
local _og = clonefunction(_rg)
local _ow = clonefunction(warn)
local _owt = clonefunction(task.wait)
local _oc = clonefunction(os.clock)
local _oti = clonefunction(os.time)
local _op = clonefunction(pcall)
local _oip = clonefunction(ipairs)
local _ots = clonefunction(tostring)
local _orm = clonefunction(math.random)
local _off = clonefunction(string.format)
local _ogrmt = clonefunction(getrawmetatable)
local _oiro = clonefunction(isreadonly)
local _osr = setreadonly and clonefunction(setreadonly) or nil

local function _kick(m)
    for _ = 1, 30 do _ow(">> ได้แค่นี้หรอ:>") _owt(0.1) end
    _owt(0.3)
    _CL:Kick("[RainX] " .. (m or "ได้แค่นี้หรอ:>"))
end

do if isfunctionhooked then for _, f in _oip({request, gethwid}) do local ok, h = _op(isfunctionhooked, f) if ok and h == true then _kick("H1") return end end end end
do if request ~= _rr or gethwid ~= _rg then _kick("H2") return end end
do local ok, genv = _op(getgenv) if ok and genv and genv.request and genv.request ~= _rr then _kick("H3") return end end
do
    local ok, genv = _op(getgenv)
    if ok and genv and genv.gethwid and genv.gethwid ~= _rg then _kick("H4") return end
    local ok2, hw1 = _op(_og) local ok3, hw2 = _op(_rg)
    if ok2 and ok3 and hw1 ~= hw2 then _kick("H4b") return end
end
do local t1 = _oc() local s = 0 for i = 1, 50000 do s = s + i end local t2 = _oc() if (t2-t1) <= 0 or (t2-t1) > 60 then _kick("T1") return end end
do
    if isfunctionhooked then local ok, h = _op(isfunctionhooked, getrawmetatable) if ok and h == true then _kick("M1") return end end
    local ok, mt = _op(_ogrmt, game)
    if ok and mt then local ok2, ro = _op(_oiro, mt) if ok2 and ro == false then _kick("M1b") return end end
end
do if _osr and setreadonly and isfunctionhooked then local ok, h = _op(isfunctionhooked, setreadonly) if ok and h == true then _kick("M2") return end end end
do if not islclosure(function() end) then _kick("LC1") return end end
do local ok, tb = _op(debug.traceback) if ok and tb then if tb:find("http") or tb:find("dump") then _kick("DB1") return end end end
do local ok, str = _op(_ots, print) if ok and str and str:find("Lua") then _kick("DB2") return end end
do
    if _orm() == _orm() then _kick("RNG1") return end
    if isfunctionhooked and isfunctionhooked(math.random) then _kick("RNG2") return end
end
do
    if getgc then
        local ok, gc = _op(getgc, true)
        if ok and gc then
            for _, v in _oip(gc) do
                if type(v) == "table" then _op(function() local _ = rawget(v, "Zombies") and rawget(v, "ZombieModels") end) end
            end
        end
    end
end
do
    _op(function()
        local h = Instance.new("Hat")
        h.Name = "__t_" .. _ots(_orm(1000, 9999))
        h.Parent = workspace
        local name = h.Name
        h:Destroy()
        if workspace:FindFirstChild(name) then _kick("HAT1") return end
    end)
end

local _hw = _og()
local _ky = _ots(getgenv().key or "")
if _ky == "" then _kick("NO_KEY") return end

local _uid = _ots(_PS.LocalPlayer.UserId)
local _acc = _ots(math.floor(_PS.LocalPlayer.AccountAge or 0))
local _fp = _hw .. _uid .. _acc

local function _nn()
    local h = ""
    for i = 1, 32 do h = h .. _off("%x", _orm(0, 15)) end
    return h
end

local _nc = _nn()
local _t1 = _oti()

local _ok1, _r1 = _op(function()
    return _or({ Url = _S .. "/cdn-cgi/challenge", Method = "POST", Headers = {["Content-Type"] = "application/json"}, Body = _HS:JSONEncode({key = _ky, hwid = _hw, ts = _t1, nonce = _nc, fp = _fp}) })
end)
if not _ok1 or not _r1 or not _r1.Body then _kick("NET1") return end

local _d1 = _HS:JSONDecode(_r1.Body)
local _errs = {key="Key ไม่ถูกต้อง", exp="Key หมดอายุแล้ว", hwid="reset hwid ก่อน", rate="ช้าลงหน่อย", replay="กลับไปนอนก่อน"}
if not _d1 or _d1.e then
    for _ = 1, 30 do _ow(">> ได้แค่นี้หรอ:>") _owt(0.1) end _owt(0.3)
    _CL:Kick("[RainX] " .. (_errs[_d1 and _d1.e] or "ได้แค่นี้หรอ:>"))
    return
end
if not _d1.s or not _d1.k then _kick("NET2") return end

local _t2 = _oti()
local _ok2, _r2 = _op(function()
    return _or({ Url = _S .. "/cdn-cgi/token", Method = "POST", Headers = {["Content-Type"] = "application/json"}, Body = _HS:JSONEncode({s = _d1.s, hwid = _hw, ts = _t2, nonce = _nc, fp = _fp}) })
end)
if not _ok2 or not _r2 or not _r2.Body then _kick("NET3") return end

local _d2 = _HS:JSONDecode(_r2.Body)
if not _d2 then _kick("NET4") return end
if _d2.e then
    for _ = 1, 30 do _ow(">> ได้แค่นี้หรอ:>") _owt(0.1) end _owt(0.3)
    _CL:Kick("[RainX] " .. (_errs[_d2.e] or "ได้แค่นี้หรอ:>"))
    return
end
if not _d2.d or not _d2.iv or not _d2.t then _kick("NET5") return end

local _at = nil
local _ok3, _plain = _op(function() return crypt.decrypt(_d2.d, _d1.k:sub(1, 32), _d2.iv, "GCM", _d2.t) end)
if _ok3 and _plain then
    local _ok4, _pl = _op(function() return _HS:JSONDecode(_plain) end)
    if _ok4 and _pl then
        if _pl.ok == false then _kick("AUTH1") return end
        _at = _pl.activeToken
    end
end

if not game:IsLoaded() then game.Loaded:Wait() end
repeat task.wait() until game.Players.LocalPlayer and game.Players.LocalPlayer.PlayerGui and workspace

if _at then
    task.spawn(function()
        while task.wait(30) do
            local _tok = _oti()
            local ok, r = _op(function()
                return _or({ Url = _S .. "/cdn-cgi/heartbeat", Method = "POST", Headers = {["Content-Type"] = "application/json"}, Body = _HS:JSONEncode({hwid = _hw, token = _at, ts = _tok}) })
            end)
            if not ok or not r or not r.Body then _CL:Kick("[RainX] Session หมดอายุ") break end
            local ok2, rj = _op(function() return _HS:JSONDecode(r.Body) end)
            if not ok2 or not rj or not rj.alive then _CL:Kick("[RainX] Session หมดอายุ") break end
        end
    end)
end
`;

async function obfuscate(code, scriptName) {
    try {
        const res = await fetch("https://moonveil.cc/api/obfuscate", {
            method: "POST",
            headers: { "Authorization": "Bearer mv-secret-f21db0eb-92fe-42fc-9d20-0e175a44beec", "Content-Type": "application/json" },
            body: JSON.stringify({
                script: code,
                options: {
                    cffDecomposeExpr: true, cffEnable: true, cffHoistLocals: true,
                    embedRuntime: true, mangleConstLift: 0, mangleEnable: true,
                    mangleGlobals: true, mangleNamedIndex: true, mangleNumbers: true,
                    mangleSelfCalls: true, mangleStrings: true, prettify: false,
                    vmDebug: false, vmSafeEnv: true, vmWrapScript: true
                }
            })
        });
        const rawText = await res.text();
        if (!res.ok || !rawText.trim()) return { success: false, stage: `obfuscate (${res.status})` };
        const pasteRes = await fetch("https://pastefy.app/api/v2/paste", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": "Bearer ccZFKS97zNu94petuhZaq9uWUq6rtypxMejTX0NyZRTNYZ0tRdbnwCevXquE" },
            body: JSON.stringify({ content: rawText, title: `RainX - ${scriptName}`, visibility: "UNLISTED" })
        });
        if (!pasteRes.ok) return { success: false, stage: `pastefy (${pasteRes.status})` };
        const pasteData = await pasteRes.json();
        const rawUrl = pasteData?.paste?.raw_url;
        if (!rawUrl) return { success: false, stage: "pastefy (no url)" };
        return { success: true, url: rawUrl };
    } catch (e) { return { success: false, stage: e.message }; }
}

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });

const commands = [
    new SlashCommandBuilder().setName("admin_role").setDescription("เลือกยศแอดมิน").addRoleOption(o => o.setName("role").setDescription("ยศ").setRequired(true)),
    new SlashCommandBuilder().setName("generate_key").setDescription("สร้างคีย์").addIntegerOption(o => o.setName("days").setDescription("วัน (0=ถาวร)").setRequired(true)).addIntegerOption(o => o.setName("amount").setDescription("จำนวน").setRequired(false)),
    new SlashCommandBuilder().setName("deletekey").setDescription("ลบคีย์").addStringOption(o => o.setName("key_name").setDescription("คีย์").setRequired(true)),
    new SlashCommandBuilder().setName("keyinfo").setDescription("ดูข้อมูลคีย์").addStringOption(o => o.setName("key_name").setDescription("คีย์").setRequired(true)),
    new SlashCommandBuilder().setName("updatefile").setDescription("อัพโหลดสคริปต์").addStringOption(o => o.setName("name").setDescription("ชื่อ").setRequired(true)).addAttachmentOption(o => o.setName("file").setDescription(".lua/.txt").setRequired(true)),
    new SlashCommandBuilder().setName("deletefile").setDescription("ลบสคริปต์").addStringOption(o => o.setName("name").setDescription("ชื่อ").setRequired(true)),
    new SlashCommandBuilder().setName("listscripts").setDescription("รายชื่อสคริปต์"),
    new SlashCommandBuilder().setName("dashboard").setDescription("ภาพรวมของ Server นี้"),
    new SlashCommandBuilder().setName("setup").setDescription("ตั้งค่าแผง").addStringOption(o => o.setName("project_name").setDescription("ชื่อโปรเจกต์").setRequired(true)).addAttachmentOption(o => o.setName("background").setDescription("รูปพื้นหลัง").setRequired(true)),
    new SlashCommandBuilder().setName("sethwidresettime").setDescription("ตั้ง Cooldown HWID").addIntegerOption(o => o.setName("hours").setDescription("ชั่วโมง").setRequired(true)),
    new SlashCommandBuilder().setName("rent_guild").setDescription("[OWNER] เปิด License ให้ Server").addStringOption(o => o.setName("guild_id").setDescription("Guild ID").setRequired(true)).addIntegerOption(o => o.setName("days").setDescription("จำนวนวัน (0=ถาวร)").setRequired(true)).addStringOption(o => o.setName("note").setDescription("ชื่อลูกค้า/หมายเหตุ").setRequired(false)),
    new SlashCommandBuilder().setName("renew_guild").setDescription("[OWNER] ต่ออายุ License Server").addStringOption(o => o.setName("guild_id").setDescription("Guild ID").setRequired(true)).addIntegerOption(o => o.setName("days").setDescription("จำนวนวันที่จะเพิ่ม").setRequired(true)),
    new SlashCommandBuilder().setName("revoke_guild").setDescription("[OWNER] ยกเลิก License Server").addStringOption(o => o.setName("guild_id").setDescription("Guild ID").setRequired(true)),
    new SlashCommandBuilder().setName("guild_status").setDescription("[OWNER] เช็ค License Server").addStringOption(o => o.setName("guild_id").setDescription("Guild ID (ว่าง = server นี้)").setRequired(false)),
    new SlashCommandBuilder().setName("all_guilds").setDescription("[OWNER] ดูทุก Server ที่เช่าอยู่"),
].map(c => c.toJSON());

const rest = new REST({ version: "10" }).setToken(TOKEN);

client.once("ready", async () => {
    await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands });
    console.log(`Logged in as ${client.user.tag}`);
    setInterval(() => fetch(`${SERVER_URL}/ping`).catch(() => {}), 10 * 60 * 1000);
});

client.on("interactionCreate", async (interaction) => {
    if (interaction.isChatInputCommand()) {
        const { commandName } = interaction;
        const guildId = interaction.guildId;

        // ====== OWNER COMMANDS ======
        if (commandName === "rent_guild") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!isBotOwner(interaction.user.id)) return interaction.editReply({ content: "คำสั่งนี้ใช้ได้เฉพาะ Bot Owner" });
            const gid = interaction.options.getString("guild_id");
            const days = interaction.options.getInteger("days");
            const note = interaction.options.getString("note") || "";
            const result = await ownerPost("/guild/license", { guildId: gid, days, note });
            if (!result.ok) return interaction.editReply({ content: `เกิดข้อผิดพลาด: ${result.error || "unknown"}` });
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle("เปิด License สำเร็จ").setColor(0x2ecc71).addFields(
                { name: "Guild ID", value: gid, inline: true },
                { name: "Duration", value: days === 0 ? "ถาวร" : `${days} วัน`, inline: true },
                { name: "หมดอายุ", value: tsToDate(result.expiresAt), inline: true },
                { name: "หมายเหตุ", value: note || "-", inline: false }
            )] });
        }

        if (commandName === "renew_guild") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!isBotOwner(interaction.user.id)) return interaction.editReply({ content: "คำสั่งนี้ใช้ได้เฉพาะ Bot Owner" });
            const gid = interaction.options.getString("guild_id");
            const days = interaction.options.getInteger("days");
            const result = await ownerPost("/guild/renew", { guildId: gid, days });
            if (!result.ok) return interaction.editReply({ content: `เกิดข้อผิดพลาด: ${result.error || "ไม่พบ Guild"}` });
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle("ต่ออายุ License สำเร็จ").setColor(0x3498db).addFields(
                { name: "Guild ID", value: gid, inline: true },
                { name: "เพิ่ม", value: `${days} วัน`, inline: true },
                { name: "หมดอายุใหม่", value: tsToDate(result.expiresAt), inline: true }
            )] });
        }

        if (commandName === "revoke_guild") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!isBotOwner(interaction.user.id)) return interaction.editReply({ content: "คำสั่งนี้ใช้ได้เฉพาะ Bot Owner" });
            const gid = interaction.options.getString("guild_id");
            const result = await ownerDelete(`/guild/license/${gid}`);
            if (!result.ok) return interaction.editReply({ content: "ไม่พบ License หรือเกิดข้อผิดพลาด" });
            return interaction.editReply({ content: `ยกเลิก License ของ Guild \`${gid}\` เรียบร้อยแล้ว` });
        }

        if (commandName === "guild_status") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!isBotOwner(interaction.user.id)) return interaction.editReply({ content: "คำสั่งนี้ใช้ได้เฉพาะ Bot Owner" });
            const gid = interaction.options.getString("guild_id") || guildId;
            const result = await serverGet(`/guild/check/${gid}`);
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle("Guild License Status").setColor(result.ok ? 0x2ecc71 : 0xe74c3c).addFields(
                { name: "Guild ID", value: gid, inline: true },
                { name: "Status", value: result.ok ? "Active" : "Expired / ไม่มี License", inline: true },
                { name: "หมดอายุ", value: tsToDate(result.expiresAt), inline: true },
                { name: "เหลือเวลา", value: timeLeft(result.expiresAt), inline: true },
                { name: "หมายเหตุ", value: result.note || "-", inline: false }
            )] });
        }

        if (commandName === "all_guilds") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!isBotOwner(interaction.user.id)) return interaction.editReply({ content: "คำสั่งนี้ใช้ได้เฉพาะ Bot Owner" });
            const result = await ownerGet("/guild/licenses");
            const licenses = Array.isArray(result.licenses) ? result.licenses : Object.values(result.licenses || {});
            if (licenses.length === 0) return interaction.editReply({ content: "ยังไม่มี Guild ที่เช่าอยู่" });
            const now = Math.floor(Date.now() / 1000);
            const active = licenses.filter(l => l.active && (l.expiresAt === -1 || l.expiresAt > now));
            const expired = licenses.filter(l => !l.active || (l.expiresAt !== -1 && l.expiresAt <= now));
            const desc = licenses.map(l => {
                const status = (!l.active || (l.expiresAt !== -1 && l.expiresAt <= now)) ? "หมดอายุ" : "Active";
                return `**${l.guildId}** — ${status} | เหลือ: ${timeLeft(l.expiresAt)}${l.note ? ` | ${l.note}` : ""}`;
            }).join("\n");
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle("ทุก Guild ที่เช่าอยู่").setColor(0x5865F2).setDescription(desc.slice(0, 4000)).addFields(
                { name: "Active", value: String(active.length), inline: true },
                { name: "Expired", value: String(expired.length), inline: true },
                { name: "Total", value: String(licenses.length), inline: true }
            )] });
        }

        // ====== NORMAL COMMANDS (per guild, require license) ======
        if (commandName === "admin_role") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            if (!interaction.member.permissions.has("Administrator")) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const role = interaction.options.getRole("role");
            await updateGuildCfg(guildId, { adminRoleId: role.id });
            return interaction.editReply({ content: `ตั้งยศแอดมินเป็น ${role}` });
        }

        if (commandName === "sethwidresettime") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const hours = interaction.options.getInteger("hours");
            await updateGuildCfg(guildId, { hwidResetCooldownHours: hours });
            return interaction.editReply({ content: `HWID Cooldown = **${hours} ชั่วโมง**` });
        }

        if (commandName === "generate_key") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const days = interaction.options.getInteger("days");
            const amount = Math.min(interaction.options.getInteger("amount") ?? 1, 50);
            const duration = days === 0 ? -1 : days * 86400;
            const result = await serverPost("/keys/generate", { duration, amount, guildId });
            if (!result.ok) return interaction.editReply({ content: "สร้างคีย์ไม่สำเร็จ" });
            const chunks = [];
            for (let i = 0; i < result.keys.length; i += 10) chunks.push(result.keys.slice(i, i + 10));
            const embed = new EmbedBuilder().setTitle("Key Generated").setColor(0x2ecc71)
                .addFields({ name: "จำนวน", value: String(amount), inline: true }, { name: "Duration", value: days === 0 ? "ถาวร" : `${days} วัน`, inline: true });
            chunks.forEach((chunk, idx) => embed.addFields({ name: idx === 0 ? "Keys" : "\u200b", value: chunk.map(k => `\`${k}\``).join("\n") }));
            return interaction.editReply({ embeds: [embed] });
        }

        if (commandName === "deletekey") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const keyName = interaction.options.getString("key_name");
            const kd = await serverGet(`/keys/${keyName}`);
            if (!kd.ok) return interaction.editReply({ content: "ไม่พบคีย์" });
            if (kd.data.guildId !== guildId) return interaction.editReply({ content: "คีย์นี้ไม่ใช่ของ Server นี้" });
            const result = await serverDelete(`/keys/${keyName}`);
            return interaction.editReply({ content: result.ok ? "ลบคีย์เรียบร้อย" : "ไม่พบคีย์" });
        }

        if (commandName === "keyinfo") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const result = await serverGet(`/keys/${interaction.options.getString("key_name")}`);
            if (!result.ok) return interaction.editReply({ content: "ไม่พบคีย์" });
            if (result.data.guildId !== guildId) return interaction.editReply({ content: "คีย์นี้ไม่ใช่ของ Server นี้" });
            const d = result.data;
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle("Key Info").setColor(0xe67e22).addFields(
                { name: "Key", value: `\`${result.key}\``, inline: false },
                { name: "Active", value: String(d.active), inline: true },
                { name: "Expired", value: String(d.expired), inline: true },
                { name: "Time Left", value: timeText(d.redeemedAt, d.duration), inline: true },
                { name: "Executions", value: String(d.executionCount || 0), inline: true },
                { name: "Used By", value: d.usedBy ? `<@${d.usedBy}>` : "ยังไม่มี", inline: true },
                { name: "HWID", value: d.hwid || "ยังไม่มี", inline: false }
            )] });
        }

        if (commandName === "updatefile") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const name = interaction.options.getString("name");
            const attachment = interaction.options.getAttachment("file");
            if (!attachment.name.endsWith(".lua") && !attachment.name.endsWith(".txt"))
                return interaction.editReply({ content: "ต้องเป็น .lua หรือ .txt" });
            let scriptContent;
            try { const r = await fetch(attachment.url); scriptContent = await r.text(); }
            catch { return interaction.editReply({ content: "ดาวน์โหลดไฟล์ไม่ได้" }); }
            await interaction.editReply({ content: "กำลัง Obfuscate..." });
            const result = await obfuscate(ClientLoader + "\n\n" + scriptContent, name);
            if (!result.success) return interaction.editReply({ content: `ล้มเหลว: **${result.stage}**` });
            const scripts = { ...cfg.scripts, [name]: result.url };
            await updateGuildCfg(guildId, { scripts });
            return interaction.editReply({ content: `อัพโหลดสำเร็จ\n**ชื่อ**: \`${name}\`\n**URL**: ${result.url}` });
        }

        if (commandName === "deletefile") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const name = interaction.options.getString("name");
            if (!cfg.scripts[name]) return interaction.editReply({ content: "ไม่พบสคริปต์" });
            const scripts = { ...cfg.scripts };
            delete scripts[name];
            await updateGuildCfg(guildId, { scripts });
            return interaction.editReply({ content: "ลบสคริปต์เรียบร้อย" });
        }

        if (commandName === "listscripts") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const names = Object.keys(cfg.scripts || {});
            if (names.length === 0) return interaction.editReply({ content: "ไม่มีสคริปต์" });
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle("Scripts").setColor(0x5865F2).setDescription(names.map((n, i) => `**${i + 1}.** \`${n}\``).join("\n"))] });
        }

        if (commandName === "dashboard") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (!isAdmin(interaction.member, cfg.adminRoleId)) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const result = await serverGet(`/keys?guildId=${guildId}`);
            const values = Object.values(result.keys || {});
            const licResult = await serverGet(`/guild/check/${guildId}`);
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle(`Dashboard: ${cfg.projectName}`).setColor(0x3498db).addFields(
                { name: "Total Keys", value: String(values.length), inline: true },
                { name: "Active", value: String(values.filter(v => v.active).length), inline: true },
                { name: "Expired", value: String(values.filter(v => v.expired).length), inline: true },
                { name: "Executions", value: String(values.reduce((a, v) => a + (v.executionCount || 0), 0)), inline: true },
                { name: "Scripts", value: Object.keys(cfg.scripts || {}).length > 0 ? Object.keys(cfg.scripts).map(n => `\`${n}\``).join(", ") : "ไม่มี", inline: false },
                { name: "HWID Cooldown", value: cfg.hwidResetCooldownHours != null ? `${cfg.hwidResetCooldownHours} ชั่วโมง` : "ยังไม่ตั้งค่า", inline: true },
                { name: "License เหลือ", value: timeLeft(licResult.expiresAt), inline: true }
            )] });
        }

        if (commandName === "setup") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            if (!interaction.member.permissions.has("Administrator")) return interaction.editReply({ content: "คุณไม่มีสิทธิ์" });
            const projectName = interaction.options.getString("project_name");
            const bgUrl = interaction.options.getAttachment("background").url;
            const setupUser = interaction.member.displayName;
            await updateGuildCfg(guildId, { projectName, bgUrl, setupUser });
            await interaction.channel.send({
                embeds: [new EmbedBuilder().setTitle(`${projectName} Control Panel`).setDescription("ยินดีต้อนรับ! เลือกรายการด้านล่าง").setImage(bgUrl).setColor(0x5865F2).setFooter({ text: `Setup by ${setupUser}` })],
                components: [getMainControlRow()]
            });
            return interaction.editReply({ content: "ตั้งค่าแผงเรียบร้อย!" });
        }
    }

    if (interaction.isButton()) {
        const guildId = interaction.guildId;

        if (interaction.customId === "get_script") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            const scripts = cfg.scripts || {};
            if (Object.keys(scripts).length === 0) return interaction.editReply({ content: "ยังไม่มีสคริปต์" });
            let cached = getCachedKey(interaction.user.id, guildId);
            if (!cached) {
                const result = await serverGet(`/keys/user/${interaction.user.id}?guildId=${guildId}`);
                if (!result.ok) return interaction.editReply({ content: "กรุณา Redeem Key ก่อน" });
                setCachedKey(interaction.user.id, guildId, result.key, result.data);
                cached = getCachedKey(interaction.user.id, guildId);
            }
            if (cached.data.expired) return interaction.editReply({ content: "คีย์หมดอายุแล้ว" });
            const scriptNames = Object.keys(scripts);
            if (scriptNames.length === 1) {
                const script = `getgenv().key = "${cached.key}"\nloadstring(game:HttpGet('${scripts[scriptNames[0]]}'))()`;
                return interaction.editReply({ content: `**${scriptNames[0]}**\n\`\`\`lua\n${script}\n\`\`\`` });
            }
            const rows = [];
            let row = new ActionRowBuilder();
            scriptNames.forEach((name, idx) => {
                if (idx > 0 && idx % 5 === 0) { rows.push(row); row = new ActionRowBuilder(); }
                row.addComponents(new ButtonBuilder().setCustomId(`script_btn_${name}`).setLabel(name).setStyle(ButtonStyle.Secondary));
            });
            rows.push(row);
            if (rows.length > 5) rows.length = 5;
            return interaction.editReply({ content: "เลือกสคริปต์:", components: rows });
        }

        if (interaction.customId.startsWith("script_btn_")) {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            const scriptName = interaction.customId.slice("script_btn_".length);
            const url = (cfg.scripts || {})[scriptName];
            if (!url) return interaction.editReply({ content: "ไม่พบสคริปต์" });
            let cached = getCachedKey(interaction.user.id, guildId);
            if (!cached) {
                const result = await serverGet(`/keys/user/${interaction.user.id}?guildId=${guildId}`);
                if (!result.ok) return interaction.editReply({ content: "กรุณา Redeem Key ก่อน" });
                setCachedKey(interaction.user.id, guildId, result.key, result.data);
                cached = getCachedKey(interaction.user.id, guildId);
            }
            const script = `getgenv().key = "${cached.key}"\nloadstring(game:HttpGet('${url}'))()`;
            return interaction.editReply({ content: `**${scriptName}**\n\`\`\`lua\n${script}\n\`\`\`` });
        }

        if (interaction.customId === "redeem_key") {
            return interaction.showModal(new ModalBuilder().setCustomId("redeem_modal").setTitle("Redeem Key").addComponents(
                new ActionRowBuilder().addComponents(
                    new TextInputBuilder().setCustomId("key_input").setLabel("คีย์ของคุณ").setStyle(TextInputStyle.Short).setMinLength(32).setMaxLength(32).setRequired(true)
                )
            ));
        }

        if (interaction.customId === "reset_hwid") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            const cfg = await getGuildCfg(guildId);
            if (cfg.hwidResetCooldownHours == null) return interaction.editReply({ content: "แอดมินยังไม่ตั้งค่า Cooldown" });
            let cached = getCachedKey(interaction.user.id, guildId);
            if (!cached) {
                const result = await serverGet(`/keys/user/${interaction.user.id}?guildId=${guildId}`);
                if (!result.ok) return interaction.editReply({ content: "ยังไม่ได้ Redeem Key" });
                setCachedKey(interaction.user.id, guildId, result.key, result.data);
                cached = getCachedKey(interaction.user.id, guildId);
            }
            if (cached.data.expired) return interaction.editReply({ content: "คีย์หมดอายุแล้ว" });
            const nowSec = Math.floor(Date.now() / 1000);
            const lastReset = cached.data.lastHwidReset || 0;
            const cooldownSec = cfg.hwidResetCooldownHours * 3600;
            if (lastReset > 0 && (nowSec - lastReset) < cooldownSec) {
                const remaining = cooldownSec - (nowSec - lastReset);
                return interaction.editReply({ content: `รีเซ็ตได้อีกใน **${Math.floor(remaining/3600)} ชม. ${Math.floor((remaining%3600)/60)} นาที**` });
            }
            await serverPost(`/keys/${cached.key}/reset-hwid`, {});
            clearCachedKey(interaction.user.id, guildId);
            return interaction.editReply({ content: "รีเซ็ต HWID สำเร็จ!" });
        }

        if (interaction.customId === "key_state") {
            await interaction.deferReply({ flags: MessageFlags.Ephemeral });
            if (!await requireLicense(interaction)) return;
            let cached = getCachedKey(interaction.user.id, guildId);
            if (!cached) {
                const result = await serverGet(`/keys/user/${interaction.user.id}?guildId=${guildId}`);
                if (!result.ok) return interaction.editReply({ content: "ยังไม่ได้ Redeem Key" });
                setCachedKey(interaction.user.id, guildId, result.key, result.data);
                cached = getCachedKey(interaction.user.id, guildId);
            }
            const d = cached.data;
            return interaction.editReply({ embeds: [new EmbedBuilder().setTitle("Key State").setColor(0x3498db).addFields(
                { name: "Key", value: `\`${cached.key}\``, inline: false },
                { name: "Active", value: String(d.active), inline: true },
                { name: "Expired", value: String(d.expired), inline: true },
                { name: "Time Left", value: timeText(d.redeemedAt, d.duration), inline: true },
                { name: "Executions", value: String(d.executionCount || 0), inline: true },
                { name: "HWID", value: d.hwid || "ยังไม่มี", inline: false }
            )] });
        }
    }

    if (interaction.isModalSubmit() && interaction.customId === "redeem_modal") {
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        if (!await requireLicense(interaction)) return;
        const guildId = interaction.guildId;
        const keyName = interaction.fields.getTextInputValue("key_input").trim();
        const result = await serverPost(`/keys/${keyName}/redeem`, { userId: interaction.user.id, guildId });
        if (!result.ok) {
            const msgs = {
                "Key ไม่ถูกต้อง": "คีย์ไม่ถูกต้อง",
                "Key หมดอายุแล้ว": "คีย์หมดอายุแล้ว",
                "Key used by someone else": "คีย์ถูกใช้โดยคนอื่น",
                "Already redeemed": "คุณใช้คีย์นี้อยู่แล้ว",
                "Key นี้ไม่ใช่ของ Server นี้": "คีย์นี้ไม่ใช่ของ Server นี้"
            };
            return interaction.editReply({ content: msgs[result.reason] || "เกิดข้อผิดพลาด" });
        }
        clearCachedKey(interaction.user.id, guildId);
        return interaction.editReply({ content: `Redeem สำเร็จ!\n**Duration:** ${result.duration === -1 ? "ถาวร" : `${Math.floor(result.duration/86400)} วัน`}` });
    }
});

client.login(TOKEN);

