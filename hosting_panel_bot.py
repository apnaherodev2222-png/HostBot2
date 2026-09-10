#!/usr/bin/env python3
"""
🤖 VPS BOT HOSTING MANAGER — User Interface Bot
- Users upload ZIP, bot scans, deploys via PM2
- Flagged uploads go to admin via approval bot
- Notification worker DMs users on approve/reject
"""
from __future__ import annotations
import os, sys, asyncio, zipfile, shutil, subprocess, json, time, re, uuid
import traceback
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

try:
    import aiosqlite
except ImportError:
    print("Missing aiosqlite. pip install -r requirements.txt")
    sys.exit(1)

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes
)
from telegram.error import BadRequest

from script_scanner import scan_file

# ================== CONFIG ==================
BOT_TOKEN           = "8676256487:AAH9xNtc1jOt0EfPxSZxb_uqWCN-DWEvHgM"
APPROVAL_BOT_TOKEN  = "8529511149:AAFCeSlw6nLTaD2U2Q0Nt6TfOnxs3YfF5YE"
OWNER_ID            = 5628671567
ADMIN_IDS           = [5628671567]
SUPPORT_CHANNEL     = "https://t.me/Dev_Null_X_NODE_S"
HOME_VIDEO_URL      = "https://files.catbox.moe/m4sadt.mp4"

HOSTED_BOTS_DIR     = Path("/root/hosted_bots")
LOGS_DIR            = Path("/root/hosted_bots_logs")
DATABASE_PATH       = HOSTED_BOTS_DIR / "inf" / "bot_data.db"

MAX_ZIP_SIZE_MB     = 50
MAX_BOTS_PER_USER   = 10
MAX_FILES_PER_SCAN  = 300
MUTE_DURATION_HOURS = 2
CACHE_TTL           = 120
NOTIFY_POLL_SECONDS = 10
NOTIFIED_USERS_RETENTION_DAYS = 7
DEPLOY_SEMAPHORE    = asyncio.Semaphore(3)

HOSTED_BOTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

# ================== CACHE ==================
_cache: Dict[str, tuple] = {}
def cache_get(k):
    if k in _cache:
        ts, v = _cache[k]
        if time.time() - ts < CACHE_TTL: return v
        del _cache[k]
    return None
def cache_set(k, v): _cache[k] = (time.time(), v)
def cache_invalidate(prefix):
    for k in [k for k in _cache if k.startswith(prefix)]: del _cache[k]

# ================== SKIP EXTENSIONS FOR SCAN ==================
SKIP_SCAN_EXTS = {
    '.png','.jpg','.jpeg','.gif','.ico','.svg','.webp','.bmp',
    '.so','.dll','.dylib','.whl','.egg','.pyc','.pyo',
    '.mp3','.mp4','.avi','.mkv','.wav','.ogg','.flac',
    '.zip','.tar','.gz','.bz2','.7z','.rar','.xz',
    '.woff','.woff2','.ttf','.eot','.otf',
    '.exe','.bin','.dat','.db','.sqlite','.sqlite3',
    '.pdf','.doc','.docx','.xls','.xlsx'
}

# ================== LOGGING ==================
def log_err(msg, extra=None):
    try:
        with open(LOGS_DIR / "errors.log", "a") as f:
            f.write(f"[{datetime.now()}] {msg}\n")
            if extra: f.write(f"EXTRA: {extra}\n")
    except Exception:
        pass

def log_notify(msg):
    try:
        with open(LOGS_DIR / "notifications.log", "a") as f:
            f.write(f"[{datetime.now()}] {msg}\n")
    except Exception:
        pass

def log_admin_notify_failure(admin_id, error, text):
    """Write approval-bot notification failures to a dedicated log."""
    try:
        with open(LOGS_DIR / "admin_notification_failures.log", "a") as f:
            preview = str(text).replace("\n", " ")[:500]
            f.write(
                f"[{datetime.now()}] admin={admin_id} "
                f"error={type(error).__name__}: {error} text={preview}\n"
            )
    except Exception:
        pass

# ================== DB ==================
async def init_db():
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA busy_timeout=10000;")
        await conn.executescript("""
            CREATE TABLE IF NOT EXISTS bot_registry (
                bot_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                dir TEXT NOT NULL,
                type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                extra TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_reg_user ON bot_registry(user_id);

            CREATE TABLE IF NOT EXISTS pending_deploys (
                bot_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                staging_dir TEXT NOT NULL,
                bot_type TEXT NOT NULL,
                findings TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                scanned_at TEXT,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                reason TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_deploys(status);

            CREATE TABLE IF NOT EXISTS premium_users (
                user_id INTEGER PRIMARY KEY,
                added_at TEXT NOT NULL,
                added_by INTEGER
            );

            CREATE TABLE IF NOT EXISTS muted_users (
                user_id INTEGER PRIMARY KEY,
                mute_until TEXT NOT NULL,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS app_state (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS notified_users (
                bot_id TEXT PRIMARY KEY,
                notified_at TEXT
            );
        """)
        await conn.commit()

class DB:
    # ---- registry ----
    @staticmethod
    async def get_user_bots(uid):
        ck = f"ubots_{uid}"
        c = cache_get(ck)
        if c is not None: return c
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            conn.row_factory = aiosqlite.Row
            if uid in ADMIN_IDS:
                cur = await conn.execute("SELECT * FROM bot_registry")
            else:
                cur = await conn.execute("SELECT * FROM bot_registry WHERE user_id=?", (uid,))
            rows = await cur.fetchall()
            res = {}
            for r in rows:
                res[r["bot_id"]] = {
                    "user_id": r["user_id"], "name": r["name"],
                    "dir": r["dir"], "type": r["type"],
                    "created_at": r["created_at"],
                    **(json.loads(r["extra"]) if r["extra"] else {})
                }
            cache_set(ck, res)
            return res

    @staticmethod
    async def add_bot(bid, uid, name, bdir, btype, extra=None):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO bot_registry VALUES (?,?,?,?,?,?,?)",
                (bid, uid, name, bdir, btype, datetime.now().isoformat(),
                 json.dumps(extra) if extra else None)
            )
            await conn.commit()
        cache_invalidate("ubots_")

    @staticmethod
    async def remove_bot(bid):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            await conn.execute("DELETE FROM bot_registry WHERE bot_id=?", (bid,))
            await conn.commit()
        cache_invalidate("ubots_")

    @staticmethod
    async def count_user_bots(uid):
        bots = await DB.get_user_bots(uid)
        if uid in ADMIN_IDS: return len(bots)
        return len([b for b in bots.values() if b["user_id"] == uid])

    @staticmethod
    async def count_user_pending(uid):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM pending_deploys WHERE user_id=? AND status='pending'",
                (uid,)
            )
            r = await cur.fetchone()
            return r[0] if r else 0

    # ---- pending ----
    @staticmethod
    async def add_pending(bid, uid, name, sdir, btype, findings):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            await conn.execute(
                "INSERT INTO pending_deploys (bot_id,user_id,name,staging_dir,bot_type,findings,status,created_at,scanned_at) "
                "VALUES (?,?,?,?,?,?,'pending',?,?)",
                (bid, uid, name, sdir, btype, json.dumps(findings),
                 datetime.now().isoformat(), datetime.now().isoformat())
            )
            await conn.commit()

    @staticmethod
    async def get_pending(bid):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            conn.row_factory = aiosqlite.Row
            cur = await conn.execute("SELECT * FROM pending_deploys WHERE bot_id=?", (bid,))
            r = await cur.fetchone()
            return dict(r) if r else None

    @staticmethod
    async def set_pending_status(bid, status, admin_id=None, reason=None):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            await conn.execute(
                "UPDATE pending_deploys SET status=?,reviewed_by=?,reviewed_at=?,reason=? WHERE bot_id=?",
                (status, admin_id, datetime.now().isoformat(), reason, bid)
            )
            await conn.commit()

    # ---- premium ----
    @staticmethod
    async def is_premium(uid):
        ck = f"prem_{uid}"
        c = cache_get(ck)
        if c is not None: return c
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            cur = await conn.execute("SELECT 1 FROM premium_users WHERE user_id=?", (uid,))
            r = await cur.fetchone()
            v = bool(r)
            cache_set(ck, v)
            return v

    @staticmethod
    async def add_premium(uid, by):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO premium_users VALUES (?,?,?)",
                (uid, datetime.now().isoformat(), by)
            )
            await conn.commit()
        cache_invalidate(f"prem_{uid}")

    @staticmethod
    async def remove_premium(uid):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            cur = await conn.execute("DELETE FROM premium_users WHERE user_id=?", (uid,))
            await conn.commit()
            changed = cur.rowcount > 0
        cache_invalidate(f"prem_{uid}")
        return changed

    # ---- unlock ----
    @staticmethod
    async def is_unlocked():
        c = cache_get("unlocked")
        if c is not None: return c
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            cur = await conn.execute("SELECT value FROM app_state WHERE key='unlocked'")
            r = await cur.fetchone()
            v = (r[0].lower() == "true") if r else False
            cache_set("unlocked", v)
            return v

    @staticmethod
    async def set_unlocked(val):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO app_state VALUES ('unlocked', ?)",
                ("true" if val else "false",)
            )
            await conn.commit()
        cache_invalidate("unlocked")

    # ---- mute ----
    @staticmethod
    async def is_muted(uid) -> bool:
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            cur = await conn.execute("SELECT mute_until FROM muted_users WHERE user_id=?", (uid,))
            r = await cur.fetchone()
            if not r: return False
            try:
                until = datetime.fromisoformat(r[0])
            except Exception:
                return False
            if datetime.now() >= until:
                await conn.execute("DELETE FROM muted_users WHERE user_id=?", (uid,))
                await conn.commit()
                return False
            return True

    @staticmethod
    async def mute_user(uid, hours, reason):
        until = (datetime.now() + timedelta(hours=hours)).isoformat()
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO muted_users VALUES (?,?,?)",
                (uid, until, reason)
            )
            await conn.commit()

    @staticmethod
    async def unmute_user(uid):
        async with aiosqlite.connect(DATABASE_PATH) as conn:
            cur = await conn.execute("DELETE FROM muted_users WHERE user_id=?", (uid,))
            await conn.commit()
            return cur.rowcount > 0

async def can_use(uid):
    if uid in ADMIN_IDS: return True
    if await DB.is_unlocked(): return True
    return await DB.is_premium(uid)

# ================== ADMIN NOTIFY (via approval bot) ==================
def _post_admin_notify(url, payload):
    import requests
    response = requests.post(url, data=payload, timeout=10)
    response.raise_for_status()
    return response

async def notify_admin_via_approval_bot(text, reply_markup=None):
    for aid in ADMIN_IDS:
        try:
            url = f"https://api.telegram.org/bot{APPROVAL_BOT_TOKEN}/sendMessage"
            payload = {"chat_id": aid, "text": text, "parse_mode": "Markdown"}
            if reply_markup is not None:
                payload["reply_markup"] = json.dumps(reply_markup)
            await asyncio.to_thread(_post_admin_notify, url, payload)
        except Exception as e:
            log_admin_notify_failure(aid, e, text)
            log_err(f"notify admin {aid}: {e}")

# ================== SAFE ZIP ==================
def _is_within(root, cand):
    try:
        Path(cand).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False

def _safe_zip_extract(zip_path, dest):
    """Opens and extracts the zip entirely on whichever thread calls this —
    the ZipFile object is never shared across threads."""
    root = Path(dest).resolve()
    with zipfile.ZipFile(zip_path) as zip_ref:
        members = zip_ref.infolist()
        if len(members) > 5000:
            raise ValueError("ZIP has too many entries (max 5000)")
        expanded = 0
        for m in members:
            name = m.filename.replace("\\", "/")
            if not name or name.startswith("/") or name.startswith("../") or "/../" in name:
                raise ValueError(f"Unsafe path in ZIP: {name}")
            target = (root / name).resolve()
            if not _is_within(root, target):
                raise ValueError(f"ZIP escapes dest: {name}")
            expanded += max(0, m.file_size)
            if expanded > 200 * 1024 * 1024:
                raise ValueError("ZIP expands past 200MB")
        zip_ref.extractall(root)

# ================== SCANNER WRAPPER ==================
def scan_directory(dir_path: Path) -> Dict[str, Any]:
    res = {
        "verdict": "clear",
        "files_scanned": 0, "files_skipped": 0,
        "flagged_files": [], "high_count": 0, "medium_count": 0,
        "truncated": False,
    }
    hit_cap = False
    for root, _, files in os.walk(dir_path):
        for fname in files:
            if res["files_scanned"] >= MAX_FILES_PER_SCAN:
                hit_cap = True
                break
            fp = Path(root) / fname
            if fp.suffix.lower() in SKIP_SCAN_EXTS:
                res["files_skipped"] += 1
                continue
            try:
                verdict, findings = scan_file(fp)
                res["files_scanned"] += 1
                if verdict == "flagged":
                    rel = str(fp.relative_to(dir_path))
                    res["flagged_files"].append({"file": rel, "findings": findings})
                    for _, sev in findings:
                        if sev == "high": res["high_count"] += 1
                        elif sev == "medium": res["medium_count"] += 1
            except Exception as e:
                log_err(f"scan {fp}: {e}")
        if hit_cap:
            break

    if hit_cap:
        # There were still more files left when we stopped scanning —
        # never let an incompletely-scanned upload come back "clear".
        # Send it to manual review instead of silently auto-deploying
        # whatever we didn't get to.
        res["truncated"] = True
        res["verdict"] = "flagged"
        res["flagged_files"].append({
            "file": "(scan limit reached)",
            "findings": [(f"Upload exceeds {MAX_FILES_PER_SCAN}-file scan limit — "
                          "remaining files were not scanned", "high")]
        })
        res["high_count"] += 1
    elif res["high_count"] >= 1 or res["medium_count"] >= 2:
        res["verdict"] = "flagged"
    return res

def _build_findings_text(scan_result, max_files=5, max_per_file=3):
    lines = []
    for ff in scan_result["flagged_files"][:max_files]:
        lines.append(f"📄 `{ff['file']}`")
        for label, sev in ff["findings"][:max_per_file]:
            emo = "🔴" if sev == "high" else "🟡"
            lines.append(f"  {emo} {label[:80]}")
    if len(scan_result["flagged_files"]) > max_files:
        lines.append(f"_... and {len(scan_result['flagged_files']) - max_files} more files_")
    return "\n".join(lines)

# ================== HOSTED BOT CONTROL ==================
class HostedBot:
    def __init__(self, bid, name, bdir, btype, uid=None):
        self.bot_id = bid
        self.name = name
        self.bot_dir = str(bdir)
        self.bot_type = btype
        self.user_id = uid
        self.service_name = f"hosted-bot-{bid}"

    def is_running(self):
        try:
            r = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout:
                try:
                    for p in json.loads(r.stdout):
                        if p.get("name") == self.service_name:
                            return p.get("pm2_env", {}).get("status") == "online"
                except Exception:
                    pass
            return False
        except Exception:
            return False

    def get_logs(self, lines=30):
        try:
            r = subprocess.run(
                ["pm2", "logs", self.service_name, "--lines", str(lines), "--nostream"],
                capture_output=True, text=True, timeout=10
            )
            txt = (r.stdout or "") + (r.stderr or "")
            if txt.strip():
                return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', txt)[-3500:]
            lf = f"/root/.pm2/logs/{self.service_name}-out.log"
            if os.path.exists(lf):
                with open(lf) as f:
                    return f.read()[-3500:] or "Empty"
            return "No logs yet."
        except Exception as e:
            return f"Log error: {e}"

    def start(self) -> bool:
        try:
            if self.bot_type in ("nodejs", "whatsapp"):
                pkg = os.path.join(self.bot_dir, "package.json")
                use_npm = False
                main_file = "index.js"
                if os.path.exists(pkg):
                    try:
                        with open(pkg) as f:
                            p = json.load(f)
                            use_npm = bool(p.get("scripts", {}).get("start"))
                            main_file = p.get("main", "index.js")
                    except Exception:
                        pass
                if use_npm:
                    r = subprocess.run(
                        ["pm2", "start", "npm", "--name", self.service_name, "--", "start"],
                        capture_output=True, text=True, timeout=25, cwd=self.bot_dir
                    )
                else:
                    target = os.path.join(self.bot_dir, main_file)
                    if not os.path.exists(target):
                        for f in os.listdir(self.bot_dir):
                            if f.endswith(".js"):
                                target = os.path.join(self.bot_dir, f); break
                    r = subprocess.run(
                        ["pm2", "start", target, "--name", self.service_name],
                        capture_output=True, text=True, timeout=25, cwd=self.bot_dir
                    )
                subprocess.run(["pm2", "save"], capture_output=True, timeout=5)
                return r.returncode == 0
            else:
                main_file = "main.py"
                for mf in ("main.py", "bot.py", "app.py", "run.py"):
                    if os.path.exists(os.path.join(self.bot_dir, mf)):
                        main_file = mf; break
                target = os.path.join(self.bot_dir, main_file)
                r = subprocess.run(
                    ["pm2", "start", target, "--name", self.service_name,
                     "--interpreter", "python3", "--cwd", self.bot_dir],
                    capture_output=True, text=True, timeout=25
                )
                subprocess.run(["pm2", "save"], capture_output=True, timeout=5)
                return r.returncode == 0
        except Exception as e:
            log_err(f"start {self.name}: {e}")
            return False

    def stop(self) -> bool:
        try:
            subprocess.run(["pm2", "stop", self.service_name], capture_output=True, timeout=15)
            return True
        except Exception:
            return False

    def restart(self) -> bool:
        try:
            subprocess.run(["pm2", "restart", self.service_name], capture_output=True, timeout=15)
            return True
        except Exception:
            return False

    def delete(self):
        try:
            subprocess.run(["pm2", "delete", self.service_name], capture_output=True, timeout=10)
            subprocess.run(["pm2", "save"], capture_output=True, timeout=5)
        except Exception:
            pass

# ================== SYSTEM MONITOR ==================
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

def get_system_stats():
    if not HAS_PSUTIL: return None
    cpu = psutil.cpu_percent(interval=0.3)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    up = time.time() - psutil.boot_time()
    td = timedelta(seconds=int(up))
    d, h, m = td.days, td.seconds // 3600, (td.seconds % 3600) // 60
    uptime = " ".join(x for x in (f"{d}d" if d else "", f"{h}h" if h else "", f"{m}m") if x) or "0m"
    return {
        "cpu": cpu,
        "ram_used": ram.used / (1024**3), "ram_total": ram.total / (1024**3),
        "ram_pct": ram.percent,
        "disk_used": disk.used / (1024**3), "disk_total": disk.total / (1024**3),
        "disk_pct": disk.percent, "uptime": uptime,
    }

# ================== KEYBOARDS ==================
def kb_main():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🤖 My Bots", callback_data="my_bots")],
        [InlineKeyboardButton("📦 Deploy New Bot", callback_data="deploy")],
        [InlineKeyboardButton("📊 VPS Status", callback_data="vps_status")],
        [InlineKeyboardButton("⚙️ Settings", callback_data="settings")],
        [InlineKeyboardButton("📢 Channel", url=SUPPORT_CHANNEL)],
    ])

def kb_bot_actions(bid, running):
    rows = []
    if running:
        rows.append([
            InlineKeyboardButton("🔴 Stop", callback_data=f"stop:{bid}"),
            InlineKeyboardButton("🔄 Restart", callback_data=f"restart:{bid}"),
        ])
    else:
        rows.append([InlineKeyboardButton("🟢 Start", callback_data=f"start:{bid}")])
    rows.append([
        InlineKeyboardButton("📋 Logs", callback_data=f"logs:{bid}"),
        InlineKeyboardButton("📊 Status", callback_data=f"bot_status:{bid}"),
    ])
    rows.append([InlineKeyboardButton("🗑️ Delete", callback_data=f"delete:{bid}")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="my_bots")])
    return InlineKeyboardMarkup(rows)

def kb_back(to="menu"):
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data=to)]])

def kb_confirm_delete(bid):
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("❌ Cancel", callback_data=f"bot_detail:{bid}"),
        InlineKeyboardButton("✅ Delete", callback_data=f"confirm_delete:{bid}"),
    ]])

def kb_deploy_types():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🟢 Node.js Bot", callback_data="deploy_type:nodejs")],
        [InlineKeyboardButton("🐍 Python Bot", callback_data="deploy_type:python")],
        [InlineKeyboardButton("💬 WhatsApp Bot (Baileys)", callback_data="deploy_type:whatsapp")],
        [InlineKeyboardButton("🔙 Back", callback_data="menu")],
    ])

# ================== HANDLERS ==================
async def safe_edit(query, text, markup=None):
    try:
        is_media = bool(query.message and (
            query.message.video or query.message.photo or
            query.message.animation or query.message.document))
        if is_media:
            try: await query.message.delete()
            except Exception: pass
            await query.message.chat.send_message(text, parse_mode="Markdown", reply_markup=markup)
        else:
            await query.edit_message_text(text, parse_mode="Markdown", reply_markup=markup)
    except BadRequest as e:
        if "Message is not modified" not in str(e):
            raise

async def check_access(update) -> bool:
    u = update.effective_user
    if not u: return False
    if not await can_use(u.id):
        if update.callback_query:
            try: await update.callback_query.answer("🔒 Premium required", show_alert=True)
            except Exception: pass
        elif update.message:
            await update.message.reply_text(
                f"🔒 Access denied.\nYour ID: `{u.id}`", parse_mode="Markdown")
        return False
    return True

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u: return
    if not await can_use(u.id):
        await update.message.reply_text(f"🔒 Access denied.\nYour ID: `{u.id}`", parse_mode="Markdown")
        return
    caption = (
        "🤖 **VPS Bot Hosting Manager**\n\n"
        "🟢 Node.js | 🐍 Python | 💬 WhatsApp\n\n"
        f"User ID: `{u.id}`\n"
        "➡️ Pick an option below."
    )
    try:
        await update.message.reply_video(
            video=HOME_VIDEO_URL,
            caption=caption,
            parse_mode="Markdown",
            reply_markup=kb_main()
        )
    except Exception as e:
        log_err(f"cmd_start reply_video failed: {e}")
        await update.message.reply_text(caption, parse_mode="Markdown", reply_markup=kb_main())

async def cmd_unlock(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or u.id != OWNER_ID: return
    args = ctx.args
    if not args or args[0].lower() not in ("on", "off"):
        cur = await DB.is_unlocked()
        await update.message.reply_text(
            f"Status: {'🔓 UNLOCKED' if cur else '🔒 LOCKED'}\nUse `/unlock on|off`",
            parse_mode="Markdown")
        return
    await DB.set_unlocked(args[0].lower() == "on")
    await update.message.reply_text(f"✅ Set to **{args[0].upper()}**", parse_mode="Markdown")

async def cmd_addpremium(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or u.id not in ADMIN_IDS: return
    if not ctx.args:
        await update.message.reply_text("Usage: `/addpremium <user_id>`", parse_mode="Markdown")
        return
    try: tid = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user ID"); return
    await DB.add_premium(tid, u.id)
    await update.message.reply_text(f"✅ Added premium: `{tid}`", parse_mode="Markdown")

async def cmd_removepremium(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or u.id not in ADMIN_IDS: return
    if not ctx.args:
        await update.message.reply_text("Usage: `/removepremium <user_id>`", parse_mode="Markdown")
        return
    try: tid = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("Invalid ID"); return
    ok = await DB.remove_premium(tid)
    await update.message.reply_text(f"{'✅ Removed' if ok else '❌ Not found'}: `{tid}`", parse_mode="Markdown")

async def cmd_unmute(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or u.id not in ADMIN_IDS: return
    if not ctx.args:
        await update.message.reply_text("Usage: `/unmute <user_id>`", parse_mode="Markdown")
        return
    try:
        tid = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user ID")
        return
    ok = await DB.unmute_user(tid)
    await update.message.reply_text(
        f"{'✅ Unmuted' if ok else '❌ Not muted'}: `{tid}`", parse_mode="Markdown")

async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u: return
    was_waiting = bool(ctx.user_data.get("awaiting_zip"))
    ctx.user_data["awaiting_zip"] = False
    ctx.user_data.pop("deploy_type", None)
    await update.message.reply_text(
        "✅ Cancelled — no longer waiting for a ZIP." if was_waiting
        else "Nothing to cancel.")

async def cmd_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or u.id not in ADMIN_IDS: return
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM pending_deploys WHERE status='pending' ORDER BY created_at DESC LIMIT 50")
        rows = await cur.fetchall()
    if not rows:
        await update.message.reply_text("✅ No pending deploys.")
        return
    for r in rows:
        txt = (
            f"⏳ **Pending Deploy**\n"
            f"User: `{r['user_id']}`\nBot: `{r['name']}` ({r['bot_type']})\n"
            f"ID: `{r['bot_id']}`"
        )
        await update.message.reply_text(txt, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Approve", callback_data=f"host_approve:{r['bot_id']}"),
                InlineKeyboardButton("❌ Reject", callback_data=f"host_reject:{r['bot_id']}"),
            ]]))

async def cb_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    u = update.effective_user
    if not await check_access(update): return

    data = q.data or ""
    parts = data.split(":")
    action = parts[0] if parts else ""
    bid = parts[1] if len(parts) > 1 else ""

    if action in ("host_approve", "host_reject") and bid and u.id not in ADMIN_IDS:
        try: await q.answer("Admin only", show_alert=True)
        except Exception: pass
        return

    try: await q.answer()
    except Exception: pass

    if data == "menu":
        await safe_edit(q, "🤖 **VPS Bot Manager**\n\n➡️ Pick an option:", kb_main())
    elif data == "my_bots":
        await show_my_bots(update, ctx)
    elif action == "bot_detail" and bid:
        await show_bot_detail(update, ctx, bid)
    elif action in ("start", "stop", "restart") and bid:
        await do_action(update, ctx, bid, action)
    elif action == "logs" and bid:
        await show_logs(update, ctx, bid)
    elif action == "bot_status" and bid:
        await show_bot_status(update, ctx, bid)
    elif action == "delete" and bid:
        await safe_edit(q, "⚠️ **Delete this bot?**", kb_confirm_delete(bid))
    elif action == "confirm_delete" and bid:
        await do_delete(update, ctx, bid)
    elif data == "deploy":
        await safe_edit(q, "📦 **Deploy New Bot**\n\n➡️ Choose type:", kb_deploy_types())
    elif action == "deploy_type" and bid:
        ctx.user_data["deploy_type"] = bid
        ctx.user_data["awaiting_zip"] = True
        await safe_edit(q,
            f"📦 **Deploy {bid.title()} Bot**\n\n➡️ Send a ZIP with your bot code.",
            kb_back("deploy"))
    elif data == "vps_status":
        await show_vps(update, ctx)
    elif data == "refresh_vps":
        await show_vps(update, ctx)
    elif data == "settings":
        txt = (
            "⚙️ **Settings**\n\n"
            f"Your ID: `{u.id}`\n"
            f"Premium: `{await DB.is_premium(u.id)}`\n"
            f"Bots: `{await DB.count_user_bots(u.id)}`"
        )
        await safe_edit(q, txt, kb_back("menu"))
    elif action == "host_approve" and bid:
        await execute_approval(bid, u.id, approve=True)
        try: await q.edit_message_text(f"✅ Approved: `{bid}`", parse_mode="Markdown")
        except Exception: pass
    elif action == "host_reject" and bid:
        await execute_approval(bid, u.id, approve=False)
        try: await q.edit_message_text(f"❌ Rejected: `{bid}`", parse_mode="Markdown")
        except Exception: pass

async def show_my_bots(update, ctx):
    q = update.callback_query
    u = update.effective_user
    bots = await DB.get_user_bots(u.id)
    if u.id not in ADMIN_IDS:
        bots = {k: v for k, v in bots.items() if v["user_id"] == u.id}
    if not bots:
        await safe_edit(q, "⚠️ **No bots deployed yet.**",
            InlineKeyboardMarkup([
                [InlineKeyboardButton("📦 Deploy", callback_data="deploy")],
                [InlineKeyboardButton("🔙 Back", callback_data="menu")],
            ]))
        return
    rows = []
    for bid, info in bots.items():
        b = HostedBot(bid, info["name"], info["dir"], info["type"], info["user_id"])
        st = "🟢" if b.is_running() else "🔴"
        emo = {"nodejs": "🟢", "python": "🐍", "whatsapp": "💬"}.get(info["type"], "🤖")
        rows.append([InlineKeyboardButton(f"{st} {emo} {info['name']}", callback_data=f"bot_detail:{bid}")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="menu")])
    await safe_edit(q, f"🤖 **Your Bots** ({len(bots)})", InlineKeyboardMarkup(rows))

async def show_bot_detail(update, ctx, bid):
    q = update.callback_query
    u = update.effective_user
    bots = await DB.get_user_bots(u.id)
    if bid not in bots:
        try: await q.answer("Not found", show_alert=True)
        except Exception: pass
        return
    info = bots[bid]
    if u.id not in ADMIN_IDS and info["user_id"] != u.id:
        try: await q.answer("Not yours", show_alert=True)
        except Exception: pass
        return
    b = HostedBot(bid, info["name"], info["dir"], info["type"], info["user_id"])
    running = b.is_running()
    txt = (
        f"🤖 **{info['name']}**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Status: `{'Running' if running else 'Stopped'}`\n"
        f"Type: `{info['type']}`\n"
        f"Owner: `{info['user_id']}`\n"
        f"Dir: `{info['dir']}`\n"
    )
    await safe_edit(q, txt, kb_bot_actions(bid, running))

async def do_action(update, ctx, bid, action):
    q = update.callback_query
    u = update.effective_user
    bots = await DB.get_user_bots(u.id)
    if bid not in bots: return
    info = bots[bid]
    if u.id not in ADMIN_IDS and info["user_id"] != u.id:
        try: await q.answer("Not yours", show_alert=True)
        except Exception: pass
        return
    b = HostedBot(bid, info["name"], info["dir"], info["type"], info["user_id"])
    ok = False
    if action == "start": ok = b.start()
    elif action == "stop": ok = b.stop()
    elif action == "restart": ok = b.restart()
    await asyncio.sleep(0.5)
    await show_bot_detail(update, ctx, bid)
    try: await q.answer(f"{'✅' if ok else '❌'} {action} {'ok' if ok else 'failed'}", show_alert=not ok)
    except Exception: pass

async def show_logs(update, ctx, bid):
    q = update.callback_query
    u = update.effective_user
    bots = await DB.get_user_bots(u.id)
    if bid not in bots: return
    info = bots[bid]
    if u.id not in ADMIN_IDS and info["user_id"] != u.id: return
    b = HostedBot(bid, info["name"], info["dir"], info["type"], info["user_id"])
    logs = b.get_logs(25)
    txt = f"📋 **Logs: {info['name']}**\n```\n{logs[-3000:]}\n```"
    await safe_edit(q, txt, InlineKeyboardMarkup([[
        InlineKeyboardButton("🔙 Back", callback_data=f"bot_detail:{bid}")
    ]]))

async def show_bot_status(update, ctx, bid):
    q = update.callback_query
    u = update.effective_user
    bots = await DB.get_user_bots(u.id)
    if bid not in bots: return
    info = bots[bid]
    if u.id not in ADMIN_IDS and info["user_id"] != u.id: return
    b = HostedBot(bid, info["name"], info["dir"], info["type"], info["user_id"])
    txt = (
        f"📊 **Status: {info['name']}**\n"
        f"Running: `{b.is_running()}`\n"
        f"Service: `{b.service_name}`"
    )
    await safe_edit(q, txt, InlineKeyboardMarkup([[
        InlineKeyboardButton("🔙 Back", callback_data=f"bot_detail:{bid}")
    ]]))

async def do_delete(update, ctx, bid):
    q = update.callback_query
    u = update.effective_user
    bots = await DB.get_user_bots(u.id)
    if bid not in bots: return
    info = bots[bid]
    if u.id not in ADMIN_IDS and info["user_id"] != u.id: return
    b = HostedBot(bid, info["name"], info["dir"], info["type"], info["user_id"])
    b.stop(); b.delete()
    try:
        if os.path.exists(info["dir"]):
            shutil.rmtree(info["dir"], ignore_errors=True)
    except Exception: pass
    await DB.remove_bot(bid)
    await safe_edit(q, "✅ Bot deleted.", kb_back("my_bots"))

async def show_vps(update, ctx):
    q = update.callback_query
    st = get_system_stats()
    if not st:
        await safe_edit(q, "❌ psutil not installed.", kb_back("menu"))
        return
    txt = (
        f"📊 **VPS Status**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💻 CPU: `{st['cpu']:.1f}%`\n"
        f"🧠 RAM: `{st['ram_used']:.2f}/{st['ram_total']:.2f} GB ({st['ram_pct']}%)`\n"
        f"💾 Disk: `{st['disk_used']:.2f}/{st['disk_total']:.2f} GB ({st['disk_pct']}%)`\n"
        f"⏱️ Uptime: `{st['uptime']}`"
    )
    await safe_edit(q, txt, InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh", callback_data="refresh_vps")],
        [InlineKeyboardButton("🔙 Back", callback_data="menu")],
    ]))

# ================== UPLOAD ==================
async def handle_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not await can_use(u.id): return
    if not ctx.user_data.get("awaiting_zip"): return
    doc = update.message.document
    if not doc: return

    if await DB.is_muted(u.id):
        await update.message.reply_text(
            "🚫 You're temporarily muted due to a flagged upload. Try again later.")
        return

    if doc.file_size is None:
        await update.message.reply_text(
            "❌ ZIP file size could not be determined. Please upload the ZIP again.")
        return

    if doc.file_size > MAX_ZIP_SIZE_MB * 1024 * 1024:
        await update.message.reply_text(f"❌ ZIP too big (max {MAX_ZIP_SIZE_MB}MB)")
        return

    bot_type = ctx.user_data.get("deploy_type", "python")
    ctx.user_data["awaiting_zip"] = False

    if u.id not in ADMIN_IDS:
        cnt = await DB.count_user_bots(u.id) + await DB.count_user_pending(u.id)
        if cnt >= MAX_BOTS_PER_USER:
            await update.message.reply_text(
                f"❌ Max {MAX_BOTS_PER_USER} bots per user (including pending review).")
            return

    status = await update.message.reply_text("⏳ Downloading...")

    async with DEPLOY_SEMAPHORE:
        staging = None
        try:
            f = await ctx.bot.get_file(doc.file_id)
            fb = await f.download_as_bytearray()

            if len(fb) > MAX_ZIP_SIZE_MB * 1024 * 1024:
                await status.edit_text(f"❌ ZIP too big (max {MAX_ZIP_SIZE_MB}MB)")
                return

            bot_id = f"{u.id}_{uuid.uuid4().hex[:8]}"
            bot_name = doc.file_name.rsplit(".", 1)[0][:30]

            staging = HOSTED_BOTS_DIR / f"_staging_{bot_id}"
            staging.mkdir(parents=True, exist_ok=True)
            os.chmod(staging, 0o700)

            zp = staging / "temp.zip"
            with open(zp, "wb") as fp:
                fp.write(fb)

            await status.edit_text("📦 Extracting...")
            await asyncio.to_thread(_safe_zip_extract, zp, staging)
            zp.unlink()

            await status.edit_text("🔎 Scanning...")
            sr = await asyncio.to_thread(scan_directory, staging)

            if sr["verdict"] == "clear":
                final_dir = HOSTED_BOTS_DIR / bot_id
                shutil.move(str(staging), str(final_dir))
                staging = None

                await DB.add_bot(bot_id, u.id, bot_name, str(final_dir), bot_type)
                b = HostedBot(bot_id, bot_name, str(final_dir), bot_type, u.id)
                started = b.start()

                if started:
                    await status.edit_text(
                        f"✅ **Deployed!**\nName: `{bot_name}`\n"
                        f"Files scanned: `{sr['files_scanned']}`",
                        parse_mode="Markdown", reply_markup=kb_back("my_bots"))
                else:
                    await status.edit_text(
                        f"⚠️ **Registered, but failed to start.**\nName: `{bot_name}`\n"
                        f"Check logs from the bot's detail page and try Start again.",
                        parse_mode="Markdown", reply_markup=kb_back("my_bots"))
            else:
                await DB.add_pending(bot_id, u.id, bot_name, str(staging),
                                     bot_type, sr["flagged_files"])
                staging = None  # don't delete on finally

                admin_text = (
                    f"🚨 **Pending Deploy — Review**\n\n"
                    f"👤 User: `{u.id}` (@{u.username or 'no_username'})\n"
                    f"🤖 Bot: `{bot_name}` ({bot_type})\n"
                    f"🆔 ID: `{bot_id}`\n\n"
                    f"📊 Files: `{sr['files_scanned']}` scanned, "
                    f"`{len(sr['flagged_files'])}` flagged\n"
                    f"🔴 High: `{sr['high_count']}` | 🟡 Medium: `{sr['medium_count']}`\n\n"
                    f"**Findings:**\n{_build_findings_text(sr)}"
                )
                markup = {"inline_keyboard": [[
                    {"text": "✅ Approve", "callback_data": f"approve:{bot_id}"},
                    {"text": "❌ Reject", "callback_data": f"reject:{bot_id}"},
                ]]}
                await notify_admin_via_approval_bot(admin_text, markup)

                await status.edit_text(
                    f"⏳ **Under Review**\n\n"
                    f"Scanner flagged `{len(sr['flagged_files'])}` file(s).\n"
                    f"Admin will review shortly.",
                    parse_mode="Markdown")
        except Exception as e:
            log_err(f"deploy: {e}", traceback.format_exc())
            await status.edit_text(f"❌ Deploy failed: `{str(e)[:150]}`", parse_mode="Markdown")
            if staging and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

# ================== APPROVAL (backup path from hosting bot) ==================
async def _claim_pending(bot_id: str):
    """Atomically flip pending -> processing so a double-click (or a race
    with approval_bot.py's own execute_approval, which shares this DB)
    can only ever be acted on once."""
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM pending_deploys WHERE bot_id=?", (bot_id,))
        row = await cur.fetchone()
        if not row:
            return None
        upd = await conn.execute(
            "UPDATE pending_deploys SET status='processing' WHERE bot_id=? AND status='pending'",
            (bot_id,)
        )
        await conn.commit()
        if upd.rowcount != 1:
            return None
        return dict(row)

async def execute_approval(bot_id, admin_id, approve: bool):
    """Backup path: admin clicks from hosting bot. Only updates DB;
    notification_worker will DM user via hosting bot's own token."""
    p = await _claim_pending(bot_id)
    if not p:
        return False
    staging = Path(p["staging_dir"])

    try:
        if not approve:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            await DB.set_pending_status(bot_id, "rejected", admin_id,
                                        reason="admin rejected after review")
            await DB.mute_user(p["user_id"], MUTE_DURATION_HOURS, "flagged upload")
            return True

        if not staging.exists():
            # Staging already gone with no registry entry means a previous
            # attempt crashed after the move but before it recorded success —
            # don't fabricate a "rejected" over a bot actually sitting deployed.
            existing = await DB.get_user_bots(p["user_id"])
            if bot_id in existing:
                await DB.set_pending_status(bot_id, "approved", admin_id,
                                            reason="admin approved (recovered)")
                return True
            await DB.set_pending_status(bot_id, "rejected", admin_id, "staging missing")
            return False

        final_dir = HOSTED_BOTS_DIR / bot_id
        shutil.move(str(staging), str(final_dir))
        await DB.add_bot(bot_id, p["user_id"], p["name"], str(final_dir), p["bot_type"])
        b = HostedBot(bot_id, p["name"], str(final_dir), p["bot_type"], p["user_id"])
        started = b.start()
        reason = "admin approved" if started else "admin approved (pm2 start failed — check logs)"
        await DB.set_pending_status(bot_id, "approved", admin_id, reason=reason)
        return True
    except Exception as e:
        log_err(f"execute_approval: {e}", traceback.format_exc())
        await DB.set_pending_status(bot_id, "error", admin_id, reason=f"exception: {e}"[:200])
        return False

# ================== NOTIFICATION WORKER ==================
async def notification_worker(app):
    """Polls DB for approved/rejected deploys and DMs users via hosting bot token."""
    while True:
        try:
            async with aiosqlite.connect(DATABASE_PATH) as conn:
                conn.row_factory = aiosqlite.Row
                cur = await conn.execute("""
                    SELECT * FROM pending_deploys
                    WHERE status IN ('approved','rejected')
                      AND reviewed_at IS NOT NULL
                      AND bot_id NOT IN (SELECT bot_id FROM notified_users)
                """)
                rows = await cur.fetchall()

                # Retain notification history for 7 days, then clean it up.
                cleanup_cutoff = (
                    datetime.now() - timedelta(days=NOTIFIED_USERS_RETENTION_DAYS)
                ).isoformat()
                await conn.execute(
                    "DELETE FROM notified_users "
                    "WHERE notified_at IS NOT NULL AND notified_at < ?",
                    (cleanup_cutoff,)
                )

                for r in rows:
                    if r["status"] == "approved":
                        msg = (
                            f"✅ **Bot approved, deploy started!**\n"
                            f"Name: `{r['name']}`\n"
                            f"Type: `{r['bot_type']}`"
                        )
                        if r["reason"] and "failed" in r["reason"].lower():
                            msg += f"\n⚠️ `{r['reason'][:200]}`"
                    else:
                        reason = r["reason"] or "N/A"
                        msg = (
                            f"❌ **Bot rejected by admin.**\n"
                            f"Name: `{r['name']}`\n"
                            f"Reason: `{reason[:200]}`\n"
                            f"You've been muted for {MUTE_DURATION_HOURS}h."
                        )
                    try:
                        await app.bot.send_message(r["user_id"], msg, parse_mode="Markdown")
                        log_notify(f"{r['status']} -> user {r['user_id']} (bot {r['bot_id']})")
                        await conn.execute(
                            "INSERT OR REPLACE INTO notified_users VALUES (?,?)",
                            (r["bot_id"], datetime.now().isoformat())
                        )
                    except Exception as e:
                        # Leave it unmarked so the worker can retry later.
                        log_err(f"notify {r['user_id']}: {e}")
                await conn.commit()
        except Exception as e:
            log_err(f"notification_worker: {e}")
        await asyncio.sleep(NOTIFY_POLL_SECONDS)

# ================== STALE CLEANUP ==================
async def cleanup_stale_pending():
    cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT bot_id,staging_dir FROM pending_deploys WHERE status='pending' AND created_at<?",
            (cutoff,))
        rows = await cur.fetchall()
        for r in rows:
            d = Path(r["staging_dir"])
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
            await conn.execute(
                "UPDATE pending_deploys SET status='expired' WHERE bot_id=?", (r["bot_id"],))
        await conn.commit()

# ================== MAIN ==================
def main():
    if not BOT_TOKEN:
        print("No BOT_TOKEN"); sys.exit(1)

    async def _boot():
        await init_db()
        await cleanup_stale_pending()
    asyncio.run(_boot())

    async def _post_init(app):
        asyncio.create_task(notification_worker(app))
        print(f"👂 Notification worker started (poll: {NOTIFY_POLL_SECONDS}s)")

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(_post_init)
        .build()
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("unlock", cmd_unlock))
    app.add_handler(CommandHandler("addpremium", cmd_addpremium))
    app.add_handler(CommandHandler("removepremium", cmd_removepremium))
    app.add_handler(CommandHandler("pending", cmd_pending))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CallbackQueryHandler(cb_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    print("🤖 Hosting panel bot started.")
    app.run_polling()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
