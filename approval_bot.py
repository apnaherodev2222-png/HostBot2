#!/usr/bin/env python3
"""
🛡️ Approval Bot — Admin interface for pending deploys.
Only touches shared DB. User DMs handled by hosting bot's notification worker.
"""
from __future__ import annotations
import os, sys, shutil, subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict

import aiosqlite
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes
)

# ================== CONFIG ==================
APPROVAL_BOT_TOKEN = "8529511149:AAGSFMzraaKEBL0KDrbXZit9TsPZ5xJ68_U"
OWNER_ID           = 5628671567
ADMIN_IDS          = [5628671567]

HOSTED_BOTS_DIR = Path("/root/hosted_bots")
DATABASE_PATH   = HOSTED_BOTS_DIR / "inf" / "bot_data.db"
LOGS_DIR        = Path("/root/hosted_bots_logs")
MUTE_HOURS      = 2

LOGS_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

async def ensure_schema():
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
            CREATE TABLE IF NOT EXISTS muted_users (
                user_id INTEGER PRIMARY KEY,
                mute_until TEXT NOT NULL,
                reason TEXT
            );
        """)
        await conn.commit()

def log(msg, extra=None):
    try:
        with open(LOGS_DIR / "approval_bot.log", "a") as f:
            f.write(f"[{datetime.now()}] {msg}\n")
            if extra: f.write(f"EXTRA: {extra}\n")
    except Exception:
        pass

# ================== DB ==================
async def get_pending(bot_id: str) -> Optional[Dict]:
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM pending_deploys WHERE bot_id=?", (bot_id,))
        r = await cur.fetchone()
        return dict(r) if r else None

async def set_pending(bot_id: str, status: str, admin_id: int, reason: str = None):
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        await conn.execute(
            "UPDATE pending_deploys SET status=?,reviewed_by=?,reviewed_at=?,reason=? WHERE bot_id=?",
            (status, admin_id, datetime.now().isoformat(), reason, bot_id)
        )
        await conn.commit()

async def add_bot(bot_id, uid, name, bdir, btype):
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        await conn.execute(
            "INSERT OR REPLACE INTO bot_registry VALUES (?,?,?,?,?,?,?)",
            (bot_id, uid, name, bdir, btype, datetime.now().isoformat(), None)
        )
        await conn.commit()

async def mute_user(uid, hours, reason):
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        await conn.execute(
            "INSERT OR REPLACE INTO muted_users VALUES (?,?,?)",
            (uid, (datetime.now() + timedelta(hours=hours)).isoformat(), reason)
        )
        await conn.commit()

# ================== PM2 START ==================
def start_pm2(bot_id, bot_dir, bot_type):
    svc = f"hosted-bot-{bot_id}"
    try:
        if bot_type in ("nodejs", "whatsapp"):
            target = None
            for f in os.listdir(bot_dir):
                if f.endswith(".js"):
                    target = os.path.join(bot_dir, f); break
            if not target: return False
            r = subprocess.run(["pm2", "start", target, "--name", svc],
                               capture_output=True, text=True, timeout=25, cwd=bot_dir)
        else:
            main = "main.py"
            for mf in ("main.py", "bot.py", "app.py", "run.py"):
                if os.path.exists(os.path.join(bot_dir, mf)):
                    main = mf; break
            target = os.path.join(bot_dir, main)
            r = subprocess.run(
                ["pm2", "start", target, "--name", svc,
                 "--interpreter", "python3", "--cwd", bot_dir],
                capture_output=True, text=True, timeout=25
            )
        subprocess.run(["pm2", "save"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception as e:
        log(f"pm2 start {bot_id}: {e}")
        return False

# ================== APPROVE / REJECT ==================
async def claim_pending(bot_id: str) -> Optional[Dict]:
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

async def get_bot_registry_entry(bot_id: str) -> Optional[Dict]:
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM bot_registry WHERE bot_id=?", (bot_id,))
        r = await cur.fetchone()
        return dict(r) if r else None

async def execute_approval(bot_id: str, admin_id: int, approve: bool) -> bool:
    p = await claim_pending(bot_id)
    if not p:
        return False
    staging = Path(p["staging_dir"])

    try:
        if not approve:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            await set_pending(bot_id, "rejected", admin_id, "admin rejected after review")
            await mute_user(p["user_id"], MUTE_HOURS, "flagged upload")
            return True

        if not staging.exists():
            if await get_bot_registry_entry(bot_id):
                await set_pending(bot_id, "approved", admin_id, "admin approved (recovered)")
                return True
            await set_pending(bot_id, "rejected", admin_id, "staging missing")
            return False

        final_dir = HOSTED_BOTS_DIR / bot_id
        shutil.move(str(staging), str(final_dir))
        await add_bot(bot_id, p["user_id"], p["name"], str(final_dir), p["bot_type"])
        started = start_pm2(bot_id, str(final_dir), p["bot_type"])
        reason = "admin approved" if started else "admin approved (pm2 start failed — check logs)"
        await set_pending(bot_id, "approved", admin_id, reason)
        return True
    except Exception as e:
        log(f"execute_approval: {e}")
        await set_pending(bot_id, "error", admin_id, f"exception: {e}"[:200])
        return False

# ================== HANDLERS ==================
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u: return
    if u.id not in ADMIN_IDS:
        await update.message.reply_text(f"🔒 Admin only.\nYour ID: `{u.id}`", parse_mode="Markdown")
        return
    await update.message.reply_text(
        "🛡️ **Approval Bot**\n\n"
        "I notify you when a user uploads a flagged ZIP.\n"
        "Use the buttons in my alerts to Approve or Reject.\n\n"
        "Commands:\n"
        "`/pending` — list pending\n"
        "`/whoami` — your ID",
        parse_mode="Markdown"
    )

async def cmd_whoami(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if u:
        await update.message.reply_text(f"Your ID: `{u.id}`", parse_mode="Markdown")

async def cmd_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or u.id not in ADMIN_IDS: return
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT * FROM pending_deploys WHERE status='pending' ORDER BY created_at DESC LIMIT 50"
        )
        rows = await cur.fetchall()
    if not rows:
        await update.message.reply_text("✅ No pending deploys.")
        return
    for r in rows:
        txt = (
            f"⏳ **Pending**\n"
            f"👤 User: `{r['user_id']}`\n"
            f"🤖 Bot: `{r['name']}` ({r['bot_type']})\n"
            f"🆔 ID: `{r['bot_id']}`"
        )
        markup = InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ Approve", callback_data=f"approve:{r['bot_id']}"),
            InlineKeyboardButton("❌ Reject",  callback_data=f"reject:{r['bot_id']}"),
        ]])
        await update.message.reply_text(txt, parse_mode="Markdown", reply_markup=markup)

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
    async with aiosqlite.connect(DATABASE_PATH) as conn:
        cur = await conn.execute("DELETE FROM muted_users WHERE user_id=?", (tid,))
        await conn.commit()
        changed = cur.rowcount > 0
    await update.message.reply_text(
        f"{'✅ Unmuted' if changed else '❌ Not muted'}: `{tid}`", parse_mode="Markdown")

async def cb_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    u = update.effective_user

    if u.id not in ADMIN_IDS:
        try: await q.answer("Admin only", show_alert=True)
        except Exception: pass
        return

    try: await q.answer()
    except Exception: pass

    data = q.data or ""
    if ":" not in data: return
    action, bot_id = data.split(":", 1)
    if action not in ("approve", "reject"): return

    ok = await execute_approval(bot_id, u.id, approve=(action == "approve"))
    try:
        await q.edit_message_text(
            ("✅ Approved: " if action == "approve" else "❌ Rejected: ") + f"`{bot_id}`",
            parse_mode="Markdown"
        )
    except Exception:
        pass

# ================== MAIN ==================
async def _post_init(app):
    """Runs inside PTB's own event loop. Safe place for async setup."""
    await ensure_schema()

def main():
    if not APPROVAL_BOT_TOKEN:
        print("No approval token"); sys.exit(1)

    app = (
        Application.builder()
        .token(APPROVAL_BOT_TOKEN)
        .post_init(_post_init)
        .build()
    )
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("pending", cmd_pending))
    app.add_handler(CommandHandler("whoami", cmd_whoami))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CallbackQueryHandler(cb_handler))

    print("🛡️ Approval bot started.")
    app.run_polling()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
