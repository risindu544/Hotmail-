import asyncio
import csv
import io
import logging
import os
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Optional

import dns.resolver
from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application, CommandHandler, ContextTypes, MessageHandler, filters
)

# ============================================================
# CONFIG
# ============================================================
BOT_TOKEN     = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS     = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()}
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "20"))
BATCH_SIZE    = int(os.getenv("BATCH_SIZE", "100"))
DNS_TIMEOUT   = float(os.getenv("DNS_TIMEOUT", "4"))
DNS_RETRIES   = int(os.getenv("DNS_RETRIES", "2"))
RATE_LIMIT    = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))
DATA_DIR      = Path(os.getenv("DATA_DIR", "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH       = DATA_DIR / "checker.db"

ALLOWED_DOMAINS = {
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.it", "hotmail.es",
    "outlook.co.uk", "outlook.fr", "outlook.de", "outlook.jp",
    "live.co.uk", "live.fr", "live.de", "live.it", "live.nl",
    "live.ca", "live.com.au",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("live-checker")

EMAIL_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9]"
    r"(?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$", re.I)

LIVE = "live"

# ============================================================
# DB
# ============================================================
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id     INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    total       INTEGER NOT NULL DEFAULT 0,
    processed   INTEGER NOT NULL DEFAULT 0,
    live        INTEGER NOT NULL DEFAULT 0,
    started_at  REAL NOT NULL,
    finished_at REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_chat ON jobs(chat_id, status);

CREATE TABLE IF NOT EXISTS live_emails (
    job_id     INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    mx_hosts   TEXT,
    checked_at REAL,
    PRIMARY KEY (job_id, email)
);
CREATE INDEX IF NOT EXISTS idx_live_job ON live_emails(job_id);

CREATE TABLE IF NOT EXISTS rate (
    user_id INTEGER NOT NULL,
    window  INTEGER NOT NULL,
    count   INTEGER NOT NULL,
    PRIMARY KEY (user_id, window)
);
"""

def _db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def db_init():
    with closing(_db()) as c:
        c.executescript(SCHEMA); c.commit()

# ============================================================
# RATE LIMIT
# ============================================================
def rate_check(user_id: int) -> bool:
    window = int(time.time() // 60)
    with closing(_db()) as c:
        row = c.execute("SELECT count FROM rate WHERE user_id=? AND window=?",
                        (user_id, window)).fetchone()
        n = (row["count"] if row else 0) + 1
        if n > RATE_LIMIT: return False
        c.execute("INSERT INTO rate(user_id,window,count) VALUES(?,?,?) "
                  "ON CONFLICT(user_id,window) DO UPDATE SET count=?",
                  (user_id, window, n, n)); c.commit()
    return True

# ============================================================
# JOB API
# ============================================================
def create_job(chat_id: int, user_id: int, total: int) -> int:
    with closing(_db()) as c:
        cur = c.execute(
            "INSERT INTO jobs(chat_id,user_id,total,started_at) VALUES(?,?,?,?)",
            (chat_id, user_id, total, time.time()))
        c.commit()
        return cur.lastrowid

def get_job(job_id: int) -> Optional[sqlite3.Row]:
    with closing(_db()) as c:
        return c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()

def active_job(chat_id: int) -> Optional[sqlite3.Row]:
    with closing(_db()) as c:
        return c.execute(
            "SELECT * FROM jobs WHERE chat_id=? AND status='running' "
            "ORDER BY id DESC LIMIT 1", (chat_id,)).fetchone()

def latest_job(chat_id: int) -> Optional[sqlite3.Row]:
    with closing(_db()) as c:
        return c.execute(
            "SELECT * FROM jobs WHERE chat_id=? ORDER BY id DESC LIMIT 1",
            (chat_id,)).fetchone()

def update_job(job_id: int, **fields):
    if not fields: return
    cols = ", ".join(f"{k}=?" for k in fields)
    with closing(_db()) as c:
        c.execute(f"UPDATE jobs SET {cols} WHERE id=?",
                  [*fields.values(), job_id]); c.commit()

def bump(job_id: int, hits: int):
    with closing(_db()) as c:
        c.execute("UPDATE jobs SET processed=processed+?, live=live+? WHERE id=?",
                  (hits, hits, job_id)); c.commit()

def record_live(job_id: int, email: str, mx_hosts: str):
    with closing(_db()) as c:
        c.execute(
            "INSERT OR IGNORE INTO live_emails(job_id,email,mx_hosts,checked_at) "
            "VALUES(?,?,?,?)", (job_id, email, mx_hosts, time.time()))
        c.commit()

def live_emails(job_id: int) -> list[sqlite3.Row]:
    with closing(_db()) as c:
        return c.execute(
            "SELECT * FROM live_emails WHERE job_id=? ORDER BY email",
            (job_id,)).fetchall()

def counts(job_id: int) -> dict:
    with closing(_db()) as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return {"live": r["live"], "processed": r["processed"],
                "total": r["total"], "status": r["status"]}

# ============================================================
# DNS
# ============================================================
def mx_lookup_sync(domain: str) -> tuple[bool, str]:
    for attempt in range(DNS_RETRIES + 1):
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT + 2
        try:
            answers = resolver.resolve(domain, "MX")
            hosts = sorted({str(r.exchange).rstrip(".") for r in answers})
            if hosts:
                return True, ", ".join(hosts)
            return False, ""
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False, ""
        except (dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout):
            if attempt == DNS_RETRIES:
                return False, ""
            time.sleep(0.3 * (attempt + 1))
        except Exception as exc:
            log.warning("MX unexpected %s: %s", domain, exc)
            return False, ""
    return False, ""

async def classify_one(email: str) -> tuple[str, bool, str]:
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return email, False, ""
    local, domain = email.rsplit("@", 1)
    if len(local) > 64:
        return email, False, ""
    if domain not in ALLOWED_DOMAINS:
        return email, False, ""
    ok, hosts = await asyncio.to_thread(mx_lookup_sync, domain)
    return email, ok, hosts

# ============================================================
# PARSER
# ============================================================
def extract_emails(raw: bytes, filename: str) -> list[str]:
    text = raw.decode("utf-8-sig", errors="replace")
    rows = csv.reader(io.StringIO(text)) if filename.lower().endswith(".csv") \
           else [ln.split() for ln in text.splitlines()]
    out, seen = [], set()
    for row in rows:
        for cell in row:
            for tok in re.split(r"[\s,;]+", (cell or "").strip()):
                tok = tok.strip('"').strip("'").lower()
                if "@" not in tok or tok in seen: continue
                seen.add(tok); out.append(tok)
    return out

# ============================================================
# DUMP — live only
# ============================================================
def build_live_dump(job_id: int, partial: bool = False) -> bytes:
    job = get_job(job_id)
    rows = live_emails(job_id)

    lines = [
        "HOTMAIL / OUTLOOK LIVE DUMP",
        "=" * 60,
        f"Job ID:      {job_id}",
        f"Status:      {'PARTIAL' if partial else job['status'].upper()}",
        f"Started:     {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(job['started_at']))}",
        f"Total:       {job['total']}",
        f"Processed:   {job['processed']}",
        f"LIVE:        {job['live']}",
        "Verification: DOMAIN_LEVEL_ONLY — mailbox existence NOT verified",
        "=" * 60,
        "",
        f"### LIVE ({len(rows)})",
        *([f"  {r['email']} ({r['mx_hosts']})" if r['mx_hosts'] else f"  {r['email']}" for r in rows] if rows else ["  (none)"]),
        "",
        "=" * 60,
        f"LIVE={job['live']}",
        "=" * 60,
    ]
    return "\n".join(lines).encode("utf-8")

# ============================================================
# PROGRESS
# ============================================================
class Progress:
    def __init__(self, bot, chat_id: int):
        self.bot, self.chat_id = bot, chat_id
        self.msg_id: Optional[int] = None
        self.last_edit = 0.0
    async def update(self, text: str, force: bool = False):
        now = time.time()
        if not force and now - self.last_edit < 2.0: return
        self.last_edit = now
        try:
            if self.msg_id is None:
                m = await self.bot.send_message(self.chat_id, text,
                                                 disable_notification=True)
                self.msg_id = m.message_id
            else:
                await self.bot.edit_message_text(
                    text, chat_id=self.chat_id, message_id=self.msg_id,
                    disable_web_page_preview=True)
        except Exception:
            pass

# ============================================================
# JOB RUNNER
# ============================================================
async def run_job(ctx: ContextTypes.DEFAULT_TYPE, job_id: int, emails: list[str]):
    job = get_job(job_id)
    if not job: return
    chat_id = job["chat_id"]
    prog = Progress(ctx.bot, chat_id)
    try:
        for i in range(0, len(emails), BATCH_SIZE):
            jr = get_job(job_id)
            if not jr or jr["status"] != "running":
                break
            batch = emails[i:i + BATCH_SIZE]
            results = await asyncio.gather(*(classify_one(e) for e in batch))
            hits = 0
            for email, ok, hosts in results:
                if ok:
                    record_live(job_id, email, hosts)
                    hits += 1
            bump(job_id, hits)
            c = counts(job_id)
            await prog.update(
                f"⏳ {c['processed']}/{c['total']}\n🟢 LIVE {c['live']}")

        update_job(job_id, status="done", finished_at=time.time())
        content = build_live_dump(job_id)
        bio = io.BytesIO(content); bio.name = f"live_dump_{job_id}.txt"
        c = counts(job_id)
        await ctx.bot.send_document(
            chat_id=chat_id, document=bio,
            caption=f"✅ Done — 🟢 {c['live']} live out of {c['total']}")
        await prog.update(
            f"✅ Done — LIVE {c['live']} / {c['total']}", force=True)

    except asyncio.CancelledError:
        update_job(job_id, status="stopped", finished_at=time.time())
        content = build_live_dump(job_id, partial=True)
        bio = io.BytesIO(content); bio.name = f"live_dump_{job_id}_partial.txt"
        try:
            c = counts(job_id)
            await ctx.bot.send_document(
                chat_id=chat_id, document=bio,
                caption=f"🛑 Stopped — 🟢 {c['live']} live. /resume to continue.")
        except Exception:
            log.exception("partial dump failed")
        raise
    except Exception:
        log.exception("job %s failed", job_id)
        update_job(job_id, status="error", finished_at=time.time())
        try:
            await ctx.bot.send_message(chat_id,
                text="❌ Job failed — /dump for partial results.")
        except Exception:
            pass

# ============================================================
# HANDLERS
# ============================================================
HELP = (
    "<b>Hotmail Live Checker</b>\n\n"
    "<b>Lifecycle</b>\n"
    "/check — upload .txt or .csv\n"
    "/status — live counters\n"
    "/stop — cancel (partial dump kept)\n"
    "/resume — restart a stopped job\n"
    "/dump — full live dump\n"
    "/live — list live entries\n"
    "/export — CSV export\n\n"
    "<i>Verification: DOMAIN_LEVEL_ONLY — mailbox existence NOT verified.</i>\n"
    "<i>LIVE = syntax valid + allowed Microsoft domain + MX present</i>"
)

async def _guard(update: Update) -> bool:
    if not rate_check(update.effective_user.id):
        await update.message.reply_text(
            f"Rate limit ({RATE_LIMIT}/min). Try later.")
        return False
    return True

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP, parse_mode=ParseMode.HTML)

async def help_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP, parse_mode=ParseMode.HTML)

async def check_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _guard(update): return
    await update.message.reply_text(
        "📤 Upload .txt or .csv. Only valid Microsoft domains with MX will be kept.")

async def status_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = active_job(update.effective_chat.id) or latest_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No jobs yet.")
        return
    elapsed = time.time() - job["started_at"]
    rate = job["processed"] / elapsed if elapsed > 0 else 0
    pct = (job["processed"] / job["total"] * 100) if job["total"] else 0
    text = (
        f"<b>Job #{job['id']}</b> — {job['status']}\n"
        f"Total:      {job['total']}\n"
        f"Processed:  {job['processed']} ({pct:.1f}%)\n"
        f"🟢 LIVE:    {job['live']}\n"
        f"Remaining:  {job['total'] - job['processed']}\n"
        f"Speed:      {rate:.1f}/s\n"
        f"Elapsed:    {elapsed:.1f}s"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)

async def stop_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = active_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No active job.")
        return
    update_job(job["id"], status="stopped", finished_at=time.time())
    task = ctx.chat_data.get("task")
    if task and not task.done(): task.cancel()
    await update.message.reply_text(
        f"🛑 Stopping #{job['id']}. Partial dump incoming, /resume to continue.")

async def resume_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _guard(update): return
    with closing(_db()) as c:
        row = c.execute(
            "SELECT * FROM jobs WHERE chat_id=? AND status IN ('stopped','error') "
            "ORDER BY id DESC LIMIT 1", (update.effective_chat.id,)).fetchone()
    if not row:
        await update.message.reply_text("No stopped job.")
        return
    update_job(row["id"], status="running")
    await update.message.reply_text(
        f"▶️ Resuming #{row['id']}.")

async def dump_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = latest_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job to dump.")
        return
    content = build_live_dump(job["id"], partial=(job["status"] != "done"))
    bio = io.BytesIO(content); bio.name = f"live_dump_{job['id']}.txt"
    await update.message.reply_document(
        document=bio, caption=f"#{job['id']} — 🟢 {job['live']} live")

async def live_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = latest_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job.")
        return
    rows = live_emails(job["id"])
    if not rows:
        await update.message.reply_text(f"No live entries in job #{job['id']}.")
        return
    lines = [f"<b>LIVE ({len(rows)})</b>"]
    for r in rows[:200]:
        mx = f" ({r['mx_hosts']})" if r['mx_hosts'] else ""
        lines.append(f"<code>{r['email']}</code>{mx}")
    if len(rows) > 200:
        lines.append(f"… +{len(rows)-200} more. Use /dump for full.")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)

async def export_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = latest_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job.")
        return
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["email", "mx_hosts", "verification"])
    for r in live_emails(job["id"]):
        w.writerow([r["email"], r["mx_hosts"], "DOMAIN_LEVEL_ONLY"])
    data = buf.getvalue().encode("utf-8")
    bio = io.BytesIO(data); bio.name = f"live_{job['id']}.csv"
    await update.message.reply_document(
        document=bio, caption=f"CSV — job #{job['id']}")

# ============================================================
# FILE INTAKE
# ============================================================
async def process_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _guard(update): return
    doc = update.message.document
    if not doc: return
    filename = doc.file_name or "upload.txt"
    if not filename.lower().endswith((".txt", ".csv")):
        await update.message.reply_text("Please upload .txt or .csv."); return
    if doc.file_size and doc.file_size > MAX_UPLOAD_MB * 1024 * 1024:
        await update.message.reply_text(f"File exceeds {MAX_UPLOAD_MB} MB."); return
    if active_job(update.effective_chat.id):
        await update.message.reply_text("A job is running. /stop first."); return

    await update.message.chat.send_action(ChatAction.TYPING)
    tg = await ctx.bot.get_file(doc.file_id)
    raw = bytes(await tg.download_as_bytearray())
    emails = extract_emails(raw, filename)
    if not emails:
        await update.message.reply_text("No emails found."); return

    job_id = create_job(update.effective_chat.id,
                        update.effective_user.id, len(emails))
    ctx.chat_data["task"] = asyncio.create_task(run_job(ctx, job_id, emails))
    await update.message.reply_text(
        f"✅ Job #{job_id} — {len(emails)} emails.\n"
        f"Only valid syntax + allowed Microsoft domain + MX passes.\n"
        f"/live /dump anytime.")

# ============================================================
# RECOVERY
# ============================================================
async def recover(app: Application):
    with closing(_db()) as c:
        rows = c.execute("SELECT * FROM jobs WHERE status='running'").fetchall()
    for r in rows:
        log.info("recover job %s (%s pending)", r["id"], r["total"] - r["processed"])

# ============================================================
# ENTRY
# ============================================================
def main():
    if not BOT_TOKEN:
        raise SystemExit("Set BOT_TOKEN.")
    db_init()
    app = Application.builder().token(BOT_TOKEN).post_init(recover).build()
    for name, fn in [
        ("start", start), ("help", help_cmd), ("check", check_cmd),
        ("status", status_cmd), ("stop", stop_cmd), ("resume", resume_cmd),
        ("dump", dump_cmd), ("live", live_cmd), ("export", export_cmd),
    ]:
        app.add_handler(CommandHandler(name, fn))
    app.add_handler(MessageHandler(filters.Document.ALL, process_file))
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
