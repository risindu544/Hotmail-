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
log = logging.getLogger("bulk-checker")

EMAIL_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9]"
    r"(?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$", re.I)

# ============================================================
# CLASSIFICATION
#   LIVE    = syntax ok + MX present (domain resolves, MX answers)
#   DEAD    = syntax ok but domain NXDOMAIN / no MX / no A
#   UNKNOWN = syntax ok but DNS timed out / network error / retries exhausted
#   SKIP    = bad syntax or non-Microsoft domain (not counted)
# ============================================================
LIVE, DEAD, UNKNOWN, SKIP = "live", "dead", "unknown", "skip"

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
    status      TEXT NOT NULL DEFAULT 'running',   -- running | done | stopped | error
    total       INTEGER NOT NULL DEFAULT 0,
    processed   INTEGER NOT NULL DEFAULT 0,
    live        INTEGER NOT NULL DEFAULT 0,
    dead        INTEGER NOT NULL DEFAULT 0,
    unknown     INTEGER NOT NULL DEFAULT 0,
    started_at  REAL NOT NULL,
    finished_at REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_chat   ON jobs(chat_id, status);

CREATE TABLE IF NOT EXISTS emails (
    job_id  INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    email   TEXT NOT NULL,
    status  TEXT NOT NULL DEFAULT 'pending',   -- pending | done
    verdict TEXT,                                -- live | dead | unknown | skip
    detail  TEXT,
    mx_hosts TEXT,
    checked_at REAL,
    PRIMARY KEY (job_id, email)
);
CREATE INDEX IF NOT EXISTS idx_emails_job_status ON emails(job_id, status);
CREATE INDEX IF NOT EXISTS idx_emails_job_verdict ON emails(job_id, verdict);

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
def create_job(chat_id: int, user_id: int, emails: list[str]) -> int:
    with closing(_db()) as c:
        cur = c.execute(
            "INSERT INTO jobs(chat_id,user_id,total,started_at) VALUES(?,?,?,?)",
            (chat_id, user_id, len(emails), time.time()))
        job_id = cur.lastrowid
        c.executemany("INSERT OR IGNORE INTO emails(job_id,email) VALUES(?,?)",
                      [(job_id, e) for e in emails]); c.commit()
        return job_id

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

def bump(job_id: int, verdict: str):
    """Increment processed and the right bucket, atomically."""
    col = {"live": "live", "dead": "dead", "unknown": "unknown"}.get(verdict)
    with closing(_db()) as c:
        if col:
            c.execute(f"UPDATE jobs SET processed=processed+1, {col}={col}+1 WHERE id=?",
                      (job_id,))
        else:
            c.execute("UPDATE jobs SET processed=processed+1 WHERE id=?", (job_id,))
        c.commit()

def record(job_id: int, email: str, verdict: str,
           detail: str = "", mx_hosts: str = ""):
    with closing(_db()) as c:
        c.execute(
            "UPDATE emails SET status='done', verdict=?, detail=?, mx_hosts=?, "
            "checked_at=? WHERE job_id=? AND email=?",
            (verdict, detail, mx_hosts, time.time(), job_id, email))
        c.commit()

def pending_emails(job_id: int) -> list[str]:
    with closing(_db()) as c:
        return [r["email"] for r in c.execute(
            "SELECT email FROM emails WHERE job_id=? AND status='pending'",
            (job_id,)).fetchall()]

def emails_by_verdict(job_id: int, verdict: str) -> list[sqlite3.Row]:
    with closing(_db()) as c:
        return c.execute(
            "SELECT * FROM emails WHERE job_id=? AND verdict=? ORDER BY email",
            (job_id, verdict)).fetchall()

def counts(job_id: int) -> dict:
    with closing(_db()) as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return {"live": r["live"], "dead": r["dead"],
                "unknown": r["unknown"], "processed": r["processed"],
                "total": r["total"], "status": r["status"]}

def stats_for_chat(chat_id: int) -> dict:
    with closing(_db()) as c:
        r = c.execute(
            "SELECT COUNT(*) AS jobs, COALESCE(SUM(processed),0) AS proc, "
            "       COALESCE(SUM(live),0) AS live, "
            "       COALESCE(SUM(dead),0) AS dead, "
            "       COALESCE(SUM(unknown),0) AS unk "
            "FROM jobs WHERE chat_id=?", (chat_id,)).fetchone()
        return dict(r)

# ============================================================
# DNS — returns (verdict, mx_hosts, detail)
# ============================================================
def mx_lookup_sync(domain: str) -> tuple[str, str, str]:
    for attempt in range(DNS_RETRIES + 1):
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT + 2
        try:
            answers = resolver.resolve(domain, "MX")
            hosts = sorted({str(r.exchange).rstrip(".") for r in answers})
            if hosts:
                return LIVE, ", ".join(hosts), "mx_ok"
            return DEAD, "", "mx_empty"
        except dns.resolver.NXDOMAIN:
            return DEAD, "", "nxdomain"
        except dns.resolver.NoAnswer:
            return DEAD, "", "no_mx_record"
        except dns.resolver.NoNameservers:
            if attempt == DNS_RETRIES:
                return UNKNOWN, "", "no_nameservers"
            time.sleep(0.3 * (attempt + 1))
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            if attempt == DNS_RETRIES:
                return UNKNOWN, "", "dns_timeout"
            time.sleep(0.3 * (attempt + 1))
        except Exception as exc:
            log.warning("MX unexpected %s: %s", domain, exc)
            return UNKNOWN, "", f"err:{type(exc).__name__}"
    return UNKNOWN, "", "retries_exhausted"

async def classify_one(email: str) -> tuple[str, str, str, str]:
    """Returns (email, verdict, mx_hosts, detail)."""
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return email, SKIP, "", "syntax_invalid"
    local, domain = email.rsplit("@", 1)
    if len(local) > 64:
        return email, SKIP, "", "local_too_long"
    if domain not in ALLOWED_DOMAINS:
        return email, SKIP, "", "domain_not_allowed"
    verdict, hosts, detail = await asyncio.to_thread(mx_lookup_sync, domain)
    return email, verdict, hosts, detail

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
# DUMP — three sections
# ============================================================
def build_dump(job_id: int, partial: bool = False) -> bytes:
    job = get_job(job_id)
    live = emails_by_verdict(job_id, LIVE)
    dead = emails_by_verdict(job_id, DEAD)
    unk  = emails_by_verdict(job_id, UNKNOWN)

    def _fmt(r):
        mx = f" ({r['mx_hosts']})" if r['mx_hosts'] else ""
        det = f" [{r['detail']}]" if r['detail'] else ""
        return f"  {r['email']}{mx}{det}"

    lines = [
        "HOTMAIL / OUTLOOK BULK CHECK — LIVE / DEAD / UNKNOWN",
        "=" * 60,
        f"Job ID:      {job_id}",
        f"Status:      {'PARTIAL' if partial else job['status'].upper()}",
        f"Started:     {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(job['started_at']))}",
        f"Total:       {job['total']}",
        f"Processed:   {job['processed']}",
        f"Live:        {job['live']}",
        f"Dead:        {job['dead']}",
        f"Unknown:     {job['unknown']}",
        "Verification: DOMAIN_LEVEL_ONLY — mailbox existence NOT verified",
        "=" * 60,
        "",
        f"### LIVE ({len(live)})",
        *[_fmt(r) for r in live] if live else ["  (none)"],
        "",
        f"### DEAD ({len(dead)})",
        *[_fmt(r) for r in dead] if dead else ["  (none)"],
        "",
        f"### UNKNOWN ({len(unk)})",
        *[_fmt(r) for r in unk] if unk else ["  (none)"],
        "",
        "=" * 60,
        f"LIVE={job['live']}  DEAD={job['dead']}  UNKNOWN={job['unknown']}",
        "=" * 60,
    ]
    return "\n".join(lines).encode("utf-8")

# ============================================================
# PROGRESS (single edited message)
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
async def run_job(ctx: ContextTypes.DEFAULT_TYPE, job_id: int):
    job = get_job(job_id)
    if not job: return
    chat_id = job["chat_id"]
    prog = Progress(ctx.bot, chat_id)
    try:
        todo = pending_emails(job_id)
        for i in range(0, len(todo), BATCH_SIZE):
            jr = get_job(job_id)
            if not jr or jr["status"] != "running":
                break
            batch = todo[i:i + BATCH_SIZE]
            results = await asyncio.gather(*(classify_one(e) for e in batch))
            for email, verdict, hosts, detail in results:
                record(job_id, email, verdict, detail, hosts)
                bump(job_id, verdict)
            c = counts(job_id)
            await prog.update(
                f"⏳ {c['processed']}/{c['total']}\n"
                f"🟢 LIVE {c['live']}   🔴 DEAD {c['dead']}   ⚪ UNK {c['unknown']}")

        update_job(job_id, status="done", finished_at=time.time())
        content = build_dump(job_id)
        bio = io.BytesIO(content); bio.name = f"checker_dump_{job_id}.txt"
        c = counts(job_id)
        await ctx.bot.send_document(
            chat_id=chat_id, document=bio,
            caption=(f"✅ Done — 🟢 {c['live']} live · "
                     f"🔴 {c['dead']} dead · ⚪ {c['unknown']} unknown"))
        await prog.update(
            f"✅ Done — LIVE {c['live']}  DEAD {c['dead']}  UNKNOWN {c['unknown']}",
            force=True)

    except asyncio.CancelledError:
        update_job(job_id, status="stopped", finished_at=time.time())
        content = build_dump(job_id, partial=True)
        bio = io.BytesIO(content); bio.name = f"checker_dump_{job_id}_partial.txt"
        try:
            c = counts(job_id)
            await ctx.bot.send_document(
                chat_id=chat_id, document=bio,
                caption=(f"🛑 Stopped — 🟢 {c['live']} 🔴 {c['dead']} ⚪ {c['unknown']}. "
                         f"/resume to continue."))
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
    "<b>Bulk Checker — live / dead / unknown</b>\n\n"
    "<b>Lifecycle</b>\n"
    "/check — upload .txt or .csv\n"
    "/status — live counters\n"
    "/stop — cancel (partial dump kept)\n"
    "/resume — restart a stopped job\n"
    "/dump — full three-section dump\n"
    "/live — list live entries\n"
    "/dead — list dead entries\n"
    "/unknown — list unknown entries\n"
    "/export — CSV export\n"
    "/stats — lifetime totals\n\n"
    "<b>Admin</b>\n"
    "/broadcast &lt;text&gt;\n"
    "/cleanup [hours]\n\n"
    "<i>Verification: DOMAIN_LEVEL_ONLY — mailbox existence NOT verified.</i>\n"
    "<i>LIVE = MX present · DEAD = NXDOMAIN/no MX · UNKNOWN = timeout/error</i>"
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
        "📤 Upload .txt or .csv. Each email classified LIVE / DEAD / UNKNOWN.")

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
        f"🔴 DEAD:    {job['dead']}\n"
        f"⚪ UNKNOWN: {job['unknown']}\n"
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
    ctx.chat_data["task"] = asyncio.create_task(run_job(ctx, row["id"]))
    await update.message.reply_text(
        f"▶️ Resuming #{row['id']} — {len(pending_emails(row['id']))} left.")

async def dump_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = latest_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job to dump.")
        return
    content = build_dump(job["id"], partial=(job["status"] != "done"))
    bio = io.BytesIO(content); bio.name = f"checker_dump_{job['id']}.txt"
    await update.message.reply_document(
        document=bio,
        caption=(f"#{job['id']} — 🟢 {job['live']} · "
                 f"🔴 {job['dead']} · ⚪ {job['unknown']}"))

async def _list_verdict(update: Update, ctx: ContextTypes.DEFAULT_TYPE, verdict: str,
                         label: str):
    job = latest_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job.")
        return
    rows = emails_by_verdict(job["id"], verdict)
    if not rows:
        await update.message.reply_text(f"No {label} entries in job #{job['id']}.")
        return
    lines = [f"<b>{label.upper()} ({len(rows)})</b>"]
    for r in rows[:200]:
        detail = f" [{r['detail']}]" if r['detail'] else ""
        mx = f" ({r['mx_hosts']})" if r['mx_hosts'] else ""
        lines.append(f"<code>{r['email']}</code>{mx}{detail}")
    if len(rows) > 200:
        lines.append(f"… +{len(rows)-200} more. Use /dump for full.")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)

async def live_cmd(update, ctx):    await _list_verdict(update, ctx, LIVE,    "live")
async def dead_cmd(update, ctx):    await _list_verdict(update, ctx, DEAD,    "dead")
async def unknown_cmd(update, ctx): await _list_verdict(update, ctx, UNKNOWN, "unknown")

async def export_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    job = latest_job(update.effective_chat.id)
    if not job:
        await update.message.reply_text("No job.")
        return
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["email", "verdict", "detail", "mx_hosts", "verification"])
    with closing(_db()) as c:
        for r in c.execute(
            "SELECT * FROM emails WHERE job_id=? AND status='done' ORDER BY email",
            (job["id"],)):
            w.writerow([r["email"], r["verdict"], r["detail"], r["mx_hosts"],
                        "DOMAIN_LEVEL_ONLY"])
    data = buf.getvalue().encode("utf-8")
    bio = io.BytesIO(data); bio.name = f"checker_{job['id']}.csv"
    await update.message.reply_document(
        document=bio, caption=f"CSV — job #{job['id']}")

async def stats_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    s = stats_for_chat(update.effective_chat.id)
    await update.message.reply_text(
        f"<b>Lifetime</b>\nJobs: {s['jobs']}\nProcessed: {s['proc']}\n"
        f"🟢 Live: {s['live']}\n🔴 Dead: {s['dead']}\n⚪ Unknown: {s['unk']}",
        parse_mode=ParseMode.HTML)

async def broadcast_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("Admin only."); return
    text = " ".join(ctx.args)
    if not text:
        await update.message.reply_text("Usage: /broadcast <text>"); return
    with closing(_db()) as c:
        ids = [r["chat_id"] for r in c.execute(
            "SELECT DISTINCT chat_id FROM jobs").fetchall()]
    ok = 0
    for cid in ids:
        try: await ctx.bot.send_message(cid, text); ok += 1
        except Exception: pass
        await asyncio.sleep(0.05)
    await update.message.reply_text(f"Sent to {ok}/{len(ids)}.")

async def cleanup_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("Admin only."); return
    hours = 24
    if ctx.args:
        try: hours = int(ctx.args[0])
        except: pass
    cutoff = time.time() - hours * 3600
    with closing(_db()) as c:
        n = c.execute(
            "DELETE FROM jobs WHERE status IN ('done','stopped','error') "
            "AND finished_at<?", (cutoff,)).rowcount
        c.commit()
    await update.message.reply_text(f"Deleted {n} old jobs (>{hours}h).")

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
                        update.effective_user.id, emails)
    ctx.chat_data["task"] = asyncio.create_task(run_job(ctx, job_id))
    await update.message.reply_text(
        f"✅ Job #{job_id} — {len(emails)} emails.\n"
        f"Classification: 🟢 LIVE (MX ok) · 🔴 DEAD (no MX) · ⚪ UNKNOWN (timeout).\n"
        f"/live /dead /unknown anytime. /dump for the full report.")

# ============================================================
# RECOVERY
# ============================================================
async def recover(app: Application):
    with closing(_db()) as c:
        rows = c.execute("SELECT * FROM jobs WHERE status='running'").fetchall()
    for r in rows:
        log.info("recover job %s (%s pending)", r["id"],
                 len(pending_emails(r["id"])))

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
        ("dump", dump_cmd),
        ("live", live_cmd), ("dead", dead_cmd), ("unknown", unknown_cmd),
        ("export", export_cmd), ("stats", stats_cmd),
        ("broadcast", broadcast_cmd), ("cleanup", cleanup_cmd),
    ]:
        app.add_handler(CommandHandler(name, fn))
    app.add_handler(MessageHandler(filters.Document.ALL, process_file))
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()