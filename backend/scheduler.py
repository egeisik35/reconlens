"""
Background scheduler — re-checks all monitored domains every 24 hours.
Uses APScheduler's BackgroundScheduler (runs in a daemon thread).
"""
import json
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from database import get_conn
from monitor import take_snapshot, diff_snapshots
from mailer import send_alert

logger = logging.getLogger(__name__)
_scheduler = BackgroundScheduler(daemon=True)


def _check_all() -> None:
    """Job: iterate every stored monitor, diff, alert on changes."""
    conn = get_conn()
    rows = conn.execute("SELECT id, domain, email, snapshot FROM monitors").fetchall()
    conn.close()

    logger.info("Scheduler: checking %d monitors", len(rows))

    for row in rows:
        monitor_id = row["id"]
        domain     = row["domain"]
        email      = row["email"]

        try:
            old_snapshot = json.loads(row["snapshot"]) if row["snapshot"] else {}
            new_snapshot = take_snapshot(domain)
            changes      = diff_snapshots(old_snapshot, new_snapshot)

            now = datetime.now(timezone.utc).isoformat()
            conn = get_conn()
            conn.execute(
                "UPDATE monitors SET snapshot=?, last_checked=? WHERE id=?",
                (json.dumps(new_snapshot), now, monitor_id),
            )
            conn.commit()
            conn.close()

            if changes:
                logger.info("%s: %d change(s) — alerting %s", domain, len(changes), email)
                send_alert(domain=domain, email=email,
                           monitor_id=monitor_id, changes=changes)
            else:
                logger.info("%s: no changes", domain)

        except Exception as exc:
            logger.error("Monitor check failed for %s: %s", domain, exc, exc_info=True)


def start_scheduler() -> None:
    _scheduler.add_job(
        _check_all,
        trigger=IntervalTrigger(hours=24),
        id="check_all_monitors",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Scheduler started — monitors checked every 24 hours")


def stop_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
