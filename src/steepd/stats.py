"""The operator's four lines: accounts, items, thirty days of inbound mail, and the volume.

Rendered once here and served two ways -- `python -m steepd stats` on the box, and
`GET /admin/stats` behind STATS_TOKEN from anywhere -- so the two can never disagree.
Emails *sent* are not counted; Resend's dashboard is the record of those.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from steepd.db import Database
from steepd.storage import ItemStorage

INBOUND_WINDOW = timedelta(days=30)


def human_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    value = float(size_bytes)
    for unit in ("KB", "MB", "GB"):
        value /= 1024
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}".replace(".0 ", " ")
    return f"{value:.1f} GB"


def render_stats(database: Database, storage: ItemStorage, *, now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    counts = database.stats(inbound_since=(moment - INBOUND_WINDOW).isoformat())
    report = storage.storage_report()
    pending = counts["tenants"] - counts["tenants_confirmed"]
    free_plan = counts["tenants_confirmed"] - counts["tenants_paid"]
    used = report.total_bytes - report.free_bytes
    low = "  (LOW)" if report.low else ""
    lines = [
        f"Accounts:       {counts['tenants']} ({counts['tenants_confirmed']} confirmed, {pending} pending); "
        f"{free_plan} free, {counts['tenants_paid']} paid",
        f"Items:          {counts['items']} ({counts['books']} books, {counts['articles']} articles), "
        f"{human_size(counts['item_bytes'])} stored",
        f"Inbound (30d):  {counts['inbound']} emails; {counts['inbound_filed']} filed, "
        f"{counts['inbound_rejected']} rejected, {counts['inbound_unknown_inbox']} to unknown inboxes, "
        f"{counts['inbound_sender_refused']} refused by sender policy",
        f"Volume:         {human_size(used)} used of {human_size(report.total_bytes)}, "
        f"{human_size(report.free_bytes)} free{low}",
    ]
    return "\n".join(lines) + "\n"
