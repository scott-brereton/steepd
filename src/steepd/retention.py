"""The periodic sweep: expire items past their plan's retention, and drop dead auth rows.

What an item's retention is comes from its tenant's plan *at sweep time* (steepd.plans),
never from anything stamped on the item. An upgrade therefore rescues items that were
already inside their last day, and a downgrade puts old items in scope for the next pass.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

# _utc, not a local copy: it rejects naive datetimes instead of reading them as system
# local time, and a second implementation is a second thing that can quietly lose that.
from steepd.auth import _utc
from steepd.db import Database
from steepd.plans import KNOWN_PLANS, retention_for
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

LOGGER = logging.getLogger("steepd.retention")


# Well past the longest retry schedule Resend's webhook delivery runs, so a row is only
# dropped once nothing could ever legitimately replay its event id.
WEBHOOK_EVENT_RETENTION = timedelta(days=30)

# Long enough that someone who signed up and then went away for a week can still follow the
# link in their inbox; past that the row is only holding a name nobody claimed.
PENDING_TENANT_RETENTION = timedelta(days=7)

# The refusal list is a diagnostic -- "why did nothing arrive?" -- and a sender nobody has
# tried in a month is no longer part of that answer.
REFUSED_SENDER_RETENTION = timedelta(days=30)


@dataclass(frozen=True, slots=True)
class SweepResult:
    items_deleted: int
    sessions_pruned: int
    magic_tokens_pruned: int
    webhook_events_pruned: int = 0
    pending_tenants_deleted: int = 0
    refused_senders_pruned: int = 0


def run_sweep(database: Database, storage: ItemStorage, *, now: datetime | None = None) -> SweepResult:
    moment = _utc(now)
    stamp = moment.isoformat()

    items_deleted = 0
    for plan in KNOWN_PLANS:
        retention = retention_for(plan)
        if retention is None:
            continue
        cutoff = (moment - retention).isoformat()
        # Pages are re-read from the start rather than walked by offset: a successful
        # delete removes the row that was just read. `progressed` is the termination
        # guard -- a page whose items all fail to delete would otherwise be read forever.
        while True:
            expired = database.list_items_past_retention(cutoff=cutoff, plan=plan)
            progressed = False
            for item in expired:
                try:
                    if storage.delete(TenantScope(item.tenant_id), item.id):
                        items_deleted += 1
                        progressed = True
                except Exception:
                    # One unreadable file or wedged row must not cost the rest of the pass,
                    # including the session and token pruning below.
                    LOGGER.exception("Retention could not delete item id=%s", item.id)
            if not progressed:
                break

    return SweepResult(
        items_deleted=items_deleted,
        sessions_pruned=database.delete_expired_sessions(now=stamp),
        magic_tokens_pruned=database.prune_magic_tokens(now=stamp),
        webhook_events_pruned=database.prune_webhook_events(before=(moment - WEBHOOK_EVENT_RETENTION).isoformat()),
        pending_tenants_deleted=database.delete_unconfirmed_tenants(
            before=(moment - PENDING_TENANT_RETENTION).isoformat()
        ),
        refused_senders_pruned=database.prune_refused_senders(before=(moment - REFUSED_SENDER_RETENTION).isoformat()),
    )


def start_retention_thread(
    database: Database,
    storage: ItemStorage,
    *,
    interval_seconds: float = 3600.0,
) -> threading.Thread:
    """Run run_sweep forever on a daemon thread, and return it.

    Daemon so a shutdown is never held up by a sleeping sweep, and every exception is
    caught per pass: retention that dies on one bad pass is worse than useless, because
    nothing else reports that items stopped expiring.
    """

    def loop() -> None:
        while True:
            try:
                result = run_sweep(database, storage)
            except Exception:
                LOGGER.exception("Retention sweep failed")
            else:
                if any(
                    (
                        result.items_deleted,
                        result.sessions_pruned,
                        result.magic_tokens_pruned,
                        result.webhook_events_pruned,
                        result.pending_tenants_deleted,
                        result.refused_senders_pruned,
                    )
                ):
                    LOGGER.info(
                        "Retention swept items=%d sessions=%d magic_tokens=%d webhook_events=%d "
                        "pending_tenants=%d refused_senders=%d",
                        result.items_deleted,
                        result.sessions_pruned,
                        result.magic_tokens_pruned,
                        result.webhook_events_pruned,
                        result.pending_tenants_deleted,
                        result.refused_senders_pruned,
                    )
            time.sleep(interval_seconds)

    thread = threading.Thread(target=loop, name="steepd-retention", daemon=True)
    thread.start()
    return thread
