"""What a plan buys: storage room, and how long an item is kept.

Both are read from the tenant's *current* plan every time they are needed -- neither is
copied onto the item at store time. That is what makes an upgrade protect items already
stored and a downgrade subject them, immediately and with no migration.

Unknown plan values fail closed to the free limits. A plan string arrives from the
database, so an unrecognised one means either an unfinished migration or a corrupted row;
handing it the paid allowance would make the cheapest way past a quota a bad write.
"""

from __future__ import annotations

from datetime import timedelta

FREE_PLAN = "free"
PAID_PLAN = "paid"
KNOWN_PLANS = (FREE_PLAN, PAID_PLAN)

FREE_QUOTA_BYTES = 100 * 1024 * 1024
PAID_QUOTA_BYTES = 5 * 1024 * 1024 * 1024
FREE_RETENTION = timedelta(days=7)


def quota_bytes(plan: str) -> int:
    return PAID_QUOTA_BYTES if plan == PAID_PLAN else FREE_QUOTA_BYTES


def retention_for(plan: str) -> timedelta | None:
    """How long an item of this plan's tenant is kept, or None for kept-until-deleted."""
    return None if plan == PAID_PLAN else FREE_RETENTION
