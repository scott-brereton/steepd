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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from steepd.config import Settings

FREE_PLAN = "free"
PAID_PLAN = "paid"
KNOWN_PLANS = (FREE_PLAN, PAID_PLAN)


def quota_bytes(plan: str, *, settings: Settings) -> int:
    return settings.paid_quota_bytes if plan == PAID_PLAN else settings.free_quota_bytes


def retention_for(plan: str, *, settings: Settings) -> timedelta | None:
    """How long an item of this plan's tenant is kept, or None for kept-until-deleted."""
    return None if plan == PAID_PLAN else settings.free_retention
