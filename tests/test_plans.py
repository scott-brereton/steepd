from datetime import timedelta

import pytest

from steepd.plans import (
    FREE_PLAN,
    FREE_QUOTA_BYTES,
    FREE_RETENTION,
    KNOWN_PLANS,
    PAID_PLAN,
    PAID_QUOTA_BYTES,
    quota_bytes,
    retention_for,
)


def test_the_published_limits_are_what_the_pricing_page_promises():
    assert FREE_QUOTA_BYTES == 100 * 1024 * 1024
    assert PAID_QUOTA_BYTES == 5 * 1024 * 1024 * 1024
    assert FREE_RETENTION == timedelta(days=7)


def test_free_is_capped_and_expires_while_paid_is_roomier_and_kept():
    assert quota_bytes(FREE_PLAN) == FREE_QUOTA_BYTES
    assert quota_bytes(PAID_PLAN) == PAID_QUOTA_BYTES
    assert retention_for(FREE_PLAN) == FREE_RETENTION
    assert retention_for(PAID_PLAN) is None


@pytest.mark.parametrize("plan", ["", "PAID", "enterprise", "paid ", "trial"])
def test_an_unrecognised_plan_gets_the_free_limits(plan):
    """Fail closed. A plan string only ever arrives from the database, so an unknown one
    means a bad row or an unfinished migration -- and giving that the paid allowance would
    make a corrupt write the cheapest way past both the quota and retention."""
    assert quota_bytes(plan) == FREE_QUOTA_BYTES
    assert retention_for(plan) == FREE_RETENTION


def test_known_plans_covers_exactly_the_two_plans_that_exist():
    """The retention sweep iterates KNOWN_PLANS, so a plan missing from it is a plan whose
    items are never swept."""
    assert set(KNOWN_PLANS) == {FREE_PLAN, PAID_PLAN}
