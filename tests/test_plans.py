from datetime import timedelta

import pytest

from steepd.config import Settings
from steepd.plans import (
    FREE_PLAN,
    KNOWN_PLANS,
    PAID_PLAN,
    quota_bytes,
    retention_for,
)


@pytest.fixture(params=[{}, {"free_quota_bytes": 4096, "paid_quota_bytes": 8192, "free_retention": timedelta(days=14)}])
def settings(tmp_path, request):
    return Settings(data_dir=tmp_path, public_base_url="http://localhost:8000", **request.param)


def test_free_is_capped_and_expires_while_paid_is_roomier_and_kept(settings):
    assert quota_bytes(FREE_PLAN, settings=settings) == settings.free_quota_bytes
    assert quota_bytes(PAID_PLAN, settings=settings) == settings.paid_quota_bytes
    assert retention_for(FREE_PLAN, settings=settings) == settings.free_retention
    assert retention_for(PAID_PLAN, settings=settings) is None


@pytest.mark.parametrize("plan", ["", "PAID", "enterprise", "paid ", "trial"])
def test_an_unrecognised_plan_gets_the_free_limits(plan, settings):
    """Fail closed. A plan string only ever arrives from the database, so an unknown one
    means a bad row or an unfinished migration -- and giving that the paid allowance would
    make a corrupt write the cheapest way past both the quota and retention."""
    assert quota_bytes(plan, settings=settings) == settings.free_quota_bytes
    assert retention_for(plan, settings=settings) == settings.free_retention


def test_known_plans_covers_exactly_the_two_plans_that_exist():
    """The retention sweep iterates KNOWN_PLANS, so a plan missing from it is a plan whose
    items are never swept."""
    assert set(KNOWN_PLANS) == {FREE_PLAN, PAID_PLAN}
