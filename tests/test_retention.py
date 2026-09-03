import threading
from datetime import UTC, datetime, timedelta, timezone

import pytest

from steepd import app as app_module
from steepd import retention
from steepd.config import Settings
from steepd.db import Database
from steepd.epubgen import build_epub
from steepd.plans import FREE_PLAN, PAID_PLAN
from steepd.retention import SweepResult, run_sweep, start_retention_thread
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
PLUS_TEN = timezone(timedelta(hours=10))


@pytest.fixture
def service(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url="http://localhost:8000")
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    return database, storage


def _stored(database, storage, tenant_id, title, *, age_days):
    """Store a real EPUB, then age it. created_at is rewritten directly because the sweep
    reads it and nothing else can set it -- the file on disk is genuine, so a deletion is
    observable through the filesystem and not only through the row."""
    scope = TenantScope(tenant_id)
    payload = build_epub(
        title=title, author="Author", language="en", identifier=f"urn:uuid:{title}", body_html="<p>hi</p>"
    )
    item = storage.store_bytes(scope, payload, filename=f"{title}.epub", kind="book", source="email").item
    created_at = (NOW - timedelta(days=age_days)).isoformat()
    with database._connect() as connection:
        connection.execute("UPDATE items SET created_at = ? WHERE id = ?", (created_at, item.id))
    return storage.path_for(item), item


def test_old_webhook_event_rows_are_pruned_and_recent_ones_kept(service):
    """One row per inbound email, forever, was the only table without a sweep. Recent rows
    stay because a provider may still retry their event id; thirty-day-old ones cannot be."""
    database, storage = service
    ancient = (NOW - retention.WEBHOOK_EVENT_RETENTION - timedelta(days=1)).isoformat()
    recent = (NOW - timedelta(days=1)).isoformat()
    assert database.record_webhook_event("resend", "evt-old", ancient, "ok")
    assert database.record_webhook_event("resend", "evt-new", recent, "ok")

    result = run_sweep(database, storage, now=NOW)

    assert result.webhook_events_pruned == 1
    assert not database.webhook_event_exists("resend", "evt-old")
    assert database.webhook_event_exists("resend", "evt-new")


def test_a_free_tenants_item_past_seven_days_goes_and_a_younger_one_stays(service):
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    old_path, old_item = _stored(database, storage, tenant.id, "Old", age_days=8)
    fresh_path, fresh_item = _stored(database, storage, tenant.id, "Fresh", age_days=6)

    result = run_sweep(database, storage, now=NOW)

    assert result.items_deleted == 1
    scope = TenantScope(tenant.id)
    assert [item.id for item in database.list_items(scope)] == [fresh_item.id]
    assert database.get_item(scope, old_item.id) is None
    # The file goes with the row: an expired item that leaves its bytes on disk is a quota
    # the tenant can never get back.
    assert not old_path.exists()
    assert fresh_path.exists()


def test_a_paid_tenants_old_item_is_kept_until_they_delete_it(service):
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    database.set_tenant_plan(tenant.id, PAID_PLAN)
    path, item = _stored(database, storage, tenant.id, "Ancient", age_days=400)

    result = run_sweep(database, storage, now=NOW)

    assert result.items_deleted == 0
    assert database.get_item(TenantScope(tenant.id), item.id) is not None
    assert path.exists()


def test_upgrading_before_the_sweep_rescues_items_already_past_retention(service):
    """The plan-at-sweep-time property. Retention is not stamped on the item, so paying
    protects what is already stored -- there is no expiry to rewrite and no window in which
    a new subscriber loses the library they just paid to keep."""
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    path, item = _stored(database, storage, tenant.id, "Rescued", age_days=30)
    assert database.tenant_by_id(tenant.id).plan == FREE_PLAN

    database.set_tenant_plan(tenant.id, PAID_PLAN)
    result = run_sweep(database, storage, now=NOW)

    assert result.items_deleted == 0
    assert database.get_item(TenantScope(tenant.id), item.id) is not None
    assert path.exists()


def test_downgrading_puts_old_items_back_in_scope(service):
    """The other half of the same property, and the reason it is not merely convenient:
    an account that stops paying must stop consuming paid-tier storage."""
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    database.set_tenant_plan(tenant.id, PAID_PLAN)
    path, item = _stored(database, storage, tenant.id, "Lapsed", age_days=30)
    assert run_sweep(database, storage, now=NOW).items_deleted == 0

    database.set_tenant_plan(tenant.id, FREE_PLAN)
    result = run_sweep(database, storage, now=NOW)

    assert result.items_deleted == 1
    assert database.get_item(TenantScope(tenant.id), item.id) is None
    assert not path.exists()


def test_one_tenants_expiry_leaves_another_tenants_library_alone(service):
    database, storage = service
    alice = database.create_tenant(email="a@example.com", inbox_local="a.1")
    bob = database.create_tenant(email="b@example.com", inbox_local="b.2")
    database.set_tenant_plan(bob.id, PAID_PLAN)
    _stored(database, storage, alice.id, "Alice old", age_days=8)
    bob_path, bob_item = _stored(database, storage, bob.id, "Bob old", age_days=8)

    assert run_sweep(database, storage, now=NOW).items_deleted == 1

    assert database.list_items(TenantScope(alice.id)) == []
    assert database.get_item(TenantScope(bob.id), bob_item.id) is not None
    assert bob_path.exists()


def test_the_sweep_pages_past_the_query_limit(service):
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    for index in range(5):
        _stored(database, storage, tenant.id, f"Old {index}", age_days=8)

    result = run_sweep(database, storage, now=NOW)

    assert result.items_deleted == 5
    assert database.count_items(TenantScope(tenant.id)) == 0


def test_expired_sessions_and_spent_magic_links_are_pruned(service):
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    past = (NOW - timedelta(hours=1)).isoformat()
    future = (NOW + timedelta(hours=1)).isoformat()
    database.insert_session(token_hash="dead", tenant_id=tenant.id, created_at=past, expires_at=past)
    database.insert_session(token_hash="live", tenant_id=tenant.id, created_at=past, expires_at=future)
    database.insert_magic_token(token_hash="stale", tenant_id=tenant.id, expires_at=past)
    database.insert_magic_token(token_hash="pending", tenant_id=tenant.id, expires_at=future)

    result = run_sweep(database, storage, now=NOW)

    assert result == SweepResult(items_deleted=0, sessions_pruned=1, magic_tokens_pruned=1)
    assert database.session_tenant(token_hash="live", now=NOW.isoformat()).id == tenant.id
    with database._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM magic_tokens").fetchone()[0] == 1


def test_an_item_that_will_not_delete_does_not_abort_the_pass(service, monkeypatch):
    """One wedged item must not stop the rest of the sweep, or a single bad row freezes
    retention for every tenant until someone notices."""
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    _, doomed = _stored(database, storage, tenant.id, "Wedged", age_days=8)
    _, other = _stored(database, storage, tenant.id, "Deletable", age_days=8)
    database.insert_session(
        token_hash="dead", tenant_id=tenant.id, created_at=NOW.isoformat(),
        expires_at=(NOW - timedelta(hours=1)).isoformat(),
    )
    real_delete = storage.delete

    def flaky(scope, item_id):
        if item_id == doomed.id:
            raise OSError("disk is having a day")
        return real_delete(scope, item_id)

    monkeypatch.setattr(storage, "delete", flaky)
    result = run_sweep(database, storage, now=NOW)

    assert result.items_deleted == 1
    # The pass ran to the end: the session pruning after the item loop still happened.
    assert result.sessions_pruned == 1
    assert database.get_item(TenantScope(tenant.id), other.id) is None
    assert database.get_item(TenantScope(tenant.id), doomed.id) is not None


def test_a_naive_now_is_refused_rather_than_guessed_at(service):
    """Same doctrine as auth._utc: astimezone() would read a naive datetime as system local
    time, which in an eastern offset moves the cutoff forward and deletes items a day
    early."""
    database, storage = service
    with pytest.raises(ValueError):
        run_sweep(database, storage, now=datetime(2026, 3, 1, 12, 0))


def test_a_now_in_another_zone_is_converted_not_rejected(service):
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    _, item = _stored(database, storage, tenant.id, "Old", age_days=8)

    assert run_sweep(database, storage, now=NOW.astimezone(PLUS_TEN)).items_deleted == 1
    assert database.get_item(TenantScope(tenant.id), item.id) is None


class _IdleDatabase:
    """What the two thread tests sweep over. The thread has no stop signal by design -- it
    is a daemon that lives as long as the process -- so it keeps ticking after monkeypatch
    puts the real run_sweep back, and a bare object() there would spend the rest of the
    session printing AttributeError tracebacks from a test that already passed.
    """

    def list_items_past_retention(self, *, cutoff, plan, limit=500):
        return []

    def delete_expired_sessions(self, *, now):
        return 0

    def prune_webhook_events(self, *, before):
        return 0

    def prune_magic_tokens(self, *, now):
        return 0

    def delete_unconfirmed_tenants(self, *, before):
        return 0

    def prune_refused_senders(self, *, before):
        return 0


def test_the_thread_is_a_daemon_that_keeps_sweeping(monkeypatch):
    """Daemon so shutdown never waits on a sleeping sweep, and named so it is identifiable
    in a thread dump. run_sweep is stubbed rather than slept on: this test is about the
    loop, and a real interval would make it a timing test."""
    swept = threading.Event()
    calls = []

    def fake_sweep(database, storage, *, now=None):
        calls.append(now)
        swept.set()
        return SweepResult(items_deleted=0, sessions_pruned=0, magic_tokens_pruned=0)

    monkeypatch.setattr(retention, "run_sweep", fake_sweep)
    thread = start_retention_thread(_IdleDatabase(), None, interval_seconds=0.05)

    assert swept.wait(timeout=5.0), "the retention thread never ran a sweep"
    assert thread.daemon is True
    assert thread.name == "steepd-retention"
    assert calls[0] is None, "the loop must sweep against the real clock"


def test_a_failing_pass_does_not_kill_the_thread(monkeypatch):
    """Retention that dies on one exception is worse than no retention: nothing else
    reports that items have stopped expiring."""
    recovered = threading.Event()
    attempts = []

    def fake_sweep(database, storage, *, now=None):
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("database is locked")
        recovered.set()
        return SweepResult(items_deleted=0, sessions_pruned=0, magic_tokens_pruned=0)

    monkeypatch.setattr(retention, "run_sweep", fake_sweep)
    thread = start_retention_thread(_IdleDatabase(), None, interval_seconds=0.05)

    assert recovered.wait(timeout=5.0), "the thread stopped after the first failing pass"
    assert thread.is_alive()


@pytest.mark.parametrize(
    ("environment", "expected"),
    [("production", 1), ("development", 0)],
)
def test_only_a_production_app_grows_a_sweep_thread(tmp_path, monkeypatch, environment, expected):
    """The thread is real infrastructure, so the wiring is asserted rather than started:
    a test suite that spawned one per app would have sweeps deleting fixtures underneath
    other tests."""
    started = []
    monkeypatch.setattr(app_module, "start_retention_thread", lambda *args, **kwargs: started.append(args))

    app_module.create_app(
        Settings(
            data_dir=tmp_path,
            public_base_url="https://reader.example.com",
            app_environment=environment,
        )
    )

    assert len(started) == expected


def test_a_sign_up_that_never_chose_an_address_is_removed_after_seven_days(service):
    database, storage = service
    stale = database.create_pending_tenant(email="stale@example.com")
    fresh = database.create_pending_tenant(email="fresh@example.com")
    with database._connect() as connection:
        connection.execute(
            "UPDATE tenants SET created_at = ? WHERE id = ?", ((NOW - timedelta(days=8)).isoformat(), stale.id)
        )

    result = run_sweep(database, storage, now=NOW)

    assert result.pending_tenants_deleted == 1
    assert database.tenant_by_id(stale.id) is None
    assert database.tenant_by_id(fresh.id) is not None


def test_old_refused_senders_are_pruned(service):
    database, storage = service
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    database.record_refused_sender(tenant.id, "old@example.com", now=(NOW - timedelta(days=31)).isoformat())
    database.record_refused_sender(tenant.id, "new@example.com", now=(NOW - timedelta(days=1)).isoformat())

    result = run_sweep(database, storage, now=NOW)

    assert result.refused_senders_pruned == 1
    assert [r.address for r in database.list_refused_senders(tenant.id)] == ["new@example.com"]
