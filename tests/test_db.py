from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from steepd import db as db_module
from steepd.db import (
    MAX_ALLOWED_SENDERS,
    MAX_REFUSED_SENDERS,
    SCHEMA_VERSION,
    AllowedSenderCapReached,
    Database,
    DatabaseTooNew,
)
from steepd.inboxnames import is_placeholder
from steepd.models import Item, OrganizationGuard
from steepd.tenancy import TenantScope

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "steepd.sqlite3")
    db.initialize()
    return db


def _version(database):
    with database._connect() as connection:
        return connection.execute("PRAGMA user_version").fetchone()[0]


def _tenant_columns(database):
    with database._connect() as connection:
        return {row["name"] for row in connection.execute("PRAGMA table_info(tenants)")}


def _build_version_4_database(path):
    """A file in the v4 shape: no new columns, no new tables, user_version 4."""
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE tenants (
                id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, inbox_local TEXT NOT NULL UNIQUE,
                opds_username TEXT NOT NULL UNIQUE, opds_password_hash TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL
            );
            INSERT INTO tenants VALUES ('t1', 'ada@example.com', 'ada.1', 'ada.1', 'scrypt$00$00', 'free',
                                        '2026-08-01T00:00:00+00:00');
            PRAGMA user_version = 4;
            """
        )
    return Database(path)


def test_fresh_database_is_version_8_with_every_table(database):
    assert _version(database) == SCHEMA_VERSION == 8
    with database._connect() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(tenants)")}
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"inbox_confirmed_at", "sender_policy"} <= columns
    assert {"allowed_senders", "refused_senders", "retired_inbox_locals", "email_verification_relays"} <= tables
    assert {"newsletter_preferences", "publications", "newsletter_organization"} <= tables
    assert "trashed_items" in tables


def test_a_version_4_database_upgrades_in_place_and_existing_tenants_are_confirmed(tmp_path):
    database = _build_version_4_database(tmp_path / "old.sqlite3")
    database.initialize()
    database.initialize()  # idempotent

    assert _version(database) == 8
    tenant = database.tenant_by_email("ada@example.com")
    assert tenant is not None
    assert tenant.inbox_confirmed_at == "2026-08-01T00:00:00+00:00"
    assert tenant.sender_policy == "anyone"
    assert database.tenant_by_inbox_local("ada.1") is not None


def test_a_version_5_database_gains_the_relay_table_without_losing_accounts(tmp_path):
    database = Database(tmp_path / "version-5.sqlite3")
    database.initialize()
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    with database._connect() as connection:
        connection.execute("DROP TABLE email_verification_relays")
        connection.execute("PRAGMA user_version = 5")

    database.initialize()

    assert _version(database) == 8
    assert database.tenant_by_id(tenant.id) == tenant
    with database._connect() as connection:
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "email_verification_relays" in tables


def test_a_half_finished_migration_leaves_the_database_untouched_and_still_upgradable(tmp_path, monkeypatch):
    """Without a transaction the first ALTER would survive the failure, and every later
    initialize() would die on "duplicate column name" -- a service that can never boot."""
    database = _build_version_4_database(tmp_path / "old.sqlite3")
    monkeypatch.setattr(
        db_module,
        "_MIGRATE_4_TO_5",
        # Fails at the last moment, after both ALTERs and the backfill have run.
        db_module._MIGRATE_4_TO_5.replace(
            "PRAGMA user_version = 5;",
            "PRAGMA user_version = 5;\nINSERT INTO no_such_table VALUES (1);",
        ),
    )

    with pytest.raises(sqlite3.OperationalError):
        database.initialize()

    assert _version(database) == 4
    assert "inbox_confirmed_at" not in _tenant_columns(database)

    monkeypatch.undo()
    database.initialize()
    assert _version(database) == 8
    assert database.tenant_by_email("ada@example.com").inbox_confirmed_at == "2026-08-01T00:00:00+00:00"


def test_a_populated_version_6_database_gains_the_new_tables_and_keeps_its_library(tmp_path):
    """The realistic upgrade: a live v6 file with accounts and items in it."""
    database = Database(tmp_path / "version-6.sqlite3")
    database.initialize()
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    item = _item("i1", tenant.id, title="Issue 1", source="newsletter")
    database.insert_item(TenantScope(tenant.id), item)
    with database._connect() as connection:
        for table in ("newsletter_organization", "publications", "newsletter_preferences"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DROP INDEX items_tenant_id_idx")
        connection.execute("PRAGMA user_version = 6")

    database.initialize()

    assert _version(database) == 8
    assert database.get_item(TenantScope(tenant.id), "i1") == item
    with database._connect() as connection:
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"newsletter_preferences", "publications", "newsletter_organization"} <= tables


def test_a_populated_version_7_database_gains_the_trash_table_and_keeps_its_library(tmp_path):
    database = Database(tmp_path / "version-7.sqlite3")
    database.initialize()
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    item = _item("i1", tenant.id, title="Book", source="email")
    database.insert_item(TenantScope(tenant.id), item)
    with database._connect() as connection:
        connection.execute("DROP TABLE trashed_items")
        connection.execute("PRAGMA user_version = 7")

    database.initialize()

    assert _version(database) == 8
    assert database.get_item(TenantScope(tenant.id), "i1") == item
    assert database.trash_summary(TenantScope(tenant.id)) == (0, 0)


def test_an_interrupted_additive_upgrade_finishes_on_the_next_start(tmp_path, monkeypatch):
    """Additive DDL needs no rollback: executescript commits statement by statement, and
    the version write is last, so a half-applied schema is simply resumed."""
    database = Database(tmp_path / "version-6.sqlite3")
    database.initialize()
    with database._connect() as connection:
        connection.execute("DROP TABLE newsletter_organization")
        connection.execute("PRAGMA user_version = 6")

    monkeypatch.setattr(
        db_module,
        "SCHEMA",
        db_module.SCHEMA.replace("PRAGMA user_version = 8;", "INSERT INTO no_such_table VALUES (1);"),
    )
    with pytest.raises(sqlite3.OperationalError):
        database.initialize()
    assert _version(database) == 6

    monkeypatch.undo()
    database.initialize()

    assert _version(database) == 8
    with database._connect() as connection:
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "newsletter_organization" in tables


def test_a_database_from_a_newer_release_is_refused_rather_than_half_understood(tmp_path):
    database = Database(tmp_path / "future.sqlite3")
    database.initialize()
    with database._connect() as connection:
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")

    with pytest.raises(DatabaseTooNew):
        database.initialize()

    assert _version(database) == SCHEMA_VERSION + 1

def test_email_verification_relay_is_expiring_one_shot_and_claimed_atomically(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    future = (NOW + timedelta(minutes=5)).isoformat()

    assert database.enable_email_verification_relay(tenant.id, expires_at=future) is True
    assert database.email_verification_relay_expires_at(tenant.id, now=NOW.isoformat()) == future

    assert database.claim_email_verification_relay(tenant.id, event_id="evt-1", now=NOW.isoformat()) is True
    assert database.claim_email_verification_relay(tenant.id, event_id="evt-2", now=NOW.isoformat()) is False

    assert database.release_email_verification_relay(tenant.id, event_id="evt-wrong") is False
    assert database.release_email_verification_relay(tenant.id, event_id="evt-1") is True
    assert database.claim_email_verification_relay(tenant.id, event_id="evt-2", now=NOW.isoformat()) is True
    assert database.complete_email_verification_relay(tenant.id, event_id="evt-2") is True
    assert database.email_verification_relay_expires_at(tenant.id, now=NOW.isoformat()) is None


def test_an_expired_or_disabled_email_verification_relay_cannot_be_claimed(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    past = (NOW - timedelta(seconds=1)).isoformat()

    database.enable_email_verification_relay(tenant.id, expires_at=past)
    assert database.email_verification_relay_expires_at(tenant.id, now=NOW.isoformat()) is None
    assert database.claim_email_verification_relay(tenant.id, event_id="evt-old", now=NOW.isoformat()) is False

    database.enable_email_verification_relay(tenant.id, expires_at=(NOW + timedelta(minutes=5)).isoformat())
    assert database.disable_email_verification_relay(tenant.id) is True
    assert database.disable_email_verification_relay(tenant.id) is False
    assert database.claim_email_verification_relay(tenant.id, event_id="evt-off", now=NOW.isoformat()) is False


def test_enabling_a_relay_for_an_unknown_tenant_does_not_create_an_orphan(database):
    assert (
        database.enable_email_verification_relay(
            "missing", expires_at=(NOW + timedelta(minutes=5)).isoformat()
        )
        is False
    )


def test_deleting_a_tenant_cascades_its_email_verification_relay(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    database.enable_email_verification_relay(tenant.id, expires_at=(NOW + timedelta(minutes=5)).isoformat())

    assert database.delete_tenant(tenant.id) is True
    assert database.email_verification_relay_expires_at(tenant.id, now=NOW.isoformat()) is None


def test_a_pending_tenant_holds_a_placeholder_and_is_invisible_to_inbox_routing(database):
    tenant = database.create_pending_tenant(email="ines@example.com")
    assert is_placeholder(tenant.inbox_local)
    assert tenant.opds_username == tenant.inbox_local
    assert tenant.inbox_confirmed_at is None
    assert database.tenant_by_inbox_local(tenant.inbox_local) is None
    # The device-auth path looks a tenant up by this name. A sign-up that has not chosen
    # an address yet has no catalogue, so the placeholder must not sign anything in --
    # and the password it was created with is one nobody has been shown.
    assert database.tenant_by_opds_username(tenant.opds_username) is None
    assert database.tenant_by_email("ines@example.com") is not None


def test_create_tenant_is_confirmed_at_creation(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada.1")
    assert tenant.inbox_confirmed_at is not None
    assert database.tenant_by_inbox_local("ada.1").id == tenant.id


def test_confirming_sets_both_names_and_the_stamp_and_only_once(database):
    tenant = database.create_pending_tenant(email="ines@example.com")
    assert database.confirm_inbox_local(tenant.id, "ines") is True
    confirmed = database.tenant_by_id(tenant.id)
    assert confirmed.inbox_local == confirmed.opds_username == "ines"
    assert confirmed.inbox_confirmed_at is not None
    assert database.tenant_by_opds_username("ines").id == tenant.id
    assert database.tenant_by_inbox_local("ines").id == tenant.id
    assert database.confirm_inbox_local(tenant.id, "other") is False
    assert database.tenant_by_id(tenant.id).inbox_local == "ines"


def test_availability_sees_live_names_case_insensitively_and_retired_names(database):
    live = database.create_tenant(email="ada@example.com", inbox_local="ada")
    assert database.inbox_local_available("ada") is False
    assert database.inbox_local_available("ADA") is False
    assert database.inbox_local_available("ines") is True
    # The UNIQUE constraint is the last word behind the availability check.
    with pytest.raises(sqlite3.IntegrityError):
        database.create_tenant(email="x@example.com", inbox_local="ada")
    assert database.delete_tenant(live.id)
    assert database.inbox_local_available("ada") is False
    pending = database.create_pending_tenant(email="ines@example.com")
    assert database.inbox_local_available(pending.inbox_local) is False


def test_deleting_a_pending_tenant_retires_nothing(database):
    pending = database.create_pending_tenant(email="ines@example.com")
    database.delete_tenant(pending.id)
    with database._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM retired_inbox_locals").fetchone()[0] == 0


def test_unconfirmed_tenants_older_than_the_cutoff_are_deleted(database):
    old = database.create_pending_tenant(email="old@example.com")
    fresh = database.create_pending_tenant(email="fresh@example.com")
    confirmed = database.create_tenant(email="ada@example.com", inbox_local="ada")
    with database._connect() as connection:
        connection.execute(
            "UPDATE tenants SET created_at = ? WHERE id IN (?, ?)",
            ((NOW - timedelta(days=8)).isoformat(), old.id, confirmed.id),
        )
    cutoff = (NOW - timedelta(days=7)).isoformat()

    assert database.delete_unconfirmed_tenants(before=cutoff) == 1
    assert database.tenant_by_id(old.id) is None
    assert database.tenant_by_id(fresh.id) is not None
    assert database.tenant_by_id(confirmed.id) is not None


def test_sender_policy_accepts_only_the_two_values(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    assert database.set_sender_policy(tenant.id, "listed") is True
    assert database.tenant_by_id(tenant.id).sender_policy == "listed"
    with pytest.raises(ValueError):
        database.set_sender_policy(tenant.id, "everyone")
    assert database.set_sender_policy("missing", "anyone") is False


def test_allowed_senders_add_list_remove_and_cap(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    assert database.add_allowed_sender(tenant.id, "news@dispatch.example") is True
    assert database.add_allowed_sender(tenant.id, "news@dispatch.example") is False
    assert database.list_allowed_senders(tenant.id) == ["news@dispatch.example"]
    assert database.remove_allowed_sender(tenant.id, "news@dispatch.example") is True
    assert database.remove_allowed_sender(tenant.id, "news@dispatch.example") is False
    for n in range(MAX_ALLOWED_SENDERS):
        database.add_allowed_sender(tenant.id, f"s{n}@example.com")
    with pytest.raises(AllowedSenderCapReached):
        database.add_allowed_sender(tenant.id, "one-too-many@example.com")


def test_is_sender_allowed_follows_the_policy(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    assert database.is_sender_allowed(tenant, "stranger@example.com") is True
    database.set_sender_policy(tenant.id, "listed")
    tenant = database.tenant_by_id(tenant.id)
    assert database.is_sender_allowed(tenant, "stranger@example.com") is False
    assert database.is_sender_allowed(tenant, "ada@example.com") is True
    database.add_allowed_sender(tenant.id, "news@dispatch.example")
    assert database.is_sender_allowed(tenant, "news@dispatch.example") is True


def test_refused_senders_are_counted_listed_newest_first_capped_and_prunable(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    t0 = NOW.isoformat()
    t1 = (NOW + timedelta(minutes=1)).isoformat()
    database.record_refused_sender(tenant.id, "a@example.com", now=t0)
    database.record_refused_sender(tenant.id, "a@example.com", now=t1)
    database.record_refused_sender(tenant.id, "b@example.com", now=t0)
    listed = database.list_refused_senders(tenant.id)
    assert [(r.address, r.count) for r in listed] == [("a@example.com", 2), ("b@example.com", 1)]
    assert listed[0].last_seen_at == t1

    for n in range(MAX_REFUSED_SENDERS + 5):
        database.record_refused_sender(tenant.id, f"r{n}@example.com", now=(NOW + timedelta(hours=n + 1)).isoformat())
    assert len(database.list_refused_senders(tenant.id, limit=100)) == MAX_REFUSED_SENDERS

    database.clear_refused_sender(tenant.id, "r24@example.com")
    assert all(r.address != "r24@example.com" for r in database.list_refused_senders(tenant.id, limit=100))
    assert database.prune_refused_senders(before=(NOW + timedelta(hours=100)).isoformat()) == MAX_REFUSED_SENDERS - 1


def _open_descriptors() -> int:
    import os

    return len(os.listdir("/dev/fd"))


def test_reads_and_writes_do_not_leak_file_descriptors(database):
    """Every method opens its own connection; without an explicit close each one left a
    descriptor behind until the garbage collector happened to reap it, so a burst of cheap
    requests could exhaust the process's limit."""
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    database.tenant_by_id(tenant.id)  # warm anything lazily opened
    before = _open_descriptors()
    for _ in range(200):
        database.tenant_by_id(tenant.id)
        database.health()
        database.set_sender_policy(tenant.id, "anyone")
    assert _open_descriptors() - before <= 3


def _item(item_id: str, tenant_id: str, *, title: str, source: str) -> Item:
    return Item(
        id=item_id,
        tenant_id=tenant_id,
        kind="article",
        sha256=item_id.ljust(64, "0"),
        storage_name=f"{item_id}.epub",
        download_filename=f"{title}.epub",
        title=title,
        author="",
        language="en",
        identifier=f"urn:test:{item_id}",
        source_url="https://example.com/story",
        size_bytes=100,
        created_at=NOW.isoformat(),
        expires_at=None,
        source=source,
    )


def test_item_titles_are_scoped_to_the_tenant_and_requested_source(database):
    """Another tenant's save and this tenant's newsletter must not consume a numeric
    suffix intended only for this tenant's current Saved items."""
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob")
    alice_scope = TenantScope(alice.id)
    bob_scope = TenantScope(bob.id)
    database.insert_item(alice_scope, _item("alice-url-1", alice.id, title="Story", source="url"))
    database.insert_item(alice_scope, _item("alice-url-2", alice.id, title="Story (2)", source="url"))
    database.insert_item(alice_scope, _item("alice-news", alice.id, title="Newsletter title", source="newsletter"))
    database.insert_item(bob_scope, _item("bob-url", bob.id, title="Bob's story", source="url"))

    assert database.list_item_titles(alice_scope, source="url") == ["Story", "Story (2)"]
    assert database.list_item_titles(alice_scope, source="newsletter") == ["Newsletter title"]


# -- newsletter organization ------------------------------------------------
# The shape under test throughout: an absent newsletter_organization row is the waiting
# state. Nothing is enqueued at import, so these tests insert items and then check that
# the worker's selection finds them by absence.

STAMP = NOW.isoformat()
LATER = (NOW + timedelta(minutes=5)).isoformat()
# Inside the 120-second lease _claim takes out, which the commit guard checks.
DURING_LEASE = (NOW + timedelta(seconds=30)).isoformat()


def _guard(database, tenant, *, token, plan="free", cutoff=None, now=DURING_LEASE, catalogue=None, settings=None):
    preferences = database.newsletter_preferences(TenantScope(tenant.id))
    return OrganizationGuard(
        lease_token=token,
        settings_revision=settings if settings is not None else preferences.settings_revision,
        catalogue_revision=catalogue if catalogue is not None else preferences.catalogue_revision,
        plan=plan,
        retention_cutoff=cutoff,
        now=now,
    )


def _enabled_tenant(database, *, email="ada@example.com", inbox="ada", items=("i1",)):
    tenant = database.create_tenant(email=email, inbox_local=inbox)
    scope = TenantScope(tenant.id)
    for index, item_id in enumerate(items):
        database.insert_item(scope, _item(item_id, tenant.id, title=f"Issue {index}", source="newsletter"))
    database.set_newsletter_organization(
        scope, enabled=True, consent_version=1, settings_revision=None, now=STAMP
    )
    return tenant, scope



def _publication(database, scope, publication_id, name, *, now):
    """A publication row without an issue, the way an owner's earlier correction left one.

    Inserted directly: production creates publications only alongside an assignment, and
    these tests want the bare record to exercise everything downstream of that.
    """
    with database._connect() as connection:
        connection.execute(
            """
            INSERT INTO publications (
                tenant_id, id, name, original_name, identification_note, merged_into_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, '', NULL, ?, ?)
            """,
            (scope.tenant_id, publication_id, name, name, now, now),
        )

def _claim(database, scope, *, token="tok", cutoff=None, now=STAMP, max_attempts=2):
    return database.claim_organization_item(
        scope,
        now=now,
        lease_token=token,
        lease_until=(NOW + timedelta(seconds=120)).isoformat(),
        retention_cutoff=cutoff,
        max_attempts=max_attempts,
    )


def test_a_newsletter_with_no_row_is_the_waiting_state_and_is_claimed_by_absence(database):
    tenant, scope = _enabled_tenant(database)
    assert database.organization_row(scope, "i1") is None

    claimed = _claim(database, scope)

    assert claimed is not None and claimed.item_id == "i1"
    assert database.organization_row(scope, "i1")["state"] == "running"


def test_books_and_saved_webpages_are_never_eligible_work(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    scope = TenantScope(tenant.id)
    database.insert_item(scope, _item("saved", tenant.id, title="A page", source="url"))
    book = _item("book", tenant.id, title="A book", source="upload")
    database.insert_item(scope, Item(**{**book.as_dict(), "kind": "book"}))
    database.set_newsletter_organization(scope, enabled=True, consent_version=1, settings_revision=None, now=STAMP)

    assert _claim(database, scope) is None


def test_only_one_of_two_competing_claims_receives_a_token(database):
    tenant, scope = _enabled_tenant(database)

    first = _claim(database, scope, token="a")
    second = _claim(database, scope, token="b")

    assert first is not None
    assert second is None, "a live lease must not be handed to a second worker"


def test_an_expired_lease_is_recovered_through_the_same_claim_path(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="stale")

    recovered = _claim(database, scope, token="fresh", now=(NOW + timedelta(minutes=10)).isoformat())

    assert recovered is not None and recovered.item_id == "i1"
    assert database.organization_row(scope, "i1")["lease_token"] == "fresh"


def test_an_expired_lease_with_no_attempts_left_is_failed_rather_than_dispatched_again(database):
    tenant, scope = _enabled_tenant(database)
    claimed = _claim(database, scope, token="t1")
    revision = database.newsletter_preferences(scope).settings_revision
    for _ in range(2):
        assert database.consume_dispatch_allowance(
            scope, "i1", lease_token="t1", day="2026-09-03", now=STAMP, daily_limit=500,
            settings_revision=revision, required_consent_version=1,
        ) is not None

    failed = database.finalize_exhausted_claims(
        scope, now=(NOW + timedelta(minutes=10)).isoformat(), max_attempts=2
    )

    assert failed == 1
    row = database.organization_row(scope, "i1")
    assert row["state"] == "failed" and row["not_before"] is None
    assert claimed is not None


def test_new_deliveries_are_selected_before_older_untouched_backlog(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    scope = TenantScope(tenant.id)
    for item_id, created in (("old", NOW - timedelta(days=3)), ("new", NOW - timedelta(minutes=1))):
        base = _item(item_id, tenant.id, title=item_id, source="newsletter")
        database.insert_item(scope, Item(**{**base.as_dict(), "created_at": created.isoformat()}))
    database.set_newsletter_organization(scope, enabled=True, consent_version=1, settings_revision=None, now=STAMP)

    assert _claim(database, scope).item_id == "new"


def test_a_due_retry_outranks_newer_untouched_backlog(database):
    """An explicitly requested Retry must not queue behind every newer issue."""
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    scope = TenantScope(tenant.id)

    def add(item_id, created):
        base = _item(item_id, tenant.id, title=item_id, source="newsletter")
        database.insert_item(scope, Item(**{**base.as_dict(), "created_at": created.isoformat()}))

    add("old", NOW - timedelta(days=3))
    database.set_newsletter_organization(scope, enabled=True, consent_version=1, settings_revision=None, now=STAMP)
    _claim(database, scope, token="t")
    database.record_organization_outcome(
        scope, "old", guard=_guard(database, tenant, token="t"), state="failed", error_code="boom"
    )
    assert database.retry_organization_items(scope, [("old", "t")], now=STAMP) == 1
    add("new", NOW - timedelta(minutes=1))

    assert _claim(database, scope, token="t2").item_id == "old"


def test_retention_excludes_an_expired_item_from_selection(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    scope = TenantScope(tenant.id)
    base = _item("ancient", tenant.id, title="Ancient", source="newsletter")
    database.insert_item(scope, Item(**{**base.as_dict(), "created_at": (NOW - timedelta(days=30)).isoformat()}))
    database.set_newsletter_organization(scope, enabled=True, consent_version=1, settings_revision=None, now=STAMP)

    cutoff = (NOW - timedelta(days=7)).isoformat()
    assert _claim(database, scope, cutoff=cutoff) is None
    assert _claim(database, scope, cutoff=None) is not None, "an unlimited plan keeps it eligible"


def test_the_daily_allowance_is_spent_atomically_and_resets_on_the_next_utc_day(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    revision = database.newsletter_preferences(scope).settings_revision

    spend = dict(lease_token="t", now=STAMP, daily_limit=2, settings_revision=revision, required_consent_version=1)
    assert database.consume_dispatch_allowance(scope, "i1", day="2026-09-03", **spend) == 1
    assert database.consume_dispatch_allowance(scope, "i1", day="2026-09-03", **spend) == 2
    assert database.consume_dispatch_allowance(scope, "i1", day="2026-09-03", **spend) is None
    assert database.consume_dispatch_allowance(scope, "i1", day="2026-09-04", **spend) == 1


def test_spending_is_refused_once_the_setting_has_moved_on(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    captured = database.newsletter_preferences(scope).settings_revision
    database.set_newsletter_organization(
        scope, enabled=False, consent_version=1, settings_revision=captured, now=STAMP
    )

    assert (
        database.consume_dispatch_allowance(
            scope, "i1", lease_token="t", day="2026-09-03", now=STAMP, daily_limit=500,
            settings_revision=captured, required_consent_version=1,
        )
        is None
    )


def test_a_preflight_release_keeps_the_attempt_allowance_intact(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")

    assert database.release_organization_claim(scope, "i1", lease_token="t", now=STAMP) is True

    row = database.organization_row(scope, "i1")
    assert (row["state"], row["attempts"]) == ("retry", 0)


def test_a_model_answer_creates_its_publication_and_assignment_together(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")

    created = database.create_and_assign_publication(
        scope, "i1", guard=_guard(database, tenant, token="t"), publication_id="p1",
        name="Stratechery",
    )

    assert created is not None and created.name == created.original_name == "Stratechery"
    assert database.organization_row(scope, "i1")["publication_id"] == "p1"


def test_a_rejected_answer_leaves_no_orphan_publication_behind(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    stale = _guard(database, tenant, token="t", catalogue=999)

    assert (
        database.create_and_assign_publication(
            scope, "i1", guard=stale, publication_id="p1", name="Stratechery"
        )
        is None
    )
    assert database.canonical_publications(scope) == []
    assert database.organization_row(scope, "i1")["publication_id"] is None


def test_a_stale_worker_cannot_overwrite_a_manual_correction(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    guard = _guard(database, tenant, token="t")
    _publication(database, scope, "chosen", "Dense Discovery", now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="chosen", now=STAMP)

    assert (
        database.create_and_assign_publication(
            scope, "i1", guard=guard, publication_id="p1", name="Stratechery"
        )
        is None
    )
    assert (
        database.record_organization_outcome(scope, "i1", guard=guard, state="failed", error_code="boom") is False
    ), "a late failure must not stamp over a newer manual decision either"
    assert database.organization_row(scope, "i1")["publication_id"] == "chosen"


def test_a_plan_change_during_the_request_refuses_the_commit(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    guard = _guard(database, tenant, token="t", plan="free")
    database.set_tenant_plan(tenant.id, "paid")

    assert database.record_organization_outcome(scope, "i1", guard=guard, state="unrecognized") is False


def test_manual_assignment_works_before_the_worker_has_touched_the_item(database):
    tenant, scope = _enabled_tenant(database)
    _publication(database, scope, "p1", "Dense Discovery", now=STAMP)

    assert database.assign_publication_manually(scope, "i1", publication_id="p1", now=STAMP) is True

    row = database.organization_row(scope, "i1")
    assert (row["state"], row["manual"], row["publication_id"]) == ("done", 1, "p1")


def test_an_owner_can_correct_their_own_earlier_correction(database):
    """Worker guards must never become a lock on the person using the product."""
    tenant, scope = _enabled_tenant(database)
    _publication(database, scope, "wrong", "Stratechery", now=STAMP)
    _publication(database, scope, "right", "Dense Discovery", now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="wrong", now=STAMP)

    assert database.assign_publication_manually(scope, "i1", publication_id="right", now=STAMP) is True
    assert database.organization_row(scope, "i1")["publication_id"] == "right"

    assert database.assign_publication_manually(scope, "i1", publication_id=None, now=STAMP) is True
    row = database.organization_row(scope, "i1")
    assert (row["state"], row["manual"], row["publication_id"]) == ("done", 1, None), "Keep ungrouped is a decision"


def test_create_and_assign_replay_is_detected_on_this_item_only(database):
    tenant, scope = _enabled_tenant(database, items=("i1", "i2"))
    _publication(database, scope, "p1", "Stratechery", now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="p1", now=STAMP)

    assert database.manual_assignment_matching(scope, "i1", "Stratechery") == "p1"
    assert database.manual_assignment_matching(scope, "i2", "Stratechery") is None, "names are not identities"


def test_merging_requires_two_distinct_canonical_records_and_repoints_old_aliases(database):
    tenant, scope = _enabled_tenant(database, items=("i1", "i2"))
    for pid, name in (("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")):
        _publication(database, scope, pid, name, now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="a", now=STAMP)

    assert database.merge_publications(scope, source_id="a", target_id="b", now=STAMP) is True
    assert database.organization_row(scope, "i1")["publication_id"] == "b"
    assert database.merge_publications(scope, source_id="a", target_id="c", now=STAMP) is False
    assert database.merge_publications(scope, source_id="b", target_id="b", now=STAMP) is False

    assert database.merge_publications(scope, source_id="b", target_id="c", now=STAMP) is True
    assert database.publication(scope, "a").merged_into_id == "c", "resolution stays one hop"
    assert database.resolve_publication(scope, "a").id == "c"


def test_a_retry_form_replayed_after_a_newer_attempt_changes_nothing(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="old")
    database.record_organization_outcome(
        scope, "i1", guard=_guard(database, tenant, token="old", now=STAMP), state="failed", error_code="boom"
    )
    database.retry_organization_items(scope, [("i1", "old")], now=STAMP)
    _claim(database, scope, token="new")

    assert database.retry_organization_items(scope, [("i1", "old")], now=STAMP) == 0


def test_every_organization_method_is_scoped_to_its_own_tenant(database):
    ada, ada_scope = _enabled_tenant(database)
    bob, bob_scope = _enabled_tenant(database, email="bob@example.com", inbox="bob", items=("b1",))
    _publication(database, ada_scope, "p1", "Stratechery", now=STAMP)

    assert database.assign_publication_manually(bob_scope, "i1", publication_id=None, now=STAMP) is False
    assert database.assign_publication_manually(bob_scope, "b1", publication_id="p1", now=STAMP) is False
    assert database.edit_publication(bob_scope, "p1", name="Taken", identification_note="", now=STAMP) is False
    assert database.publication(bob_scope, "p1") is None


def test_progress_and_counts_describe_currently_retained_items(database):
    tenant, scope = _enabled_tenant(database, items=("i1", "i2", "i3"))
    _claim(database, scope, token="t")
    database.create_and_assign_publication(
        scope, "i3", guard=_guard(database, tenant, token="t"), publication_id="p1", name="Alpha"
    )
    database.assign_publication_manually(scope, "i2", publication_id=None, now=STAMP)

    progress = database.organization_progress(scope, retention_cutoff=None)

    assert (progress.organized, progress.waiting, progress.total) == (2, 1, 3)
    assert database.count_unorganized_newsletters(scope, retention_cutoff=None) == 2
    assert [s.issue_count for s in database.list_publication_summaries(scope)] == [1]


def test_an_expired_issue_takes_its_organization_row_and_moves_the_catalogue_clock(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    database.create_and_assign_publication(
        scope, "i1", guard=_guard(database, tenant, token="t"), publication_id="p1", name="Alpha"
    )
    before = database.newsletter_preferences(scope).catalogue_updated_at

    database.delete_item(scope, "i1", now=LATER)

    assert database.organization_row(scope, "i1") is None
    assert database.list_publication_summaries(scope) == [], "an empty publication leaves browsing"
    assert database.canonical_publications(scope)[0].id == "p1", "but keeps its identity for the next issue"
    assert database.newsletter_preferences(scope).catalogue_updated_at != before


# -- regressions from review ------------------------------------------------


def test_a_result_arriving_after_its_lease_expired_cannot_commit(database):
    """The guard compares not_before against the clock, so the clock has to be current."""
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    late = _guard(database, tenant, token="t", now=(NOW + timedelta(minutes=10)).isoformat())

    assert (
        database.create_and_assign_publication(
            scope, "i1", guard=late, publication_id="p1", name="Late"
        )
        is None
    )
    assert database.canonical_publications(scope) == []


def test_enabled_accounts_with_nothing_to_do_do_not_crowd_out_one_that_has(database):
    """Idle accounts never claim, so they never advance last_served_at, so without this
    they sit at the front of the ordering forever and starve whoever sorts after them."""
    busy = None
    for index in range(40):
        tenant = database.create_tenant(email=f"t{index:02d}@example.com", inbox_local=f"t{index:02d}")
        scope = TenantScope(tenant.id)
        database.set_newsletter_organization(
            scope, enabled=True, consent_version=1, settings_revision=None, now=STAMP
        )
        if index == 39:
            database.insert_item(scope, _item("work", tenant.id, title="Waiting", source="newsletter"))
            busy = scope

    candidates = database.organization_candidates(
        now=STAMP,
        now_day="2026-09-03",
        retention_cutoffs={"free": None, "paid": None},
        daily_limit=500,
        required_consent_version=1,
    )

    assert [c.tenant_id for c in candidates] == [busy.tenant_id]


def test_a_retry_row_with_no_attempts_left_is_finalized_rather_than_stranded(database):
    """It cannot be claimed (attempts spent) and cannot be retried (not terminal), so
    without this it would sit invisible forever."""
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    revision = database.newsletter_preferences(scope).settings_revision
    for _ in range(2):
        database.consume_dispatch_allowance(
            scope, "i1", lease_token="t", day="2026-09-03", now=STAMP, daily_limit=500,
            settings_revision=revision, required_consent_version=1,
        )
    database.record_organization_outcome(
        scope, "i1", guard=_guard(database, tenant, token="t"), state="retry",
        error_code="provider_unavailable", retry_at=STAMP,
    )

    assert database.finalize_exhausted_claims(scope, now=LATER, max_attempts=2) == 1
    row = database.organization_row(scope, "i1")
    assert (row["state"], row["error_code"]) == ("failed", "provider_unavailable")
    assert database.retry_organization_items(scope, [("i1", "t")], now=LATER) == 1


def test_a_released_claim_keeps_every_attempt_that_reached_the_provider(database):
    """A rejected key is still a dispatch. Giving the attempt back let a 500 followed by a
    401 buy the item a third and fourth paid try."""
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    revision = database.newsletter_preferences(scope).settings_revision
    database.consume_dispatch_allowance(
        scope, "i1", lease_token="t", day="2026-09-03", now=STAMP, daily_limit=500,
        settings_revision=revision, required_consent_version=1,
    )

    database.release_organization_claim(scope, "i1", lease_token="t", now=STAMP)

    row = database.organization_row(scope, "i1")
    assert (row["state"], row["attempts"]) == ("retry", 1)
    assert database.newsletter_preferences(scope).attempts_today == 1


def test_dispatch_stops_when_the_consent_version_moves_on(database):
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    revision = database.newsletter_preferences(scope).settings_revision

    assert (
        database.consume_dispatch_allowance(
            scope, "i1", lease_token="t", day="2026-09-03", now=STAMP, daily_limit=500,
            settings_revision=revision, required_consent_version=2,
        )
        is None
    ), "a broader policy must be agreed again before anything else is sent"


def test_assigning_an_older_issue_moves_the_publication_feed_clock(database):
    tenant, scope = _enabled_tenant(database, items=("i1", "i2"))
    _publication(database, scope, "p1", "Alpha", now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="p1", now=STAMP)
    before = database.publication(scope, "p1").updated_at

    database.assign_publication_manually(scope, "i2", publication_id="p1", now=LATER)

    assert database.publication(scope, "p1").updated_at != before


def test_purging_an_account_signs_its_other_browsers_out_before_deleting_anything(database):
    tenant, scope = _enabled_tenant(database)
    database.insert_session(
        token_hash="other-browser", tenant_id=tenant.id, created_at=STAMP,
        expires_at=(NOW + timedelta(days=7)).isoformat(),
    )

    database.pause_newsletter_organization(scope, now=STAMP)

    assert database.session_tenant(token_hash="other-browser", now=STAMP) is None
    assert database.newsletter_preferences(scope).enabled is False


def test_accounts_holding_only_expired_issues_are_not_candidates(database):
    """The work check has to respect retention, or a shelf of expired-but-unswept issues
    makes an account look busy forever and keeps the queue in front of everyone else."""
    tenant = database.create_tenant(email="stale@example.com", inbox_local="stale")
    scope = TenantScope(tenant.id)
    old = _item("ancient", tenant.id, title="Ancient", source="newsletter")
    database.insert_item(scope, Item(**{**old.as_dict(), "created_at": (NOW - timedelta(days=60)).isoformat()}))
    database.set_newsletter_organization(
        scope, enabled=True, consent_version=1, settings_revision=None, now=STAMP
    )
    cutoff = (NOW - timedelta(days=7)).isoformat()

    def candidates(cutoffs, consent=1):
        return database.organization_candidates(
            now=STAMP, now_day="2026-09-03", retention_cutoffs=cutoffs,
            daily_limit=500, required_consent_version=consent,
        )

    assert candidates({"free": cutoff, "paid": None}) == []
    assert len(candidates({"free": None, "paid": None})) == 1, "an unlimited plan still has it"


def test_an_account_whose_consent_is_superseded_stops_being_offered_work(database):
    """Otherwise the worker prepares its issues over and over, is refused at dispatch, and
    reports a successful pass each time while nothing moves."""
    tenant, scope = _enabled_tenant(database)

    current = database.organization_candidates(
        now=STAMP, now_day="2026-09-03", retention_cutoffs={"free": None, "paid": None},
        daily_limit=500, required_consent_version=1,
    )
    superseded = database.organization_candidates(
        now=STAMP, now_day="2026-09-03", retention_cutoffs={"free": None, "paid": None},
        daily_limit=500, required_consent_version=2,
    )

    assert len(current) == 1 and superseded == []


def test_an_item_that_has_spent_its_allowance_is_finished_rather_than_retried(database):
    """Where a released claim ends up once both dispatches are gone: terminal, visible,
    and available for an explicit Retry -- not looping on the worker's money."""
    tenant, scope = _enabled_tenant(database)
    _claim(database, scope, token="t")
    revision = database.newsletter_preferences(scope).settings_revision
    for _ in range(2):
        database.consume_dispatch_allowance(
            scope, "i1", lease_token="t", day="2026-09-03", now=STAMP, daily_limit=500,
            settings_revision=revision, required_consent_version=1,
        )
    database.release_organization_claim(scope, "i1", lease_token="t", now=STAMP)

    assert database.finalize_exhausted_claims(scope, now=LATER, max_attempts=2) == 1
    assert database.organization_row(scope, "i1")["state"] == "failed"


def test_moving_an_issue_moves_the_clock_on_both_publications(database):
    tenant, scope = _enabled_tenant(database, items=("i1",))
    for pid, name in (("a", "Alpha"), ("b", "Beta")):
        _publication(database, scope, pid, name, now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="a", now=STAMP)
    before = {p.id: p.updated_at for p in database.canonical_publications(scope)}

    database.assign_publication_manually(scope, "i1", publication_id="b", now=LATER)

    after = {p.id: p.updated_at for p in database.canonical_publications(scope)}
    assert after["b"] != before["b"], "the publication that gained it"
    assert after["a"] != before["a"], "and the one that lost it, whose feed also changed"


def test_a_preferences_row_starts_at_the_revision_the_empty_form_renders(database):
    """Written explicitly rather than left to the column default.

    A database created by an earlier build of this schema carries a different default, and
    CREATE TABLE IF NOT EXISTS will not change it -- so relying on the default meant the
    first enable kept failing on exactly the files that already existed.
    """
    tenant = database.create_tenant(email="new@example.com", inbox_local="new")
    scope = TenantScope(tenant.id)
    database.insert_item(scope, _item("i1", tenant.id, title="Issue", source="newsletter"))
    # Recreate the table as an earlier build defined it, with the default the empty form
    # does not render. CREATE TABLE IF NOT EXISTS on the next start leaves it that way.
    create = re.search(r"CREATE TABLE IF NOT EXISTS newsletter_preferences \(.*?\);", db_module.SCHEMA, re.S).group(0)
    assert "settings_revision INTEGER NOT NULL DEFAULT 0" in create
    with database._connect() as connection:
        connection.execute("DROP TABLE newsletter_preferences")
        connection.execute(
            create.replace(
                "settings_revision INTEGER NOT NULL DEFAULT 0", "settings_revision INTEGER NOT NULL DEFAULT 1"
            )
        )

    # A correction creates the row without turning anything on.
    database.assign_publication_manually(scope, "i1", publication_id=None, now=STAMP)

    assert database.newsletter_preferences(scope).settings_revision == 0
    assert database.set_newsletter_organization(
        scope, enabled=True, consent_version=1, settings_revision=0, now=STAMP
    ) is True, "and the form rendered from it saves first time"


# -- saved pages by site ------------------------------------------------------


def _saved(database, scope, item_id, *, url, created):
    base = _item(item_id, scope.tenant_id, title=item_id, source="url")
    database.insert_item(scope, Item(**{**base.as_dict(), "source_url": url, "created_at": created}))


def test_saved_pages_group_by_the_site_in_their_url(database):
    """The site is the host: scheme, path, query and fragment dropped, lowercased, and a
    leading www. removed. A port stays, because it is part of where the page came from."""
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    scope = TenantScope(tenant.id)
    _saved(database, scope, "a", url="https://www.example.com/a?x=1", created="2026-01-01T00:00:00+00:00")
    _saved(database, scope, "b", url="http://example.com", created="2026-01-03T00:00:00+00:00")
    _saved(database, scope, "c", url="https://example.com?q=1", created="2026-01-02T00:00:00+00:00")
    _saved(database, scope, "d", url="https://Other.Example.org/p#frag", created="2026-01-01T00:00:00+00:00")
    _saved(database, scope, "e", url="https://example.com:8080/x", created="2026-01-01T00:00:00+00:00")
    _saved(database, scope, "f", url="", created="2026-01-01T00:00:00+00:00")
    _saved(database, scope, "g", url="not a url", created="2026-01-01T00:00:00+00:00")
    # A newsletter from the same host is not a saved page, and another account's page
    # is not this account's.
    newsletter = _item("n", tenant.id, title="n", source="newsletter")
    database.insert_item(scope, Item(**{**newsletter.as_dict(), "source_url": "https://example.com/n"}))
    other = database.create_tenant(email="bob@example.com", inbox_local="bob")
    _saved(
        database, TenantScope(other.id), "theirs", url="https://example.com/theirs", created="2026-01-09T00:00:00+00:00"
    )

    sites = database.list_saved_sites(scope)

    assert [(s.host, s.page_count) for s in sites] == [
        ("example.com", 3), ("example.com:8080", 1), ("other.example.org", 1)
    ]
    assert sites[0].updated_at == "2026-01-03T00:00:00+00:00", "the newest page of that site"
    assert database.count_saved_sites(scope) == 3
    saved = dict(kind="article", source="url")
    assert database.count_items(scope, **saved, site="example.com") == 3, "the filter agrees with the grouping"
    assert {i.id for i in database.list_items(scope, **saved, site="example.com")} == {"a", "b", "c"}
    assert database.count_items(scope, kind="article", source="url") == 7, "pages without a site still count as saved"


# -- trash ---------------------------------------------------------------------


def test_a_trashed_item_leaves_every_item_query_and_restores_unchanged(database):
    tenant = database.create_tenant(email="ada@example.com", inbox_local="ada")
    scope = TenantScope(tenant.id)
    item = _item("i1", tenant.id, title="Book", source="email")
    database.insert_item(scope, item)

    assert database.trash_item(scope, "i1", now=STAMP) == item
    assert database.get_item(scope, "i1") is None
    assert database.list_items(scope) == []
    assert database.count_items(scope) == 0
    assert database.list_authors(scope) == []
    assert database.item_by_sha256(scope, item.sha256) is None
    assert database.get_trashed_item(scope, "i1").item == item
    assert database.trash_summary(scope) == (1, item.size_bytes)
    assert database.tenant_storage_bytes(scope) == item.size_bytes

    assert database.restore_item(scope, "i1", now=STAMP) == item
    assert database.get_trashed_item(scope, "i1") is None
    assert database.trash_summary(scope) == (0, 0)


def test_trash_is_scoped_to_the_tenant(database):
    ada = database.create_tenant(email="ada@example.com", inbox_local="ada")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob")
    database.insert_item(TenantScope(ada.id), _item("i1", ada.id, title="Book", source="email"))

    assert database.trash_item(TenantScope(bob.id), "i1", now=STAMP) is None
    database.trash_item(TenantScope(ada.id), "i1", now=STAMP)
    assert database.get_trashed_item(TenantScope(bob.id), "i1") is None
    assert database.restore_item(TenantScope(bob.id), "i1", now=STAMP) is None
    assert database.delete_trashed_item(TenantScope(bob.id), "i1") is False
    assert database.list_trashed_items(TenantScope(bob.id)) == []


def test_restore_puts_back_a_manual_assignment(database):
    _, scope = _enabled_tenant(database)
    _publication(database, scope, "p1", "Dense Discovery", now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="p1", now=STAMP)

    database.trash_item(scope, "i1", now=STAMP)
    assert database.organization_row(scope, "i1") is None
    database.restore_item(scope, "i1", now=STAMP)

    row = database.organization_row(scope, "i1")
    assert (row["state"], row["manual"], row["publication_id"]) == ("done", 1, "p1")


def test_restore_follows_a_merge_made_while_the_item_was_trashed(database):
    _, scope = _enabled_tenant(database)
    _publication(database, scope, "p1", "Dense Discovery", now=STAMP)
    _publication(database, scope, "p2", "Dense Discovery (2)", now=STAMP)
    database.assign_publication_manually(scope, "i1", publication_id="p1", now=STAMP)

    database.trash_item(scope, "i1", now=STAMP)
    assert database.merge_publications(scope, source_id="p1", target_id="p2", now=STAMP)
    database.restore_item(scope, "i1", now=STAMP)

    assert database.organization_row(scope, "i1")["publication_id"] == "p2"


def test_an_unorganized_item_restores_as_still_waiting(database):
    _, scope = _enabled_tenant(database)
    database.trash_item(scope, "i1", now=STAMP)
    database.restore_item(scope, "i1", now=STAMP)
    assert database.organization_row(scope, "i1") is None
