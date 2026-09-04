from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from steepd import db as db_module
from steepd.db import MAX_ALLOWED_SENDERS, MAX_REFUSED_SENDERS, SCHEMA_VERSION, AllowedSenderCapReached, Database
from steepd.inboxnames import is_placeholder
from steepd.models import Item
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


def test_fresh_database_is_version_6_with_email_verification_relays(database):
    assert _version(database) == SCHEMA_VERSION == 6
    with database._connect() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(tenants)")}
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"inbox_confirmed_at", "sender_policy"} <= columns
    assert {"allowed_senders", "refused_senders", "retired_inbox_locals", "email_verification_relays"} <= tables


def test_a_version_4_database_upgrades_in_place_and_existing_tenants_are_confirmed(tmp_path):
    database = _build_version_4_database(tmp_path / "old.sqlite3")
    database.initialize()
    database.initialize()  # idempotent

    assert _version(database) == 6
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

    assert _version(database) == 6
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
    assert _version(database) == 6
    assert database.tenant_by_email("ada@example.com").inbox_confirmed_at == "2026-08-01T00:00:00+00:00"


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
