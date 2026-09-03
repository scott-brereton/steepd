import re
from datetime import UTC, datetime

import pytest

from steepd import words
from steepd.auth import verify_password
from steepd.db import Database
from steepd.models import Item
from steepd.tenancy import TenantScope

# Kept in step with tests/test_words.py.
PASSPHRASE = re.compile(r"^[a-z]+\.[a-z]+\.[a-z]+$")


def _item(
    tenant_id: str,
    item_id: str,
    sha: str,
    *,
    author: str = "An author",
    created_at: str | None = None,
    size_bytes: int = 1024,
) -> Item:
    return Item(
        id=item_id,
        tenant_id=tenant_id,
        kind="book",
        sha256=sha,
        storage_name=f"{item_id}.epub",
        download_filename="book.epub",
        title="A book",
        author=author,
        language="en",
        identifier="",
        source_url="",
        size_bytes=size_bytes,
        created_at=created_at or datetime.now(UTC).isoformat(),
        expires_at=None,
        source="email",
    )


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "steepd.sqlite3")
    db.initialize()
    return db


def test_tenants_cannot_see_each_others_items(database):
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")
    a_scope, b_scope = TenantScope(alice.id), TenantScope(bob.id)

    database.insert_item(a_scope, _item(alice.id, "item-a", "sha-a"))

    assert len(database.list_items(a_scope)) == 1
    assert database.list_items(b_scope) == []
    assert database.get_item(b_scope, "item-a") is None
    assert database.item_by_sha256(b_scope, "sha-a") is None
    assert database.count_items(b_scope) == 0
    assert database.delete_item(b_scope, "item-a") is False
    assert database.get_item(a_scope, "item-a") is not None


def test_same_file_can_exist_for_two_tenants(database):
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")

    database.insert_item(TenantScope(alice.id), _item(alice.id, "item-a", "same-sha"))
    database.insert_item(TenantScope(bob.id), _item(bob.id, "item-b", "same-sha"))

    assert database.item_by_sha256(TenantScope(alice.id), "same-sha").id == "item-a"
    assert database.item_by_sha256(TenantScope(bob.id), "same-sha").id == "item-b"


def test_author_count_only_counts_the_scoped_tenants_authors(database):
    """count_authors drives pagination on the authors feed. If it stopped filtering on
    tenant_id it would report every tenant's author total, leaking how much other people
    have in their library even though the page itself only lists the caller's authors."""
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")
    a_scope, b_scope = TenantScope(alice.id), TenantScope(bob.id)

    database.insert_item(a_scope, _item(alice.id, "item-a", "sha-a", author="Ada Lovelace"))
    for index, author in enumerate(["Grace Hopper", "Alan Turing", "Ken Thompson"]):
        database.insert_item(b_scope, _item(bob.id, f"item-b{index}", f"sha-b{index}", author=author))

    assert database.count_authors(a_scope) == 1
    assert database.count_authors(b_scope) == 3
    assert [author.name for author in database.list_authors(a_scope)] == ["Ada Lovelace"]


def test_latest_item_time_does_not_leak_another_tenants_activity(database):
    """latest_created_at supplies the root feed's <updated> timestamp. Unscoped, it would
    move whenever any other tenant received an item -- a side channel that tells a quiet
    tenant when strangers are active, and makes their own feed look freshly updated."""
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")
    carol = database.create_tenant(email="carol@example.com", inbox_local="carol.c3")

    alice_time = "2024-01-01T00:00:00+00:00"
    bob_time = "2025-06-01T00:00:00+00:00"
    database.insert_item(TenantScope(alice.id), _item(alice.id, "item-a", "sha-a", created_at=alice_time))
    database.insert_item(TenantScope(bob.id), _item(bob.id, "item-b", "sha-b", created_at=bob_time))

    assert database.latest_created_at(TenantScope(alice.id)) == alice_time
    assert database.latest_created_at(TenantScope(bob.id)) == bob_time
    assert database.latest_created_at(TenantScope(carol.id)) == "1970-01-01T00:00:00Z"


def test_storage_usage_counts_only_the_scoped_tenants_bytes(database):
    """tenant_storage_bytes is the left-hand side of the quota check. Unscoped, it would
    sum every tenant's library, so one heavy account would lock everybody else out of
    uploading -- and the total would tell each of them how much strangers have stored."""
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")
    carol = database.create_tenant(email="carol@example.com", inbox_local="carol.c3")
    a_scope, b_scope = TenantScope(alice.id), TenantScope(bob.id)

    database.insert_item(a_scope, _item(alice.id, "item-a1", "sha-a1", size_bytes=1_000))
    database.insert_item(a_scope, _item(alice.id, "item-a2", "sha-a2", size_bytes=2_500))
    database.insert_item(b_scope, _item(bob.id, "item-b", "sha-b", size_bytes=9_000_000))

    assert database.tenant_storage_bytes(a_scope) == 3_500
    assert database.tenant_storage_bytes(b_scope) == 9_000_000
    # SUM over no rows is NULL, which is nought bytes used, not an empty library that
    # cannot be added to.
    assert database.tenant_storage_bytes(TenantScope(carol.id)) == 0


def test_insert_item_rejects_an_item_belonging_to_another_tenant(database):
    """insert_item's scope check is the last line of defence against a caller that has
    resolved one tenant but built the Item from another's data. Without it the row lands in
    the victim's library, where it is invisible to the caller and undeletable by them."""
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")
    a_scope, b_scope = TenantScope(alice.id), TenantScope(bob.id)

    with pytest.raises(ValueError):
        database.insert_item(a_scope, _item(bob.id, "item-b", "sha-b"))

    assert database.list_items(a_scope) == []
    assert database.list_items(b_scope) == []


def test_setting_a_plan_rejects_a_name_the_plan_rules_would_not_recognise(database):
    """An unrecognised plan is not stored, because quota_bytes and retention_for fail
    closed: 'Paid' in the column would read as free and quietly cap and expire a paying
    tenant's library rather than failing where the mistake was made."""
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    assert alice.plan == "free"

    with pytest.raises(ValueError):
        database.set_tenant_plan(alice.id, "Paid")

    assert database.tenant_by_id(alice.id).plan == "free"
    assert database.set_tenant_plan(alice.id, "paid") is True
    assert database.tenant_by_id(alice.id).plan == "paid"
    assert database.set_tenant_plan("not-a-tenant", "paid") is False


def test_tenant_lookup_by_inbox_is_case_insensitive(database):
    created = database.create_tenant(email="alice@example.com", inbox_local="Alice.A1")
    assert database.tenant_by_inbox_local("alice.a1").id == created.id
    assert database.tenant_by_inbox_local("nobody") is None


def test_deleting_a_tenant_leaves_no_rows_of_theirs_behind(database):
    """Account deletion has to be complete. A surviving items row keeps a file on disk
    reachable by nothing, and a surviving newsletter_deliveries row keeps a record of what
    the person read after they asked us to forget them."""
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    a_scope = TenantScope(alice.id)
    database.insert_item(a_scope, _item(alice.id, "item-a", "sha-a"))
    database.record_newsletter_delivery(
        a_scope,
        provider="test",
        email_id="mail-a",
        message_id="<a@example.com>",
        content_sha256="content-a",
        source_url="",
        item_id="item-a",
        forwarded_at=datetime.now(UTC).isoformat(),
    )

    assert database.delete_tenant(alice.id) is True

    assert database.tenant_by_inbox_local("alice.a1") is None
    assert database.list_items(a_scope) == []
    with database._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM newsletter_deliveries").fetchone()[0] == 0


def test_deleting_a_tenant_does_not_touch_another_tenants_rows(database):
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")
    a_scope, b_scope = TenantScope(alice.id), TenantScope(bob.id)
    database.insert_item(a_scope, _item(alice.id, "item-a", "shared-sha"))
    database.insert_item(b_scope, _item(bob.id, "item-b", "shared-sha"))

    assert database.delete_tenant(alice.id) is True

    assert database.tenant_by_inbox_local("bob.b2").id == bob.id
    assert [item.id for item in database.list_items(b_scope)] == ["item-b"]
    assert database.count_items(b_scope) == 1


def test_deleting_an_unknown_tenant_reports_that_nothing_happened(database):
    database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    assert database.delete_tenant("not-a-tenant") is False
    assert database.tenant_by_inbox_local("alice.a1") is not None


# -- device passwords ---------------------------------------------------------
# These are typed by hand on an e-ink keyboard, so they are three-word passphrases
# rather than random tokens. See the comment in Database.create_tenant.


def test_a_new_tenants_device_password_is_a_three_word_passphrase(database):
    tenant, device_password = database.create_tenant_with_password(
        email="alice@example.com", inbox_local="alice.a1"
    )

    assert PASSPHRASE.match(device_password), device_password
    assert set(device_password.split(".")) <= set(words.WORDS)
    # The plaintext is returned to the caller and never stored; only its hash is.
    assert device_password not in tenant.opds_password_hash
    assert verify_password(device_password, tenant.opds_password_hash)


def test_a_rotated_device_password_is_a_passphrase_that_verifies_against_the_stored_hash(database):
    tenant, original = database.create_tenant_with_password(email="alice@example.com", inbox_local="alice.a1")

    rotated = database.rotate_device_password(tenant.id)

    assert PASSPHRASE.match(rotated), rotated
    assert rotated != original
    stored = database.tenant_by_id(tenant.id).opds_password_hash
    assert verify_password(rotated, stored)
    assert not verify_password(original, stored)


def test_the_no_return_tenant_constructor_uses_the_same_generator(database, monkeypatch):
    """create_tenant discards the plaintext, so the only observable is that whatever it
    hashed came from the passphrase generator. Pin it to a known value to see it."""
    pinned = "maple.otter.lantern"
    monkeypatch.setattr("steepd.words.generate_passphrase", lambda *args, **kwargs: pinned)

    tenant = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")

    assert verify_password(pinned, tenant.opds_password_hash)


def test_device_passwords_are_not_reused_between_tenants(database):
    first, first_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    second, second_password = database.create_tenant_with_password(email="b@example.com", inbox_local="b.2")

    assert first_password != second_password
    assert not verify_password(first_password, second.opds_password_hash)
