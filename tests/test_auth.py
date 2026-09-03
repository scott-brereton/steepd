# reader-service/tests/test_auth.py
import hashlib
import secrets
from datetime import UTC, datetime, timedelta, timezone

import pytest

from steepd import auth
from steepd.auth import (
    MAGIC_TOKEN_ISSUANCE_CAP,
    SESSION_TTL,
    authenticate_device,
    consume_magic_token,
    hash_password,
    issue_magic_token,
    issue_session,
    resolve_session,
    revoke_session,
    verify_password,
)
from steepd.db import Database


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "steepd.sqlite3")
    db.initialize()
    return db


@pytest.fixture(autouse=True)
def _empty_credential_cache():
    """The credential cache is process-global and outlives any one tmp_path database, so a
    verification cached by one test would otherwise answer another test's call."""
    auth._reset_credential_cache()
    yield
    auth._reset_credential_cache()


def _count_scrypt_calls(monkeypatch) -> list:
    calls = []
    original_scrypt = hashlib.scrypt

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return original_scrypt(*args, **kwargs)

    monkeypatch.setattr("steepd.auth.hashlib.scrypt", spy)
    return calls


def test_password_hash_round_trip():
    stored = hash_password("correct horse")
    assert stored != "correct horse"
    assert verify_password("correct horse", stored) is True
    assert verify_password("wrong", stored) is False


def test_device_auth_returns_the_owning_tenant(database):
    tenant, device_password = database.create_tenant_with_password(
        email="a@example.com", inbox_local="a.1"
    )
    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    assert authenticate_device(database, tenant.opds_username, "nope") is None
    assert authenticate_device(database, "someone-else", device_password) is None


def test_magic_token_is_single_use(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    token = issue_magic_token(database, "a@example.com")

    assert consume_magic_token(database, token).id == tenant.id
    assert consume_magic_token(database, token) is None


def test_magic_token_expires(database):
    database.create_tenant(email="a@example.com", inbox_local="a.1")
    token = issue_magic_token(database, "a@example.com")
    later = datetime.now(UTC) + timedelta(minutes=16)
    assert consume_magic_token(database, token, now=later) is None


def test_magic_token_for_unknown_email_is_none(database):
    assert issue_magic_token(database, "nobody@example.com") == ""


@pytest.mark.parametrize(
    "stored",
    [
        "scrypt$zz$zz",  # not valid hex
        "scrypt$abc$def",  # odd-length hex
        "bogus$a$b",  # wrong scheme
        "",  # empty
        "scrypt$onefield",  # wrong field count
    ],
)
def test_verify_password_rejects_a_malformed_stored_hash_without_raising(stored):
    # A corrupted or hand-edited opds_password_hash must fail closed (401), not blow up
    # with an unhandled exception on the Basic-auth path.
    assert verify_password("anything", stored) is False


def test_magic_token_expiry_survives_a_non_utc_clock(database):
    # expires_at is compared as a string, so the caller's datetime must be normalised to
    # UTC before formatting -- otherwise a same-instant, non-UTC-offset "now" that is
    # actually past expiry can sort as "earlier" and the token gets redeemed anyway.
    database.create_tenant(email="a@example.com", inbox_local="a.1")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    token = issue_magic_token(database, "a@example.com", now=issued_at)

    sixteen_minutes_later = issued_at + timedelta(minutes=16)
    non_utc_but_same_instant = sixteen_minutes_later.astimezone(timezone(timedelta(hours=-5)))

    assert consume_magic_token(database, token, now=non_utc_but_same_instant) is None


def test_issue_magic_token_does_the_same_work_for_a_known_and_unknown_email(database, monkeypatch):
    # Generating and hashing the token must not be skipped on the unknown-email path --
    # skipping it would make issuance measurably faster and let a caller enumerate which
    # emails have accounts by timing the response. Assert the code path directly rather
    # than timing it, which would be flaky.
    calls = []
    original_token_urlsafe = secrets.token_urlsafe

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return original_token_urlsafe(*args, **kwargs)

    database.create_tenant(email="a@example.com", inbox_local="a.1")
    monkeypatch.setattr("steepd.auth.secrets.token_urlsafe", spy)

    issue_magic_token(database, "a@example.com")
    assert len(calls) == 1

    issue_magic_token(database, "nobody@example.com")
    assert len(calls) == 2


def test_device_auth_does_the_same_work_for_a_known_and_unknown_username(database, monkeypatch):
    # Skipping the password hash on the unknown-username path makes the two outcomes
    # distinguishable by response time. A device username is the tenant's inbox_local, so
    # that timing leaks the private inbox address an attacker could then post content to --
    # the same property Task 7's discard-don't-bounce rule protects. Assert the code path
    # rather than the clock: a wall-clock threshold flakes under CI load.
    calls = []
    original_scrypt = hashlib.scrypt

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return original_scrypt(*args, **kwargs)

    tenant, device_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    monkeypatch.setattr("steepd.auth.hashlib.scrypt", spy)

    assert authenticate_device(database, tenant.opds_username, "wrong password") is None
    assert len(calls) == 1

    assert authenticate_device(database, "nobody", "wrong password") is None
    assert len(calls) == 2

    # The dummy hash is only a cost equaliser. It must never authenticate anyone, including
    # a caller who somehow supplies the exact password it was built from.
    assert authenticate_device(database, "nobody", device_password) is None
    assert len(calls) == 3


def test_repeat_device_auth_reuses_the_cached_result_instead_of_rehashing(database, monkeypatch):
    # The whole point of the cache: an e-reader walking the catalogue re-presents the same
    # credentials on every request and must not pay ~35ms of scrypt each time.
    tenant, device_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    calls = _count_scrypt_calls(monkeypatch)

    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    assert len(calls) == 1

    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    assert len(calls) == 1


def test_a_repeated_wrong_password_is_cached_too(database, monkeypatch):
    """Caching only successes would rebuild the oracle the constant-work path removed.

    A cached success answers in microseconds. If a failure still paid scrypt, an attacker
    could tell a right password from a wrong one by re-sending the same guess twice and
    timing the second attempt -- no account access needed, and none of the constant-work
    care in authenticate_device would help, because the difference is now in the cache
    rather than in the hashing.
    """
    tenant, device_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    calls = _count_scrypt_calls(monkeypatch)

    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    calls_for_a_repeated_success = len(calls)

    calls.clear()
    assert authenticate_device(database, tenant.opds_username, "wrong") is None
    assert authenticate_device(database, tenant.opds_username, "wrong") is None
    calls_for_a_repeated_failure = len(calls)

    assert calls_for_a_repeated_failure == calls_for_a_repeated_success == 1


def test_an_unknown_username_is_cached_without_reopening_the_enumeration_oracle(database, monkeypatch):
    # The absent-tenant path caches its denial like any other, so a repeated probe for a
    # non-existent username is as fast as a repeated probe for a real one.
    database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    calls = _count_scrypt_calls(monkeypatch)

    assert authenticate_device(database, "nobody", "guess") is None
    assert authenticate_device(database, "nobody", "guess") is None
    assert len(calls) == 1


def test_cached_credentials_stop_being_trusted_after_the_ttl(database, monkeypatch):
    # Drive the clock rather than sleeping for a minute. _clock is monotonic in production;
    # the test only needs it to move forward.
    tenant, device_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    fake_now = 1000.0
    monkeypatch.setattr("steepd.auth._clock", lambda: fake_now)
    calls = _count_scrypt_calls(monkeypatch)

    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    assert len(calls) == 1

    fake_now += auth._CREDENTIAL_CACHE_TTL - 1
    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    assert len(calls) == 1

    fake_now += 2
    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id
    assert len(calls) == 2


def test_a_full_credential_cache_does_not_grow_without_bound(database, monkeypatch):
    database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    monkeypatch.setattr(auth, "_CREDENTIAL_CACHE_MAX_ENTRIES", 8)

    for index in range(50):
        assert authenticate_device(database, f"nobody-{index}", "guess") is None

    assert len(auth._credential_cache) <= 8


def test_rotating_the_device_password_retires_the_old_one(database):
    tenant, original_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    assert authenticate_device(database, tenant.opds_username, original_password).id == tenant.id

    rotated = database.rotate_device_password(tenant.id)
    assert rotated != original_password

    # The cache is deliberately not invalidated on rotation -- see authenticate_device -- so
    # the old password would keep working for up to the TTL. Clear it here to assert the
    # stored hash really changed rather than asserting the grace period.
    auth._reset_credential_cache()

    assert authenticate_device(database, tenant.opds_username, original_password) is None
    assert authenticate_device(database, tenant.opds_username, rotated).id == tenant.id


def test_rotating_an_unknown_tenants_password_changes_nothing(database):
    tenant, device_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    assert database.rotate_device_password("not-a-tenant") is None
    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id


def test_deleting_a_tenant_stops_their_device_password_working(database):
    tenant, device_password = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    assert authenticate_device(database, tenant.opds_username, device_password).id == tenant.id

    assert database.delete_tenant(tenant.id) is True

    # A cached success must not outlive the tenant it names: the username no longer resolves,
    # so the entry is not trusted even inside its TTL.
    assert authenticate_device(database, tenant.opds_username, device_password) is None


def test_magic_token_issuance_is_capped_per_tenant(database):
    """Without a cap, anyone who knows an address can make us mail it link after link --
    a mailbox flood aimed at someone else, sent from our domain and our reputation."""
    database.create_tenant(email="a@example.com", inbox_local="a.1")

    issued = [issue_magic_token(database, "a@example.com") for _ in range(MAGIC_TOKEN_ISSUANCE_CAP)]
    assert all(issued)

    assert issue_magic_token(database, "a@example.com") == ""

    # The links already sent keep working; the cap suppresses new ones, it does not
    # invalidate outstanding ones.
    assert consume_magic_token(database, issued[0]) is not None


def test_the_cap_counts_only_live_tokens(database):
    database.create_tenant(email="a@example.com", inbox_local="a.1")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)

    for _ in range(MAGIC_TOKEN_ISSUANCE_CAP):
        assert issue_magic_token(database, "a@example.com", now=issued_at) != ""
    assert issue_magic_token(database, "a@example.com", now=issued_at) == ""

    # Once the earlier batch has expired it is neither redeemable nor counted, so a tenant
    # is not locked out of signing in tomorrow by five links they never clicked today.
    later = issued_at + timedelta(hours=1)
    assert issue_magic_token(database, "a@example.com", now=later) != ""


def test_the_cap_is_per_tenant(database):
    database.create_tenant(email="a@example.com", inbox_local="a.1")
    database.create_tenant(email="b@example.com", inbox_local="b.2")

    for _ in range(MAGIC_TOKEN_ISSUANCE_CAP):
        issue_magic_token(database, "a@example.com")

    assert issue_magic_token(database, "a@example.com") == ""
    assert issue_magic_token(database, "b@example.com") != ""


def test_issuance_prunes_consumed_and_expired_tokens(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)

    consumed = issue_magic_token(database, "a@example.com", now=issued_at)
    consume_magic_token(database, consumed, now=issued_at)
    issue_magic_token(database, "a@example.com", now=issued_at)  # left to expire

    later = issued_at + timedelta(hours=1)
    issue_magic_token(database, "a@example.com", now=later)

    # Only the row just written survives: nothing reads a consumed or expired token, and
    # without pruning the table grows for the lifetime of the service.
    assert database.count_active_magic_tokens(tenant.id, now=later.isoformat()) == 1
    with database._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM magic_tokens").fetchone()[0] == 1


def test_session_round_trip(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    token = issue_session(database, tenant.id)

    assert token
    assert resolve_session(database, token).id == tenant.id
    assert resolve_session(database, "not-a-session") is None


def test_only_the_session_hash_is_stored(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    token = issue_session(database, tenant.id)

    with database._connect() as connection:
        stored = connection.execute("SELECT token_hash FROM sessions").fetchall()

    assert [row["token_hash"] for row in stored] == [hashlib.sha256(token.encode("utf-8")).hexdigest()]


def test_session_expires(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    token = issue_session(database, tenant.id, now=issued_at)

    assert resolve_session(database, token, now=issued_at + SESSION_TTL - timedelta(minutes=1)) is not None
    assert resolve_session(database, token, now=issued_at + SESSION_TTL + timedelta(minutes=1)) is None


def test_session_expiry_survives_a_non_utc_clock(database):
    # expires_at is compared as a string, exactly like the magic-token expiry, so a caller's
    # non-UTC-but-equivalent instant must not sort as "earlier" and revive a dead session.
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    token = issue_session(database, tenant.id, now=issued_at)

    past_expiry = issued_at + SESSION_TTL + timedelta(minutes=1)
    non_utc_but_same_instant = past_expiry.astimezone(timezone(timedelta(hours=-5)))

    assert resolve_session(database, token, now=non_utc_but_same_instant) is None


def test_session_rejects_a_naive_datetime(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    with pytest.raises(ValueError):
        issue_session(database, tenant.id, now=datetime(2026, 1, 1, 12, 0, 0))

    token = issue_session(database, tenant.id)
    with pytest.raises(ValueError):
        resolve_session(database, token, now=datetime(2026, 1, 1, 12, 0, 0))


def test_revoking_a_session_ends_it(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    token = issue_session(database, tenant.id)
    other = issue_session(database, tenant.id)

    revoke_session(database, token)

    assert resolve_session(database, token) is None
    assert resolve_session(database, other).id == tenant.id
    # Revoking an unknown token is a no-op, not an error: sign-out must work with a stale
    # cookie the same way it works with a live one.
    revoke_session(database, "not-a-session")


def test_issuing_a_session_sweeps_expired_ones(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    issue_session(database, tenant.id, now=issued_at)

    issue_session(database, tenant.id, now=issued_at + SESSION_TTL + timedelta(days=1))

    # No scheduler exists, so issuance is the only thing that ever removes a dead row.
    with database._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_sessions_are_not_shared_between_tenants(database):
    alice = database.create_tenant(email="alice@example.com", inbox_local="alice.a1")
    bob = database.create_tenant(email="bob@example.com", inbox_local="bob.b2")

    alice_token = issue_session(database, alice.id)
    bob_token = issue_session(database, bob.id)

    assert resolve_session(database, alice_token).id == alice.id
    assert resolve_session(database, bob_token).id == bob.id


def test_deleting_a_tenant_takes_their_sessions_and_tokens_with_it(database):
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    session_token = issue_session(database, tenant.id)
    magic_token = issue_magic_token(database, "a@example.com")

    assert database.delete_tenant(tenant.id) is True

    assert resolve_session(database, session_token) is None
    assert consume_magic_token(database, magic_token) is None
    with database._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM magic_tokens").fetchone()[0] == 0


def test_the_absent_tenant_hash_is_a_real_hash_of_the_same_shape(database):
    # If the dummy were malformed, verify_password would reject it on the parse and return
    # before hashing -- reinstating the fast path while the spy test above still passed,
    # because parsing happens inside verify_password rather than in authenticate_device.
    scheme, salt_hex, key_hex = auth._ABSENT_TENANT_PASSWORD_HASH.split("$")
    assert scheme == "scrypt"
    assert len(bytes.fromhex(salt_hex)) == 16
    assert len(bytes.fromhex(key_hex)) == 32
    assert verify_password("anything", auth._ABSENT_TENANT_PASSWORD_HASH) is False


def test_a_cached_success_cannot_survive_the_inbox_name_moving_to_another_tenant(database):
    """The cache stores a tenant id and authenticate_device must compare it against who the
    username resolves to NOW. Without that comparison, this sequence authenticates one
    tenant's old password as a different tenant: alice authenticates (outcome cached),
    deletes her account, and someone else registers the same inbox name inside the cache
    TTL. The stale entry names alice's id, the lookup returns the newcomer, and trusting
    the entry without the id check would hand alice's credentials the newcomer's library."""
    alice, password = database.create_tenant_with_password(email="alice@example.com", inbox_local="ada.1")
    assert authenticate_device(database, "ada.1", password).id == alice.id  # cached

    assert database.delete_tenant(alice.id)
    newcomer, _ = database.create_tenant_with_password(email="new@example.com", inbox_local="ada.1")

    resolved = authenticate_device(database, "ada.1", password)
    assert resolved is None, "a stale cached success must never authenticate against the reassigned name"
