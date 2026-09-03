from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, status

from steepd.models import Tenant

if TYPE_CHECKING:
    from steepd.db import Database

MAGIC_TOKEN_TTL = timedelta(minutes=15)
SESSION_TTL = timedelta(days=30)

# Per tenant, counted over tokens that are still live. Without it, anyone who knows an
# address can make us mail it an unbounded number of sign-in links.
MAGIC_TOKEN_ISSUANCE_CAP = 5


# -- device passwords -----------------------------------------------------
# The one hasher for the project. db.py hashes a device password on insert;
# this module hashes and verifies it for HTTP Basic. Keeping both here means
# there is exactly one place that knows the cost parameters and the stored
# format, so they cannot silently drift apart.


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, key_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
    except ValueError:
        return False
    candidate_key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return hmac.compare_digest(candidate_key, expected_key)


# Verified against on the unknown-username path so that branch costs the same scrypt work
# as the known one. Built once at import, not per call: hashing it per request would put
# the cost back on both branches but double it, and the value is never compared to anything
# a caller supplies -- the password below is random and discarded.
_ABSENT_TENANT_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


# -- credential cache -------------------------------------------------------
# Every OPDS request carries HTTP Basic credentials and there is no session, so an
# e-reader pays a ~35ms scrypt per catalogue tap and an unauthenticated caller can
# saturate the threadpool by repeating a request. This caches the *outcome* of a
# verification for a minute, keyed on the credentials themselves.
#
# Successes and failures are both cached, and that symmetry is the security property:
# if only successes were, a repeat of the right password would answer in microseconds
# while a repeat of a wrong one still paid scrypt, turning the cache into exactly the
# password oracle the constant-work path in authenticate_device exists to prevent. With
# both cached, timing distinguishes only "this pair has been tried before", which the
# attacker doing the retrying already knows.

_CREDENTIAL_CACHE_TTL = 60.0
_CREDENTIAL_CACHE_MAX_ENTRIES = 1024
# Never a tenant id: ids are 32 hex characters, so this sentinel cannot be one.
_DENIED = "no"

# Monotonic, so a system clock step cannot extend an entry's life. Bound at module
# scope rather than called through time.monotonic so tests can drive it without sleeping.
_clock = time.monotonic
_credential_cache: dict[str, tuple[float, str]] = {}
_credential_cache_lock = threading.Lock()


def _credential_key(username: str, password: str) -> str:
    """Hash the two fields separately before combining them.

    Fixed-width digests make the concatenation unambiguous: no username/password pair can
    be rearranged into another pair with the same key. The plaintext password is never
    stored, and the key is not derived from opds_password_hash -- reusing the stored hash
    as key material would put a password-equivalent value in a second place.
    """
    digest = hashlib.sha256()
    digest.update(hashlib.sha256(username.encode("utf-8")).digest())
    digest.update(hashlib.sha256(password.encode("utf-8")).digest())
    return digest.hexdigest()


def _cached_outcome(key: str) -> str | None:
    now = _clock()
    with _credential_cache_lock:
        entry = _credential_cache.get(key)
        if entry is None:
            return None
        expires_at, outcome = entry
        if expires_at <= now:
            del _credential_cache[key]
            return None
        return outcome


def _remember_outcome(key: str, outcome: str) -> None:
    now = _clock()
    with _credential_cache_lock:
        if len(_credential_cache) >= _CREDENTIAL_CACHE_MAX_ENTRIES:
            for expired in [k for k, (expires_at, _) in _credential_cache.items() if expires_at <= now]:
                del _credential_cache[expired]
            if len(_credential_cache) >= _CREDENTIAL_CACHE_MAX_ENTRIES:
                # Deliberately not an LRU. Every entry is a verification that can simply be
                # redone, so the worst a full flush costs is one scrypt per active device,
                # which is cheaper than the risk of an eviction policy subtly retaining an
                # entry it should have dropped.
                _credential_cache.clear()
        _credential_cache[key] = (now + _CREDENTIAL_CACHE_TTL, outcome)


def _reset_credential_cache() -> None:
    """Test seam. Nothing in the running service should need to clear the cache."""
    with _credential_cache_lock:
        _credential_cache.clear()


def authenticate_device(database: Database, username: str, password: str) -> Tenant | None:
    """Resolve device credentials to a tenant, doing the same work either way.

    Returning early on an unknown username skips scrypt entirely and makes the two
    outcomes trivially distinguishable by response time -- measured at 0.13ms against
    39ms, a factor of ~295, far above any network jitter and needing only a handful of
    samples per guess. That is not ordinary user enumeration: a device username *is* the
    tenant's inbox_local, so the timing leaks the private inbox address and lets an
    attacker post content into a stranger's library. It is the property Task 7's
    discard-don't-bounce rule protects, reopened through a different door.
    """
    tenant = database.tenant_by_opds_username(username)
    key = _credential_key(username, password)
    outcome = _cached_outcome(key)
    if outcome == _DENIED:
        return None
    if outcome is not None and tenant is not None and tenant.id == outcome:
        return tenant
    # Either a miss, or a cached success whose username now resolves elsewhere (the tenant
    # was deleted, or the name was reassigned). Both fall through to a real verification
    # rather than trusting the entry, so a stale success can only ever cost a scrypt.
    #
    # A rotated password is the one case the cache papers over: the old password keeps
    # working for up to _CREDENTIAL_CACHE_TTL seconds after rotate_device_password. That
    # grace is accepted rather than plumbing invalidation hooks through every writer.
    stored = _ABSENT_TENANT_PASSWORD_HASH if tenant is None else tenant.opds_password_hash
    # Evaluated before the branch, never inside it: `tenant is None or not verify_password(...)`
    # would short-circuit and restore the fast path this exists to remove.
    matches = verify_password(password, stored)
    if tenant is None or not matches:
        _remember_outcome(key, _DENIED)
        return None
    _remember_outcome(key, tenant.id)
    return tenant


# -- magic links ------------------------------------------------------------
# Sign-in has no password to remember, reset, or store: a single-use link
# mailed to the tenant's address. Only the token's hash is ever persisted, so
# a database dump does not yield working login links.


def _utc(now: datetime | None) -> datetime:
    """Reject a naive datetime instead of guessing at its zone.

    astimezone() reads a naive datetime as system local time. In a western offset that
    fails closed -- a token looks older than it is -- but in an eastern one it fails open:
    a token that should have expired is still redeemable. Both callers below compare the
    result against a stored ISO string, so a wrong guess here is silent.
    """
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ValueError("now must be an aware datetime")
    return now.astimezone(UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_magic_token(database: Database, email: str, *, now: datetime | None = None) -> str:
    # Generate and hash the token unconditionally, whether or not the email is known, so
    # this branch and the known-email branch below do the same work. Skipping straight to
    # `return ""` on an unknown email would make the response time itself reveal whether
    # the account exists.
    moment = _utc(now)
    token = secrets.token_urlsafe(32)
    token_hash = _token_hash(token)
    # Above the tenant lookup so both branches pay for it. Consumed and expired rows are
    # dead weight -- redeem_magic_token will never match one again -- and issuance is the
    # only path that adds rows, so pruning here needs no scheduler.
    database.prune_magic_tokens(now=moment.isoformat())
    tenant = database.tenant_by_email(email)
    if tenant is None:
        # Do not reveal whether an account exists for this address.
        return ""
    if database.count_active_magic_tokens(tenant.id, now=moment.isoformat()) >= MAGIC_TOKEN_ISSUANCE_CAP:
        # The same silent "" as the unknown-email branch, reached after the same token
        # generation, so a caller cannot tell a capped account from an absent one. Live
        # links stay valid; the cap only stops another one being minted and mailed.
        return ""
    expires_at = (moment + MAGIC_TOKEN_TTL).isoformat()
    database.insert_magic_token(token_hash=token_hash, tenant_id=tenant.id, expires_at=expires_at)
    return token


def consume_magic_token(database: Database, token: str, *, now: datetime | None = None) -> Tenant | None:
    # Normalise to UTC before formatting: expiry is compared as a string in db.py, so a
    # caller passing a non-UTC-but-equivalent instant must not silently disable expiry.
    moment = _utc(now)
    return database.redeem_magic_token(token_hash=_token_hash(token), now=moment.isoformat())


# -- browser sessions -------------------------------------------------------
# What a redeemed magic link turns into. Same storage discipline as the tokens
# above: the raw value lives only in the caller's cookie, and only its hash is
# persisted, so a database dump does not yield a usable session.


def issue_session(database: Database, tenant_id: str, *, now: datetime | None = None) -> str:
    moment = _utc(now)
    token = secrets.token_urlsafe(32)
    # Opportunistic: sign-in is the only event that reliably happens, and no scheduler
    # exists to sweep the table on its own.
    database.delete_expired_sessions(now=moment.isoformat())
    database.insert_session(
        token_hash=_token_hash(token),
        tenant_id=tenant_id,
        created_at=moment.isoformat(),
        expires_at=(moment + SESSION_TTL).isoformat(),
    )
    return token


def resolve_session(database: Database, token: str, *, now: datetime | None = None) -> Tenant | None:
    moment = _utc(now)
    return database.session_tenant(token_hash=_token_hash(token), now=moment.isoformat())


def revoke_session(database: Database, token: str) -> None:
    """Sign-out. Deleting rather than marking revoked keeps "row exists and is unexpired"
    the single condition resolve_session has to check."""
    database.delete_session(token_hash=_token_hash(token))


# -- same-origin guard --------------------------------------------------
# Ported from the single-tenant service this codebase grew out of. Keeps the
# Origin: null fix: this app sets Referrer-Policy: no-referrer, and under
# that policy Chrome sends Origin: null on form-submission navigations.


def same_origin_guard(public_base_url: str) -> Callable[[Request], None]:
    expected = urlsplit(public_base_url)
    expected_origin = f"{expected.scheme}://{expected.netloc}".lower()

    def verify(request: Request) -> None:
        fetch_site = request.headers.get("sec-fetch-site", "").lower()
        if fetch_site == "cross-site":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-site request rejected")
        origin = request.headers.get("origin")
        if not origin:
            return
        if origin.strip().lower() == "null":
            # This app sets Referrer-Policy: no-referrer, and under that policy
            # Chrome sends Origin: null on form-submission navigations. Every
            # browser upload and delete arrives this way. Sec-Fetch-Site is a
            # forbidden header name, so a same-origin value here is asserted by
            # the browser and cannot be set by page script.
            if fetch_site == "same-origin":
                return
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin rejected")
        parsed = urlsplit(origin)
        actual_origin = f"{parsed.scheme}://{parsed.netloc}".lower()
        if actual_origin != expected_origin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin rejected")

    return verify
