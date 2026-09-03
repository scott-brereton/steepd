"""Tests for the per-IP rate limits.

Almost everything here drives real HTTP through TestClient rather than calling the
limiter directly, because the interesting behaviour is not the counting -- it is *where*
in the stack the counting happens. A limiter that returns the right verdicts but runs
below authentication still pays the scrypt it exists to avoid, and only a request that
goes through the whole middleware stack can show that.

Distinct client addresses come from TestClient's own `client=` argument, which is what
populates ASGI's scope["client"]; the limiter reads nothing else about the caller.

Time is driven through the limiter's injectable clock. Windows here are fifteen minutes
and an hour long, so no test can afford to sleep through one.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from steepd.app import create_app
from steepd.auth import _reset_credential_cache
from steepd.config import Settings
from steepd.ratelimit import (
    _UNKNOWN_CLIENT,
    ADDRESS_BUCKET,
    OPDS_AUTH_BUCKET,
    POLICIES,
    SIGNIN_BUCKET,
    SIGNUP_BUCKET,
    Policy,
    RateLimiter,
)

BASE_URL = "http://localhost:8000"
INBOX_DOMAIN = "read.example.test"
ONE_IP = ("198.51.100.7", 4001)
OTHER_IP = ("203.0.113.9", 4002)

SIGNUP_LIMIT = POLICIES[SIGNUP_BUCKET].limit
SIGNIN_LIMIT = POLICIES[SIGNIN_BUCKET].limit
OPDS_LIMIT = POLICIES[OPDS_AUTH_BUCKET].limit


class FakeClock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def app(tmp_path, monkeypatch):
    """A fresh app, so the limiter's windows start empty for every test.

    Per-app state is the reason no reset seam is needed here: `create_app` builds its own
    RateLimiter and hangs it on app.state, exactly as it does the database. The one piece
    of state that *is* module-global is auth.py's credential cache, so that gets cleared.
    """
    _reset_credential_cache()
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL, inbox_domain=INBOX_DOMAIN)
    built = create_app(settings)
    monkeypatch.setattr("steepd.web.send_email", lambda settings, **message: None)
    return built


@pytest.fixture
def clock(app):
    """Drive the limiter's windows without sleeping."""
    fake = FakeClock()
    app.state.rate_limiter.clock = fake
    return fake


def _client(app, address=ONE_IP) -> TestClient:
    return TestClient(app, base_url=BASE_URL, client=address)


def _auth_header(username: str, password: str) -> dict[str, str]:
    raw = f"{username}:{password}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


def _scrypt_counter(monkeypatch) -> list[int]:
    """Count real scrypt calls. The list is a single mutable cell so callers can zero it."""
    calls = [0]
    real = hashlib.scrypt

    def counting(*args, **kwargs):
        calls[0] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(hashlib, "scrypt", counting)
    return calls


# -- the sign-up and sign-in cannons -----------------------------------------


def test_sixth_signup_from_one_address_is_refused(app):
    """Five sign-ups an hour, and the sixth is the mail cannon starting up."""
    client = _client(app)
    for index in range(SIGNUP_LIMIT):
        response = client.post("/signup", data={"email": f"reader{index}@example.test"})
        assert response.status_code == 200, f"attempt {index + 1} should have been served"

    refused = client.post("/signup", data={"email": "stranger@example.test"})
    assert refused.status_code == 429
    assert "Too many attempts. Try again in a few minutes." in refused.text
    assert refused.headers["content-type"].startswith("text/html")
    # A window's worth of seconds, never zero: a client honouring Retry-After: 0 would
    # retry straight into another refusal.
    retry_after = int(refused.headers["retry-after"])
    assert 0 < retry_after <= POLICIES[SIGNUP_BUCKET].window_seconds


def test_a_refused_address_does_not_refuse_anyone_else(app):
    """The limit is per address. One abuser must not close sign-up for the world."""
    abuser = _client(app, ONE_IP)
    for index in range(SIGNUP_LIMIT + 1):
        abuser.post("/signup", data={"email": f"spray{index}@example.test"})
    assert abuser.post("/signup", data={"email": "spray-again@example.test"}).status_code == 429

    bystander = _client(app, OTHER_IP)
    assert bystander.post("/signup", data={"email": "real.person@example.test"}).status_code == 200


def test_the_window_expiring_restores_service(app, clock):
    client = _client(app)
    for index in range(SIGNUP_LIMIT):
        client.post("/signup", data={"email": f"reader{index}@example.test"})
    assert client.post("/signup", data={"email": "sixth@example.test"}).status_code == 429

    clock.advance(POLICIES[SIGNUP_BUCKET].window_seconds + 1)
    assert client.post("/signup", data={"email": "an.hour.later@example.test"}).status_code == 200


def test_signin_has_its_own_larger_allowance(app):
    """Separate buckets: spending sign-up's five must not spend sign-in's ten."""
    client = _client(app)
    for index in range(SIGNUP_LIMIT + 1):
        client.post("/signup", data={"email": f"reader{index}@example.test"})
    assert client.post("/signup", data={"email": "over@example.test"}).status_code == 429

    for attempt in range(SIGNIN_LIMIT):
        assert client.post("/signin", data={"email": "reader0@example.test"}).status_code == 200, attempt
    assert client.post("/signin", data={"email": "reader0@example.test"}).status_code == 429


# -- the OPDS scrypt burner ---------------------------------------------------


def _tenant(app):
    return app.state.database.create_tenant_with_password(email="ada@example.test", inbox_local="ada.1")


def test_failed_basic_auth_is_refused_after_the_limit_without_paying_a_scrypt(app, monkeypatch):
    """The test this whole module exists for.

    Twenty wrong guesses are answered with 401s. The twenty-first is answered above the
    route, and the assertion that matters is not its status code but the scrypt count: if
    the short-circuit ever moves below authentication, the limiter still returns 429 while
    the CPU cost it was built to remove is quietly back.

    Every guess is a password that has not been tried before, which matters twice over.
    It is the residual auth.py names -- a repeated pair is answered from the credential
    cache, so only a spray of unique ones costs a scrypt each -- and it is what makes the
    count below mean anything. With a repeated pair the cache would report zero scrypts
    whether or not the short-circuit existed, and this test would pass a build that had
    lost it.
    """
    tenant, _ = _tenant(app)
    client = _client(app)
    for attempt in range(OPDS_LIMIT):
        header = _auth_header(tenant.opds_username, f"guess-{attempt}")
        assert client.get("/opds", headers=header).status_code == 401, attempt

    calls = _scrypt_counter(monkeypatch)
    refused = client.get("/opds", headers=_auth_header(tenant.opds_username, "a guess never tried"))
    # Asserted before the status code on purpose: a limiter that answers 429 from below
    # authentication passes the status assertion and has changed nothing about the cost.
    assert calls[0] == 0, "the over-limit request reached password verification"
    assert refused.status_code == 429
    assert refused.headers["content-type"].startswith("text/plain")
    assert "Too many failed sign-in attempts." in refused.text
    assert 0 < int(refused.headers["retry-after"]) <= POLICIES[OPDS_AUTH_BUCKET].window_seconds


def test_a_polling_ereader_is_never_throttled(app):
    """Successes are not counted, at any volume.

    An e-reader carries Basic credentials on every catalogue tap and refresh, so a limiter
    that counted them would throttle the one client that is behaving. Thirty successful
    fetches is well past the twenty-failure limit; a wrong password afterwards must still
    reach authentication and come back 401, not 429.
    """
    tenant, password = _tenant(app)
    client = _client(app)
    good = _auth_header(tenant.opds_username, password)
    for tap in range(30):
        assert client.get("/opds", headers=good).status_code == 200, tap

    assert client.get("/opds", headers=_auth_header(tenant.opds_username, "wrong")).status_code == 401


def test_repeated_wrong_credentials_still_count_although_they_are_cached(app):
    """A 401 served from the credential cache is cheap for us and still a wrong password.

    The same pair every time, so auth.py answers all but the first from its cache. Not
    counting those would give an attacker a free retry for every pair already tried.
    """
    tenant, _ = _tenant(app)
    client = _client(app)
    header = _auth_header(tenant.opds_username, "one wrong passphrase")
    for attempt in range(OPDS_LIMIT):
        assert client.get("/opds", headers=header).status_code == 401, attempt
    assert client.get("/opds", headers=header).status_code == 429


def test_an_unauthenticated_401_still_prompts_for_credentials(app):
    """WWW-Authenticate survives the limiter being in the stack but not tripped.

    It is the header that makes an e-reader ask for a username and password instead of
    silently showing an empty library, and the limiter now wraps every /opds response.
    """
    client = _client(app)
    response = client.get("/opds")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Basic realm=")


def test_a_challenge_without_credentials_never_counts_against_the_limit(app):
    """A reader that does challenge-then-retry sends a bare request first and is told 401
    with WWW-Authenticate. That is the protocol working, not a wrong password, and it used
    to count: twenty catalogue taps took a correctly configured device out for a quarter
    of an hour."""
    tenant, password = _tenant(app)
    client = _client(app)
    for _ in range(OPDS_LIMIT * 2):
        response = client.get("/opds")
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Basic realm=")

    assert client.get("/opds", headers=_auth_header(tenant.opds_username, password)).status_code == 200
    # And the real thing still counts from the same address, so the exemption is narrow.
    for _ in range(OPDS_LIMIT):
        client.get("/opds", headers=_auth_header(tenant.opds_username, "wrong"))
    assert client.get("/opds", headers=_auth_header(tenant.opds_username, password)).status_code == 429


def test_the_opds_limit_is_per_address_and_expires(app, clock):
    tenant, password = _tenant(app)
    blocked = _client(app, ONE_IP)
    header = _auth_header(tenant.opds_username, "wrong")
    for _ in range(OPDS_LIMIT):
        blocked.get("/opds", headers=header)
    assert blocked.get("/opds", headers=header).status_code == 429

    elsewhere = _client(app, OTHER_IP)
    assert elsewhere.get("/opds", headers=_auth_header(tenant.opds_username, password)).status_code == 200

    clock.advance(POLICIES[OPDS_AUTH_BUCKET].window_seconds + 1)
    assert blocked.get("/opds", headers=header).status_code == 401


def test_a_download_is_not_limited_by_a_bad_guess_elsewhere(app):
    """Only 401s count, so an authenticated request on any /opds path stays served."""
    tenant, password = _tenant(app)
    client = _client(app)
    good = _auth_header(tenant.opds_username, password)
    for _ in range(OPDS_LIMIT - 1):
        client.get("/opds", headers=_auth_header(tenant.opds_username, "wrong"))
    assert client.get("/opds/recent", headers=good).status_code == 200


# -- what is deliberately not limited -----------------------------------------


def test_pages_and_the_signed_webhook_are_never_limited(app):
    """Everything outside the policy table is unlimited, and stays that way under load."""
    client = _client(app)
    for _ in range(SIGNUP_LIMIT * 4):
        assert client.get("/signup").status_code == 200
        assert client.get("/signin").status_code == 200
        assert client.get("/healthz").status_code == 200

    # The webhook is svix-signed, so an unsigned body is rejected before it costs
    # anything. Its 400 is the signature check answering, and it never becomes a 429.
    for _ in range(SIGNUP_LIMIT * 4):
        response = client.post("/webhooks/inbound-email", content=b"{}")
        assert response.status_code != 429
        assert response.status_code in {400, 503}


def test_a_request_without_a_client_address_shares_one_bucket(app):
    """ASGI leaves scope["client"] optional. Missing must not mean unlimited."""
    client = TestClient(app, base_url=BASE_URL, client=None)
    for index in range(SIGNUP_LIMIT):
        assert client.post("/signup", data={"email": f"anon{index}@example.test"}).status_code == 200
    assert client.post("/signup", data={"email": "anon-over@example.test"}).status_code == 429
    # Named explicitly, so this cannot pass because the transport supplied an address of
    # its own: the shared bucket is the one the addressless path counts into.
    assert app.state.rate_limiter.blocked(SIGNUP_BUCKET, _UNKNOWN_CLIENT) is True


# -- the counter itself -------------------------------------------------------


def test_windows_are_pruned_and_capped():
    """Memory is bounded whatever an attacker does with source addresses.

    Two mechanisms, tested together because they back each other up: a key whose window
    has expired is dropped the next time it is touched, and admitting a new key into a
    full table sweeps the expired ones first and flushes everything if that was not
    enough. Neither can grow the dict past the cap.
    """
    clock = FakeClock()
    limiter = RateLimiter({"b": Policy(limit=1, window_seconds=10.0)}, clock=clock, max_keys=8)
    for index in range(8):
        assert limiter.allow("b", f"key-{index}") is True
    assert len(limiter._windows) == 8

    clock.advance(11)
    # Every existing window is expired now, so the sweep alone makes room.
    assert limiter.allow("b", "key-new") is True
    assert len(limiter._windows) == 1

    for index in range(7):
        limiter.allow("b", f"fresh-{index}")
    assert len(limiter._windows) == 8
    # Nothing is expired this time, so the fallback flush is what keeps the cap.
    limiter.allow("b", "one-too-many")
    assert len(limiter._windows) <= 8


def test_the_verdict_and_the_count_are_separable():
    """`blocked` reports without counting, which is what lets /opds count only 401s."""
    limiter = RateLimiter({"b": Policy(limit=2, window_seconds=10.0)}, clock=FakeClock())
    assert limiter.blocked("b", "k") is False
    for _ in range(20):
        assert limiter.blocked("b", "k") is False, "a read-only check must not spend the allowance"
    assert limiter.allow("b", "k") is True
    assert limiter.allow("b", "k") is True
    assert limiter.blocked("b", "k") is True
    assert limiter.allow("b", "k") is False


def test_an_auth_lockout_ends_when_its_window_does(app, clock):
    """A lockout that never expires turns a fat-fingered passphrase into a support case.

    Twenty mistyped attempts must cost fifteen minutes, not a process restart: the window
    has to expire on the limiter's own clock, and the first attempt after it expires must
    reach real verification again -- with the right password, the reader is back. Mutation
    testing found this untested: freezing the auth window's expiry left the whole suite
    green while permanently locking out anyone who hit the limit once.
    """
    tenant, password = _tenant(app)
    client = _client(app)
    for attempt in range(OPDS_LIMIT):
        assert client.get("/opds", headers=_auth_header(tenant.opds_username, f"typo-{attempt}")).status_code == 401

    right_password = _auth_header(tenant.opds_username, password)
    assert client.get("/opds", headers=right_password).status_code == 429

    clock.advance(POLICIES[OPDS_AUTH_BUCKET].window_seconds + 1)
    assert client.get("/opds", headers=right_password).status_code == 200


def test_the_address_page_is_limited_per_address(app, clock):
    """Thirty tries an hour is a person fixing typos; more is a namespace scan."""
    limit = POLICIES[ADDRESS_BUCKET].limit
    client = _client(app)
    for _ in range(limit):
        assert client.post("/account/address", data={"name": "x"}, follow_redirects=False).status_code != 429
    assert client.post("/account/address", data={"name": "x"}, follow_redirects=False).status_code == 429
    clock.advance(POLICIES[ADDRESS_BUCKET].window_seconds + 1)
    assert client.post("/account/address", data={"name": "x"}, follow_redirects=False).status_code != 429
