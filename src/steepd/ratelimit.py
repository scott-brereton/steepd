"""Per-IP request limits on the four endpoints a public launch exposes to abuse.

Free sign-ups open four doors, and all four are per-client-address problems:

1. `POST /signup` creates a tenant *and* mails a magic link to whatever address the
   body carries. Scripted, that is a mail cannon pointed at strangers from our own
   domain, and the cost is the domain's sending reputation rather than our CPU.
2. `POST /signin` is the same cannon aimed at addresses the caller already knows.
   `MAGIC_TOKEN_ISSUANCE_CAP` bounds how many live links one *account* can have; it
   does not bound how many requests one client can make.
3. `POST /account/address` says whether a name is free, which unlimited is a namespace scan.
4. Unauthenticated HTTP Basic attempts on `/opds` each burn a ~35ms scrypt. The
   credential cache in auth.py only dedupes *repeated* pairs, so a spray of unique
   passwords pays the full cost every time -- the residual that section names, and
   the assumption behind three-word device passphrases.

One instance serves everything, so the state is in-process: a dict of fixed-window
counters, not a new piece of infrastructure. Counters are held on the app instance
(`app.state.rate_limiter`) rather than at module scope, so two apps in one process --
which is what the test suite is -- cannot see each other's windows.

Fixed windows rather than sliding: a caller who waits out the window gets the full
allowance again, which at these limits is the difference between 5 sign-ups an hour
and 10 across an hour boundary. Neither number changes what an abuser can do, and a
fixed window is one integer and one timestamp per key instead of a deque of them.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Lock

from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SIGNUP_BUCKET = "signup"
SIGNIN_BUCKET = "signin"
ADDRESS_BUCKET = "address"
OPDS_AUTH_BUCKET = "opds-auth"

_HOUR = 3600.0
_QUARTER_HOUR = 900.0


@dataclass(frozen=True, slots=True)
class Policy:
    limit: int
    window_seconds: float


# The whole policy. Everything absent from this table is unlimited: the webhook is
# svix-signed (an unsigned body is rejected before it costs anything), GET pages are
# cheap, and a download is the thing a paying tenant came for.
POLICIES: Mapping[str, Policy] = {
    # A human signs up once. Five forgives a typo, a back button, and a lightly shared
    # NAT; it does not forgive a script working through an address list.
    SIGNUP_BUCKET: Policy(limit=5, window_seconds=_HOUR),
    # Twice sign-up's: asking for a fresh link because the last mail is slow is a normal
    # thing to do, and the request is idempotent from the caller's point of view.
    SIGNIN_BUCKET: Policy(limit=10, window_seconds=_HOUR),
    # Choosing an address is one field, fixed a couple of times at most. Thirty an hour
    # is generous for a person and useless for enumerating which names exist.
    ADDRESS_BUCKET: Policy(limit=30, window_seconds=_HOUR),
    # Counted only on 401s (see RateLimitMiddleware). Twenty wrong guesses in fifteen
    # minutes is nobody typing a passphrase off a screen, and against the ~2^38.8 of a
    # three-word passphrase it is the online guessing bound that tradeoff assumes.
    OPDS_AUTH_BUCKET: Policy(limit=20, window_seconds=_QUARTER_HOUR),
}

# Sized so a plausible burst of real traffic fits with room to spare, while the dict
# stays small enough that a full scan of it is cheap.
MAX_TRACKED_KEYS = 10_000

# Every address is one key, so a request that arrives without one shares a single
# bucket rather than escaping the limiter. ASGI leaves scope["client"] optional and a
# test transport may omit it; unlimited would be the wrong direction to fail in.
_UNKNOWN_CLIENT = "unknown"

# Not built through web.py's `_page`: that helper is private to the browser layer and
# carries its stylesheet and wordmark, and this response has to serve a client that may
# have arrived at a form route with no session and no interest in either.
_TOO_MANY_HTML = (
    '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    "<title>Too many attempts</title>\n</head>\n"
    "<body>\n<main>\n<p>Too many attempts. Try again in a few minutes.</p>\n</main>\n</body>\n</html>\n"
)

# Plain text for /opds: an e-reader shows the body of a failed catalogue fetch verbatim
# if it shows it at all, and marked-up HTML arrives as tag soup on the screen.
_TOO_MANY_TEXT = "Too many failed sign-in attempts. Try again in a few minutes.\n"

_TOO_MANY_REQUESTS = 429


@dataclass(slots=True)
class _Window:
    started_at: float
    count: int


class RateLimiter:
    """Fixed-window counters keyed on (bucket, client key).

    Thread-safe: FastAPI runs sync routes in a threadpool, so two requests from one
    address really are concurrent, and a read-modify-write of a counter outside a lock
    would lose increments in exactly the burst the limiter exists to catch.
    """

    def __init__(
        self,
        policies: Mapping[str, Policy] = POLICIES,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = MAX_TRACKED_KEYS,
    ) -> None:
        self.policies = dict(policies)
        # Monotonic, so a system clock step cannot end a window early or extend it.
        # A public attribute rather than a private one because it is the test seam:
        # windows are minutes to hours long and no test should sleep through one.
        self.clock = clock
        self._max_keys = max_keys
        self._windows: dict[tuple[str, str], _Window] = {}
        self._lock = Lock()

    def allow(self, bucket: str, key: str) -> bool:
        """Count one attempt and report whether it was within the limit."""
        policy = self.policies[bucket]
        now = self.clock()
        with self._lock:
            window = self._live_window(bucket, key, policy, now)
            if window is None:
                self._evict_if_full(now)
                window = _Window(started_at=now, count=0)
                self._windows[(bucket, key)] = window
            window.count += 1
            return window.count <= policy.limit

    def blocked(self, bucket: str, key: str) -> bool:
        """Report whether the limit is already spent, without counting anything.

        The read-only half of the pair. `/opds` needs a verdict *before* the request is
        served but only counts once the response turns out to be a 401, and a rejected
        request must not push its own window further out.
        """
        policy = self.policies[bucket]
        now = self.clock()
        with self._lock:
            window = self._live_window(bucket, key, policy, now)
            return window is not None and window.count >= policy.limit

    def retry_after(self, bucket: str, key: str) -> int:
        """Whole seconds until this key's window resets, for the Retry-After header."""
        policy = self.policies[bucket]
        now = self.clock()
        with self._lock:
            window = self._live_window(bucket, key, policy, now)
            remaining = policy.window_seconds if window is None else window.started_at + policy.window_seconds - now
        # Never zero: a client that honours Retry-After: 0 retries immediately and is
        # refused again, which is the busy loop the header exists to prevent.
        return max(1, math.ceil(remaining))

    def _live_window(self, bucket: str, key: str, policy: Policy, now: float) -> _Window | None:
        """Return the unexpired window for this key, dropping it if it has expired.

        Caller holds the lock. This is the opportunistic prune: every key that is still
        being touched cleans up after itself, so the bulk sweep below only ever has to
        deal with keys nobody has come back to.
        """
        window = self._windows.get((bucket, key))
        if window is None:
            return None
        if now - window.started_at >= policy.window_seconds:
            del self._windows[(bucket, key)]
            return None
        return window

    def _evict_if_full(self, now: float) -> None:
        """Caller holds the lock. Runs only when a new key is about to be admitted."""
        if len(self._windows) < self._max_keys:
            return
        expired = [
            key
            for key, window in self._windows.items()
            if now - window.started_at >= self.policies[key[0]].window_seconds
        ]
        for key in expired:
            del self._windows[key]
        if len(self._windows) >= self._max_keys:
            # Deliberately not an LRU, for the same reason auth.py's credential cache is
            # not: an eviction policy that picks victims by recency lets the single
            # noisiest address push out the entry recording its own behaviour. A full
            # flush forgives everyone at once, but it takes ten thousand distinct
            # addresses probing inside one window to reach, and it costs each of them at
            # most one extra window's allowance.
            self._windows.clear()


def _client_key(scope: Scope) -> str:
    """The address the limits are counted against.

    uvicorn runs with proxy_headers=True and forwarded_allow_ips="*" (see __main__.py),
    so behind Railway's proxy scope["client"] has already been rewritten to the
    X-Forwarded-For client rather than the proxy's own address. That is the dependency:
    the app must stay reachable only through that proxy, because a client that can open
    a connection to the container directly can choose its own key by sending the header.
    """
    client = scope.get("client")
    if not client:
        return _UNKNOWN_CLIENT
    return str(client[0])


def _carries_authorization(scope: Scope) -> bool:
    return any(name.lower() == b"authorization" and value for name, value in scope.get("headers", []))


def _is_opds(path: str) -> bool:
    return path == "/opds" or path.startswith("/opds/")


class RateLimitMiddleware:
    """Apply POLICIES per client address, refusing over-limit requests with a 429."""

    # Only POSTs are limited here: the matching GETs render an empty form and cost
    # nothing, and limiting them would break a reader who reloads the page.
    form_buckets = {
        "/signup": SIGNUP_BUCKET,
        "/signin": SIGNIN_BUCKET,
        "/account/address": ADDRESS_BUCKET,
    }

    def __init__(self, app: ASGIApp, *, limiter: RateLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        key = _client_key(scope)

        if _is_opds(path):
            await self._call_opds(scope, receive, send, key)
            return

        bucket = self.form_buckets.get(path) if scope.get("method") == "POST" else None
        if bucket is None:
            await self.app(scope, receive, send)
            return
        if not self.limiter.allow(bucket, key):
            await self._reject(scope, receive, send, bucket, key, body=_TOO_MANY_HTML, media_type="text/html")
            return
        await self.app(scope, receive, send)

    async def _call_opds(self, scope: Scope, receive: Receive, send: Send, key: str) -> None:
        """Count failures, never successes, and refuse before authentication runs.

        An e-reader polls its catalogue constantly and every one of those requests
        carries Basic credentials, so counting successes would throttle exactly the
        client that is behaving. Counting failures is done by watching the status on the
        way out, because whether a request was a failure is not knowable on the way in.

        The short-circuit is the point of the whole exercise: an over-limit request is
        answered here, above the route and therefore above `authenticate_device`, so the
        scrypt is never paid. Letting it through and refusing afterwards would leave the
        CPU cost intact and limit only the useful half of the response.

        Consequence, accepted: once an address is over the limit, even correct credentials
        from it are refused until the window resets, so twenty wrong guesses from behind a
        shared NAT take the good device out with them for fifteen minutes. Exempting the
        valid ones would mean verifying the password to decide whether to refuse, which is
        the scrypt this branch exists to avoid.
        """
        if self.limiter.blocked(OPDS_AUTH_BUCKET, key):
            await self._reject(
                scope, receive, send, OPDS_AUTH_BUCKET, key, body=_TOO_MANY_TEXT, media_type="text/plain"
            )
            return

        # Only a request that actually offered credentials can be a wrong guess. A reader
        # that does challenge-then-retry sends a bare request first and gets a 401 that
        # is an invitation, not a failure; counting those took a correctly configured
        # device out after twenty catalogue taps, and a shared address after fewer.
        offered_credentials = _carries_authorization(scope)

        async def counting_send(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] == 401 and offered_credentials:
                # A 401 served from the credential cache counts too. It is cheap for us,
                # but it is still a wrong password arriving, which is the thing being
                # bounded -- and not counting it would hand an attacker a free retry for
                # every pair they had already tried once.
                self.limiter.allow(OPDS_AUTH_BUCKET, key)
            await send(message)

        await self.app(scope, receive, counting_send)

    async def _reject(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        bucket: str,
        key: str,
        *,
        body: str,
        media_type: str,
    ) -> None:
        response = Response(
            body,
            status_code=_TOO_MANY_REQUESTS,
            media_type=media_type,
            headers={"Retry-After": str(self.limiter.retry_after(bucket, key)), "Cache-Control": "no-store"},
        )
        await response(scope, receive, send)
