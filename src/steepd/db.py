from __future__ import annotations

import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from steepd import words
from steepd.auth import hash_password
from steepd.inboxnames import is_placeholder, normalize_inbox_local, placeholder_inbox_local
from steepd.models import AuthorSummary, Item, RefusedSender, Tenant
from steepd.plans import KNOWN_PLANS
from steepd.tenancy import TenantScope

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    inbox_local TEXT NOT NULL UNIQUE,
    opds_username TEXT NOT NULL UNIQUE,
    opds_password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL,
    -- NULL until the owner chose the address (steepd.inboxnames). Routing ignores
    -- a tenant while this is NULL; its inbox_local is a hidden placeholder.
    inbox_confirmed_at TEXT,
    -- 'anyone' or 'listed'. Applied in inbound.py after the tenant resolves.
    sender_policy TEXT NOT NULL DEFAULT 'anyone'
);

CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('book', 'article')),
    sha256 TEXT NOT NULL,
    -- Globally unique: one row per file on disk. MUST be derived only from the
    -- random item id, never from sha256 or a filename. sha256 is unique only
    -- per tenant (two tenants may own the same book), so a content-derived
    -- storage_name would make one tenant's insert collide with another's --
    -- a cross-tenant DoS and a membership oracle. See Task 5's invariant.
    storage_name TEXT NOT NULL UNIQUE,
    download_filename TEXT NOT NULL,
    title TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT '',
    identifier TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    created_at TEXT NOT NULL,
    -- Reserved, always NULL. Retention is computed from the tenant's current plan at
    -- sweep time (see steepd.plans), deliberately not stamped here: a per-item expiry
    -- would have to be rewritten for every item a tenant owns on an upgrade.
    expires_at TEXT,
    source TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS items_tenant_sha_idx ON items(tenant_id, sha256);
CREATE INDEX IF NOT EXISTS items_tenant_created_idx ON items(tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS items_tenant_author_idx ON items(tenant_id, author COLLATE NOCASE, created_at DESC);
CREATE INDEX IF NOT EXISTS items_expires_idx ON items(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS webhook_events (
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    received_at TEXT NOT NULL,
    result TEXT NOT NULL,
    PRIMARY KEY (provider, event_id)
);

-- Stops a repeat forward of the same newsletter creating a second article. The keys are
-- per tenant, not global: two people may legitimately forward the same newsletter, exactly
-- as two people may own the same book. Deduping here rather than on items.sha256 is
-- deliberate -- a generated EPUB is not byte-deterministic (the archive embeds build
-- timestamps), whereas content_sha256 is a hash of the converted HTML and so is stable.
CREATE TABLE IF NOT EXISTS newsletter_deliveries (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    email_id TEXT NOT NULL,
    message_id TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    item_id TEXT NOT NULL DEFAULT '',
    forwarded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, provider, email_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS newsletter_message_id_idx
    ON newsletter_deliveries(tenant_id, provider, message_id) WHERE message_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS newsletter_content_sha256_idx
    ON newsletter_deliveries(tenant_id, provider, content_sha256);

-- Single-use sign-in links. Only the hash of the token is stored, never the
-- token itself, so a database dump does not yield working login links.
CREATE TABLE IF NOT EXISTS magic_tokens (
    token_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

-- What a redeemed magic link becomes. Only the hash of the session token is
-- stored, for the same reason as magic_tokens: a database dump must not hand
-- anyone a working browser session.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Who a tenant on the 'listed' policy accepts mail from, on top of their own account
-- email, which is always accepted and never stored here.
CREATE TABLE IF NOT EXISTS allowed_senders (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    address   TEXT NOT NULL,        -- normalized: casefolded, bare address
    added_at  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, address)
);

-- Senders a 'listed' policy turned away, so the account page can offer to allow them
-- with one click. Bounded per tenant on insert and pruned by the sweep: a record for
-- the owner to act on, not a log.
CREATE TABLE IF NOT EXISTS refused_senders (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, address)
);

-- Names that belonged to a deleted account, held back forever. A newsletter still
-- being sent to a deleted account's address would otherwise land in the library of
-- whoever claimed the name next. Placeholder names are never retired: they are not
-- advertised and cannot be chosen.
CREATE TABLE IF NOT EXISTS retired_inbox_locals (
    inbox_local TEXT PRIMARY KEY,
    retired_at  TEXT NOT NULL
);

PRAGMA user_version = 5;
"""

SCHEMA_VERSION = 5

# Columns cannot be added by CREATE TABLE IF NOT EXISTS, so a database already carrying
# tenants gets them by hand. Every existing account keeps its name and counts as
# confirmed: nothing in this migration prompts or alters a live tenant.
#
# BEGIN/COMMIT because executescript runs its statements one at a time, each committing
# on its own. Without them a failure after the first ALTER would leave the column in
# place with user_version still 4, and every later initialize() would die on "duplicate
# column name" -- a service that can never boot again. SQLite keeps user_version in the
# transactional header, so the whole block is all or nothing.
_MIGRATE_4_TO_5 = """
BEGIN;
ALTER TABLE tenants ADD COLUMN inbox_confirmed_at TEXT;
ALTER TABLE tenants ADD COLUMN sender_policy TEXT NOT NULL DEFAULT 'anyone';
UPDATE tenants SET inbox_confirmed_at = created_at WHERE inbox_confirmed_at IS NULL;
PRAGMA user_version = 5;
COMMIT;
"""

# A hand-kept list of correspondents, not a mailing list: 50 is far past what anyone
# curating one by hand reaches, and it keeps a compromised session from filling the table.
MAX_ALLOWED_SENDERS = 50
# The account page shows the handful of most recent refusals. Older ones are dropped on
# insert so a flood of refused mail cannot grow the table without bound.
MAX_REFUSED_SENDERS = 20
SENDER_POLICIES = ("anyone", "listed")


class AllowedSenderCapReached(ValueError):
    pass


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._write_lock = threading.RLock()

    def initialize(self) -> None:
        """Create or upgrade the schema. A fresh database reads version 0, skips the
        migration and gets the v5 CREATEs; a v5 database re-runs SCHEMA, which is all
        IF NOT EXISTS."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock, self._session() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version == 4:
                connection.executescript(_MIGRATE_4_TO_5)
            connection.executescript(SCHEMA)

    def health(self) -> bool:
        """A real round trip to the file, not just a successful connect: a connection to a
        missing or unreadable database only fails once a statement runs."""
        try:
            with self._session() as connection:
                connection.execute("SELECT 1 FROM tenants LIMIT 1").fetchone()
        except sqlite3.Error:
            return False
        return True

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        """One connection for one unit of work: commit on success, roll back on error, and
        always close. The bare sqlite3 context manager does the first two but not the
        third, and a service that opens a connection per request without closing it leaks a
        file descriptor per request until the garbage collector happens to reap it. Rows
        and rowcounts read inside the block stay valid after it: sqlite3.Row is a plain
        tuple and Cursor.rowcount is an attribute, neither needs the connection."""
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _tenant(row: sqlite3.Row | None) -> Tenant | None:
        return Tenant(**dict(row)) if row is not None else None

    @staticmethod
    def _item(row: sqlite3.Row | None) -> Item | None:
        return Item(**dict(row)) if row is not None else None

    # -- tenants ------------------------------------------------------

    def _insert_tenant(self, *, email: str, inbox_local: str, opds_password_hash: str, confirmed: bool) -> Tenant:
        """Shared by every tenant constructor. create_tenant generates a random device
        password before calling this; a future password-based constructor would hash a
        caller-supplied password and call this the same way.

        The name is written as given: whether it is well formed and free is the caller's
        question, asked through steepd.inboxnames and inbox_local_available."""
        normalized_email = email.casefold()
        normalized_inbox_local = normalize_inbox_local(inbox_local)
        created_at = datetime.now(UTC).isoformat()
        tenant = Tenant(
            id=secrets.token_hex(16),
            email=normalized_email,
            inbox_local=normalized_inbox_local,
            opds_username=normalized_inbox_local,
            opds_password_hash=opds_password_hash,
            plan="free",
            created_at=created_at,
            inbox_confirmed_at=created_at if confirmed else None,
            sender_policy="anyone",
        )
        with self._write_lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO tenants (
                    id, email, inbox_local, opds_username, opds_password_hash, plan, created_at,
                    inbox_confirmed_at, sender_policy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant.id,
                    tenant.email,
                    tenant.inbox_local,
                    tenant.opds_username,
                    tenant.opds_password_hash,
                    tenant.plan,
                    tenant.created_at,
                    tenant.inbox_confirmed_at,
                    tenant.sender_policy,
                ),
            )
        return tenant

    def create_tenant(self, *, email: str, inbox_local: str) -> Tenant:
        # A three-word passphrase rather than a random token, here and at the other two
        # generation sites. This password is typed on an e-ink keyboard -- a Xteink X4
        # CrossPoint, or KOReader on a Kobo -- where every character is a slow, deliberate
        # tap and a mixed-case token is genuinely painful. "maple.otter.lantern" is not.
        # steepd.words carries the entropy arithmetic and what defends it.
        #
        # Only the hash is ever stored and nothing reads the format back, so passwords
        # issued before this change keep working untouched.
        device_password = words.generate_passphrase()
        return self._insert_tenant(
            email=email,
            inbox_local=inbox_local,
            opds_password_hash=hash_password(device_password),
            confirmed=True,
        )

    def create_tenant_with_password(self, *, email: str, inbox_local: str) -> tuple[Tenant, str]:
        """Like create_tenant, but also returns the plaintext device password. Shown once
        to the caller and never stored -- only its hash lands in opds_password_hash."""
        device_password = words.generate_passphrase()  # see create_tenant for why a passphrase
        tenant = self._insert_tenant(
            email=email,
            inbox_local=inbox_local,
            opds_password_hash=hash_password(device_password),
            confirmed=True,
        )
        return tenant, device_password

    def create_pending_tenant(self, *, email: str) -> Tenant:
        """A sign-up that has not yet proven its email. The name is a placeholder nothing
        routes to; confirm_inbox_local replaces it once the owner has chosen."""
        device_password = words.generate_passphrase()  # see create_tenant for why a passphrase
        return self._insert_tenant(
            email=email,
            inbox_local=placeholder_inbox_local(),
            opds_password_hash=hash_password(device_password),
            confirmed=False,
        )

    def inbox_local_available(self, name: str) -> bool:
        """False when a live tenant holds the name or a deleted one retired it. Callers ask
        this for a readable answer; the UNIQUE constraint is the last word."""
        normalized = normalize_inbox_local(name)
        with self._session() as connection:
            live = connection.execute("SELECT 1 FROM tenants WHERE inbox_local = ?", (normalized,)).fetchone()
            retired = connection.execute(
                "SELECT 1 FROM retired_inbox_locals WHERE inbox_local = ?", (normalized,)
            ).fetchone()
        return live is None and retired is None

    def confirm_inbox_local(self, tenant_id: str, name: str) -> bool:
        """Write the chosen name. The WHERE is the whole once-only rule: a second call, or a
        double submit, matches no row. A race for the same name surfaces as IntegrityError
        from the UNIQUE constraint, which the caller reports as taken."""
        normalized = normalize_inbox_local(name)
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                UPDATE tenants SET inbox_local = ?, opds_username = ?, inbox_confirmed_at = ?
                 WHERE id = ? AND inbox_confirmed_at IS NULL
                """,
                (normalized, normalized, datetime.now(UTC).isoformat(), tenant_id),
            )
        return cursor.rowcount == 1

    def delete_unconfirmed_tenants(self, *, before: str) -> int:
        """Drop sign-ups that never proved their email. They can hold no items -- nothing is
        delivered to a placeholder -- and their sessions and tokens cascade away."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "DELETE FROM tenants WHERE inbox_confirmed_at IS NULL AND created_at < ?", (before,)
            )
        return cursor.rowcount

    def tenant_by_inbox_local(self, local: str) -> Tenant | None:
        """Unconfirmed tenants never resolve: mail to a placeholder is discarded exactly
        like mail to an address nobody holds."""
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM tenants WHERE inbox_local = ? AND inbox_confirmed_at IS NOT NULL",
                (local.casefold(),),
            ).fetchone()
        return self._tenant(row)

    def tenant_by_opds_username(self, username: str) -> Tenant | None:
        """Unconfirmed tenants never resolve, for the reason tenant_by_inbox_local gives:
        a placeholder is not an address anybody holds, and a sign-up that has not chosen
        yet has no catalogue to sign in to."""
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM tenants WHERE opds_username = ? AND inbox_confirmed_at IS NOT NULL",
                (username.casefold(),),
            ).fetchone()
        return self._tenant(row)

    def tenant_by_id(self, tenant_id: str) -> Tenant | None:
        with self._session() as connection:
            row = connection.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        return self._tenant(row)

    def set_tenant_plan(self, tenant_id: str, plan: str) -> bool:
        """Move a tenant between plans. Returns False if the tenant is unknown.

        Rejects an unknown plan name rather than storing it: quota_bytes and retention_for
        fail closed to the free limits for anything they do not recognise, so a typo here
        would silently downgrade a paying tenant instead of failing loudly.
        """
        if plan not in KNOWN_PLANS:
            raise ValueError(f"Unknown plan: {plan!r}")
        with self._write_lock, self._session() as connection:
            cursor = connection.execute("UPDATE tenants SET plan = ? WHERE id = ?", (plan, tenant_id))
        return cursor.rowcount == 1

    def tenant_by_email(self, email: str) -> Tenant | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM tenants WHERE email = ?", (email.casefold(),)
            ).fetchone()
        return self._tenant(row)

    def rotate_device_password(self, tenant_id: str) -> str | None:
        """Replace the tenant's device password and return the new plaintext, or None if the
        tenant is unknown. Same doctrine as create_tenant_with_password: the caller shows it
        once, only the hash is stored, and there is no way to read it back afterwards."""
        device_password = words.generate_passphrase()  # see create_tenant for why a passphrase
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "UPDATE tenants SET opds_password_hash = ? WHERE id = ?",
                (hash_password(device_password), tenant_id),
            )
        if cursor.rowcount != 1:
            return None
        return device_password

    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete the tenant row; items, magic_tokens, sessions and newsletter_deliveries go
        with it through ON DELETE CASCADE (foreign_keys is ON for every connection).

        Files on disk are not this method's concern and are not reachable once the rows are
        gone, so callers delete them first through ItemStorage.delete_all_for_tenant. Doing
        it in that order leaves an orphaned file on a crash, which is recoverable; the other
        order leaves a row pointing at a file that no longer exists.
        """
        with self._write_lock, self._session() as connection:
            row = connection.execute("SELECT inbox_local FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
            if row is None:
                return False
            if not is_placeholder(row["inbox_local"]):
                # Retired, never released: a newsletter still flowing to this address must
                # not land in whoever would otherwise claim the name next.
                connection.execute(
                    "INSERT OR IGNORE INTO retired_inbox_locals (inbox_local, retired_at) VALUES (?, ?)",
                    (row["inbox_local"], datetime.now(UTC).isoformat()),
                )
            cursor = connection.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
        return cursor.rowcount == 1

    # -- sender policy ----------------------------------------------------
    # Two lists behind one tenant setting: who a 'listed' tenant accepts mail from,
    # and who was turned away, so the account page can offer to allow them.

    def set_sender_policy(self, tenant_id: str, policy: str) -> bool:
        """Switch the tenant between accepting mail from anyone and from a list.

        Returns False if the tenant is unknown. An unrecognised policy raises rather than
        being stored: is_sender_allowed reads anything it does not know as 'anyone', so a
        typo here would quietly reopen an inbox the owner meant to close.
        """
        if policy not in SENDER_POLICIES:
            raise ValueError(f"Unknown sender policy: {policy!r}")
        with self._write_lock, self._session() as connection:
            cursor = connection.execute("UPDATE tenants SET sender_policy = ? WHERE id = ?", (policy, tenant_id))
        return cursor.rowcount == 1

    def list_allowed_senders(self, tenant_id: str) -> list[str]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT address FROM allowed_senders WHERE tenant_id = ? ORDER BY address", (tenant_id,)
            ).fetchall()
        return [row["address"] for row in rows]

    def add_allowed_sender(self, tenant_id: str, address: str) -> bool:
        """Returns True if the address was added, False if it was already listed."""
        with self._write_lock, self._session() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM allowed_senders WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()[0]
            if count >= MAX_ALLOWED_SENDERS:
                raise AllowedSenderCapReached(f"At most {MAX_ALLOWED_SENDERS} senders can be listed")
            cursor = connection.execute(
                "INSERT OR IGNORE INTO allowed_senders (tenant_id, address, added_at) VALUES (?, ?, ?)",
                (tenant_id, address, datetime.now(UTC).isoformat()),
            )
        return cursor.rowcount == 1

    def remove_allowed_sender(self, tenant_id: str, address: str) -> bool:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "DELETE FROM allowed_senders WHERE tenant_id = ? AND address = ?", (tenant_id, address)
            )
        return cursor.rowcount == 1

    def is_sender_allowed(self, tenant: Tenant, address: str) -> bool:
        """`address` is already normalized (casefolded, bare). The account's own email is
        always allowed under a listed policy without being stored in the list."""
        if tenant.sender_policy != "listed":
            return True
        if address == tenant.email:
            return True
        with self._session() as connection:
            row = connection.execute(
                "SELECT 1 FROM allowed_senders WHERE tenant_id = ? AND address = ?", (tenant.id, address)
            ).fetchone()
        return row is not None

    def record_refused_sender(self, tenant_id: str, address: str, *, now: str) -> None:
        with self._write_lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO refused_senders (tenant_id, address, count, last_seen_at) VALUES (?, ?, 1, ?)
                ON CONFLICT(tenant_id, address) DO UPDATE SET count = count + 1, last_seen_at = excluded.last_seen_at
                """,
                (tenant_id, address, now),
            )
            # Bounded per tenant: the page shows five, and a flood must not grow the table.
            connection.execute(
                """
                DELETE FROM refused_senders WHERE tenant_id = ? AND address NOT IN (
                    SELECT address FROM refused_senders WHERE tenant_id = ?
                     ORDER BY last_seen_at DESC LIMIT ?
                )
                """,
                (tenant_id, tenant_id, MAX_REFUSED_SENDERS),
            )

    def list_refused_senders(self, tenant_id: str, *, limit: int = 5) -> list[RefusedSender]:
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT address, count, last_seen_at FROM refused_senders
                 WHERE tenant_id = ? ORDER BY last_seen_at DESC, address LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [
            RefusedSender(address=row["address"], count=row["count"], last_seen_at=row["last_seen_at"]) for row in rows
        ]

    def clear_refused_sender(self, tenant_id: str, address: str) -> None:
        with self._write_lock, self._session() as connection:
            connection.execute("DELETE FROM refused_senders WHERE tenant_id = ? AND address = ?", (tenant_id, address))

    def prune_refused_senders(self, *, before: str) -> int:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute("DELETE FROM refused_senders WHERE last_seen_at < ?", (before,))
        return cursor.rowcount

    # -- magic-link sign-in ---------------------------------------------
    # issue/consume live in steepd.auth, which owns the token generation,
    # hashing, and expiry math; these two methods are the storage primitives
    # they call into.

    def insert_magic_token(self, *, token_hash: str, tenant_id: str, expires_at: str) -> None:
        with self._write_lock, self._session() as connection:
            connection.execute(
                "INSERT INTO magic_tokens (token_hash, tenant_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, tenant_id, expires_at),
            )

    def redeem_magic_token(self, *, token_hash: str, now: str) -> Tenant | None:
        """Atomically marks a token consumed and returns the tenant it belonged to, or None
        if the token is unknown, already consumed, or expired. The UPDATE's WHERE clause is
        the entire check-and-set: it reads and writes consumed_at in one statement, so two
        concurrent redemptions of the same token cannot both succeed."""
        with self._write_lock, self._session() as connection:
            row = connection.execute(
                """
                UPDATE magic_tokens
                   SET consumed_at = ?
                 WHERE token_hash = ?
                   AND consumed_at IS NULL
                   AND expires_at > ?
             RETURNING tenant_id
                """,
                (now, token_hash, now),
            ).fetchone()
            if row is None:
                return None
            tenant_row = connection.execute(
                "SELECT * FROM tenants WHERE id = ?", (row["tenant_id"],)
            ).fetchone()
        return self._tenant(tenant_row)

    def prune_magic_tokens(self, *, now: str) -> int:
        """Drop consumed and expired rows. Nothing reads either -- redeem_magic_token
        requires consumed_at IS NULL and an expiry in the future -- so this is the only
        thing standing between the table and unbounded growth."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "DELETE FROM magic_tokens WHERE consumed_at IS NOT NULL OR expires_at <= ?", (now,)
            )
        return cursor.rowcount

    def count_active_magic_tokens(self, tenant_id: str, *, now: str) -> int:
        """Counts only tokens that could still be redeemed, which is what the issuance cap is
        about: an expired or spent link costs nothing to have outstanding."""
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) FROM magic_tokens
                 WHERE tenant_id = ? AND consumed_at IS NULL AND expires_at > ?
                """,
                (tenant_id, now),
            ).fetchone()
        return int(row[0])

    # -- browser sessions -------------------------------------------------
    # issue/resolve/revoke live in steepd.auth alongside the magic-link pair;
    # these are the storage primitives they call.

    def insert_session(self, *, token_hash: str, tenant_id: str, created_at: str, expires_at: str) -> None:
        with self._write_lock, self._session() as connection:
            connection.execute(
                "INSERT INTO sessions (token_hash, tenant_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, tenant_id, created_at, expires_at),
            )

    def session_tenant(self, *, token_hash: str, now: str) -> Tenant | None:
        """The expiry is part of the lookup, not a check the caller could forget: there is no
        method here that resolves a session token without it."""
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT tenants.*
                  FROM sessions
                  JOIN tenants ON tenants.id = sessions.tenant_id
                 WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
        return self._tenant(row)

    def delete_session(self, *, token_hash: str) -> None:
        with self._write_lock, self._session() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def delete_expired_sessions(self, *, now: str) -> int:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        return cursor.rowcount

    # -- items ----------------------------------------------------------
    # Every method below takes scope: TenantScope as its first positional parameter,
    # and every statement that touches items filters on tenant_id = ?. There is
    # deliberately no method here that reads or writes an item without a scope.

    def insert_item(self, scope: TenantScope, item: Item) -> None:
        if item.tenant_id != scope.tenant_id:
            raise ValueError("item.tenant_id does not match scope.tenant_id")
        with self._write_lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO items (
                    id, tenant_id, kind, sha256, storage_name, download_filename, title, author,
                    language, identifier, source_url, size_bytes, created_at, expires_at, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.id,
                    item.tenant_id,
                    item.kind,
                    item.sha256,
                    item.storage_name,
                    item.download_filename,
                    item.title,
                    item.author,
                    item.language,
                    item.identifier,
                    item.source_url,
                    item.size_bytes,
                    item.created_at,
                    item.expires_at,
                    item.source,
                ),
            )

    def get_item(self, scope: TenantScope, item_id: str) -> Item | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id)
            ).fetchone()
        return self._item(row)

    def item_by_sha256(self, scope: TenantScope, sha256: str) -> Item | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM items WHERE tenant_id = ? AND sha256 = ?", (scope.tenant_id, sha256)
            ).fetchone()
        return self._item(row)

    @staticmethod
    def _item_filters(
        scope: TenantScope,
        *,
        kind: str | None,
        author: str | None,
        query: str | None,
        source: str | None,
    ) -> tuple[str, list[Any]]:
        clauses = ["tenant_id = ?"]
        params: list[Any] = [scope.tenant_id]
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        if author is not None:
            # Must stay identical to list_authors' grouping expression. That query folds every
            # blank author into the display name 'Unknown' and the authors feed emits an href
            # carrying that name, so a plain `author = ?` here matches no row and the shelf
            # advertises a count it then delivers an empty feed for.
            clauses.append("(CASE WHEN TRIM(author) = '' THEN 'Unknown' ELSE author END) = ? COLLATE NOCASE")
            params.append(author)
        if source is not None:
            clauses.append("source = ?")
            params.append(source)
        if query:
            clauses.append("(title LIKE ? COLLATE NOCASE OR author LIKE ? COLLATE NOCASE)")
            params.extend([f"%{query}%", f"%{query}%"])
        return " AND ".join(clauses), params

    # Fixed ORDER BY clauses keyed by name. The clause is interpolated into SQL, so it must
    # only ever come from this dict -- never from caller input -- and an unknown name is a
    # KeyError, not a fallback, so a typo at a call site fails loudly in tests.
    _ITEM_ORDERINGS = {
        "newest": "created_at DESC, id DESC",
        "oldest": "created_at ASC, id ASC",
        "title": "title COLLATE NOCASE ASC, created_at ASC, id ASC",
    }

    def list_items(
        self,
        scope: TenantScope,
        *,
        kind: str | None = None,
        author: str | None = None,
        query: str | None = None,
        source: str | None = None,
        limit: int = 50,
        offset: int = 0,
        order: str = "newest",
    ) -> list[Item]:
        where, params = self._item_filters(scope, kind=kind, author=author, query=query, source=source)
        ordering = self._ITEM_ORDERINGS[order]
        sql = f"SELECT * FROM items WHERE {where} ORDER BY {ordering} LIMIT ? OFFSET ?"
        with self._session() as connection:
            rows = connection.execute(sql, [*params, limit, offset]).fetchall()
        return [self._item(row) for row in rows]

    def count_items(
        self,
        scope: TenantScope,
        *,
        kind: str | None = None,
        author: str | None = None,
        query: str | None = None,
        source: str | None = None,
    ) -> int:
        where, params = self._item_filters(scope, kind=kind, author=author, query=query, source=source)
        with self._session() as connection:
            row = connection.execute(f"SELECT COUNT(*) FROM items WHERE {where}", params).fetchone()
        return int(row[0])

    def list_authors(self, scope: TenantScope, *, limit: int = 50, offset: int = 0) -> list[AuthorSummary]:
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT CASE WHEN TRIM(author) = '' THEN 'Unknown' ELSE author END AS name,
                       COUNT(*) AS item_count,
                       MAX(created_at) AS updated_at
                  FROM items
                 WHERE tenant_id = ?
              GROUP BY name COLLATE NOCASE
              ORDER BY name COLLATE NOCASE
                 LIMIT ? OFFSET ?
                """,
                (scope.tenant_id, limit, offset),
            ).fetchall()
        return [
            AuthorSummary(name=row["name"], item_count=row["item_count"], updated_at=row["updated_at"])
            for row in rows
        ]

    def count_authors(self, scope: TenantScope) -> int:
        with self._session() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM (SELECT CASE WHEN TRIM(author) = '' THEN 'Unknown' ELSE author END AS name "
                "FROM items WHERE tenant_id = ? GROUP BY name COLLATE NOCASE)",
                (scope.tenant_id,),
            ).fetchone()
        return int(row[0])

    def latest_created_at(self, scope: TenantScope) -> str:
        with self._session() as connection:
            row = connection.execute(
                "SELECT MAX(created_at) FROM items WHERE tenant_id = ?", (scope.tenant_id,)
            ).fetchone()
        return row[0] or "1970-01-01T00:00:00Z"

    def tenant_storage_bytes(self, scope: TenantScope) -> int:
        """What this tenant's stored items add up to, for the quota check in ItemStorage.

        SUM returns NULL for a tenant with no items, which is 0 bytes used.
        """
        with self._session() as connection:
            row = connection.execute(
                "SELECT SUM(size_bytes) FROM items WHERE tenant_id = ?", (scope.tenant_id,)
            ).fetchone()
        return int(row[0] or 0)

    def delete_item(self, scope: TenantScope, item_id: str) -> bool:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "DELETE FROM items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id)
            )
            if cursor.rowcount == 1:
                # The delivery record goes with the article it produced. It exists to stop a
                # repeat forward filing a second copy while the first is in the library; kept
                # past the item it would refuse the same newsletter forever, so that a reader
                # whose copy expired or was deleted by mistake could never get it back.
                connection.execute(
                    "DELETE FROM newsletter_deliveries WHERE tenant_id = ? AND item_id = ?",
                    (scope.tenant_id, item_id),
                )
        return cursor.rowcount == 1

    # -- operator stats ------------------------------------------------------
    # Read by `python -m steepd stats` only. Unscoped by design, like the sweep: it is a
    # count over every tenant, never a row from one.

    def stats(self, *, inbound_since: str) -> dict[str, int]:
        with self._session() as connection:
            tenants = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(inbox_confirmed_at IS NOT NULL) AS confirmed,
                       SUM(plan = 'paid') AS paid
                  FROM tenants
                """
            ).fetchone()
            items = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(kind = 'book') AS books,
                       SUM(kind = 'article') AS articles,
                       COALESCE(SUM(size_bytes), 0) AS bytes
                  FROM items
                """
            ).fetchone()
            inbound = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(result LIKE '%imported=%' AND result NOT LIKE '%imported=0;%') AS filed,
                       SUM(result LIKE '%rejected=%' AND result NOT LIKE '%rejected=0') AS rejected,
                       SUM(result = 'unknown-inbox') AS unknown_inbox,
                       SUM(result = 'sender-refused') AS sender_refused
                  FROM webhook_events
                 WHERE received_at >= ?
                """,
                (inbound_since,),
            ).fetchone()
        return {
            "tenants": int(tenants["total"] or 0),
            "tenants_confirmed": int(tenants["confirmed"] or 0),
            "tenants_paid": int(tenants["paid"] or 0),
            "items": int(items["total"] or 0),
            "books": int(items["books"] or 0),
            "articles": int(items["articles"] or 0),
            "item_bytes": int(items["bytes"] or 0),
            "inbound": int(inbound["total"] or 0),
            "inbound_filed": int(inbound["filed"] or 0),
            "inbound_rejected": int(inbound["rejected"] or 0),
            "inbound_unknown_inbox": int(inbound["unknown_inbox"] or 0),
            "inbound_sender_refused": int(inbound["sender_refused"] or 0),
        }

    # -- retention sweep ---------------------------------------------------
    # The one items read with no TenantScope, and the exception that the rule above is
    # written to survive: a sweep is by definition about every tenant at once, so there is
    # no scope to take. It is narrow on purpose -- it selects by plan and age only, returns
    # whole Items rather than ids, and does not delete. Callers act on what comes back
    # through TenantScope(item.tenant_id), so the deletion itself is scoped like any other.

    def list_items_past_retention(self, *, cutoff: str, plan: str, limit: int = 500) -> list[Item]:
        """Items of tenants on `plan` created before `cutoff`, oldest first.

        The plan is joined at query time rather than read from a column on items: retention
        is a property of what the tenant pays for today, so an upgrade lifts this filter off
        items already stored and a downgrade drops it onto them, with nothing to migrate.
        Both sides of the created_at comparison are ISO-8601 UTC strings, which order
        lexicographically for a fixed offset -- everything this codebase writes is +00:00.
        """
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT items.*
                  FROM items
                  JOIN tenants ON tenants.id = items.tenant_id
                 WHERE tenants.plan = ? AND items.created_at < ?
              ORDER BY items.created_at ASC, items.id ASC
                 LIMIT ?
                """,
                (plan, cutoff, limit),
            ).fetchall()
        return [self._item(row) for row in rows]

    # -- webhook replay protection ---------------------------------------

    def webhook_event_exists(self, provider: str, event_id: str) -> bool:
        with self._session() as connection:
            row = connection.execute(
                "SELECT 1 FROM webhook_events WHERE provider = ? AND event_id = ?", (provider, event_id)
            ).fetchone()
            return row is not None

    def record_webhook_event(self, provider: str, event_id: str, received_at: str, result: str) -> bool:
        """Claim an event id. False means it was already claimed, which is how a replay --
        or a provider retry racing the delivery it is retrying -- is told apart from new work."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO webhook_events(provider, event_id, received_at, result) VALUES (?, ?, ?, ?)",
                (provider, event_id, received_at, result),
            )
            return cursor.rowcount == 1

    def update_webhook_event(self, provider: str, event_id: str, result: str) -> None:
        with self._write_lock, self._session() as connection:
            connection.execute(
                "UPDATE webhook_events SET result = ? WHERE provider = ? AND event_id = ?",
                (result, provider, event_id),
            )

    def release_webhook_event(self, provider: str, event_id: str) -> None:
        """Give a claimed event id back, so the provider's retry of a delivery that failed
        part-way is processed rather than dismissed as a replay."""
        with self._write_lock, self._session() as connection:
            connection.execute(
                "DELETE FROM webhook_events WHERE provider = ? AND event_id = ?", (provider, event_id)
            )

    def prune_webhook_events(self, *, before: str) -> int:
        """Drop replay-protection rows older than `before`. A provider retries a failed
        delivery for a day or so; anything older can never be replayed by it, and the table
        otherwise grows by one row per inbound email forever."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute("DELETE FROM webhook_events WHERE received_at < ?", (before,))
        return cursor.rowcount

    # -- newsletter delivery deduplication ---------------------------------
    # Keyed per tenant, like every items query. A repeat forward -- same email, same
    # message id, or the same converted content -- must not create a second article
    # for that tenant, but must stay invisible to every other tenant.

    def newsletter_delivery_exists(
        self,
        scope: TenantScope,
        provider: str,
        email_id: str,
        message_id: str,
        content_sha256: str,
    ) -> bool:
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT 1
                  FROM newsletter_deliveries
                 WHERE tenant_id = ?
                   AND provider = ?
                   AND (email_id = ? OR content_sha256 = ? OR (? <> '' AND message_id = ?))
                """,
                (scope.tenant_id, provider, email_id, content_sha256, message_id, message_id),
            ).fetchone()
            return row is not None

    def record_newsletter_delivery(
        self,
        scope: TenantScope,
        *,
        provider: str,
        email_id: str,
        message_id: str,
        content_sha256: str,
        source_url: str,
        item_id: str,
        forwarded_at: str,
    ) -> bool:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO newsletter_deliveries(
                    tenant_id, provider, email_id, message_id, content_sha256, source_url,
                    item_id, forwarded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope.tenant_id,
                    provider,
                    email_id,
                    message_id,
                    content_sha256,
                    source_url,
                    item_id,
                    forwarded_at,
                ),
            )
            return cursor.rowcount == 1
