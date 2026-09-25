from __future__ import annotations

import secrets
import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from steepd import words
from steepd.auth import hash_password
from steepd.inboxnames import is_placeholder, normalize_inbox_local, placeholder_inbox_local
from steepd.models import (
    AuthorSummary,
    ClaimedOrganization,
    Item,
    NewsletterPreferences,
    OrganizationCandidate,
    OrganizationGuard,
    OrganizationProgress,
    Publication,
    PublicationSummary,
    RefusedSender,
    SiteSummary,
    Tenant,
    TrashedItem,
    UnorganizedIssue,
)
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
    sender_policy TEXT NOT NULL DEFAULT 'anyone',
    -- 1 when the owner turned on Star and Delete in the reader catalogue (steepd.opds).
    reader_actions INTEGER NOT NULL DEFAULT 0 CHECK (reader_actions IN (0, 1))
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
    source TEXT NOT NULL,
    starred_at TEXT,
    -- See Item.revision.
    revision INTEGER NOT NULL DEFAULT 0
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

-- A tenant can deliberately relay one inbound message to their registered account
-- address, for services such as Gmail that prove a forwarding destination by email.
-- claimed_event_id is an atomic lease: concurrent webhook deliveries cannot both spend
-- the same five-minute window. At most one row exists per tenant, so expired rows are
-- bounded by the account count and are replaced the next time the checkbox is enabled.
CREATE TABLE IF NOT EXISTS email_verification_relays (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    claimed_event_id TEXT
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

-- Whether a tenant has opted into automatic newsletter organization, plus the small
-- amount of coordination state the worker needs. An absent row means disabled, so a GET
-- that merely renders the account page can never opt anybody in.
CREATE TABLE IF NOT EXISTS newsletter_preferences (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    consent_version INTEGER NOT NULL DEFAULT 0,
    consented_at TEXT,
    -- Bumped whenever consent or the enabled flag changes. A worker captures this before
    -- it spends and re-checks it when it commits, so an answer produced for a setting the
    -- owner has since withdrawn cannot be applied -- including an Off/On race.
    -- Starts at 0 so the very first settings form, rendered before any row exists,
    -- submits a revision that matches. Starting at 1 made every first enable a
    -- conflict, which is to say the feature could never be switched on at all.
    settings_revision INTEGER NOT NULL DEFAULT 0,
    -- Bumped whenever the publication choices a classifier was shown change: a create,
    -- rename, merge or manual assignment. Without it two overlapping first issues would
    -- both answer "new" against the same empty catalogue and create duplicate records.
    catalogue_revision INTEGER NOT NULL DEFAULT 1,
    catalogue_updated_at TEXT,
    -- Round-robin marker: the least recently served enabled tenant is chosen first, so one
    -- account's backlog cannot hold up another account's new delivery.
    last_served_at TEXT,
    attempt_day TEXT,
    attempts_today INTEGER NOT NULL DEFAULT 0
);

-- A publication is the label issues are grouped under; its feed is a query for those
-- issues, not a second collection with copied memberships. Names are labels and never
-- identities: two publications may legitimately share a display name, and nothing merges
-- records because names or domains look alike. Only the owner combines them.
CREATE TABLE IF NOT EXISTS publications (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    -- The name at creation, kept as an identification clue after a rename. A rename is a
    -- display change, not an instruction to stop recognising the publication it names.
    original_name TEXT NOT NULL CHECK (length(original_name) BETWEEN 1 AND 120),
    identification_note TEXT NOT NULL DEFAULT '' CHECK (length(identification_note) <= 500),
    -- Set when this record was combined into another. Merged rows are kept rather than
    -- deleted: their names and notes stay as clues for the survivor, and their old OPDS
    -- URLs keep resolving. Redirects stay one hop -- merging a survivor repoints the
    -- aliases already pointing at it, so resolution never walks a chain.
    merged_into_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, merged_into_id) REFERENCES publications(tenant_id, id),
    CHECK (merged_into_id IS NULL OR merged_into_id <> id)
);

-- One row per newsletter item the worker has touched. THE ABSENCE OF A ROW IS THE WAITING
-- STATE: a retained newsletter with no row here is work still to do. That is why
-- insert_item() is untouched by this feature -- there is nothing to enqueue at import --
-- why enabling needs no bulk scheduling pass, and why re-enabling naturally picks up the
-- deliveries that arrived while the setting was off.
CREATE TABLE IF NOT EXISTS newsletter_organization (
    tenant_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    publication_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('running', 'retry', 'done', 'unrecognized', 'failed')),
    -- Protects an owner's decision, including Keep ungrouped, from every worker write.
    manual INTEGER NOT NULL DEFAULT 0 CHECK (manual IN (0, 1)),
    attempts INTEGER NOT NULL DEFAULT 0,
    -- Also the result token a Retry form submits. It identifies which result is being
    -- retried; it is not a credential, and it is not a way to commit work over HTTP.
    -- Every claim replaces it, so a stale form cannot restart a newer cycle.
    lease_token TEXT,
    -- One column, two mutually exclusive meanings that `state` names: the lease expiry
    -- while running, and the next eligible time while retrying. Always NULL once terminal,
    -- so a finished row can never be selected as due work.
    not_before TEXT,
    error_code TEXT,
    PRIMARY KEY (tenant_id, item_id),
    FOREIGN KEY (tenant_id, item_id) REFERENCES items(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, publication_id) REFERENCES publications(tenant_id, id),
    CHECK (CASE WHEN state IN ('running', 'retry') THEN not_before IS NOT NULL ELSE not_before IS NULL END),
    CHECK (state <> 'running' OR lease_token IS NOT NULL),
    -- An assignment exists only on a finished row, and a finished row without one is the
    -- owner's explicit Keep ungrouped. A model answering "cannot identify" is
    -- 'unrecognized', which is a successful answer; 'failed' is an operational failure.
    CHECK (publication_id IS NULL OR state = 'done'),
    CHECK (state <> 'done' OR publication_id IS NOT NULL OR manual = 1),
    CHECK (manual = 0 OR state = 'done'),
    CHECK (error_code IS NULL OR state IN ('retry', 'failed'))
);

-- Parent key for the two composite foreign keys above. SQLite enforces a composite FK
-- only when the referenced columns carry a unique index; items(id) alone is not one.
CREATE UNIQUE INDEX IF NOT EXISTS items_tenant_id_idx ON items(tenant_id, id);
CREATE INDEX IF NOT EXISTS newsletter_organization_publication_idx
    ON newsletter_organization(tenant_id, publication_id, item_id);
-- Due work: expired leases and retries that have come due. Partial, because terminal rows
-- hold NULL here and are exactly the rows this index must never have to skip.
CREATE INDEX IF NOT EXISTS newsletter_organization_due_idx
    ON newsletter_organization(tenant_id, not_before) WHERE not_before IS NOT NULL;
CREATE INDEX IF NOT EXISTS publications_name_idx
    ON publications(tenant_id, name COLLATE NOCASE, id);

-- Items their owner deleted, kept for TRASH_RETENTION (steepd.storage) so a mistaken
-- Delete can be undone. A table of its own rather than a flag on items: every list, count,
-- search and feed reads items, so none of them needs a filter that could be forgotten. The
-- file stays where it was on disk until a purge, and its bytes still count toward quota.
CREATE TABLE IF NOT EXISTS trashed_items (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    storage_name TEXT NOT NULL UNIQUE,
    download_filename TEXT NOT NULL,
    title TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT '',
    identifier TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    source TEXT NOT NULL,
    starred_at TEXT,
    revision INTEGER NOT NULL DEFAULT 0,
    deleted_at TEXT NOT NULL,
    -- A finished newsletter_organization row, copied here because that row is removed with
    -- the item (ON DELETE CASCADE). Restore puts it back, so a restored issue keeps its
    -- publication, or the owner's Keep ungrouped, instead of being classified again.
    -- NULL organization_state means there was nothing finished to keep.
    organization_state TEXT,
    organization_publication_id TEXT,
    organization_manual INTEGER NOT NULL DEFAULT 0,
    organization_attempts INTEGER NOT NULL DEFAULT 0,
    organization_error_code TEXT
);

-- Per tenant, like items_tenant_sha_idx: re-sending a trashed file restores it rather than
-- storing a second copy, so there is never more than one.
CREATE UNIQUE INDEX IF NOT EXISTS trashed_items_tenant_sha_idx ON trashed_items(tenant_id, sha256);
CREATE INDEX IF NOT EXISTS trashed_items_tenant_deleted_idx ON trashed_items(tenant_id, deleted_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS trashed_items_deleted_idx ON trashed_items(deleted_at);
CREATE INDEX IF NOT EXISTS items_tenant_starred_idx
    ON items(tenant_id, starred_at DESC, id DESC) WHERE starred_at IS NOT NULL;

PRAGMA user_version = 8;
"""

SCHEMA_VERSION = 8

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

# The reader-actions columns, for tables that predate them, keyed by the column whose
# absence means the table needs them. Applied in one transaction for the same reason as
# _MIGRATE_4_TO_5. A table that does not exist yet gets its columns from SCHEMA instead.
_READER_ACTION_COLUMNS = {
    "items": (
        "revision",
        (
            "ALTER TABLE items ADD COLUMN starred_at TEXT",
            "ALTER TABLE items ADD COLUMN revision INTEGER NOT NULL DEFAULT 0",
        ),
    ),
    "tenants": (
        "reader_actions",
        ("ALTER TABLE tenants ADD COLUMN reader_actions INTEGER NOT NULL DEFAULT 0 CHECK (reader_actions IN (0, 1))",),
    ),
}

# A hand-kept list of correspondents, not a mailing list: 50 is far past what anyone
# curating one by hand reaches, and it keeps a compromised session from filling the table.
MAX_ALLOWED_SENDERS = 50
# The account page shows the handful of most recent refusals. Older ones are dropped on
# insert so a flood of refused mail cannot grow the table without bound.
MAX_REFUSED_SENDERS = 20
SENDER_POLICIES = ("anyone", "listed")


# The site a saved page came from, computed from its stored URL: everything after the
# scheme up to the first "/", "?" or "#", lowercased, without a leading "www.". A URL with
# no scheme gives "". One expression, used for grouping and for filtering alike, so a
# count and the list it introduces always agree. Ports stay: they are part of the origin.
_SITE_AFTER_SCHEME = (
    "CASE WHEN instr(source_url, '://') > 0 THEN substr(source_url, instr(source_url, '://') + 3) ELSE '' END"
)
_SITE_HOST = (
    f"lower(substr(({_SITE_AFTER_SCHEME}), 1, min("
    f"instr(({_SITE_AFTER_SCHEME}) || '/', '/'), "
    f"instr(({_SITE_AFTER_SCHEME}) || '?', '?'), "
    f"instr(({_SITE_AFTER_SCHEME}) || '#', '#')) - 1))"
)
SITE_SQL = f"CASE WHEN ({_SITE_HOST}) LIKE 'www.%' THEN substr(({_SITE_HOST}), 5) ELSE ({_SITE_HOST}) END"


# The columns items and trashed_items share, in one order, so moving a row between them
# is a single INSERT ... SELECT that cannot drop or misplace one.
_ITEM_COLUMNS = (
    "id",
    "tenant_id",
    "kind",
    "sha256",
    "storage_name",
    "download_filename",
    "title",
    "author",
    "language",
    "identifier",
    "source_url",
    "size_bytes",
    "created_at",
    "expires_at",
    "source",
    "starred_at",
    "revision",
)
_ITEM_COLUMN_LIST = ", ".join(_ITEM_COLUMNS)


class AllowedSenderCapReached(ValueError):
    pass


class DatabaseTooNew(RuntimeError):
    """The file on disk was written by a later version of Steepd.

    Running an older binary against a newer schema is the one case initialize() must
    refuse rather than repair: CREATE TABLE IF NOT EXISTS would silently skip tables it
    does not know about, and the service would then read and write a shape it half
    understands. A rolled-back deployment should fail loudly and stay off.
    """


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._write_lock = threading.RLock()

    def initialize(self) -> None:
        """Create or upgrade the schema. A fresh database reads version 0, skips the
        migration and gets the current CREATEs; a v5 database gains the relay table
        through CREATE TABLE IF NOT EXISTS, without rewriting the tenants table; a v6
        database gains the three newsletter-organization tables the same way.

        7 -> 8 also adds columns to items and tenants, through _READER_ACTION_COLUMNS.

        6 -> 7 and the new trash table need no migration branch because they are only tables and indexes, which
        CREATE ... IF NOT EXISTS expresses idempotently. executescript commits each
        statement on its own, so an interrupted run leaves some tables present and
        user_version behind -- and the next start finishes the job rather than having to
        undo it. That is why the version write is the last statement in SCHEMA.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock, self._session() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise DatabaseTooNew(
                    f"Database schema version {version} is newer than this application "
                    f"supports ({SCHEMA_VERSION}); refusing to start"
                )
            if version == 4:
                connection.executescript(_MIGRATE_4_TO_5)
            statements: list[str] = []
            for table, (marker, alters) in _READER_ACTION_COLUMNS.items():
                columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
                if columns and marker not in columns:
                    statements.extend(alters)
            if statements:
                connection.executescript("BEGIN;\n" + ";\n".join(statements) + ";\nCOMMIT;")
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
        if row is None:
            return None
        values = dict(row)
        values["reader_actions"] = bool(values.get("reader_actions", 0))
        return Tenant(**values)

    @staticmethod
    def _item(row: sqlite3.Row | None) -> Item | None:
        return Item(**dict(row)) if row is not None else None

    @staticmethod
    def _trashed_item(row: sqlite3.Row | None) -> TrashedItem | None:
        if row is None:
            return None
        values = dict(row)
        return TrashedItem(
            item=Item(**{column: values[column] for column in _ITEM_COLUMNS}), deleted_at=values["deleted_at"]
        )

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
        """Delete the tenant row; items, auth rows, verification relays and newsletter
        deliveries go with it through ON DELETE CASCADE (foreign_keys is ON for every connection).

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

    # -- temporary email-verification relay -------------------------------

    def enable_email_verification_relay(self, tenant_id: str, *, expires_at: str) -> bool:
        """Arm or renew one tenant's one-shot relay, returning False for an unknown tenant.

        Re-enabling also clears an in-flight claim. That is deliberate: the owner just
        asked for a fresh five-minute window, and completion of the older webhook is
        scoped to its event id so it cannot delete the replacement.
        """
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                INSERT INTO email_verification_relays (tenant_id, expires_at, claimed_event_id)
                SELECT id, ?, NULL FROM tenants WHERE id = ?
                ON CONFLICT(tenant_id) DO UPDATE SET
                    expires_at = excluded.expires_at,
                    claimed_event_id = NULL
                """,
                (expires_at, tenant_id),
            )
        return cursor.rowcount == 1

    def disable_email_verification_relay(self, tenant_id: str) -> bool:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "DELETE FROM email_verification_relays WHERE tenant_id = ?", (tenant_id,)
            )
        return cursor.rowcount == 1

    def email_verification_relay_expires_at(self, tenant_id: str, *, now: str) -> str | None:
        """Return the deadline only while the window can still be used.

        A claimed row remains visible as on for the brief time its email is being relayed;
        it disappears after the send succeeds. An expired row reads as off without needing
        a write on every account-page request.
        """
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT expires_at FROM email_verification_relays
                 WHERE tenant_id = ? AND expires_at > ?
                """,
                (tenant_id, now),
            ).fetchone()
        return str(row["expires_at"]) if row is not None else None

    def claim_email_verification_relay(self, tenant_id: str, *, event_id: str, now: str) -> bool:
        """Atomically reserve an active window for one webhook delivery."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                UPDATE email_verification_relays
                   SET claimed_event_id = ?
                 WHERE tenant_id = ?
                   AND expires_at > ?
                   AND claimed_event_id IS NULL
                """,
                (event_id, tenant_id, now),
            )
        return cursor.rowcount == 1

    def release_email_verification_relay(self, tenant_id: str, *, event_id: str) -> bool:
        """Hand a failed relay back so a webhook retry can make the same attempt."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                UPDATE email_verification_relays SET claimed_event_id = NULL
                 WHERE tenant_id = ? AND claimed_event_id = ?
                """,
                (tenant_id, event_id),
            )
        return cursor.rowcount == 1

    def complete_email_verification_relay(self, tenant_id: str, *, event_id: str) -> bool:
        """Spend the window after its claimed message was successfully relayed."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                DELETE FROM email_verification_relays
                 WHERE tenant_id = ? AND claimed_event_id = ?
                """,
                (tenant_id, event_id),
            )
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

    def set_reader_actions(self, tenant_id: str, enabled: bool) -> bool:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "UPDATE tenants SET reader_actions = ? WHERE id = ?", (int(enabled), tenant_id)
            )
            # The root feed's shelves change shape, so its clock has to move too.
            self._touch_catalogue(connection, tenant_id, datetime.now(UTC).isoformat())
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
        publication: str | None = None,
        site: str | None = None,
        starred: bool = False,
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
        if publication is not None:
            # A publication's feed is a query for its issues, not a second collection: the
            # membership lives in newsletter_organization and is read through EXISTS so
            # every existing ordering, page and count path keeps working untouched.
            clauses.append(
                "EXISTS (SELECT 1 FROM newsletter_organization o"
                " WHERE o.tenant_id = items.tenant_id AND o.item_id = items.id"
                " AND o.publication_id = ?)"
            )
            params.append(publication)
        if site is not None:
            clauses.append(f"({SITE_SQL}) = ?")
            params.append(site)
        if starred:
            clauses.append("starred_at IS NOT NULL")
        return " AND ".join(clauses), params

    # Fixed ORDER BY clauses keyed by name. The clause is interpolated into SQL, so it must
    # only ever come from this dict -- never from caller input -- and an unknown name is a
    # KeyError, not a fallback, so a typo at a call site fails loudly in tests.
    _ITEM_ORDERINGS = {
        "newest": "created_at DESC, id DESC",
        "oldest": "created_at ASC, id ASC",
        "title": "title COLLATE NOCASE ASC, created_at ASC, id ASC",
        "starred": "starred_at DESC, id DESC",
    }

    def list_items(
        self,
        scope: TenantScope,
        *,
        kind: str | None = None,
        author: str | None = None,
        query: str | None = None,
        source: str | None = None,
        publication: str | None = None,
        site: str | None = None,
        starred: bool = False,
        limit: int = 50,
        offset: int = 0,
        order: str = "newest",
    ) -> list[Item]:
        where, params = self._item_filters(
            scope,
            kind=kind,
            author=author,
            query=query,
            source=source,
            publication=publication,
            site=site,
            starred=starred,
        )
        ordering = self._ITEM_ORDERINGS[order]
        sql = f"SELECT * FROM items WHERE {where} ORDER BY {ordering} LIMIT ? OFFSET ?"
        with self._session() as connection:
            rows = connection.execute(sql, [*params, limit, offset]).fetchall()
        return [self._item(row) for row in rows]

    def list_item_titles(self, scope: TenantScope, *, source: str) -> list[str]:
        """Return current titles for one tenant and source, for Saved-name selection."""
        with self._session() as connection:
            rows = connection.execute(
                "SELECT title FROM items WHERE tenant_id = ? AND source = ? "
                "ORDER BY created_at ASC, id ASC",
                (scope.tenant_id, source),
            ).fetchall()
        return [str(row["title"]) for row in rows]

    def count_items(
        self,
        scope: TenantScope,
        *,
        kind: str | None = None,
        author: str | None = None,
        query: str | None = None,
        source: str | None = None,
        publication: str | None = None,
        site: str | None = None,
        starred: bool = False,
    ) -> int:
        where, params = self._item_filters(
            scope,
            kind=kind,
            author=author,
            query=query,
            source=source,
            publication=publication,
            site=site,
            starred=starred,
        )
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

    _SAVED_SITES = f"""
        SELECT {SITE_SQL} AS site, COUNT(*) AS page_count, MAX(created_at) AS updated_at
          FROM items
         WHERE tenant_id = ? AND kind = 'article' AND source = 'url'
      GROUP BY site
        HAVING site <> ''
    """

    def list_saved_sites(self, scope: TenantScope, *, limit: int = 50, offset: int = 0) -> list[SiteSummary]:
        """The sites saved pages came from, alphabetically, with counts.

        Grouped by the same expression the site filter uses, so a shelf never advertises a
        number its list then fails to deliver. A page whose URL has no scheme has no site
        and is left out here; it still appears in the flat Saved list.
        """
        with self._session() as connection:
            rows = connection.execute(
                f"{self._SAVED_SITES} ORDER BY site ASC LIMIT ? OFFSET ?", (scope.tenant_id, limit, offset)
            ).fetchall()
        return [
            SiteSummary(host=row["site"], page_count=int(row["page_count"]), updated_at=row["updated_at"])
            for row in rows
        ]

    def count_saved_sites(self, scope: TenantScope) -> int:
        with self._session() as connection:
            row = connection.execute(f"SELECT COUNT(*) FROM ({self._SAVED_SITES})", (scope.tenant_id,)).fetchone()
        return int(row[0])

    def latest_created_at(self, scope: TenantScope) -> str:
        with self._session() as connection:
            row = connection.execute(
                "SELECT MAX(created_at) FROM items WHERE tenant_id = ?", (scope.tenant_id,)
            ).fetchone()
        return row[0] or "1970-01-01T00:00:00Z"

    def tenant_storage_bytes(self, scope: TenantScope) -> int:
        """What this tenant's stored items add up to, for the quota check in ItemStorage.

        Trashed items are included: their files are still on disk until the purge. SUM
        returns NULL for a tenant with no items, which is 0 bytes used.
        """
        with self._session() as connection:
            row = connection.execute(
                "SELECT (SELECT COALESCE(SUM(size_bytes), 0) FROM items WHERE tenant_id = ?)"
                " + (SELECT COALESCE(SUM(size_bytes), 0) FROM trashed_items WHERE tenant_id = ?)",
                (scope.tenant_id, scope.tenant_id),
            ).fetchone()
        return int(row[0] or 0)

    def delete_item(self, scope: TenantScope, item_id: str, *, now: str | None = None) -> bool:
        now = now or datetime.now(UTC).isoformat()
        with self._write_lock, self._session() as connection:
            organized = connection.execute(
                """
                SELECT publication_id FROM newsletter_organization
                 WHERE tenant_id = ? AND item_id = ? AND publication_id IS NOT NULL
                """,
                (scope.tenant_id, item_id),
            ).fetchone()
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
                if organized is not None:
                    # Read before the DELETE, because the organization row goes with the
                    # item through ON DELETE CASCADE. Without this the navigation feed
                    # would keep advertising a publication whose last issue just expired:
                    # the newest surviving item's date cannot express a removal, and after
                    # an expiry it can even move backwards.
                    connection.execute(
                        "UPDATE publications SET updated_at = ? WHERE tenant_id = ? AND id = ?",
                        (now, scope.tenant_id, organized["publication_id"]),
                    )
                self._touch_catalogue(connection, scope.tenant_id, now)
        return cursor.rowcount == 1

    # -- trash ------------------------------------------------------------
    # Moving a row between items and trashed_items is the whole of soft deletion. Nothing
    # here touches files; ItemStorage calls these under its lock, which is what keeps a
    # trash, a restore, a purge and a retention delete of one item from interleaving.

    def trash_item(
        self, scope: TenantScope, item_id: str, *, now: str, expected_revision: int | None = None
    ) -> Item | None:
        """Move an item to the trash. None when this tenant has no such item, or when
        `expected_revision` is given and the item has changed since it was read."""
        with self._write_lock, self._session() as connection:
            row = connection.execute(
                "SELECT * FROM items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id)
            ).fetchone()
            if row is None or (expected_revision is not None and row["revision"] != expected_revision):
                return None
            organization = connection.execute(
                """
                SELECT state, publication_id, manual, attempts, error_code FROM newsletter_organization
                 WHERE tenant_id = ? AND item_id = ? AND state IN ('done', 'unrecognized', 'failed')
                """,
                (scope.tenant_id, item_id),
            ).fetchone()
            connection.execute(
                f"""
                INSERT INTO trashed_items (
                    {_ITEM_COLUMN_LIST}, deleted_at, organization_state, organization_publication_id,
                    organization_manual, organization_attempts, organization_error_code
                )
                SELECT {_ITEM_COLUMN_LIST}, ?, ?, ?, ?, ?, ? FROM items WHERE tenant_id = ? AND id = ?
                """,
                (
                    now,
                    organization["state"] if organization else None,
                    organization["publication_id"] if organization else None,
                    organization["manual"] if organization else 0,
                    organization["attempts"] if organization else 0,
                    organization["error_code"] if organization else None,
                    scope.tenant_id,
                    item_id,
                ),
            )
            connection.execute(
                "UPDATE trashed_items SET revision = revision + 1 WHERE tenant_id = ? AND id = ?",
                (scope.tenant_id, item_id),
            )
            # Cascades to newsletter_organization. newsletter_deliveries stays, so a repeat
            # forward of a trashed newsletter is still recognised as a repeat.
            connection.execute("DELETE FROM items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id))
            self._touch_after_move(connection, scope.tenant_id, organization, now)
        return self._item(row)

    def restore_item(
        self, scope: TenantScope, item_id: str, *, now: str, created_at: str | None = None
    ) -> Item | None:
        """Move a trashed item back. None when this tenant has no such trashed item.

        `created_at` replaces the arrival time when given: the caller passes one when the
        original would put the item straight back in front of the retention sweep.
        """
        with self._write_lock, self._session() as connection:
            row = connection.execute(
                "SELECT * FROM trashed_items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id)
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                f"INSERT INTO items ({_ITEM_COLUMN_LIST}) "
                f"SELECT {_ITEM_COLUMN_LIST} FROM trashed_items WHERE tenant_id = ? AND id = ?",
                (scope.tenant_id, item_id),
            )
            connection.execute(
                "UPDATE items SET revision = revision + 1, created_at = COALESCE(?, created_at)"
                " WHERE tenant_id = ? AND id = ?",
                (created_at, scope.tenant_id, item_id),
            )
            organization = None
            if row["organization_state"] is not None:
                # Merged publications keep their rows, so the id still resolves; a merge
                # since the trash means the survivor is where the issue belongs now.
                publication_id = row["organization_publication_id"]
                if publication_id is not None:
                    target = connection.execute(
                        "SELECT COALESCE(merged_into_id, id) FROM publications WHERE tenant_id = ? AND id = ?",
                        (scope.tenant_id, publication_id),
                    ).fetchone()
                    publication_id = target[0] if target else None
                if publication_id is not None or row["organization_publication_id"] is None:
                    connection.execute(
                        """
                        INSERT INTO newsletter_organization (
                            tenant_id, item_id, publication_id, state, manual, attempts, error_code
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scope.tenant_id,
                            item_id,
                            publication_id,
                            row["organization_state"],
                            row["organization_manual"],
                            row["organization_attempts"],
                            row["organization_error_code"],
                        ),
                    )
                    organization = {"publication_id": publication_id}
            connection.execute("DELETE FROM trashed_items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id))
            self._touch_after_move(connection, scope.tenant_id, organization, now)
            restored = connection.execute(
                "SELECT * FROM items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id)
            ).fetchone()
        return self._item(restored)

    def _touch_after_move(
        self, connection: sqlite3.Connection, tenant_id: str, organization: Mapping[str, Any] | None, now: str
    ) -> None:
        # The same clocks delete_item advances, for the same reason: the newest arrival
        # cannot express an item leaving or coming back, so a feed would look unchanged.
        if organization is not None and organization["publication_id"] is not None:
            connection.execute(
                "UPDATE publications SET updated_at = ? WHERE tenant_id = ? AND id = ?",
                (now, tenant_id, organization["publication_id"]),
            )
        self._touch_catalogue(connection, tenant_id, now)

    def set_starred(
        self, scope: TenantScope, item_id: str, *, starred: bool, expected_revision: int, now: str
    ) -> bool:
        """Set, never toggle, the star. False when the item is gone or has changed since
        `expected_revision` was read, in which case nothing is written."""
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                UPDATE items SET starred_at = ?, revision = revision + 1
                 WHERE tenant_id = ? AND id = ? AND revision = ?
                """,
                (now if starred else None, scope.tenant_id, item_id, expected_revision),
            )
            if cursor.rowcount == 1:
                self._touch_catalogue(connection, scope.tenant_id, now)
        return cursor.rowcount == 1

    def get_trashed_item(self, scope: TenantScope, item_id: str) -> TrashedItem | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM trashed_items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id)
            ).fetchone()
        return self._trashed_item(row)

    def trashed_item_by_sha256(self, scope: TenantScope, sha256: str) -> TrashedItem | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM trashed_items WHERE tenant_id = ? AND sha256 = ?", (scope.tenant_id, sha256)
            ).fetchone()
        return self._trashed_item(row)

    def list_trashed_items(self, scope: TenantScope, *, limit: int = 50, offset: int = 0) -> list[TrashedItem]:
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM trashed_items WHERE tenant_id = ? ORDER BY deleted_at DESC, id DESC LIMIT ? OFFSET ?",
                (scope.tenant_id, limit, offset),
            ).fetchall()
        return [self._trashed_item(row) for row in rows]

    def trash_summary(self, scope: TenantScope) -> tuple[int, int]:
        """How many items are in the trash, and their bytes."""
        with self._session() as connection:
            row = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM trashed_items WHERE tenant_id = ?",
                (scope.tenant_id,),
            ).fetchone()
        return int(row[0]), int(row[1])

    def delete_trashed_item(self, scope: TenantScope, item_id: str) -> bool:
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                "DELETE FROM trashed_items WHERE tenant_id = ? AND id = ?", (scope.tenant_id, item_id)
            )
            if cursor.rowcount == 1:
                # Kept while the item was recoverable; see delete_item for why it goes now.
                connection.execute(
                    "DELETE FROM newsletter_deliveries WHERE tenant_id = ? AND item_id = ?",
                    (scope.tenant_id, item_id),
                )
        return cursor.rowcount == 1

    def list_trash_past_retention(self, *, cutoff: str, limit: int = 500) -> list[TrashedItem]:
        """Trashed items deleted before `cutoff`, oldest first. Unscoped, like
        list_items_past_retention, and for the same reason: the sweep covers everyone."""
        with self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM trashed_items WHERE deleted_at < ? ORDER BY deleted_at ASC, id ASC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        return [self._trashed_item(row) for row in rows]

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

    # -- newsletter organization -------------------------------------------
    # Three tables behind one setting. The shape to hold on to: THE ABSENCE OF A
    # newsletter_organization ROW IS THE WAITING STATE. Nothing is enqueued at import,
    # nothing is scheduled when the setting is turned on, and re-enabling therefore picks
    # up the deliveries that arrived while it was off without a catch-up pass.
    #
    # Every decision below is a conditional write in the idiom redeem_magic_token uses:
    # the WHERE clause is the entire check-and-set, and rowcount decides the outcome. No
    # method here reads a value and then writes based on it across separate sessions.

    NEWSLETTER_STATES = ("running", "retry", "done", "unrecognized", "failed")

    @staticmethod
    def _preferences(row: sqlite3.Row | None) -> NewsletterPreferences | None:
        if row is None:
            return None
        return NewsletterPreferences(
            tenant_id=row["tenant_id"],
            enabled=bool(row["enabled"]),
            consent_version=int(row["consent_version"]),
            consented_at=row["consented_at"],
            settings_revision=int(row["settings_revision"]),
            catalogue_revision=int(row["catalogue_revision"]),
            catalogue_updated_at=row["catalogue_updated_at"],
            last_served_at=row["last_served_at"],
            attempt_day=row["attempt_day"],
            attempts_today=int(row["attempts_today"]),
        )

    @staticmethod
    def _publication(row: sqlite3.Row | None) -> Publication | None:
        if row is None:
            return None
        return Publication(
            tenant_id=row["tenant_id"],
            id=row["id"],
            name=row["name"],
            original_name=row["original_name"],
            identification_note=row["identification_note"],
            merged_into_id=row["merged_into_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def newsletter_preferences(self, scope: TenantScope) -> NewsletterPreferences | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM newsletter_preferences WHERE tenant_id = ?", (scope.tenant_id,)
            ).fetchone()
        return self._preferences(row)

    @staticmethod
    def _touch_catalogue(connection: sqlite3.Connection, tenant_id: str, now: str) -> None:
        """Advance the tenant's catalogue revision and timestamp.

        The revision is what an in-flight classification captured, so bumping it discards
        a result computed against publication choices the owner has since changed. The
        timestamp is what OPDS reports as `updated`, which is why enable and disable bump
        it too: the root's Newsletters entry changes target then, before any issue has
        been classified, and a reader that cached the old link would otherwise keep it.
        """
        connection.execute(
            """
            UPDATE newsletter_preferences
               SET catalogue_revision = catalogue_revision + 1, catalogue_updated_at = ?
             WHERE tenant_id = ?
            """,
            (now, tenant_id),
        )

    @staticmethod
    def _ensure_preferences(connection: sqlite3.Connection, tenant_id: str) -> None:
        """Create the row a mutation needs, without turning the feature on.

        Separate from the settings form on purpose: a manual correction is available
        whether or not automatic organization was ever enabled, and making a correction
        must not quietly opt the account into sending anything anywhere.
        """
        connection.execute(
            # settings_revision is written explicitly rather than left to the column
            # default: a database created by an earlier build of this schema carries a
            # different default, and the empty settings form renders 0 either way.
            "INSERT OR IGNORE INTO newsletter_preferences (tenant_id, settings_revision) VALUES (?, 0)",
            (tenant_id,),
        )

    def set_newsletter_organization(
        self,
        scope: TenantScope,
        *,
        enabled: bool,
        consent_version: int,
        settings_revision: int | None,
        now: str,
    ) -> bool:
        """Turn organization on or off, advancing the settings revision either way.

        `settings_revision` is the value the form was rendered with; None accepts any,
        for the first save when no row exists yet. A stale submission is refused rather
        than applied, so a tab left open on the enable form cannot undo a later Off.

        Advancing the revision on *both* transitions is what makes Off authoritative
        against work already in flight: a response that arrives afterwards fails its
        commit guard, including when the owner turns the feature straight back on.
        """
        with self._write_lock, self._session() as connection:
            self._ensure_preferences(connection, scope.tenant_id)
            cursor = connection.execute(
                """
                UPDATE newsletter_preferences
                   SET enabled = ?,
                       consent_version = MAX(consent_version, ?),
                       consented_at = CASE WHEN ? THEN ? ELSE consented_at END,
                       settings_revision = settings_revision + 1
                 WHERE tenant_id = ?
                   AND (? IS NULL OR settings_revision = ?)
                """,
                (
                    1 if enabled else 0,
                    consent_version if enabled else 0,
                    1 if enabled else 0,
                    now,
                    scope.tenant_id,
                    settings_revision,
                    settings_revision,
                ),
            )
            if cursor.rowcount == 1:
                # The root catalogue's Newsletters entry changes target on this edge.
                self._touch_catalogue(connection, scope.tenant_id, now)
        return cursor.rowcount == 1

    def pause_newsletter_organization(self, scope: TenantScope, *, now: str) -> None:
        """Stop all automatic work for this tenant and invalidate anything in flight.

        Used at the start of an account purge, before files are deleted: it must not be
        possible for another browser to re-enable organization, or for a request already
        sent to commit its answer, while the account is being removed.
        """
        with self._write_lock, self._session() as connection:
            self._ensure_preferences(connection, scope.tenant_id)
            connection.execute(
                """
                UPDATE newsletter_preferences
                   SET enabled = 0, settings_revision = settings_revision + 1
                 WHERE tenant_id = ?
                """,
                (scope.tenant_id,),
            )
            # In the same transaction, because advancing the revision alone is not enough:
            # a browser still holding a session can load the new revision and re-enable the
            # feature while the files are being deleted. Revoking here closes that window,
            # and if the purge then fails the account stays both paused and signed out.
            connection.execute("DELETE FROM sessions WHERE tenant_id = ?", (scope.tenant_id,))
            self._touch_catalogue(connection, scope.tenant_id, now)

    # The WHERE fragment every worker commit shares. It is deliberately one expression
    # rather than a sequence of reads: the write either matches a row that still satisfies
    # all of it, or it matches nothing and the paid-for answer is thrown away.
    _COMMIT_GUARD = """
               AND lease_token = ?
               AND state = 'running'
               AND manual = 0
               AND not_before > ?
               AND EXISTS (
                     SELECT 1 FROM newsletter_preferences p
                      WHERE p.tenant_id = newsletter_organization.tenant_id
                        AND p.enabled = 1
                        AND p.settings_revision = ?
                        AND p.catalogue_revision = ?)
               AND EXISTS (
                     SELECT 1 FROM items i
                       JOIN tenants t ON t.id = i.tenant_id
                      WHERE i.tenant_id = newsletter_organization.tenant_id
                        AND i.id = newsletter_organization.item_id
                        AND i.kind = 'article'
                        AND i.source = 'newsletter'
                        AND t.plan = ?
                        AND (? IS NULL OR i.created_at >= ?))
    """

    @staticmethod
    def _guard_params(guard: OrganizationGuard) -> tuple[Any, ...]:
        return (
            guard.lease_token,
            guard.now,
            guard.settings_revision,
            guard.catalogue_revision,
            guard.plan,
            guard.retention_cutoff,
            guard.retention_cutoff,
        )

    def organization_candidates(
        self,
        *,
        now: str,
        now_day: str,
        retention_cutoffs: Mapping[str, str | None],
        daily_limit: int,
        required_consent_version: int,
        limit: int = 25,
    ) -> list[OrganizationCandidate]:
        """Tenants that may be served now, least recently served first.

        The plan comes back with the row rather than being resolved here: the caller asks
        steepd.plans for the retention cutoff, so this query never carries a second copy
        of which plans expire and which do not. Capped tenants are excluded rather than
        skipped later, so one account at its daily allowance cannot block the others.

        A tenant must actually have work to be a candidate, retention included. Without
        that, accounts holding nothing but expired-and-unswept issues fill the page, never
        claim anything, never advance last_served_at, and so sit at the front of this
        ordering -- starving an account whose id happens to sort after theirs. An account
        whose recorded consent has been superseded is excluded for the same reason: its
        dispatches would be refused, and it would spin preparing the same issue forever.
        """
        if not retention_cutoffs:
            return []
        # The plan-to-cutoff pairs arrive as values, computed by the caller from
        # steepd.plans. Joining against them restricts to the allowed plans and applies
        # each plan's retention in one go, without this query knowing which plans expire.
        pairs = list(retention_cutoffs.items())
        cutoff_rows = " UNION ALL ".join(["SELECT ? AS plan, ? AS cutoff"] + ["SELECT ?, ?"] * (len(pairs) - 1))
        cutoff_params = [value for pair in pairs for value in pair]
        with self._session() as connection:
            rows = connection.execute(
                f"""
                SELECT p.tenant_id, t.plan, p.settings_revision, p.catalogue_revision
                  FROM newsletter_preferences p
                  JOIN tenants t ON t.id = p.tenant_id
                  JOIN ({cutoff_rows}) r ON r.plan = t.plan
                 WHERE p.enabled = 1
                   AND p.consent_version >= ?
                   AND (p.attempt_day IS NULL OR p.attempt_day <> ? OR p.attempts_today < ?)
                   AND EXISTS (
                         SELECT 1
                           FROM items i
                           LEFT JOIN newsletter_organization o
                                  ON o.tenant_id = i.tenant_id AND o.item_id = i.id
                          WHERE i.tenant_id = p.tenant_id
                            AND i.kind = 'article'
                            AND i.source = 'newsletter'
                            AND (r.cutoff IS NULL OR i.created_at >= r.cutoff)
                            AND (o.item_id IS NULL
                                 OR (o.manual = 0 AND o.state IN ('running', 'retry') AND o.not_before <= ?)))
              ORDER BY p.last_served_at IS NOT NULL, p.last_served_at ASC, p.tenant_id ASC
                 LIMIT ?
                """,
                (*cutoff_params, required_consent_version, now_day, daily_limit, now, limit),
            ).fetchall()
        return [
            OrganizationCandidate(
                tenant_id=row["tenant_id"],
                plan=row["plan"],
                settings_revision=int(row["settings_revision"]),
                catalogue_revision=int(row["catalogue_revision"]),
            )
            for row in rows
        ]

    def finalize_exhausted_claims(
        self, scope: TenantScope, *, now: str, max_attempts: int, error_code: str = "lease_expired"
    ) -> int:
        """Finish due rows that have no attempts left, in either non-terminal state.

        Recovering one into `running` would dispatch a third paid request for an item
        already allowed two, so it is finalized instead: readable, correctable, and
        available for an explicit Retry. `retry` is covered as well as `running` because
        a row parked there with a spent allowance can never be claimed again and would
        otherwise sit invisible forever -- neither running, nor retryable, nor terminal.
        """
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                UPDATE newsletter_organization
                   SET state = 'failed', not_before = NULL, error_code = COALESCE(error_code, ?)
                 WHERE tenant_id = ?
                   AND state IN ('running', 'retry')
                   AND manual = 0
                   AND not_before <= ?
                   AND attempts >= ?
                """,
                (error_code, scope.tenant_id, now, max_attempts),
            )
        return cursor.rowcount

    def claim_organization_item(
        self,
        scope: TenantScope,
        *,
        now: str,
        lease_token: str,
        lease_until: str,
        retention_cutoff: str | None,
        max_attempts: int,
    ) -> ClaimedOrganization | None:
        """Lease exactly one item, or return None when this tenant has nothing due.

        Two sources, in this order:

        1. Rows already under way -- a retry that has come due, or a lease that expired.
           These go first so an explicitly requested Retry is responsive instead of
           queueing behind every newer untouched issue in a large backlog.
        2. Newsletters with no row at all, newest first, found by anti-join. This is the
           whole of "scheduling": there is nothing to enqueue because absence is the
           waiting state.

        Both are single conditional statements, so a second worker during a deployment
        overlap either gets a row or gets nothing -- never a half-made claim.
        """
        with self._write_lock, self._session() as connection:
            row = connection.execute(
                """
                UPDATE newsletter_organization
                   SET state = 'running', lease_token = ?, not_before = ?, error_code = NULL
                 WHERE tenant_id = ?
                   AND item_id = (
                         SELECT o.item_id
                           FROM newsletter_organization o
                           JOIN items i ON i.tenant_id = o.tenant_id AND i.id = o.item_id
                          WHERE o.tenant_id = ?
                            AND o.manual = 0
                            AND o.state IN ('running', 'retry')
                            AND o.not_before <= ?
                            AND o.attempts < ?
                            AND i.kind = 'article'
                            AND i.source = 'newsletter'
                            AND (? IS NULL OR i.created_at >= ?)
                       ORDER BY o.not_before ASC, o.item_id ASC
                          LIMIT 1)
                   AND manual = 0
                   AND state IN ('running', 'retry')
                   AND not_before <= ?
              RETURNING item_id, attempts
                """,
                (
                    lease_token,
                    lease_until,
                    scope.tenant_id,
                    scope.tenant_id,
                    now,
                    max_attempts,
                    retention_cutoff,
                    retention_cutoff,
                    now,
                ),
            ).fetchone()

            if row is None:
                row = connection.execute(
                    """
                    INSERT INTO newsletter_organization (
                        tenant_id, item_id, state, manual, attempts, lease_token, not_before
                    )
                    SELECT i.tenant_id, i.id, 'running', 0, 0, ?, ?
                      FROM items i
                      LEFT JOIN newsletter_organization o
                             ON o.tenant_id = i.tenant_id AND o.item_id = i.id
                     WHERE i.tenant_id = ?
                       AND i.kind = 'article'
                       AND i.source = 'newsletter'
                       AND (? IS NULL OR i.created_at >= ?)
                       AND o.item_id IS NULL
                  ORDER BY i.created_at DESC, i.id DESC
                     LIMIT 1
                        ON CONFLICT (tenant_id, item_id) DO NOTHING
                  RETURNING item_id, attempts
                    """,
                    (lease_token, lease_until, scope.tenant_id, retention_cutoff, retention_cutoff),
                ).fetchone()

            if row is None:
                return None
            # Only a claim that produced work advances the fair-scheduling marker, so a
            # tenant with nothing to do never costs another tenant its turn.
            connection.execute(
                "UPDATE newsletter_preferences SET last_served_at = ? WHERE tenant_id = ?",
                (now, scope.tenant_id),
            )
        return ClaimedOrganization(
            tenant_id=scope.tenant_id,
            item_id=row["item_id"],
            lease_token=lease_token,
            attempts=int(row["attempts"]),
        )

    def consume_dispatch_allowance(
        self,
        scope: TenantScope,
        item_id: str,
        *,
        lease_token: str,
        day: str,
        now: str,
        daily_limit: int,
        settings_revision: int,
        required_consent_version: int,
    ) -> int | None:
        """Spend one dispatch from the tenant's UTC-day allowance and record the attempt.

        One transaction immediately before the request goes out, for two reasons. It is
        the cheap check that avoids knowingly paying after an Off or an exhausted cap --
        it cannot close the instant-after race, which is what the commit guard is for.
        And it persists the attempt *before* the send, so a crash mid-request never makes
        a possibly billed attempt look free.

        The consent version is a condition here, not a record: if the policy this asks
        agreement to ever broadens, raising the required version stops every account that
        agreed to the older one until they agree again, rather than carrying their old
        consent forward onto something they were never shown.

        Returns the new count for this day, or None when sending is no longer allowed.
        """
        with self._write_lock, self._session() as connection:
            row = connection.execute(
                """
                UPDATE newsletter_preferences
                   SET attempt_day = ?,
                       attempts_today = CASE WHEN attempt_day = ? THEN attempts_today + 1 ELSE 1 END
                 WHERE tenant_id = ?
                   AND enabled = 1
                   AND settings_revision = ?
                   AND consent_version >= ?
                   AND (attempt_day IS NULL OR attempt_day <> ? OR attempts_today < ?)
              RETURNING attempts_today
                """,
                (day, day, scope.tenant_id, settings_revision, required_consent_version, day, daily_limit),
            ).fetchone()
            if row is None:
                return None
            attempt = connection.execute(
                """
                UPDATE newsletter_organization
                   SET attempts = attempts + 1
                 WHERE tenant_id = ? AND item_id = ? AND lease_token = ? AND state = 'running'
                   AND manual = 0 AND not_before > ?
                """,
                (scope.tenant_id, item_id, lease_token, now),
            )
            if attempt.rowcount != 1:
                # The lease moved on between claim and dispatch. Undo the tenant-level
                # spend rather than charging an allowance against a request never sent.
                connection.execute(
                    "UPDATE newsletter_preferences SET attempts_today = attempts_today - 1 WHERE tenant_id = ?",
                    (scope.tenant_id,),
                )
                return None
        return int(row["attempts_today"])

    def release_organization_claim(self, scope: TenantScope, item_id: str, *, lease_token: str, now: str) -> bool:
        """Hand back a claim, leaving the item due again.

        A local failure before dispatch -- an unreadable file, a cap reached between claim
        and send -- never consumed an attempt in the first place, because attempts are
        spent alongside the dispatch allowance.

        Nothing is ever given back. A request that reached the provider counts, whatever
        it came back as: a rejected key is still a dispatch, and pretending otherwise let
        a 500 followed by a 401 buy an item a third and fourth paid try. An item whose
        allowance really is spent is finished by finalize_exhausted_claims, where the
        owner can still ask for it explicitly.
        """
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                UPDATE newsletter_organization
                   SET state = 'retry', not_before = ?
                 WHERE tenant_id = ? AND item_id = ? AND lease_token = ? AND state = 'running' AND manual = 0
                """,
                (now, scope.tenant_id, item_id, lease_token),
            )
        return cursor.rowcount == 1

    def assign_organization_publication(
        self, scope: TenantScope, item_id: str, *, guard: OrganizationGuard, publication_id: str
    ) -> bool:
        """Record a model answer that chose an existing publication.

        The destination must still be canonical: a publication merged away while the
        request was out is no longer a choice the model was entitled to make, and the
        catalogue revision in the guard will already have refused the write.
        """
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                f"""
                UPDATE newsletter_organization
                   SET state = 'done', publication_id = ?, not_before = NULL, error_code = NULL
                 WHERE tenant_id = ? AND item_id = ?
                   AND EXISTS (
                         SELECT 1 FROM publications pub
                          WHERE pub.tenant_id = newsletter_organization.tenant_id
                            AND pub.id = ?
                            AND pub.merged_into_id IS NULL)
                   {self._COMMIT_GUARD}
                """,
                (publication_id, scope.tenant_id, item_id, publication_id, *self._guard_params(guard)),
            )
            if cursor.rowcount == 1:
                # The publication's own feed reports this timestamp, and assigning an older
                # issue changes what that feed contains without changing the newest arrival
                # date -- so without this a reader would never refetch it.
                connection.execute(
                    "UPDATE publications SET updated_at = ? WHERE tenant_id = ? AND id = ?",
                    (guard.now, scope.tenant_id, publication_id),
                )
                self._touch_catalogue(connection, scope.tenant_id, guard.now)
        return cursor.rowcount == 1

    def create_and_assign_publication(
        self,
        scope: TenantScope,
        item_id: str,
        *,
        guard: OrganizationGuard,
        publication_id: str,
        name: str,
    ) -> Publication | None:
        """Create a publication and assign this issue to it, or do neither.

        Both writes are in one transaction and the guard runs first, so a rejected answer
        can never leave an empty publication behind. The guard write re-asserts the claim
        rather than setting a terminal state, because a `done` row with no publication
        would mean the owner's Keep ungrouped -- a different thing entirely.
        """
        with self._write_lock, self._session() as connection:
            claimed = connection.execute(
                f"""
                UPDATE newsletter_organization
                   SET state = 'running'
                 WHERE tenant_id = ? AND item_id = ?
                   {self._COMMIT_GUARD}
                """,
                (scope.tenant_id, item_id, *self._guard_params(guard)),
            )
            if claimed.rowcount != 1:
                return None
            connection.execute(
                """
                INSERT INTO publications (
                    tenant_id, id, name, original_name, identification_note,
                    merged_into_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, '', NULL, ?, ?)
                """,
                (scope.tenant_id, publication_id, name, name, guard.now, guard.now),
            )
            connection.execute(
                """
                UPDATE newsletter_organization
                   SET state = 'done', publication_id = ?, not_before = NULL, error_code = NULL
                 WHERE tenant_id = ? AND item_id = ? AND lease_token = ?
                """,
                (publication_id, scope.tenant_id, item_id, guard.lease_token),
            )
            self._touch_catalogue(connection, scope.tenant_id, guard.now)
            row = connection.execute(
                "SELECT * FROM publications WHERE tenant_id = ? AND id = ?", (scope.tenant_id, publication_id)
            ).fetchone()
        return self._publication(row)

    def record_organization_outcome(
        self,
        scope: TenantScope,
        item_id: str,
        *,
        guard: OrganizationGuard,
        state: str,
        error_code: str | None = None,
        retry_at: str | None = None,
    ) -> bool:
        """Finalize a cycle without an assignment: unknown, failed, or due to retry again.

        Guarded exactly like an assignment. An old worker must not be able to stamp a
        failure over a newer manual correction, so "no organization change" is not a
        licence to write without checking.
        """
        if state not in ("unrecognized", "failed", "retry"):
            raise ValueError(f"unsupported organization outcome: {state}")
        if (state == "retry") != (retry_at is not None):
            raise ValueError("retry outcomes need a retry time, and only retry outcomes have one")
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                f"""
                UPDATE newsletter_organization
                   SET state = ?, not_before = ?, error_code = ?
                 WHERE tenant_id = ? AND item_id = ?
                   {self._COMMIT_GUARD}
                """,
                (state, retry_at, error_code, scope.tenant_id, item_id, *self._guard_params(guard)),
            )
        return cursor.rowcount == 1

    # -- owner corrections --------------------------------------------------
    # These are the user's path, not the worker's, and they deliberately carry no
    # `manual = 0` guard: the whole point of Change publication is to overrule an earlier
    # decision, including an earlier decision of the owner's own.

    def assign_publication_manually(
        self,
        scope: TenantScope,
        item_id: str,
        *,
        publication_id: str | None,
        now: str,
    ) -> bool:
        """Set, change, or clear one issue's publication on the owner's instruction.

        An upsert, because absence is the waiting state: the item may have no row at all
        when a brand-new account corrects something before the worker has reached it. It
        also clears the lease, so a request already in flight for this item fails its
        commit guard and cannot overwrite what was just chosen here.

        `publication_id=None` is Keep ungrouped, which is a decision rather than an
        absence -- that is what `manual` on a `done` row with no publication means.
        """
        with self._write_lock, self._session() as connection:
            # This no-op-if-present insert is the transaction's first write, so everything
            # below runs with the database write lock already held. Without it the read
            # that follows could see a publication another connection was in the middle of
            # changing, and that publication's feed would never learn it lost an issue.
            self._ensure_preferences(connection, scope.tenant_id)
            previous = connection.execute(
                "SELECT publication_id FROM newsletter_organization WHERE tenant_id = ? AND item_id = ?",
                (scope.tenant_id, item_id),
            ).fetchone()
            # One statement: ownership, newsletter kind/source and a canonical destination
            # are all conditions of the write itself. Checking them in a SELECT first would
            # read outside any lock -- a merge landing in between could file the issue into
            # a publication that no longer exists to browse.
            cursor = connection.execute(
                """
                INSERT INTO newsletter_organization (
                    tenant_id, item_id, publication_id, state, manual, attempts,
                    lease_token, not_before, error_code
                )
                SELECT i.tenant_id, i.id, ?, 'done', 1, 0, NULL, NULL, NULL
                  FROM items i
                 WHERE i.tenant_id = ? AND i.id = ? AND i.kind = 'article' AND i.source = 'newsletter'
                   AND (? IS NULL OR EXISTS (
                         SELECT 1 FROM publications pub
                          WHERE pub.tenant_id = i.tenant_id AND pub.id = ? AND pub.merged_into_id IS NULL))
                ON CONFLICT (tenant_id, item_id) DO UPDATE SET
                    publication_id = excluded.publication_id,
                    state = 'done',
                    manual = 1,
                    lease_token = NULL,
                    not_before = NULL,
                    error_code = NULL
                """,
                (publication_id, scope.tenant_id, item_id, publication_id, publication_id),
            )
            if cursor.rowcount != 1:
                return False
            touched = {publication_id, previous["publication_id"] if previous else None} - {None}
            for affected in touched:
                connection.execute(
                    "UPDATE publications SET updated_at = ? WHERE tenant_id = ? AND id = ?",
                    (now, scope.tenant_id, affected),
                )
            self._touch_catalogue(connection, scope.tenant_id, now)
        return True

    def manual_assignment_matching(self, scope: TenantScope, item_id: str, name: str) -> str | None:
        """The publication this item is already manually assigned to under `name`, if any.

        Replay handling for create-and-assign, and nothing more: it is scoped to this one
        item so that a second submission of the same form does not make a second
        publication, while leaving two genuinely distinct publications free to share a
        display name. It is not name-based merging.
        """
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT p.id
                  FROM newsletter_organization o
                  JOIN publications p ON p.tenant_id = o.tenant_id AND p.id = o.publication_id
                 WHERE o.tenant_id = ? AND o.item_id = ? AND o.manual = 1
                   AND p.merged_into_id IS NULL AND p.name = ? COLLATE NOCASE
                """,
                (scope.tenant_id, item_id, name),
            ).fetchone()
        return row["id"] if row else None

    def edit_publication(
        self,
        scope: TenantScope,
        publication_id: str,
        *,
        name: str,
        identification_note: str,
        now: str,
    ) -> bool:
        """Rename and/or re-note a publication, preserving everything that identifies it.

        `original_name`, the id, the assignments and therefore the OPDS URL are all left
        alone. A rename is a change of label, not an instruction to reclassify anything.
        """
        with self._write_lock, self._session() as connection:
            cursor = connection.execute(
                """
                UPDATE publications
                   SET name = ?, identification_note = ?, updated_at = ?
                 WHERE tenant_id = ? AND id = ? AND merged_into_id IS NULL
                """,
                (name, identification_note, now, scope.tenant_id, publication_id),
            )
            if cursor.rowcount == 1:
                self._touch_catalogue(connection, scope.tenant_id, now)
        return cursor.rowcount == 1

    def merge_publications(
        self, scope: TenantScope, *, source_id: str, target_id: str, now: str
    ) -> bool:
        """Combine `source_id` into `target_id`, keeping the source row as an alias.

        The first write is the whole authorization: it succeeds only if both records are
        this tenant's, distinct, and still canonical. Everything after it is bookkeeping
        inside the same transaction. Aliases already pointing at the source are repointed
        at the target in the same breath, so resolution is always one hop and never walks
        a chain that a later merge could turn into a cycle.
        """
        if source_id == target_id:
            return False
        with self._write_lock, self._session() as connection:
            claimed = connection.execute(
                """
                UPDATE publications
                   SET merged_into_id = ?, updated_at = ?
                 WHERE tenant_id = ? AND id = ? AND merged_into_id IS NULL
                   AND EXISTS (
                         SELECT 1 FROM publications target
                          WHERE target.tenant_id = publications.tenant_id
                            AND target.id = ?
                            AND target.merged_into_id IS NULL)
                """,
                (target_id, now, scope.tenant_id, source_id, target_id),
            )
            if claimed.rowcount != 1:
                return False
            connection.execute(
                """
                UPDATE newsletter_organization SET publication_id = ?
                 WHERE tenant_id = ? AND publication_id = ?
                """,
                (target_id, scope.tenant_id, source_id),
            )
            connection.execute(
                """
                UPDATE publications SET merged_into_id = ?, updated_at = ?
                 WHERE tenant_id = ? AND merged_into_id = ? AND id <> ?
                """,
                (target_id, now, scope.tenant_id, source_id, target_id),
            )
            connection.execute(
                "UPDATE publications SET updated_at = ? WHERE tenant_id = ? AND id = ?",
                (now, scope.tenant_id, target_id),
            )
            self._touch_catalogue(connection, scope.tenant_id, now)
        return True

    def retry_organization_items(
        self, scope: TenantScope, selections: Sequence[tuple[str, str]], *, now: str
    ) -> int:
        """Start a fresh cycle for the terminal results the owner picked.

        An update, never a delete: deleting the row would return the item to the waiting
        state, where `items.created_at DESC` ordering would put an old issue behind every
        newer untouched one -- a Retry that appears to do nothing for days. `retry` with
        `not_before = now` is picked up on the next pass instead.

        Each selection carries the result token it was rendered with, so replaying an old
        form cannot restart a newer cycle. A second click before the next claim matches
        nothing, because the row is already `retry`.
        """
        if not selections:
            return 0
        changed = 0
        with self._write_lock, self._session() as connection:
            for item_id, result_token in selections:
                cursor = connection.execute(
                    """
                    UPDATE newsletter_organization
                       SET state = 'retry', attempts = 0, not_before = ?, error_code = NULL
                     WHERE tenant_id = ? AND item_id = ? AND lease_token = ?
                       AND manual = 0 AND state IN ('failed', 'unrecognized')
                    """,
                    (now, scope.tenant_id, item_id, result_token),
                )
                changed += cursor.rowcount
        return changed

    # -- reading what was organized ----------------------------------------

    _NEWSLETTER_ITEM = "kind = 'article' AND source = 'newsletter'"

    def organization_progress(self, scope: TenantScope, *, retention_cutoff: str | None) -> OrganizationProgress:
        """Counts over currently retained newsletters, derived rather than recorded.

        There is no scan-history row to drift out of step with the library: an item that
        expires takes its organization row with it through the foreign key, so these
        numbers describe what is here now. Waiting is counted by absence.
        """
        with self._session() as connection:
            row = connection.execute(
                f"""
                SELECT
                    SUM(o.item_id IS NULL)              AS waiting,
                    SUM(o.state = 'running')            AS running,
                    SUM(o.state = 'retry')              AS retrying,
                    SUM(o.state = 'done')               AS organized,
                    SUM(o.state = 'unrecognized')       AS unrecognized,
                    SUM(o.state = 'failed')             AS failed
                  FROM items i
                  LEFT JOIN newsletter_organization o
                         ON o.tenant_id = i.tenant_id AND o.item_id = i.id
                 WHERE i.tenant_id = ? AND i.{self._NEWSLETTER_ITEM}
                   AND (? IS NULL OR i.created_at >= ?)
                """,
                (scope.tenant_id, retention_cutoff, retention_cutoff),
            ).fetchone()
        return OrganizationProgress(
            waiting=int(row["waiting"] or 0),
            # A row waiting for its retry is still in progress as far as the page is
            # concerned; the distinction between the two matters only to the worker.
            running=int(row["running"] or 0) + int(row["retrying"] or 0),
            organized=int(row["organized"] or 0),
            unrecognized=int(row["unrecognized"] or 0),
            failed=int(row["failed"] or 0),
        )

    def list_unorganized_newsletters(
        self, scope: TenantScope, *, retention_cutoff: str | None, limit: int = 50, offset: int = 0
    ) -> list[UnorganizedIssue]:
        """Retained newsletters with no publication, newest first.

        Includes items still waiting as well as unknown and failed results, because from
        the reader's side they are one question -- "why is this not in a publication?" --
        and the answer is the state, not a different page.
        """
        with self._session() as connection:
            rows = connection.execute(
                f"""
                SELECT i.id, i.title, COALESCE(o.state, 'waiting') AS state, o.lease_token
                  FROM items i
                  LEFT JOIN newsletter_organization o
                         ON o.tenant_id = i.tenant_id AND o.item_id = i.id
                 WHERE i.tenant_id = ? AND i.{self._NEWSLETTER_ITEM}
                   AND (? IS NULL OR i.created_at >= ?)
                   AND (o.item_id IS NULL OR o.publication_id IS NULL)
              ORDER BY i.created_at DESC, i.id DESC
                 LIMIT ? OFFSET ?
                """,
                (scope.tenant_id, retention_cutoff, retention_cutoff, limit, offset),
            ).fetchall()
        return [
            UnorganizedIssue(
                item_id=row["id"],
                title=row["title"],
                state=row["state"],
                # Only a terminal non-manual result can be retried, so only those carry a
                # token forward to the form.
                result_token=row["lease_token"] if row["state"] in ("failed", "unrecognized") else None,
            )
            for row in rows
        ]

    def count_unorganized_newsletters(self, scope: TenantScope, *, retention_cutoff: str | None) -> int:
        with self._session() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*)
                  FROM items i
                  LEFT JOIN newsletter_organization o
                         ON o.tenant_id = i.tenant_id AND o.item_id = i.id
                 WHERE i.tenant_id = ? AND i.{self._NEWSLETTER_ITEM}
                   AND (? IS NULL OR i.created_at >= ?)
                   AND (o.item_id IS NULL OR o.publication_id IS NULL)
                """,
                (scope.tenant_id, retention_cutoff, retention_cutoff),
            ).fetchone()
        return int(row[0])

    def list_publication_summaries(
        self, scope: TenantScope, *, limit: int = 50, offset: int = 0
    ) -> list[PublicationSummary]:
        """Canonical publications that currently hold at least one retained issue.

        The inner join is what hides an empty publication from browsing without deleting
        it: when the last issue expires the row stays, holding its id and its names, and
        the shelf simply stops listing it until another issue arrives.
        """
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT p.*, COUNT(o.item_id) AS issue_count
                  FROM publications p
                  JOIN newsletter_organization o
                    ON o.tenant_id = p.tenant_id AND o.publication_id = p.id
                 WHERE p.tenant_id = ? AND p.merged_into_id IS NULL
              GROUP BY p.tenant_id, p.id
              ORDER BY p.name COLLATE NOCASE ASC, p.id ASC
                 LIMIT ? OFFSET ?
                """,
                (scope.tenant_id, limit, offset),
            ).fetchall()
        return [
            PublicationSummary(publication=self._publication(row), issue_count=int(row["issue_count"]))
            for row in rows
        ]

    def count_publications(self, scope: TenantScope) -> int:
        """How many publications the list would show, using that same filter."""
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT p.id
                      FROM publications p
                      JOIN newsletter_organization o
                        ON o.tenant_id = p.tenant_id AND o.publication_id = p.id
                     WHERE p.tenant_id = ? AND p.merged_into_id IS NULL
                  GROUP BY p.tenant_id, p.id)
                """,
                (scope.tenant_id,),
            ).fetchone()
        return int(row[0])

    def publication(self, scope: TenantScope, publication_id: str) -> Publication | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM publications WHERE tenant_id = ? AND id = ?", (scope.tenant_id, publication_id)
            ).fetchone()
        return self._publication(row)

    def resolve_publication(self, scope: TenantScope, publication_id: str) -> Publication | None:
        """The canonical record a URL refers to, following at most one merge hop.

        One hop is enough by construction: merging a survivor repoints the aliases that
        already pointed at it, so no alias ever points at another alias. An old bookmark
        therefore opens the surviving publication's feed directly, without relying on the
        reader to follow a redirect.
        """
        record = self.publication(scope, publication_id)
        if record is None or record.is_canonical:
            return record
        survivor = self.publication(scope, record.merged_into_id)
        return survivor if survivor is not None and survivor.is_canonical else None

    def canonical_publications(self, scope: TenantScope, *, limit: int = 500) -> list[Publication]:
        """Every publication the classifier may choose from, including empty ones.

        Remembered-but-empty publications are included deliberately: when the last issue
        of a publication expires and the next one arrives, it should rejoin the record it
        already had rather than start a second one with the same name.
        """
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT * FROM publications
                 WHERE tenant_id = ? AND merged_into_id IS NULL
              ORDER BY name COLLATE NOCASE ASC, id ASC
                 LIMIT ?
                """,
                (scope.tenant_id, limit),
            ).fetchall()
        return [self._publication(row) for row in rows]

    def publication_aliases(self, scope: TenantScope) -> dict[str, list[Publication]]:
        """Merged records grouped under the survivor they point at.

        Their names and notes go to the classifier as clues for that survivor: combining
        two publications should teach the next issue where to go, not throw away what the
        owner knew when they combined them.
        """
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT * FROM publications
                 WHERE tenant_id = ? AND merged_into_id IS NOT NULL
              ORDER BY name COLLATE NOCASE ASC, id ASC
                """,
                (scope.tenant_id,),
            ).fetchall()
        grouped: dict[str, list[Publication]] = {}
        for row in rows:
            grouped.setdefault(row["merged_into_id"], []).append(self._publication(row))
        return grouped

    def correction_examples(
        self, scope: TenantScope, *, per_publication: int = 3
    ) -> dict[str, list[tuple[str, str, str]]]:
        """A few manually assigned issues per publication, as (title, author, source_url).

        Read from the items themselves rather than copied into a history table, so they
        expire when the issues do and there is nothing extra to retain or purge. One
        windowed query for the whole tenant, not one query per publication.
        """
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT publication_id, title, author, source_url FROM (
                    SELECT o.publication_id, i.title, i.author, i.source_url,
                           ROW_NUMBER() OVER (
                               PARTITION BY o.publication_id ORDER BY i.created_at DESC, i.id DESC
                           ) AS rank
                      FROM newsletter_organization o
                      JOIN items i ON i.tenant_id = o.tenant_id AND i.id = o.item_id
                     WHERE o.tenant_id = ? AND o.manual = 1 AND o.publication_id IS NOT NULL)
                 WHERE rank <= ?
                """,
                (scope.tenant_id, per_publication),
            ).fetchall()
        examples: dict[str, list[tuple[str, str, str]]] = {}
        for row in rows:
            examples.setdefault(row["publication_id"], []).append(
                (row["title"], row["author"], row["source_url"])
            )
        return examples

    def organization_row(self, scope: TenantScope, item_id: str) -> dict[str, Any] | None:
        """The raw row, for tests and for the worker's own bookkeeping."""
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM newsletter_organization WHERE tenant_id = ? AND item_id = ?",
                (scope.tenant_id, item_id),
            ).fetchone()
        return dict(row) if row is not None else None

    def newsletter_catalogue_state(self, scope: TenantScope) -> tuple[bool, str | None]:
        """Whether to offer the publications feed, and when the catalogue last changed.

        One query for the two things every catalogue response needs. The feed is offered
        once organization is on *or* publications already exist, so turning the setting
        off does not hide groups the reader can still browse. The timestamp is what makes
        that switch visible: the root's Newsletters entry changes target before any issue
        has been classified, and a reader caching on `updated` would otherwise keep
        following the old link.
        """
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT
                    COALESCE((SELECT enabled FROM newsletter_preferences WHERE tenant_id = ?), 0) AS enabled,
                    EXISTS (SELECT 1 FROM publications WHERE tenant_id = ? AND merged_into_id IS NULL) AS present,
                    (SELECT catalogue_updated_at FROM newsletter_preferences WHERE tenant_id = ?) AS updated_at
                """,
                (scope.tenant_id, scope.tenant_id, scope.tenant_id),
            ).fetchone()
        return bool(row["enabled"] or row["present"]), row["updated_at"]

    def create_and_assign_for_owner(
        self, scope: TenantScope, item_id: str, *, publication_id: str, name: str, now: str
    ) -> Publication | None:
        """Create the publication the owner named and put this issue in it, or do neither.

        One transaction, so a name that cannot be assigned -- because the item is not this
        tenant's newsletter -- does not leave an empty publication behind for them to
        wonder about. Replay is handled by the caller through manual_assignment_matching,
        which is scoped to this item and is not name-based merging.
        """
        with self._write_lock, self._session() as connection:
            # The creating INSERT is the first statement and carries every condition,
            # including the replay check. Detecting a replay in a separate transaction let
            # two identical submissions both pass it and then both create a publication,
            # leaving one of them assigned and the other stranded.
            created = connection.execute(
                """
                INSERT INTO publications (
                    tenant_id, id, name, original_name, identification_note,
                    merged_into_id, created_at, updated_at
                )
                SELECT i.tenant_id, ?, ?, ?, '', NULL, ?, ?
                  FROM items i
                 WHERE i.tenant_id = ? AND i.id = ? AND i.kind = 'article' AND i.source = 'newsletter'
                   AND NOT EXISTS (
                         SELECT 1
                           FROM newsletter_organization o
                           JOIN publications pub
                             ON pub.tenant_id = o.tenant_id AND pub.id = o.publication_id
                          WHERE o.tenant_id = i.tenant_id AND o.item_id = i.id AND o.manual = 1
                            AND pub.merged_into_id IS NULL AND pub.name = ? COLLATE NOCASE)
                """,
                (publication_id, name, name, now, now, scope.tenant_id, item_id, name),
            )
            if created.rowcount != 1:
                # Either the item is not this tenant's newsletter, or this exact form has
                # already been applied to it. Told apart inside the same transaction.
                existing = connection.execute(
                    """
                    SELECT pub.* FROM newsletter_organization o
                      JOIN publications pub ON pub.tenant_id = o.tenant_id AND pub.id = o.publication_id
                     WHERE o.tenant_id = ? AND o.item_id = ? AND o.manual = 1
                       AND pub.merged_into_id IS NULL AND pub.name = ? COLLATE NOCASE
                    """,
                    (scope.tenant_id, item_id, name),
                ).fetchone()
                return self._publication(existing)
            self._ensure_preferences(connection, scope.tenant_id)
            previous = connection.execute(
                "SELECT publication_id FROM newsletter_organization WHERE tenant_id = ? AND item_id = ?",
                (scope.tenant_id, item_id),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO newsletter_organization (
                    tenant_id, item_id, publication_id, state, manual, attempts,
                    lease_token, not_before, error_code
                ) VALUES (?, ?, ?, 'done', 1, 0, NULL, NULL, NULL)
                ON CONFLICT (tenant_id, item_id) DO UPDATE SET
                    publication_id = excluded.publication_id,
                    state = 'done', manual = 1, lease_token = NULL, not_before = NULL, error_code = NULL
                """,
                (scope.tenant_id, item_id, publication_id),
            )
            # The publication this issue came from changed too, and its feed says so.
            if previous is not None and previous["publication_id"]:
                connection.execute(
                    "UPDATE publications SET updated_at = ? WHERE tenant_id = ? AND id = ?",
                    (now, scope.tenant_id, previous["publication_id"]),
                )
            self._touch_catalogue(connection, scope.tenant_id, now)
            row = connection.execute(
                "SELECT * FROM publications WHERE tenant_id = ? AND id = ?", (scope.tenant_id, publication_id)
            ).fetchone()
        return self._publication(row)
