from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

ItemKind = Literal["book", "article"]


@dataclass(frozen=True, slots=True)
class Tenant:
    id: str
    email: str
    inbox_local: str
    opds_username: str
    opds_password_hash: str
    plan: str
    created_at: str
    # NULL until the owner chose their address on first sign-in. While NULL the
    # inbox_local is a placeholder nothing routes to. See steepd.inboxnames.
    inbox_confirmed_at: str | None = None
    # "anyone" or "listed". Anything else reads as "anyone".
    sender_policy: str = "anyone"
    # Whether the reader catalogue opens an item menu with Star and Delete instead of
    # offering each item as a direct download. Off until the owner turns it on.
    reader_actions: bool = False


@dataclass(frozen=True, slots=True)
class RefusedSender:
    address: str
    count: int
    last_seen_at: str


@dataclass(frozen=True, slots=True)
class Item:
    id: str
    tenant_id: str
    kind: ItemKind
    sha256: str
    storage_name: str
    download_filename: str
    title: str
    author: str
    language: str
    identifier: str
    source_url: str
    size_bytes: int
    created_at: str
    expires_at: str | None
    source: str
    starred_at: str | None = None
    # Advanced by every star, unstar, trash and restore. A reader action carries the
    # revision its menu showed, so a request replayed later cannot undo a newer change.
    revision: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TrashedItem:
    """An item in the trash, and when it was put there."""

    item: Item
    deleted_at: str


@dataclass(frozen=True, slots=True)
class AuthorSummary:
    name: str
    item_count: int
    updated_at: str


@dataclass(frozen=True, slots=True)
class SiteSummary:
    """A site saved pages came from, and how many of them are retained now."""

    host: str
    page_count: int
    updated_at: str


@dataclass(frozen=True, slots=True)
class NewsletterPreferences:
    """One tenant's automatic-organization settings and worker coordination state.

    An absent row means disabled, so callers read this through an Optional and treat
    None and `enabled=False` the same way.
    """

    tenant_id: str
    enabled: bool
    consent_version: int
    consented_at: str | None
    # Captured before a classification request and re-checked when it commits: an answer
    # produced under consent the owner has since withdrawn must not be applied.
    settings_revision: int
    # Captured the same way, but for the publication choices the model was shown. It is
    # what stops two overlapping first issues both creating the same new publication.
    catalogue_revision: int
    catalogue_updated_at: str | None
    last_served_at: str | None
    attempt_day: str | None
    attempts_today: int


@dataclass(frozen=True, slots=True)
class Publication:
    tenant_id: str
    id: str
    name: str
    # The name this record was created with. Kept after a rename so a renamed publication
    # keeps being recognised by what its issues actually say.
    original_name: str
    identification_note: str
    # Non-null once combined into another record. Merged rows are never deleted: they
    # remain as identification clues and keep their old OPDS URLs working.
    merged_into_id: str | None
    created_at: str
    updated_at: str

    @property
    def is_canonical(self) -> bool:
        return self.merged_into_id is None


@dataclass(frozen=True, slots=True)
class PublicationSummary:
    """A publication and how many retained issues it currently holds.

    The count comes from the same filter the issue list uses, so a shelf never advertises
    a number it then fails to deliver. Counts describe what is retained now, not a
    permanent history: when the last issue expires the publication drops out of browsing
    and returns, with the same id, when another issue arrives.
    """

    publication: Publication
    issue_count: int


@dataclass(frozen=True, slots=True)
class ClaimedOrganization:
    """One item leased to the worker for a single classification cycle."""

    tenant_id: str
    item_id: str
    lease_token: str
    attempts: int


@dataclass(frozen=True, slots=True)
class OrganizationProgress:
    """What the account page reports, derived from retained items and their rows."""

    waiting: int
    running: int
    organized: int
    unrecognized: int
    failed: int

    @property
    def total(self) -> int:
        return self.waiting + self.running + self.organized + self.unrecognized + self.failed

    @property
    def outstanding(self) -> int:
        return self.waiting + self.running


@dataclass(frozen=True, slots=True)
class UnorganizedIssue:
    """A retained newsletter the owner may correct or explicitly retry.

    `result_token` is the lease token of the result being retried. It identifies which
    result a Retry form refers to; it is not a credential and not a way to commit work
    over HTTP. Every claim replaces it, so a stale form cannot restart a newer cycle.
    """

    item_id: str
    title: str
    state: str
    result_token: str | None


@dataclass(frozen=True, slots=True)
class OrganizationCandidate:
    """A tenant with organization enabled, in fair-scheduling order.

    Carries the plan so the caller can ask steepd.plans for its retention cutoff rather
    than encoding a second copy of that policy in SQL.
    """

    tenant_id: str
    plan: str
    settings_revision: int
    catalogue_revision: int


@dataclass(frozen=True, slots=True)
class OrganizationGuard:
    """Everything a worker captured before spending, re-checked when it commits.

    Passed whole so the commit's WHERE clause can be the entire check-and-set. If any of
    these has moved on -- consent withdrawn, publications renamed or merged, the lease
    taken over, the plan changed under the retention calculation, the item expired -- the
    conditional write matches no row and the answer is discarded rather than applied.
    """

    lease_token: str
    settings_revision: int
    catalogue_revision: int
    # The plan the retention cutoff was computed from, re-checked so a downgrade during
    # the request cannot apply a decision made under the old allowance.
    plan: str
    # ISO-8601 UTC, or None for a plan with no time-based expiry.
    retention_cutoff: str | None
    now: str
