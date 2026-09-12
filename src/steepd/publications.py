"""Reading a stored newsletter and deciding which publication it belongs to.

Two things live here: preparing the model's input from the EPUB Steepd already wrote, and
the worker that leases one item, asks once, and records the answer. Everything durable is
in steepd.db; the classification contract is in steepd.publication_ai. This module holds
no SQL and no HTTP of its own.

The scheduling model is worth stating once more because it is the reason there is so
little machinery here: the ABSENCE of a newsletter_organization row is the waiting state.
Nothing is enqueued when mail arrives, nothing is scheduled when the setting goes on, and
a restart recovers by doing exactly what it always does -- look for work.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, Tag

from steepd.config import CONSENT_VERSION, Settings
from steepd.db import Database
from steepd.models import Item, OrganizationGuard
from steepd.plans import retention_for
from steepd.publication_ai import (
    MAX_RETRY_AFTER_SECONDS,
    Classification,
    ClassifierError,
    Deadline,
    IssueInput,
    OpenRouterClassifier,
    PublicationChoice,
    log_attempt,
)
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

LOGGER = logging.getLogger("steepd.publications")

# Every classified item is a newsletter article this service generated through
# epubgen.build_epub, so its readable document is at one known path. This is not a
# general EPUB reader and must not become one: uploaded books are never classified, and
# the archive was already validated by inspect_epub when it was stored.
DOCUMENT_MEMBER = "EPUB/index.xhtml"

MAX_ISSUE_TEXT_BYTES = 256 * 1024
MAX_CHOICES = 200
LEASE_SECONDS = 120
# Comfortably inside the lease, so a normally returning attempt still owns its claim and
# a slow provider costs one clean failure rather than a discarded-but-billed request
# followed by a second one.
TIME_BUDGET_SECONDS = 60.0
MAX_ATTEMPTS_PER_CYCLE = 2
RETRY_DELAY_SECONDS = 30
WORKER_INTERVAL_SECONDS = 5.0
IDLE_INTERVAL_SECONDS = 60.0

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)
_SECRET = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|Bearer\s+[A-Za-z0-9._-]{16,}|[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b"
)
_BLOCK_TAGS = ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "section")


class NewsletterDocumentError(Exception):
    """The stored document could not be read. Recoverable: the issue stays readable."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TooManyPublications(NewsletterDocumentError):
    """More publications than one request can carry the complete list of."""

    def __init__(self) -> None:
        super().__init__("too_many_publications")


def read_stored_document(path: Path, *, max_bytes: int) -> str:
    """Return the readable XHTML of a stored newsletter.

    Deliberately narrow. The file was produced by this service and validated by
    inspect_epub before it was written, so there is no reason to re-run the archive
    safety scan, walk a spine, decompress images or check CRCs to answer "what does this
    issue say". One known member is read, with a ceiling, and never extracted to disk.
    """
    try:
        with zipfile.ZipFile(path, "r") as archive:
            member = _document_member(archive)
            if member is None:
                raise NewsletterDocumentError("document_missing")
            if member.file_size > max_bytes:
                raise NewsletterDocumentError("document_too_large")
            with archive.open(member, "r") as handle:
                # The declared size is an early check, not the only one: a lying header
                # must not be able to talk us into an unbounded read.
                payload = handle.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise NewsletterDocumentError("document_too_large")
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
        raise NewsletterDocumentError("document_unreadable") from exc
    return payload.decode("utf-8", "replace")


def _document_member(archive: zipfile.ZipFile) -> zipfile.ZipInfo | None:
    """The generated content document, by its known name.

    Matched on the trailing path component as well as the exact name so that an EbookLib
    upgrade which renames the container directory does not silently stop the feature;
    anything less recognisable is a failed item, not a reason to guess.
    """
    for info in archive.infolist():
        if info.filename == DOCUMENT_MEMBER:
            return info
    for info in archive.infolist():
        if info.filename.endswith("/index.xhtml") and not info.is_dir():
            return info
    return None


def visible_text(document: str) -> str:
    """Readable text with paragraph boundaries kept and invisible content dropped.

    Mastheads, bylines and footers matter here -- they are usually where a publication
    names itself -- so nothing is trimmed for being near the end. Preheaders and other
    hidden blocks are dropped because a reader never sees them either.
    """
    soup = BeautifulSoup(document, "html.parser")
    for tag in soup(["script", "style", "head", "nav"]):
        tag.decompose()
    for tag in soup.find_all(True):
        if isinstance(tag, Tag) and _is_hidden(tag):
            tag.decompose()
    for tag in soup.find_all(_BLOCK_TAGS):
        tag.insert_before("\n")
        tag.insert_after("\n")
    text = soup.get_text(" ")
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _is_hidden(tag: Tag) -> bool:
    if tag.has_attr("hidden") or str(tag.get("aria-hidden", "")).casefold() == "true":
        return True
    style = re.sub(r"\s+", "", str(tag.get("style", "")).casefold())
    return any(
        marker in style
        for marker in ("display:none", "visibility:hidden", "max-height:0", "opacity:0", "mso-hide:all")
    )


def host_of(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.casefold().removeprefix("www.")


def redact(text: str) -> str:
    """Remove what the model has no business seeing, and keep the article.

    Addresses go entirely. A URL is reduced to its host, which is the only part that says
    anything about who published the issue -- the path, query and fragment are where the
    per-reader tracking identifiers live. This is data minimisation and nothing more: the
    body of a newsletter is not anonymous and this code does not pretend otherwise.
    """
    text = _SECRET.sub("[redacted]", text)
    text = _URL.sub(lambda match: host_of(match.group(0)) or "[link]", text)
    return _EMAIL.sub("[address]", text)


def bound_text(text: str, *, max_bytes: int) -> tuple[str, bool]:
    """Fit the issue inside its byte ceiling, reporting whether anything was dropped.

    When it does not fit, the opening and the ending are kept and the middle is dropped,
    because that is where a publication names itself. The omission is reported to the
    caller so the request can say so plainly rather than passing a shortened issue off as
    the whole thing. The stored EPUB the reader opens is never shortened.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    half = max_bytes // 2
    head = encoded[:half].decode("utf-8", "ignore")
    tail = encoded[-half:].decode("utf-8", "ignore")
    return f"{head}\n[...]\n{tail}", True


def prepare_issue(item: Item, document: str, *, max_bytes: int = MAX_ISSUE_TEXT_BYTES) -> IssueInput:
    body = visible_text(document)
    text, abridged = bound_text(redact(body), max_bytes=max_bytes)
    return IssueInput(
        title=redact(item.title),
        byline=redact(item.author),
        language=item.language,
        text=text,
        source_host=host_of(item.source_url),
        abridged=abridged,
    )


def build_choices(
    database: Database, scope: TenantScope
) -> tuple[list[PublicationChoice], dict[str, str]]:
    """The publication list the model may choose from, with request-local ids.

    Real publication ids never leave the process. An answer is mapped back through the
    returned table, so an invented id -- or one belonging to another tenant -- resolves to
    nothing and the answer is refused. Merged records contribute their names and notes to
    the survivor rather than appearing as choices of their own.
    """
    # limit + 1 so a full page is distinguishable from an overflowing one.
    publications = database.canonical_publications(scope, limit=MAX_CHOICES + 1)
    if len(publications) > MAX_CHOICES:
        # Quietly dropping the tail would let the model create a second record for a
        # publication it simply was not shown, over and over. Reporting it leaves the
        # issue readable and assignable by hand instead.
        raise TooManyPublications()
    aliases = database.publication_aliases(scope)
    examples = database.correction_examples(scope)
    choices: list[PublicationChoice] = []
    mapping: dict[str, str] = {}
    for index, publication in enumerate(publications, start=1):
        request_id = f"p{index}"
        mapping[request_id] = publication.id
        merged = aliases.get(publication.id, ())
        notes = [publication.identification_note] + [alias.identification_note for alias in merged]
        choices.append(
            PublicationChoice(
                request_id=request_id,
                # Redacted on the same rules as the issue itself. These are names and
                # notes a person typed and titles and bylines that came out of email, so
                # any of them can carry an address or a tracking URL.
                name=redact(publication.name),
                original_name=redact(publication.original_name),
                note=redact(" ".join(note for note in notes if note))[:500],
                other_names=tuple(
                    dict.fromkeys(
                        redact(name)
                        for alias in merged
                        for name in (alias.name, alias.original_name)
                        if name and name != publication.name
                    )
                ),
                examples=tuple(
                    (redact(title), redact(byline), host_of(source_url))
                    for title, byline, source_url in examples.get(publication.id, ())
                ),
            )
        )
    return choices, mapping


@dataclass(slots=True)
class WorkerStatus:
    """What the account page says about the service, in fixed words.

    `paused_code` is one of the classifier's sanitized codes, never provider text: the
    page explains whether the daily allowance or the service is responsible, and nothing
    a provider wrote reaches a reader's screen.
    """

    paused_code: str | None = None
    paused_at: str | None = None

    @property
    def paused(self) -> bool:
        return self.paused_code is not None


def retention_cutoff(plan: str, settings: Settings, now: datetime) -> str | None:
    """The oldest creation time still retained for this plan, or None for no expiry.

    Asked of steepd.plans rather than restated in SQL, so there is exactly one answer to
    "how long is an item kept" and a paid account's absent expiry is not mistaken for a
    finite default. The plan travels into the commit guard alongside it, so a downgrade
    during a request cannot apply a decision made under the old allowance.
    """
    retention = retention_for(plan, settings=settings)
    return None if retention is None else (now - retention).isoformat()


class Organizer:
    """One pass of work at a time, synchronously, so tests can drive it directly."""

    def __init__(
        self,
        database: Database,
        storage: ItemStorage,
        settings: Settings,
        classifier: OpenRouterClassifier | None,
        clock: Callable[[], datetime] | None = None,
        budget_seconds: float = TIME_BUDGET_SECONDS,
    ) -> None:
        self.database = database
        self.storage = storage
        self.settings = settings
        self.classifier = classifier
        # The only source of time here, read fresh at every step rather than remembered
        # from the claim: the lease check is `not_before > now`, and comparing it against
        # the moment the lease was taken can never fail. Injectable so a test can move it
        # across a request and watch an expired lease refuse its result. None is the real
        # clock, which is what production supplies.
        self.clock = clock
        self._budget_seconds = budget_seconds
        self.status = WorkerStatus()

    def _moment(self) -> datetime:
        return self.clock() if self.clock is not None else datetime.now(UTC)

    def run_once(self) -> bool:
        """Claim and process exactly one item. True if something was attempted.

        Tenants are taken least-recently-served first, and within one tenant due retries
        and expired claims come before untouched issues, which are newest first. The
        effect is that a requested Retry is responsive, a new delivery outranks a
        backlog, and no account's backlog can starve another account.
        """
        if self.classifier is None or self.status.paused:
            return False
        moment = self._moment()
        stamp = moment.isoformat()
        day = moment.date().isoformat()
        candidates = self.database.organization_candidates(
            now=stamp,
            now_day=day,
            daily_limit=self.settings.newsletter_ai_daily_limit,
            required_consent_version=CONSENT_VERSION,
            retention_cutoffs={
                plan: retention_cutoff(plan, self.settings, moment)
                for plan in self.settings.newsletter_ai_plans
            },
        )
        for candidate in candidates:
            scope = TenantScope(candidate.tenant_id)
            cutoff = retention_cutoff(candidate.plan, self.settings, moment)
            self.database.finalize_exhausted_claims(
                scope, now=stamp, max_attempts=MAX_ATTEMPTS_PER_CYCLE
            )
            claimed = self.database.claim_organization_item(
                scope,
                now=stamp,
                lease_token=secrets.token_hex(16),
                lease_until=(moment + timedelta(seconds=LEASE_SECONDS)).isoformat(),
                retention_cutoff=cutoff,
                max_attempts=MAX_ATTEMPTS_PER_CYCLE,
            )
            if claimed is None:
                continue
            guard = OrganizationGuard(
                lease_token=claimed.lease_token,
                settings_revision=candidate.settings_revision,
                catalogue_revision=candidate.catalogue_revision,
                plan=candidate.plan,
                retention_cutoff=cutoff,
                now=stamp,
            )
            self._process(scope, claimed.item_id, guard, attempts=claimed.attempts)
            return True
        return False

    def _now(self) -> str:
        return self._moment().isoformat()

    def _at(self, guard: OrganizationGuard, now: str) -> OrganizationGuard:
        """The same guard, re-evaluated against the current clock.

        The lease check is `not_before > now`, so reusing the claim-time stamp made it
        vacuous: a result that arrived long after its lease expired still committed,
        because it was being compared against the moment the lease was taken out.

        The retention cutoff moves with it, or an issue that expired while the request was
        out would be filed into a publication the sweep is about to empty.
        """
        moment = datetime.fromisoformat(now)
        return replace(guard, now=now, retention_cutoff=retention_cutoff(guard.plan, self.settings, moment))

    def _process(self, scope: TenantScope, item_id: str, guard: OrganizationGuard, *, attempts: int) -> None:
        deadline = Deadline(self._budget_seconds)
        try:
            issue, choices, mapping = self._prepare(scope, item_id, deadline)
        except (NewsletterDocumentError, ClassifierError) as exc:
            # Nothing was sent, so nothing was billed and no inference attempt is spent
            # -- attempts are only consumed alongside the dispatch allowance below. This
            # is terminal for the cycle and stays correctable, and explicitly retryable,
            # by hand. Recorded under the lease still held: releasing it first would move
            # the row out of 'running' and the guarded write would then match nothing.
            self.database.record_organization_outcome(
                scope,
                item_id,
                guard=self._at(guard, self._now()),
                state="failed",
                error_code=getattr(exc, "code", "preparation_failed"),
            )
            return

        if deadline.remaining <= 0:
            # Preparation itself ran long. Checked here rather than inside classify, or
            # the allowance and an inference attempt would both be spent on a request that
            # was never going to be sent.
            self.database.record_organization_outcome(
                scope, item_id, guard=self._at(guard, self._now()), state="failed",
                error_code="time_budget_exhausted",
            )
            return

        dispatched_at = self._now()
        spent = self.database.consume_dispatch_allowance(
            scope,
            item_id,
            lease_token=guard.lease_token,
            # The day this is actually sent. Using the day the pass began charged a
            # request made just after midnight to the allowance that had already closed.
            day=dispatched_at[:10],
            now=dispatched_at,
            daily_limit=self.settings.newsletter_ai_daily_limit,
            settings_revision=guard.settings_revision,
            required_consent_version=CONSENT_VERSION,
        )
        if spent is None:
            # Turned off, consent superseded, or the allowance ran out between the claim
            # and the send. The item goes back to waiting with its attempts intact.
            self.database.release_organization_claim(
                scope, item_id, lease_token=guard.lease_token, now=self._now()
            )
            return

        try:
            result = self.classifier.classify(issue, choices, deadline=deadline)
        except ClassifierError as exc:
            self._record_failure(scope, item_id, guard, exc, attempts=attempts + 1)
            return
        log_attempt(result.usage, outcome=result.classification.decision, tenant_hint=scope.tenant_id[:8])
        self._commit(scope, item_id, guard, result.classification, mapping)

    def _prepare(
        self, scope: TenantScope, item_id: str, deadline: Deadline
    ) -> tuple[IssueInput, list[PublicationChoice], dict[str, str]]:
        deadline.check()
        item = self.database.get_item(scope, item_id)
        if item is None:
            raise NewsletterDocumentError("item_missing")
        document = read_stored_document(
            self.storage.path_for(item), max_bytes=self.settings.newsletter_max_body_bytes
        )
        deadline.check()
        issue = prepare_issue(item, document)
        choices, mapping = build_choices(self.database, scope)
        return issue, choices, mapping

    def _record_failure(
        self, scope: TenantScope, item_id: str, guard: OrganizationGuard, error: ClassifierError, *, attempts: int
    ) -> None:
        now = self._now()
        current = self._at(guard, now)
        if error.paused:
            # An operator problem, not this item's problem: stop dispatching entirely and
            # let the account page say so, rather than spending the rest of the allowance
            # rediscovering it one queued item at a time. The item's attempt and the daily
            # count both stand, because the request really went.
            self.status = WorkerStatus(paused_code=error.code, paused_at=now)
            LOGGER.warning("Publication worker paused: %s", error.code)
            # The attempt stands. It was a real dispatch and may have been billed, and the
            # plan is explicit that every one of those counts; an item that has now spent
            # its allowance is finished by finalize_exhausted_claims on a later pass.
            self.database.release_organization_claim(
                scope, item_id, lease_token=guard.lease_token, now=now
            )
            return
        if error.retry_after is not None and error.retry_after > MAX_RETRY_AFTER_SECONDS:
            # Asked to wait longer than we are willing to hold a claim for. Honouring the
            # header matters more than retrying, so the attempt is given up and stays
            # available for an explicit Retry -- rather than being scheduled early, which
            # is what shortening the delay to something we like would amount to.
            self.database.record_organization_outcome(
                scope, item_id, guard=current, state="failed", error_code=error.code
            )
            return
        if error.retryable and attempts < MAX_ATTEMPTS_PER_CYCLE:
            # Measured from now, not from when the claim was taken out: a request that
            # failed slowly would otherwise come due the instant it was recorded. A
            # provider that named its own delay gets it.
            delay = error.retry_after
            if delay is None:
                # Jitter, so a provider recovering from a blip is not met by every worker
                # at the same instant.
                delay = RETRY_DELAY_SECONDS + secrets.randbelow(RETRY_DELAY_SECONDS)
            retry_at = (datetime.fromisoformat(now) + timedelta(seconds=delay)).isoformat()
            self.database.record_organization_outcome(
                scope, item_id, guard=current, state="retry", error_code=error.code, retry_at=retry_at
            )
            return
        self.database.record_organization_outcome(
            scope, item_id, guard=current, state="failed", error_code=error.code
        )

    def _commit(
        self,
        scope: TenantScope,
        item_id: str,
        guard: OrganizationGuard,
        answer: Classification,
        mapping: dict[str, str],
    ) -> None:
        # Re-stamped with the current clock: the lease condition is `not_before > now`,
        # and comparing it against the moment the claim was taken would let a result that
        # arrived long after its lease expired commit anyway.
        guard = self._at(guard, self._now())
        if answer.decision == "unknown":
            # A successful "cannot identify", not a failure: the issue stays readable and
            # is offered for manual assignment, with no automatic retry.
            self.database.record_organization_outcome(scope, item_id, guard=guard, state="unrecognized")
            return
        if answer.decision == "existing":
            publication_id = mapping.get(answer.request_id or "")
            if publication_id is None:
                self.database.record_organization_outcome(
                    scope, item_id, guard=guard, state="failed", error_code="unknown_publication_id"
                )
                return
            self.database.assign_organization_publication(
                scope, item_id, guard=guard, publication_id=publication_id
            )
            return
        self.database.create_and_assign_publication(
            scope,
            item_id,
            guard=guard,
            publication_id=secrets.token_hex(8),
            name=answer.name or "",
        )


def build_classifier(settings: Settings) -> OpenRouterClassifier | None:
    """The client, or None when this deployment is not configured for inference.

    Missing configuration disables organization and nothing else: reading, browsing and
    manual corrections carry on exactly as before.
    """
    if not (settings.newsletter_ai_enabled and settings.newsletter_ai_key and settings.newsletter_ai_model):
        return None
    return OpenRouterClassifier(
        api_key=settings.newsletter_ai_key,
        model=settings.newsletter_ai_model,
        providers=settings.newsletter_ai_providers,
        max_input_price=settings.newsletter_ai_max_input_price,
        max_output_price=settings.newsletter_ai_max_output_price,
        reasoning=settings.newsletter_ai_reasoning,
    )


def start_organizer_thread(organizer: Organizer, *, stop: threading.Event | None = None) -> threading.Thread:
    """Run the organizer forever on a daemon thread, following the retention sweep.

    A thread rather than an async lifespan task because that is how this service already
    does background work, and because every call underneath is synchronous: making this
    async would mean wrapping all of the SQL and file reads to gain nothing. Daemon, so a
    shutdown is never held up; the stop event lets a test or a clean exit end the loop
    between jobs. A process killed mid-request leaves a lease, which the next pass
    recovers -- that is what leases are for.
    """
    event = stop or threading.Event()

    def loop() -> None:
        while not event.is_set():
            worked = False
            try:
                worked = organizer.run_once()
            except Exception:
                # A worker that dies on one bad pass is worse than useless: nothing else
                # reports that newsletters stopped being organized.
                LOGGER.exception("Publication organizer pass failed")
            event.wait(WORKER_INTERVAL_SECONDS if worked else IDLE_INTERVAL_SECONDS)

    thread = threading.Thread(target=loop, name="steepd-organizer", daemon=True)
    thread.start()
    return thread
