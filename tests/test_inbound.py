from __future__ import annotations

import base64
import io
import json
import logging
import sqlite3
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from urllib.parse import unquote

import httpx
import pytest
from svix.webhooks import Webhook

from steepd.config import Settings
from steepd.db import Database
from steepd.imagefetch import FetchedImage, ImageFetchError
from steepd.inbound import (
    REJECTION_REPLY_WINDOW,
    RESEND_ATTACHMENT_HOST,
    RESEND_ATTACHMENT_HOSTS,
    InboundEmailDisabled,
    InboundEmailService,
    InvalidWebhookEvent,
    InvalidWebhookSignature,
    ProviderRequestError,
    ResendInboundProvider,
    resolve_inbox_local,
)
from steepd.outbound import MAX_SUBJECT_LENGTH
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

WEBHOOK_SECRET = "whsec_" + base64.b64encode(b"steepd-tenant-test-webhook-secre").decode()
API_KEY = "re_test_api_key"
INBOX_DOMAIN = "read.steepd.app"

# convert_newsletter rejects a body with under 80 visible characters and no images
# (newsletter.py:604). That gate is product behaviour, so the fixtures use prose long
# enough to clear it rather than a toy body that would exercise the rejection path.
ARTICLE_BODY = (
    "<p>The Monday note covers three things this week: what shipped, what broke, and "
    "what we learned from the outage on Thursday afternoon.</p>"
)


def make_epub(
    *,
    title: str = "The Test Book",
    author: str = "Ada Reader",
    language: str = "en",
    identifier: str = "urn:test:book-1",
) -> bytes:
    container = """<?xml version="1.0"?>
<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container" version="1.0">
  <rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles>
</container>"""
    package = f"""<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="book-id">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:identifier id="book-id">{identifier}</dc:identifier>
    <dc:title>{title}</dc:title>
    <dc:creator>{author}</dc:creator>
    <dc:language>{language}</dc:language>
  </metadata>
  <manifest><item id="chapter" href="chapter.xhtml" media-type="application/xhtml+xml"/></manifest>
  <spine><itemref idref="chapter"/></spine>
</package>"""
    chapter = b"<html xmlns='http://www.w3.org/1999/xhtml'><body><p>Hello, reader.</p></body></html>"

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        mimetype_info = zipfile.ZipInfo("mimetype")
        mimetype_info.compress_type = zipfile.ZIP_STORED
        archive.writestr(mimetype_info, "application/epub+zip")
        archive.writestr("META-INF/container.xml", container, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("OEBPS/content.opf", package, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("OEBPS/chapter.xhtml", chapter, compress_type=zipfile.ZIP_DEFLATED)
    return output.getvalue()


def configured(settings: Settings) -> Settings:
    """Settings with Resend inbound enabled and an inbox domain to route against."""
    return replace(
        settings,
        resend_api_key=API_KEY,
        resend_webhook_secret=WEBHOOK_SECRET,
        inbox_domain=INBOX_DOMAIN,
    )


def event_body(
    *,
    sender: str = "reader@example.com",
    recipients: Sequence[str],
    email_id: str = "email-1",
    event_type: str = "email.received",
    subject: str = "Private subject must not be logged",
) -> bytes:
    return json.dumps(
        {
            "type": event_type,
            "created_at": "2026-08-28T12:00:00Z",
            "data": {
                "email_id": email_id,
                "from": sender,
                "to": list(recipients),
                "subject": subject,
                "attachments": [],
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def signed_headers(body: bytes, *, message_id: str = "msg_test_1") -> dict[str, str]:
    timestamp = datetime.now(UTC).replace(microsecond=0)
    signature = Webhook(WEBHOOK_SECRET).sign(message_id, timestamp, body.decode())
    return {
        "svix-id": message_id,
        "svix-timestamp": str(int(timestamp.timestamp())),
        "svix-signature": signature,
        "content-type": "application/json",
    }


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str
    content: bytes
    content_type: str = "application/epub+zip"
    host: str = RESEND_ATTACHMENT_HOST
    content_disposition: str = "attachment"
    content_id: str | None = None


def epub_attachment(filename: str, *, title: str | None = None, content: bytes | None = None) -> Attachment:
    stem = filename[:-5] if filename.casefold().endswith(".epub") else filename
    payload = content if content is not None else make_epub(title=title or stem, identifier=f"urn:test:{stem}")
    return Attachment(filename=filename, content=payload)


def attachment_metadata(attachment_id: str, spec: Attachment, *, email_id: str) -> dict[str, object]:
    return {
        "id": attachment_id,
        "filename": spec.filename,
        "size": len(spec.content),
        "content_type": spec.content_type,
        "content_disposition": spec.content_disposition,
        "content_id": spec.content_id,
        "download_url": f"https://{spec.host}/{email_id}/{attachment_id}?signature=test",
        "expires_at": "2026-08-28T13:00:00Z",
    }


class FakeInboundProvider(ResendInboundProvider):
    """The real ResendInboundProvider over a mock transport.

    Only the network is faked. svix signature verification, the Resend response validation
    and the attachment download-URL host checks all run for real, because those are the
    security boundary of this webhook and a double that skipped them would hide regressions.
    """

    def __init__(self, *, max_download_bytes: int = 8 * 1024 * 1024) -> None:
        super().__init__(
            api_key=API_KEY,
            webhook_secret=WEBHOOK_SECRET,
            max_download_bytes=max_download_bytes,
            transport=httpx.MockTransport(self._respond),
        )
        self.emails: dict[str, dict[str, object]] = {}
        self.attachments: dict[str, list[dict[str, object]]] = {}
        self.downloads: dict[str, bytes] = {}
        self.requests: list[httpx.Request] = []
        self.list_status = 200
        # The decoded body of every POST /emails, which is how a forward actually leaves:
        # Resend has no server-side forward route, so forward_email composes an ordinary
        # send from the received message.
        self.forwards: list[dict[str, object]] = []
        self.forward_status = 200
        self._pending: tuple[bytes, str] | None = None
        self._sequence = 0

    def queue_email(
        self,
        *,
        to: str | Sequence[str],
        subject: str = "Private subject must not be logged",
        html: str = "",
        text: str = "",
        sender: str = "reader@example.com",
        attachments: Sequence[str | Attachment] = (),
        message_id: str = "",
        email_id: str = "",
        event_type: str = "email.received",
        svix_id: str = "",
    ) -> None:
        self._sequence += 1
        email_id = email_id or f"email-{self._sequence}"
        recipients = [to] if isinstance(to, str) else list(to)

        metadata: list[dict[str, object]] = []
        for index, entry in enumerate(attachments, start=1):
            spec = epub_attachment(entry) if isinstance(entry, str) else entry
            attachment_id = f"{email_id}-att-{index}"
            self.downloads[attachment_id] = spec.content
            metadata.append(attachment_metadata(attachment_id, spec, email_id=email_id))
        self.attachments[email_id] = metadata

        self.emails[email_id] = {
            "object": "email",
            "id": email_id,
            "to": recipients,
            "from": sender,
            "created_at": "2026-08-28T12:00:00Z",
            "subject": subject,
            "html": html,
            "text": text,
            "message_id": message_id or f"<original-{self._sequence}@example.com>",
            "attachments": metadata,
        }
        body = event_body(
            sender=sender,
            recipients=recipients,
            email_id=email_id,
            subject=subject,
            event_type=event_type,
        )
        self._pending = (body, svix_id or f"msg_{self._sequence}")

    def signed_event(self) -> tuple[bytes, dict[str, str]]:
        assert self._pending is not None, "queue_email must be called before signed_event"
        body, message_id = self._pending
        return body, signed_headers(body, message_id=message_id)

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "api.resend.com":
            assert request.headers["authorization"] == f"Bearer {API_KEY}"
            if request.method == "POST" and request.url.path == "/emails":
                self.forwards.append(json.loads(request.content))
                if self.forward_status != 200:
                    return httpx.Response(self.forward_status, json={"message": "send error"})
                return httpx.Response(200, json={"id": "forwarded-email-1"})
            path = request.url.path
            wants_attachments = path.endswith("/attachments")
            if wants_attachments:
                path = path[: -len("/attachments")]
            email_id = unquote(path.removeprefix("/emails/receiving/"))
            if wants_attachments:
                if self.list_status != 200:
                    return httpx.Response(self.list_status, json={"message": "provider error"})
                return httpx.Response(
                    200,
                    json={"object": "list", "has_more": False, "data": self.attachments.get(email_id, [])},
                )
            return httpx.Response(200, json=self.emails[email_id])
        assert request.url.host in RESEND_ATTACHMENT_HOSTS
        assert "authorization" not in request.headers
        content = self.downloads[request.url.path.rsplit("/", 1)[-1]]
        return httpx.Response(200, content=content, headers={"Content-Length": str(len(content))})


def _build_env(tmp_path, inboxes: Sequence[str], *, image_fetch=None, **settings_overrides):
    settings = configured(Settings(data_dir=tmp_path, public_base_url="http://localhost:8000"))
    if settings_overrides:
        settings = replace(settings, **settings_overrides)
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    tenants = [
        database.create_tenant(email=f"{local.replace('.', '')}@example.com", inbox_local=local)
        for local in inboxes
    ]
    provider = FakeInboundProvider()
    service = InboundEmailService(settings, database, storage, provider, image_fetch=image_fetch)
    return settings, database, storage, service, tenants, provider


@pytest.fixture
def inbound_env(tmp_path):
    """One tenant with inbox local part 'a.1', wired to a fake provider."""
    _, database, _, service, tenants, provider = _build_env(tmp_path, ["a.1"])
    return database, service, TenantScope(tenants[0].id), provider


@pytest.fixture
def inbound_env_two_tenants(tmp_path):
    """Two tenants, 'a.1' and 'b.2', sharing one service - the isolation case."""
    _, database, _, service, tenants, provider = _build_env(tmp_path, ["a.1", "b.2"])
    return database, service, TenantScope(tenants[0].id), TenantScope(tenants[1].id), provider


def webhook_result(database: Database, event_id: str) -> str:
    with sqlite3.connect(database.path) as connection:
        row = connection.execute(
            "SELECT result FROM webhook_events WHERE provider = ? AND event_id = ?", ("resend", event_id)
        ).fetchone()
    return row[0] if row else ""


def stored_payload(storage: ItemStorage, scope: TenantScope, item_id: str) -> bytes:
    return storage.path_for(storage.database.get_item(scope, item_id)).read_bytes()


def stored_archive(storage: ItemStorage, database: Database, scope: TenantScope) -> dict[str, bytes]:
    """Every member of the tenant's single stored EPUB, by name."""
    item = database.list_items(scope)[0]
    with zipfile.ZipFile(io.BytesIO(stored_payload(storage, scope, item.id))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def chapter_of(members: dict[str, bytes]) -> str:
    return next(content.decode("utf-8") for name, content in members.items() if name.endswith("index.xhtml"))


def png_bytes(size: int = 32) -> bytes:
    """A payload the real fetcher would accept: PNG magic bytes plus filler to `size`."""
    header = b"\x89PNG\r\n\x1a\n"
    return header + b"x" * max(0, size - len(header))


class StubImageFetch:
    """Stands in for imagefetch.fetch_remote_image so no test resolves a host or opens a
    socket. Only the contract inbound.py depends on is reproduced -- a FetchedImage within
    the requested size limit, or ImageFetchError -- because the SSRF guard itself is the
    subject of tests/test_imagefetch.py, not of this file.
    """

    def __init__(
        self,
        content: bytes | None = None,
        *,
        error: Exception | None = None,
        content_type: str = "image/png",
        honor_max_bytes: bool = True,
    ) -> None:
        self.content = png_bytes() if content is None else content
        self.error = error
        self.content_type = content_type
        # False models a fetcher that ignores the limit it was given, which is what the
        # closure's own size check exists to catch.
        self.honor_max_bytes = honor_max_bytes
        self.calls: list[tuple[str, int]] = []

    def __call__(self, url: str, *, max_bytes: int, **_: object) -> FetchedImage:
        self.calls.append((url, max_bytes))
        if self.error is not None:
            raise self.error
        if self.honor_max_bytes and len(self.content) > max_bytes:
            raise ImageFetchError("Image exceeds the configured size limit")
        return FetchedImage(content_type=self.content_type, content=self.content)


# -- the address contract -------------------------------------------------


def test_current_resend_attachment_host_contract() -> None:
    assert RESEND_ATTACHMENT_HOST == "cdn.resend.app"
    assert RESEND_ATTACHMENT_HOSTS == {"cdn.resend.app", "inbound-cdn.resend.com"}


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("ines.a7f3@read.steepd.app", "ines.a7f3"),
        ("Ines.A7F3@Read.Steepd.App", "ines.a7f3"),
        ("ines.a7f3@elsewhere.com", ""),
        ("not-an-address", ""),
        ("", ""),
    ],
)
def test_resolve_inbox_local(address, expected):
    assert resolve_inbox_local(address, inbox_domain="read.steepd.app") == expected


def test_resolve_inbox_local_needs_a_configured_domain() -> None:
    assert resolve_inbox_local("ines.a7f3@read.steepd.app", inbox_domain="") == ""


def test_resolve_inbox_local_accepts_a_display_name_form() -> None:
    assert resolve_inbox_local("Ines <ines.a7f3@read.steepd.app>", inbox_domain=INBOX_DOMAIN) == "ines.a7f3"


# -- routing --------------------------------------------------------------


def test_email_with_epub_attachment_becomes_a_book(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", subject="A book", attachments=["novel.epub"])

    result = service.handle(*provider.signed_event())

    assert result.kind == "book"
    assert database.count_items(scope, kind="book") == 1
    assert database.count_items(scope, kind="article") == 0


def test_email_without_attachment_becomes_an_article(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note",
                         html=ARTICLE_BODY, attachments=[])

    result = service.handle(*provider.signed_event())

    assert result.kind == "article"
    assert database.count_items(scope, kind="article") == 1


def test_email_to_unknown_inbox_is_discarded(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="nobody.zz@read.steepd.app", subject="Hello", html=ARTICLE_BODY)

    result = service.handle(*provider.signed_event())

    assert result.tenant_id == ""
    assert database.count_items(scope) == 0


def test_unknown_inbox_is_recorded_and_never_reaches_the_provider(inbound_env):
    """Discarded, not bounced: an error would tell a prober which addresses exist."""
    database, service, _, provider = inbound_env
    provider.queue_email(to="nobody.zz@read.steepd.app", subject="Hello", html=ARTICLE_BODY, svix_id="msg_probe")

    result = service.handle(*provider.signed_event())

    assert result.status == "ignored"
    assert webhook_result(database, "msg_probe") == "unknown-inbox"
    assert provider.requests == []


def test_email_addressed_outside_the_inbox_domain_is_discarded(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@elsewhere.com", subject="Hello", html=ARTICLE_BODY)

    result = service.handle(*provider.signed_event())

    assert result.tenant_id == ""
    assert database.count_items(scope) == 0


def test_delivery_for_one_tenant_is_invisible_to_another(inbound_env_two_tenants):
    database, service, alice_scope, bob_scope, provider = inbound_env_two_tenants
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Note", html=ARTICLE_BODY)

    service.handle(*provider.signed_event())

    assert database.count_items(alice_scope) == 1
    assert database.count_items(bob_scope) == 0


def test_book_delivery_is_routed_to_the_addressed_tenant(inbound_env_two_tenants):
    database, service, alice_scope, bob_scope, provider = inbound_env_two_tenants
    provider.queue_email(to="b.2@read.steepd.app", subject="A book", attachments=["novel.epub"])

    result = service.handle(*provider.signed_event())

    assert result.tenant_id == bob_scope.tenant_id
    assert database.count_items(bob_scope, kind="book") == 1
    assert database.count_items(alice_scope) == 0


# -- the webhook security boundary ----------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"svix-id": "msg", "svix-timestamp": "1", "svix-signature": "v1,invalid"},
    ],
)
def test_missing_or_invalid_signature_is_rejected(inbound_env, headers):
    _, service, _, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", html=ARTICLE_BODY)
    body, _ = provider.signed_event()

    with pytest.raises(InvalidWebhookSignature):
        service.handle(body, headers)


def test_signature_is_checked_against_exact_raw_body(inbound_env):
    _, service, _, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", html=ARTICLE_BODY)
    body, headers = provider.signed_event()

    with pytest.raises(InvalidWebhookSignature):
        service.handle(body + b" ", headers)


def test_unconfigured_inbound_email_is_disabled(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url="http://localhost:8000")
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    provider = FakeInboundProvider()
    provider.queue_email(to="a.1@read.steepd.app", html=ARTICLE_BODY)
    service = InboundEmailService(settings, database, storage, provider)

    with pytest.raises(InboundEmailDisabled):
        service.handle(*provider.signed_event())


def test_inbound_email_without_an_inbox_domain_is_disabled(tmp_path):
    settings, database, storage, _, _, provider = _build_env(tmp_path, ["a.1"])
    service = InboundEmailService(replace(settings, inbox_domain=""), database, storage, provider)
    provider.queue_email(to="a.1@read.steepd.app", html=ARTICLE_BODY)

    with pytest.raises(InboundEmailDisabled):
        service.handle(*provider.signed_event())


def test_replayed_webhook_event_is_ignored(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", subject="A book", attachments=["novel.epub"])

    first = service.handle(*provider.signed_event())
    replay = service.handle(*provider.signed_event())

    assert first.imported == 1
    assert replay.status == "duplicate_event"
    assert database.count_items(scope) == 1


def test_ignored_event_type_is_recorded_without_a_provider_call(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(
        to="a.1@read.steepd.app", html=ARTICLE_BODY, event_type="email.delivered", svix_id="msg_other"
    )

    result = service.handle(*provider.signed_event())

    assert result.status == "ignored"
    assert webhook_result(database, "msg_other") == "ignored_event_type"
    assert provider.requests == []
    assert database.count_items(scope) == 0


# -- books ----------------------------------------------------------------


def test_multiple_epubs_import_and_an_invalid_one_is_rejected(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Two books",
        attachments=[
            epub_attachment("first.epub", title="First Email Book"),
            # An EPUB by declared content type rather than by extension.
            Attachment(filename="second.bin", content=make_epub(title="Second Email Book", identifier="second")),
            epub_attachment("bad.epub", content=b"not an epub"),
            Attachment(filename="notes.txt", content=b"ignore", content_type="text/plain"),
        ],
    )

    result = service.handle(*provider.signed_event())

    assert result.kind == "book"
    assert result.imported == 2
    assert result.rejected == 1
    titles = {item.title for item in database.list_items(scope)}
    assert titles == {"First Email Book", "Second Email Book"}


def test_duplicate_epub_attachments_are_content_deduplicated(inbound_env):
    database, service, scope, provider = inbound_env
    content = make_epub(title="Same Bytes", identifier="same")
    provider.queue_email(
        to="a.1@read.steepd.app",
        attachments=[
            epub_attachment("one.epub", content=content),
            epub_attachment("two.epub", content=content),
        ],
    )

    result = service.handle(*provider.signed_event())

    assert result.imported == 1
    assert result.duplicates == 1
    assert database.count_items(scope, kind="book") == 1


def test_a_non_epub_attachment_still_routes_to_an_article(inbound_env):
    """The rule is the EPUB, not the presence of any attachment at all."""
    database, service, scope, provider = inbound_env
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=ARTICLE_BODY,
        attachments=[Attachment(filename="note.txt", content=b"hello", content_type="text/plain")],
    )

    result = service.handle(*provider.signed_event())

    assert result.kind == "article"
    assert database.count_items(scope, kind="article") == 1
    assert database.count_items(scope, kind="book") == 0


def test_provider_failure_surfaces_as_a_retryable_error(inbound_env):
    _, service, _, provider = inbound_env
    provider.list_status = 503
    provider.queue_email(to="a.1@read.steepd.app", attachments=["novel.epub"])

    with pytest.raises(ProviderRequestError):
        service.handle(*provider.signed_event())


def test_unsafe_provider_download_url_is_rejected(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(
        to="a.1@read.steepd.app",
        attachments=[
            Attachment(filename="book.epub", content=make_epub(), host="attacker.example"),
        ],
    )

    with pytest.raises(ProviderRequestError):
        service.handle(*provider.signed_event())
    assert database.count_items(scope) == 0


def test_a_failed_delivery_releases_its_claim_so_the_retry_is_processed(inbound_env):
    """The event id is claimed before any work so a provider retry racing a slow delivery
    is not processed twice. The other half of that bargain: a delivery that failed must
    hand the claim back, or the retry that would have succeeded is dismissed as a replay."""
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", subject="A book", attachments=["novel.epub"])
    body, headers = provider.signed_event()
    provider.list_status = 503
    with pytest.raises(ProviderRequestError):
        service.handle(body, headers)
    assert not database.webhook_event_exists("resend", headers["svix-id"])

    provider.list_status = 200
    retried = service.handle(body, headers)

    assert retried.imported == 1
    assert database.count_items(scope) == 1


# -- telling the reader ------------------------------------------------------


def _replying_env(tmp_path, monkeypatch, **overrides):
    sent: list[dict] = []
    monkeypatch.setattr("steepd.inbound.send_email", lambda settings, **message: sent.append(message))
    built = _build_env(tmp_path, ["a.1"], mail_from_address="Steepd <noreply@steepd.example>", **overrides)
    return built, sent


def test_a_rejected_attachment_is_explained_to_the_account_holder(tmp_path, monkeypatch):
    """The webhook result is read by the provider and nobody else. Without a reply, a
    refused forward looks exactly like one still on its way. The reply goes to the
    account's registered address, not the message's From, which is whatever the sender
    wrote."""
    (_, database, _, service, tenants, provider), sent = _replying_env(tmp_path, monkeypatch)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Two books",
        sender="Someone Else <someone@else.example>",
        attachments=["good.epub", epub_attachment("broken.epub", content=b"not an epub at all")],
    )

    result = service.handle(*provider.signed_event())

    assert result.imported == 1 and result.rejected == 1
    assert len(sent) == 1
    reply = sent[0]
    assert reply["to"] == tenants[0].email
    assert reply["subject"] == "Steepd could not file: Two books"
    assert "broken.epub" in reply["text"]
    assert "The other 1 item from the same email is in your library." in reply["text"]
    assert "broken.epub" in reply["html"]


def test_nothing_is_sent_when_everything_was_filed(tmp_path, monkeypatch):
    (_, _, _, service, _, provider), sent = _replying_env(tmp_path, monkeypatch)
    provider.queue_email(to="a.1@read.steepd.app", subject="A book", attachments=["novel.epub"])
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note", html=ARTICLE_BODY)

    assert service.handle(*provider.signed_event()).rejected == 0
    assert sent == []


def test_an_unconvertible_newsletter_is_explained(tmp_path, monkeypatch):
    (_, _, _, service, tenants, provider), sent = _replying_env(tmp_path, monkeypatch)
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Empty", html="<p>Hi.</p>")

    result = service.handle(*provider.signed_event())

    assert result.rejected == 1
    assert sent[0]["to"] == tenants[0].email
    assert "readable content" in sent[0]["text"]


def test_rejection_replies_are_capped_per_tenant_per_hour(tmp_path, monkeypatch):
    """The reply is the one message an unauthenticated stranger can make us send. An
    address is guessable by design, so without a cap anyone who knows one can have Steepd
    mail its owner from our own domain, once per piece of rubbish they send."""
    (_, _, _, service, tenants, provider), sent = _replying_env(tmp_path, monkeypatch)
    clock = {"now": 1_000.0}
    service._clock = lambda: clock["now"]

    def send_one_rejected() -> None:
        provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Empty", html="<p>Hi.</p>")
        assert service.handle(*provider.signed_event()).rejected == 1

    for _ in range(6):
        send_one_rejected()

    # The sixth is refused, and refusing the reply does not change the webhook's verdict.
    assert len(sent) == 5
    assert all(message["to"] == tenants[0].email for message in sent)

    clock["now"] += REJECTION_REPLY_WINDOW + 1
    send_one_rejected()

    assert len(sent) == 6


def test_a_full_account_refuses_a_newsletter_as_a_rejection_not_an_error(tmp_path, monkeypatch):
    """Over quota, the converted article cannot be stored. That is final -- a retry meets
    the same full account -- so it is a rejection the reader hears about, and the event is
    recorded as done rather than left for the provider to retry."""
    (_, database, _, service, tenants, provider), sent = _replying_env(tmp_path, monkeypatch)
    scope = TenantScope(tenants[0].id)
    monkeypatch.setattr("steepd.storage.quota_bytes", lambda plan: 1)
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note", html=ARTICLE_BODY)
    body, headers = provider.signed_event()

    result = service.handle(body, headers)

    assert result.rejected == 1
    assert database.count_items(scope) == 0
    assert "storage limit" in sent[0]["text"]
    assert webhook_result(database, headers["svix-id"]).startswith("newsletter;")


def test_no_reply_without_an_outbound_sender_configured(tmp_path, monkeypatch):
    sent: list[dict] = []
    monkeypatch.setattr("steepd.inbound.send_email", lambda settings, **message: sent.append(message))
    _, _, _, service, _, provider = _build_env(tmp_path, ["a.1"])
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Empty", html="<p>Hi.</p>")

    assert service.handle(*provider.signed_event()).rejected == 1
    assert sent == []


def test_a_failed_image_fetch_logs_the_host_and_path_but_never_the_query_string(tmp_path, caplog):
    """Image URLs keep their query string so the fetch works; that is also where publishers
    put per-subscriber tokens, and a log line must not carry them."""
    import logging

    fetch = StubImageFetch(error=ImageFetchError("Image host resolves to a non-routable address"))
    _, _, _, service, _, provider = _build_env(tmp_path, ["a.1"], image_fetch=fetch)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=f"{ARTICLE_BODY}<img src='https://cdn.example.com/hero.png?token=SUBSCRIBER-SECRET&e=42' alt='Hero'>",
    )
    with caplog.at_level(logging.WARNING, logger="steepd.inbound"):
        service.handle(*provider.signed_event())

    assert fetch.calls and "SUBSCRIBER-SECRET" in fetch.calls[0][0]
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "https://cdn.example.com/hero.png" in logged
    assert "SUBSCRIBER-SECRET" not in logged and "token=" not in logged


def test_remote_images_stop_when_the_delivery_time_budget_is_spent(tmp_path):
    """Forty fetches at the per-request timeout is minutes inside a webhook the provider
    abandons in seconds. Once the budget is spent the remaining images degrade to alt text
    and the delivery still lands."""
    ticks = {"now": 0.0}
    fetch = StubImageFetch()

    def slow_fetch(url: str, *, max_bytes: int, **kwargs):
        ticks["now"] += 25.0
        return fetch(url, max_bytes=max_bytes, **kwargs)

    _, database, storage, service, tenants, provider = _build_env(tmp_path, ["a.1"], image_fetch=slow_fetch)
    service._clock = lambda: ticks["now"]
    scope = TenantScope(tenants[0].id)
    images = "".join(f"<img src='https://cdn.example.com/{n}.png' alt='Picture {n}'>" for n in range(1, 6))
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note", html=f"{ARTICLE_BODY}{images}")

    result = service.handle(*provider.signed_event())

    assert result.imported == 1
    # 0s, 25s and 50s are inside the sixty-second budget; the fourth and fifth are not.
    assert len(fetch.calls) == 3
    chapter = chapter_of(stored_archive(storage, database, scope))
    assert chapter.count("<img") == 3
    assert "[Picture 4]" in chapter and "[Picture 5]" in chapter


# -- articles -------------------------------------------------------------


def test_repeat_forward_of_the_same_newsletter_is_deduplicated(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note",
                         html=ARTICLE_BODY, message_id="<monday@example.com>")
    first = service.handle(*provider.signed_event())

    # A second, genuinely different webhook event carrying the same forwarded newsletter.
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note",
                         html=ARTICLE_BODY, message_id="<monday-again@example.com>")
    second = service.handle(*provider.signed_event())

    assert first.imported == 1
    assert second.duplicates == 1
    assert second.imported == 0
    assert database.count_items(scope, kind="article") == 1


def test_a_newsletter_deleted_from_the_library_can_be_forwarded_again(inbound_env):
    """The delivery record goes with the article. Kept past it, the same issue would be
    refused as a duplicate forever -- after the free tier's seven-day sweep, or a delete
    the reader regrets -- and the refusal was silent."""
    database, service, scope, provider = inbound_env
    storage = service.storage
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note",
                         html=ARTICLE_BODY, message_id="<monday@example.com>")
    first = service.handle(*provider.signed_event())
    assert first.imported == 1
    item_id = database.list_items(scope, kind="article")[0].id
    assert storage.delete(scope, item_id)

    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note",
                         html=ARTICLE_BODY, message_id="<monday@example.com>")
    second = service.handle(*provider.signed_event())

    assert second.imported == 1
    assert second.duplicates == 0
    assert database.count_items(scope, kind="article") == 1


def test_two_tenants_may_forward_the_same_newsletter(inbound_env_two_tenants):
    """Dedup keys are per tenant: one reader's forward must not block another's."""
    database, service, alice_scope, bob_scope, provider = inbound_env_two_tenants
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note",
                         html=ARTICLE_BODY, message_id="<monday@example.com>")
    service.handle(*provider.signed_event())

    provider.queue_email(to="b.2@read.steepd.app", subject="Fwd: Monday note",
                         html=ARTICLE_BODY, message_id="<monday@example.com>")
    second = service.handle(*provider.signed_event())

    assert second.imported == 1
    assert database.count_items(alice_scope, kind="article") == 1
    assert database.count_items(bob_scope, kind="article") == 1


def test_newsletter_without_readable_content_is_rejected_not_filed(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Empty", html="<p>Hi.</p>")

    result = service.handle(*provider.signed_event())

    assert result.rejected == 1
    assert result.kind == "article"
    assert database.count_items(scope) == 0


def test_newsletter_inline_image_is_downloaded_into_the_article(tmp_path):
    _, database, storage, service, tenants, provider = _build_env(tmp_path, ["a.1"])
    scope = TenantScope(tenants[0].id)
    image = b"\x89PNG\r\n\x1a\nnewsletter-image"
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=f"{ARTICLE_BODY}<img src='cid:hero-image' alt='Hero'>",
        attachments=[
            Attachment(
                filename="hero.png",
                content=image,
                content_type="image/png",
                host="inbound-cdn.resend.com",
                content_disposition="inline",
                content_id="<hero-image>",
            )
        ],
    )

    result = service.handle(*provider.signed_event())

    assert result.kind == "article"
    assert result.imported == 1
    item = database.list_items(scope)[0]
    with zipfile.ZipFile(io.BytesIO(stored_payload(storage, scope, item.id))) as archive:
        assert any(archive.read(name) == image for name in archive.namelist())


# -- remote images --------------------------------------------------------
# The product promise: an article reads offline, and opening it never calls the sender's
# CDN. Every test here therefore checks the stored archive, not just the import count.

HERO_URL = "https://cdn.example.com/hero.png"


def test_remote_newsletter_image_is_inlined_and_the_url_never_ships(tmp_path):
    image = png_bytes()
    fetch = StubImageFetch(image)
    _, database, storage, service, tenants, provider = _build_env(tmp_path, ["a.1"], image_fetch=fetch)
    scope = TenantScope(tenants[0].id)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=f"{ARTICLE_BODY}<img src='{HERO_URL}' alt='Hero'>",
    )

    result = service.handle(*provider.signed_event())

    assert result.imported == 1
    assert fetch.calls == [(HERO_URL, 10 * 1024 * 1024)]
    members = stored_archive(storage, database, scope)
    image_members = {name: content for name, content in members.items() if name.endswith("images/1.png")}
    assert list(image_members.values()) == [image]
    assert 'src="images/1.png"' in chapter_of(members)
    # Nowhere in the archive, not just in the chapter: a phone-home would work just as well
    # from the manifest or the nav document.
    assert not any(b"cdn.example.com" in content for content in members.values())


def test_failed_remote_image_fetch_degrades_to_alt_text(tmp_path):
    fetch = StubImageFetch(error=ImageFetchError("Image host resolves to a non-routable address"))
    _, database, storage, service, tenants, provider = _build_env(tmp_path, ["a.1"], image_fetch=fetch)
    scope = TenantScope(tenants[0].id)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=f"{ARTICLE_BODY}<img src='{HERO_URL}' alt='Hero'>",
    )

    result = service.handle(*provider.signed_event())

    assert result.imported == 1
    members = stored_archive(storage, database, scope)
    chapter = chapter_of(members)
    assert "<img" not in chapter
    assert "[Hero]" in chapter
    # Fail closed: a sender who makes the fetch fail must not get the live URL delivered.
    assert not any(b"cdn.example.com" in content for content in members.values())


def test_remote_image_larger_than_the_requested_limit_is_rejected(tmp_path):
    """The real fetcher enforces max_bytes, so this covers the closure's own check --
    without it a misbehaving fetcher could inline oversize bytes and leave the shared
    byte budget describing something other than what was stored."""
    fetch = StubImageFetch(png_bytes(200), honor_max_bytes=False)
    _, database, storage, service, tenants, provider = _build_env(
        tmp_path, ["a.1"], image_fetch=fetch, newsletter_max_image_bytes=64
    )
    scope = TenantScope(tenants[0].id)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=f"{ARTICLE_BODY}<img src='{HERO_URL}' alt='Hero'>",
    )

    result = service.handle(*provider.signed_event())

    assert result.imported == 1
    assert fetch.calls == [(HERO_URL, 64)]
    members = stored_archive(storage, database, scope)
    assert "[Hero]" in chapter_of(members)
    assert not any(name.endswith(".png") for name in members)


def test_remote_images_share_one_total_byte_budget(tmp_path):
    fetch = StubImageFetch(png_bytes(40))
    _, database, storage, service, tenants, provider = _build_env(
        tmp_path, ["a.1"], image_fetch=fetch, newsletter_max_total_image_bytes=50
    )
    scope = TenantScope(tenants[0].id)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=(
            f"{ARTICLE_BODY}"
            "<img src='https://cdn.example.com/one.png' alt='First'>"
            "<img src='https://cdn.example.com/two.png' alt='Second'>"
        ),
    )

    result = service.handle(*provider.signed_event())

    assert result.imported == 1
    # The second request is still made, but for only the 10 bytes left, which the payload
    # does not fit into.
    assert [call[1] for call in fetch.calls] == [50, 10]
    members = stored_archive(storage, database, scope)
    assert [name for name in members if name.endswith(".png")] == ["EPUB/images/1.png"]
    chapter = chapter_of(members)
    assert 'src="images/1.png"' in chapter
    assert "[Second]" in chapter


def test_remote_image_count_is_capped_per_newsletter(tmp_path, monkeypatch):
    """A newsletter of sliced graphics must not turn one webhook into an unbounded fan-out
    of outbound requests. The cap counts attempts, so it bounds requests rather than hits."""
    monkeypatch.setattr("steepd.inbound.MAX_REMOTE_IMAGES_PER_NEWSLETTER", 2)
    fetch = StubImageFetch()
    _, database, storage, service, tenants, provider = _build_env(tmp_path, ["a.1"], image_fetch=fetch)
    scope = TenantScope(tenants[0].id)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=(
            f"{ARTICLE_BODY}"
            "<img src='https://cdn.example.com/one.png' alt='First'>"
            "<img src='https://cdn.example.com/two.png' alt='Second'>"
            "<img src='https://cdn.example.com/three.png' alt='Third'>"
        ),
    )

    result = service.handle(*provider.signed_event())

    assert result.imported == 1
    assert [call[0] for call in fetch.calls] == [
        "https://cdn.example.com/one.png",
        "https://cdn.example.com/two.png",
    ]
    members = stored_archive(storage, database, scope)
    assert "[Third]" in chapter_of(members)


def test_an_unexpected_fetcher_error_is_not_swallowed(tmp_path):
    """Deliberate: the closure catches ImageFetchError and nothing else. Any other exception
    is a bug in our own code, and turning it into alt text would file a quietly image-less
    newsletter forever rather than surfacing the fault once."""
    fetch = StubImageFetch(error=RuntimeError("fetcher is broken"))
    _, database, _, service, tenants, provider = _build_env(tmp_path, ["a.1"], image_fetch=fetch)
    scope = TenantScope(tenants[0].id)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=f"{ARTICLE_BODY}<img src='{HERO_URL}' alt='Hero'>",
    )

    with pytest.raises(RuntimeError, match="fetcher is broken"):
        service.handle(*provider.signed_event())
    assert database.count_items(scope) == 0


def test_remote_and_inline_images_share_the_same_total_budget(tmp_path):
    """The cid: download picks up where the remote fetches left off, so a newsletter cannot
    spend the whole budget twice by carrying both kinds of image."""
    inline_image = png_bytes(20)
    fetch = StubImageFetch(png_bytes(40))
    _, database, _, service, tenants, provider = _build_env(
        tmp_path, ["a.1"], image_fetch=fetch, newsletter_max_total_image_bytes=50
    )
    scope = TenantScope(tenants[0].id)
    provider.queue_email(
        to="a.1@read.steepd.app",
        subject="Fwd: Monday note",
        html=f"{ARTICLE_BODY}<img src='{HERO_URL}' alt='Hero'><img src='cid:logo' alt='Logo'>",
        attachments=[
            Attachment(
                filename="logo.png",
                content=inline_image,
                content_type="image/png",
                host="inbound-cdn.resend.com",
                content_disposition="inline",
                content_id="<logo>",
            )
        ],
    )

    result = service.handle(*provider.signed_event())

    # 40 remote bytes plus 20 inline ones is over the 50-byte total, which the cid: path
    # reports as a conversion failure -- the existing rejected-delivery outcome.
    assert result.rejected == 1
    assert result.imported == 0
    assert database.count_items(scope) == 0


def test_stored_email_addressed_to_another_tenant_is_rejected(inbound_env_two_tenants):
    """The webhook payload and the stored email are two separate provider responses,
    and only the stored one is converted -- so the routing decision is re-checked."""
    database, service, alice_scope, bob_scope, provider = inbound_env_two_tenants
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note", html=ARTICLE_BODY)
    provider.emails["email-1"]["to"] = ["b.2@read.steepd.app"]

    with pytest.raises(InvalidWebhookEvent):
        service.handle(*provider.signed_event())
    assert database.count_items(alice_scope) == 0
    assert database.count_items(bob_scope) == 0


# -- support forwarding ---------------------------------------------------
# Resend delivers a webhook for every address on the account's receiving domains, so the
# apex support address arrives here alongside the tenant inboxes on INBOX_DOMAIN. It is
# relayed to the operator's real mailbox instead of being discarded.

SUPPORT_ADDRESS = "help@steepd.app"
FORWARD_ADDRESS = "operator@example.com"
MAIL_FROM = "Steepd <noreply@steepd.app>"


def _support_env(tmp_path, **settings_overrides):
    """One tenant on INBOX_DOMAIN plus support forwarding configured on the apex."""
    _, database, _, service, tenants, provider = _build_env(
        tmp_path,
        ["a.1"],
        support_inbound_address=SUPPORT_ADDRESS,
        support_forward_address=FORWARD_ADDRESS,
        mail_from_address=MAIL_FROM,
        **settings_overrides,
    )
    return database, service, TenantScope(tenants[0].id), provider


def test_support_email_is_forwarded_to_the_operator(tmp_path):
    database, service, scope, provider = _support_env(tmp_path)
    provider.queue_email(
        to=SUPPORT_ADDRESS,
        sender="Ada Reader <ada@example.com>",
        subject="Cannot sign in",
        html="<p>The magic link never arrived.</p>",
        text="The magic link never arrived.",
        svix_id="msg_support",
    )

    result = service.handle(*provider.signed_event())

    assert result.status == "ok"
    assert result.message == "Forwarded to support."
    # No tenant owns support mail, and nothing about it belongs in anyone's library.
    assert result.tenant_id == ""
    assert database.count_items(scope) == 0
    assert webhook_result(database, "msg_support") == "support-forwarded"

    assert len(provider.forwards) == 1
    forward = provider.forwards[0]
    assert forward["to"] == [FORWARD_ADDRESS]
    # From has to be our own verified sending domain; steepd.app is what Resend will send as.
    assert forward["from"] == MAIL_FROM
    assert forward["subject"] == "[Steepd support] Cannot sign in"
    assert forward["html"] == "<p>The magic link never arrived.</p>"
    assert forward["text"] == "The magic link never arrived."
    # The whole point of Reply-To here: the operator answers the person who wrote in, not
    # the noreply address the forward was sent from.
    assert forward["reply_to"] == ["Ada Reader <ada@example.com>"]


def test_a_forwarded_support_email_keeps_its_attachments(tmp_path):
    """The reason forwarding composes a send from the received message rather than relaying
    the body alone: a bug report is usually a screenshot, and a dropped attachment leaves
    the operator answering a message they cannot see."""
    _, service, _, provider = _support_env(tmp_path)
    screenshot = png_bytes(64)
    provider.queue_email(
        to=SUPPORT_ADDRESS,
        sender="ada@example.com",
        subject="The export button does nothing",
        text="Screenshot attached.",
        attachments=[Attachment(filename="broken.png", content=screenshot, content_type="image/png")],
    )

    service.handle(*provider.signed_event())

    attachments = provider.forwards[0]["attachments"]
    assert len(attachments) == 1
    assert attachments[0]["filename"] == "broken.png"
    assert attachments[0]["content_type"] == "image/png"
    assert base64.b64decode(attachments[0]["content"]) == screenshot


def test_a_forwarded_inline_image_keeps_its_content_id(tmp_path):
    """An inline image is referenced by cid: from the HTML, so the id has to survive the
    forward or the copy the operator opens renders with a broken image."""
    _, service, _, provider = _support_env(tmp_path)
    provider.queue_email(
        to=SUPPORT_ADDRESS,
        sender="ada@example.com",
        subject="Look at this",
        html="<p>See <img src='cid:shot'></p>",
        attachments=[
            Attachment(
                filename="shot.png",
                content=png_bytes(),
                content_type="image/png",
                host="inbound-cdn.resend.com",
                content_disposition="inline",
                content_id="<shot>",
            )
        ],
    )

    service.handle(*provider.signed_event())

    assert provider.forwards[0]["attachments"][0]["content_id"] == "shot"


def test_an_oversize_attachment_is_skipped_rather_than_losing_the_message(tmp_path):
    """Failing the whole forward would leave the operator with nothing at all, which is a
    worse answer than the message plus the parts that fit."""
    _, database, _, service, tenants, provider = _build_env(
        tmp_path,
        ["a.1"],
        support_inbound_address=SUPPORT_ADDRESS,
        support_forward_address=FORWARD_ADDRESS,
        mail_from_address=MAIL_FROM,
    )
    # Large enough that reading the message back still succeeds, small enough that the
    # attachment alone does not fit -- the case the skip exists for.
    provider.max_download_bytes = 2048
    provider.queue_email(
        to=SUPPORT_ADDRESS,
        sender="ada@example.com",
        subject="Huge log",
        text="Log attached.",
        svix_id="msg_big",
        attachments=[Attachment(filename="huge.log", content=b"x" * 8192, content_type="text/plain")],
    )

    result = service.handle(*provider.signed_event())

    assert result.status == "ok"
    assert webhook_result(database, "msg_big") == "support-forwarded"
    forward = provider.forwards[0]
    assert "attachments" not in forward
    assert forward["text"] == "Log attached."


def test_a_long_support_subject_is_capped_to_what_a_send_accepts(tmp_path):
    """get_email caps the stored subject at 2048, which is longer than a send accepts -- so
    an over-long subject has to be trimmed or the forward fails instead of delivering."""
    _, service, _, provider = _support_env(tmp_path)
    provider.queue_email(to=SUPPORT_ADDRESS, subject="N" * 2048, text="Help.")

    service.handle(*provider.signed_event())

    assert provider.forwards[0]["subject"].startswith("[Steepd support] ")
    assert len(provider.forwards[0]["subject"]) == MAX_SUBJECT_LENGTH


def test_support_mail_is_discarded_when_forwarding_is_off(tmp_path):
    """The unconfigured default: the apex address is just another unknown recipient, and
    the discard path behaves exactly as it did before forwarding existed."""
    _, database, _, service, tenants, provider = _build_env(tmp_path, ["a.1"])
    provider.queue_email(to=SUPPORT_ADDRESS, subject="Hello", html=ARTICLE_BODY, svix_id="msg_off")

    result = service.handle(*provider.signed_event())

    assert result.status == "ignored"
    assert result.message == "Recipient does not match a known inbox."
    assert webhook_result(database, "msg_off") == "unknown-inbox"
    assert provider.requests == []
    assert provider.forwards == []
    assert database.count_items(TenantScope(tenants[0].id)) == 0


def test_support_mail_is_discarded_without_a_sending_address(tmp_path):
    """MAIL_FROM_ADDRESS is what a forward is sent as. Config refuses to boot without it,
    so reaching the branch unset means the feature is off, not that we improvise a sender."""
    _, database, _, service, _, provider = _build_env(
        tmp_path,
        ["a.1"],
        support_inbound_address=SUPPORT_ADDRESS,
        support_forward_address=FORWARD_ADDRESS,
        mail_from_address="",
    )
    provider.queue_email(to=SUPPORT_ADDRESS, subject="Hello", text="Hello.", svix_id="msg_nofrom")

    result = service.handle(*provider.signed_event())

    assert result.status == "ignored"
    assert webhook_result(database, "msg_nofrom") == "unknown-inbox"
    assert provider.forwards == []


def test_a_tenant_delivery_never_reaches_the_support_branch(tmp_path):
    """Configuring support must not change what happens to mail that resolves to a tenant."""
    database, service, scope, provider = _support_env(tmp_path)
    provider.queue_email(to="a.1@read.steepd.app", subject="Fwd: Monday note", html=ARTICLE_BODY)

    result = service.handle(*provider.signed_event())

    assert result.kind == "article"
    assert database.count_items(scope, kind="article") == 1
    assert provider.forwards == []


def test_a_stranger_sharing_the_support_local_part_is_not_forwarded(tmp_path):
    """The match is on the whole address. "help@" at somebody else's domain is a stranger's
    mailbox, and forwarding it would hand the operator's address to whoever aimed it here."""
    database, service, _, provider = _support_env(tmp_path)
    provider.queue_email(to="help@elsewhere.example", subject="Hello", text="Hello.", svix_id="msg_stranger")

    result = service.handle(*provider.signed_event())

    assert result.status == "ignored"
    assert webhook_result(database, "msg_stranger") == "unknown-inbox"
    assert provider.requests == []
    assert provider.forwards == []


@pytest.mark.parametrize(
    "sender_address",
    ["operator@example.com", "noreply@steepd.app", "Steepd <noreply@steepd.app>"],
)
def test_mail_from_one_of_our_own_addresses_is_dropped_as_a_loop(tmp_path, sender_address):
    """The loop breaker. A bounce or vacation auto-reply from the operator's mailbox, or
    from our own sender address, is addressed back at help@ -- forwarding it would send it
    straight back to the mailbox that produced it."""
    database, service, _, provider = _support_env(tmp_path)
    provider.queue_email(
        to=SUPPORT_ADDRESS,
        sender=sender_address,
        subject="Out of office",
        text="I am away until Monday.",
        svix_id="msg_loop",
    )

    result = service.handle(*provider.signed_event())

    assert result.status == "ok"
    assert webhook_result(database, "msg_loop") == "support-loop-dropped"
    assert provider.forwards == []
    # The webhook event carries the sender, so a loop is dropped without reading the
    # message back from the provider at all.
    assert provider.requests == []


def test_a_failed_support_forward_is_not_retried_into_a_loop(tmp_path, caplog):
    """Resend retries any non-2xx webhook response, and a retry would re-forward rather
    than fix a send that failed -- so the failure is recorded and reported as success."""
    caplog.set_level(logging.WARNING, logger="steepd.inbound")
    database, service, _, provider = _support_env(tmp_path)
    provider.forward_status = 500
    provider.queue_email(
        to=SUPPORT_ADDRESS,
        sender="ada@example.com",
        subject="My card was charged twice",
        text="The receipt says 4111.",
        svix_id="msg_fail",
    )

    result = service.handle(*provider.signed_event())

    assert result.status == "ok"
    assert webhook_result(database, "msg_fail") == "support-forward-failed"
    assert len(provider.forwards) == 1
    # The warning says a forward failed and why; it never carries what someone wrote to us.
    assert "Failed to forward a support email" in caplog.text
    assert "My card was charged twice" not in caplog.text
    assert "4111" not in caplog.text


# -- sender policy -----------------------------------------------------------


def test_mail_to_a_pending_placeholder_is_discarded_as_unknown(inbound_env):
    database, service, scope, provider = inbound_env
    pending = database.create_pending_tenant(email="new@example.com")
    provider.queue_email(to=f"{pending.inbox_local}@read.steepd.app", subject="A book", attachments=["novel.epub"])
    body, headers = provider.signed_event()

    result = service.handle(body, headers)

    assert result.status == "ignored"
    assert webhook_result(database, headers["svix-id"]) == "unknown-inbox"
    assert provider.requests == []


def test_anyone_policy_accepts_a_stranger(inbound_env):
    database, service, scope, provider = inbound_env
    provider.queue_email(to="a.1@read.steepd.app", sender="Stranger <stranger@example.org>",
                         subject="Fwd: Monday note", html=ARTICLE_BODY)
    assert service.handle(*provider.signed_event()).imported == 1


def test_listed_policy_refuses_a_stranger_records_them_and_calls_no_provider(inbound_env):
    database, service, scope, provider = inbound_env
    database.set_sender_policy(scope.tenant_id, "listed")
    provider.queue_email(to="a.1@read.steepd.app", sender="Stranger <Stranger@Example.org>",
                         subject="Fwd: Monday note", html=ARTICLE_BODY)
    body, headers = provider.signed_event()

    result = service.handle(body, headers)

    assert result.status == "ignored" and result.tenant_id == ""
    assert webhook_result(database, headers["svix-id"]) == "sender-refused"
    assert provider.requests == []
    assert database.count_items(scope) == 0
    refused = database.list_refused_senders(scope.tenant_id)
    assert [(r.address, r.count) for r in refused] == [("stranger@example.org", 1)]


def test_listed_policy_accepts_the_account_email_and_a_listed_sender(inbound_env):
    database, service, scope, provider = inbound_env
    tenant = database.tenant_by_id(scope.tenant_id)
    database.set_sender_policy(scope.tenant_id, "listed")
    database.add_allowed_sender(scope.tenant_id, "news@dispatch.example")

    provider.queue_email(to="a.1@read.steepd.app", sender=tenant.email, subject="Fwd: One", html=ARTICLE_BODY,
                         message_id="<one@example.com>")
    assert service.handle(*provider.signed_event()).imported == 1
    provider.queue_email(to="a.1@read.steepd.app", sender="The Dispatch <news@dispatch.example>",
                         subject="Two", html=ARTICLE_BODY.replace("Monday", "Tuesday"), message_id="<two@example.com>")
    assert service.handle(*provider.signed_event()).imported == 1
    assert database.list_refused_senders(scope.tenant_id) == []


def test_refusal_sends_nothing_to_anyone(tmp_path, monkeypatch):
    (_, database, _, service, tenants, provider), sent = _replying_env(tmp_path, monkeypatch)
    database.set_sender_policy(tenants[0].id, "listed")
    provider.queue_email(to="a.1@read.steepd.app", sender="stranger@example.org", subject="Fwd: X", html=ARTICLE_BODY)
    service.handle(*provider.signed_event())
    assert sent == []


def test_the_stored_message_is_rechecked_against_the_policy(inbound_env):
    """The webhook payload and the stored email are two provider responses. If they
    disagree about the sender, the stored one -- the one actually converted -- decides."""
    database, service, scope, provider = inbound_env
    tenant = database.tenant_by_id(scope.tenant_id)
    database.set_sender_policy(scope.tenant_id, "listed")
    provider.queue_email(to="a.1@read.steepd.app", sender=tenant.email, subject="Fwd: Monday note", html=ARTICLE_BODY)
    body, headers = provider.signed_event()
    email_id = json.loads(body)["data"]["email_id"]
    provider.emails[email_id]["from"] = "stranger@example.org"

    with pytest.raises(InvalidWebhookEvent):
        service.handle(body, headers)
    assert database.count_items(scope) == 0
