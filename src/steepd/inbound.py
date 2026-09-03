from __future__ import annotations

import base64
import html as html_module
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parseaddr
from typing import Protocol
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from svix.webhooks import Webhook, WebhookVerificationError

from steepd.config import Settings
from steepd.db import Database
from steepd.epub import EPUB_MIME_TYPE, EpubImportError
from steepd.imagefetch import FetchedImage, ImageFetchError, fetch_remote_image
from steepd.models import Tenant
from steepd.newsletter import (
    SAFE_INLINE_IMAGE_TYPES,
    NewsletterConversionError,
    NewsletterDocument,
    NewsletterEmail,
    NewsletterForwardingError,
    NewsletterResource,
    RemoteImageFetcher,
    convert_newsletter,
    normalize_content_id,
)
from steepd.outbound import MAX_SUBJECT_LENGTH, OutboundEmailError, send_email
from steepd.publisher import LocalNewsletterPublisher
from steepd.ratelimit import Policy, RateLimiter
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

LOGGER = logging.getLogger("steepd.inbound")
RESEND_API_BASE_URL = "https://api.resend.com"
RESEND_ATTACHMENT_HOST = "cdn.resend.app"
RESEND_ATTACHMENT_HOSTS = frozenset({RESEND_ATTACHMENT_HOST, "inbound-cdn.resend.com"})
NEWSLETTER_PROVIDER_NAME = "resend"
WEBHOOK_PROVIDER_NAME = "resend"
USER_AGENT = "Steepd/0.1"

# One webhook must not become hundreds of outbound requests. A newsletter carrying more
# distinct image URLs than this is either a layout built entirely from sliced graphics or
# someone using our fetcher as a request amplifier; past the cap the images degrade to alt
# text, which is the same outcome as any other failed fetch.
MAX_REMOTE_IMAGES_PER_NEWSLETTER = 40

# Wall-clock ceiling on the remote image fetches of one delivery. Each fetch is bounded on
# its own (imagefetch.py), but forty of them at the per-request timeout is minutes inside
# a webhook the provider gives up on in seconds, after which it retries the same delivery.
# Past the deadline the remaining images degrade to alt text, like any other failed fetch.
REMOTE_IMAGE_TIME_BUDGET_SECONDS = 60.0

# What a claimed-but-unfinished event id is recorded as, so a row in that state can be
# recognised as "still being processed" rather than as a result.
PROCESSING_RESULT = "processing"

# Marks a relayed message in the operator's mailbox, where it arrives from our own
# MAIL_FROM_ADDRESS rather than from whoever wrote in.
SUPPORT_SUBJECT_PREFIX = "[Steepd support] "
REJECTION_SUBJECT_PREFIX = "Steepd could not file: "

# The rejection reply is the one thing an unauthenticated stranger can make this service
# send, so it is counted per tenant. Five an hour covers a person forwarding a batch that
# goes wrong; it does not cover anybody using a guessable address as a mail cannon aimed
# at its owner. In-process, like every other limit here: one instance serves everything.
REJECTION_REPLY_BUCKET = "rejection-reply"
REJECTION_REPLY_LIMIT = 5
REJECTION_REPLY_WINDOW = 3600.0


class InboundEmailError(RuntimeError):
    pass


class InboundEmailDisabled(InboundEmailError):
    pass


class InvalidWebhookSignature(InboundEmailError):
    pass


class InvalidWebhookEvent(InboundEmailError):
    pass


class ProviderRequestError(InboundEmailError):
    pass


@dataclass(frozen=True, slots=True)
class InboundAttachment:
    id: str
    filename: str
    content_type: str
    size: int
    download_url: str
    content_disposition: str
    content_id: str


@dataclass(frozen=True, slots=True)
class InboundResult:
    status: str
    message: str
    imported: int = 0
    duplicates: int = 0
    rejected: int = 0
    # The tenant the delivery was routed to. Empty when no inbox matched, which is the
    # only outcome for an email addressed to an inbox that does not exist.
    tenant_id: str = ""
    # "book" when the email carried an EPUB attachment, "article" when it did not.
    kind: str = ""
    # One line per rejection, in words the reader can act on. These are what the reply
    # email carries; they never name a file path, a tenant id or a provider URL.
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "message": self.message,
            "imported": self.imported,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "tenant_id": self.tenant_id,
            "kind": self.kind,
            "reasons": list(self.reasons),
        }


class InboundEmailProvider(Protocol):
    def verify_event(self, raw_body: bytes, headers: Mapping[str, str]) -> dict[str, object]: ...

    def list_attachments(self, email_id: str) -> list[InboundAttachment]: ...

    def get_email(self, email_id: str) -> NewsletterEmail: ...

    def download_chunks(self, attachment: InboundAttachment) -> AbstractContextManager[Iterable[bytes]]: ...

    def forward_email(self, email_id: str, *, to: str, sender: str) -> None: ...


class ResendInboundProvider:
    def __init__(
        self,
        *,
        api_key: str,
        webhook_secret: str,
        max_download_bytes: int,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_key = api_key
        self.webhook_secret = webhook_secret
        self.max_download_bytes = max_download_bytes
        self.transport = transport

    def verify_event(self, raw_body: bytes, headers: Mapping[str, str]) -> dict[str, object]:
        verification_headers = {
            "svix-id": headers.get("svix-id", ""),
            "svix-timestamp": headers.get("svix-timestamp", ""),
            "svix-signature": headers.get("svix-signature", ""),
        }
        if not all(verification_headers.values()):
            raise InvalidWebhookSignature("Missing webhook signature headers")
        try:
            Webhook(self.webhook_secret).verify(raw_body, verification_headers)
        except (WebhookVerificationError, ValueError) as exc:
            raise InvalidWebhookSignature("Invalid webhook signature") from exc
        try:
            event = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidWebhookEvent("Webhook body is not valid JSON") from exc
        if not isinstance(event, dict):
            raise InvalidWebhookEvent("Webhook body must be a JSON object")
        return event

    def list_attachments(self, email_id: str) -> list[InboundAttachment]:
        if not email_id or len(email_id) > 200:
            raise InvalidWebhookEvent("Inbound email ID is invalid")
        path = f"/emails/receiving/{quote(email_id, safe='')}/attachments"
        with httpx.Client(
            base_url=RESEND_API_BASE_URL,
            headers={"Authorization": f"Bearer {self.api_key}", "User-Agent": USER_AGENT},
            timeout=httpx.Timeout(20.0, connect=5.0),
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
        ) as client:
            try:
                response = client.get(path)
            except httpx.HTTPError as exc:
                raise ProviderRequestError("Resend attachment lookup failed") from exc
        if response.status_code != 200:
            raise ProviderRequestError(f"Resend attachment lookup returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderRequestError("Resend attachment lookup returned invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ProviderRequestError("Resend attachment lookup returned an invalid response")
        if payload.get("has_more") is True:
            raise ProviderRequestError("Resend attachment list was unexpectedly paginated")

        attachments: list[InboundAttachment] = []
        for item in payload["data"]:
            if not isinstance(item, dict):
                raise ProviderRequestError("Resend attachment metadata is invalid")
            attachment_id = item.get("id")
            filename = item.get("filename")
            content_type = item.get("content_type")
            download_url = item.get("download_url")
            size = item.get("size")
            content_disposition = item.get("content_disposition")
            content_id = item.get("content_id")
            if (
                not isinstance(attachment_id, str)
                or not isinstance(filename, str)
                or not isinstance(content_type, str)
                or not isinstance(download_url, str)
                or not isinstance(size, int)
                or size < 0
                or not isinstance(content_disposition, (str, type(None)))
                or not isinstance(content_id, (str, type(None)))
            ):
                raise ProviderRequestError("Resend attachment metadata is incomplete")
            self._validate_download_url(download_url)
            attachments.append(
                InboundAttachment(
                    id=attachment_id[:200],
                    filename=filename,
                    content_type=content_type,
                    size=size,
                    download_url=download_url,
                    content_disposition=(content_disposition or "")[:100],
                    content_id=(content_id or "")[:500],
                )
            )
        return attachments

    def get_email(self, email_id: str) -> NewsletterEmail:
        if not email_id or len(email_id) > 200:
            raise InvalidWebhookEvent("Inbound email ID is invalid")
        path = f"/emails/receiving/{quote(email_id, safe='')}"
        with httpx.Client(
            base_url=RESEND_API_BASE_URL,
            headers={"Authorization": f"Bearer {self.api_key}", "User-Agent": USER_AGENT},
            timeout=httpx.Timeout(20.0, connect=5.0),
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
        ) as client:
            try:
                response = client.get(path)
            except httpx.HTTPError as exc:
                raise ProviderRequestError("Resend email lookup failed") from exc
        if response.status_code != 200:
            raise ProviderRequestError(f"Resend email lookup returned HTTP {response.status_code}")
        if len(response.content) > self.max_download_bytes:
            raise ProviderRequestError("Resend email lookup exceeded the configured size limit")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderRequestError("Resend email lookup returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ProviderRequestError("Resend email lookup returned an invalid response")

        returned_id = payload.get("id")
        sender = payload.get("from")
        recipients = payload.get("to")
        subject = payload.get("subject")
        html = payload.get("html")
        text = payload.get("text")
        created_at = payload.get("created_at")
        message_id = payload.get("message_id")
        if (
            returned_id != email_id
            or not isinstance(sender, str)
            or not isinstance(recipients, list)
            or len(recipients) > 100
            or not all(isinstance(item, str) for item in recipients)
            or not isinstance(subject, (str, type(None)))
            or not isinstance(html, (str, type(None)))
            or not isinstance(text, (str, type(None)))
            or not isinstance(created_at, str)
            or not isinstance(message_id, (str, type(None)))
        ):
            raise ProviderRequestError("Resend email metadata is incomplete")
        html_value = html or ""
        text_value = text or ""
        if len(html_value.encode("utf-8")) + len(text_value.encode("utf-8")) > self.max_download_bytes:
            raise ProviderRequestError("Resend email body exceeded the configured size limit")
        return NewsletterEmail(
            id=email_id,
            sender=sender[:500],
            recipients=tuple(item[:500] for item in recipients),
            subject=(subject or "")[:2048],
            html=html_value,
            text=text_value,
            created_at=created_at[:100],
            message_id=(message_id or "")[:1000],
        )

    def forward_email(self, email_id: str, *, to: str, sender: str) -> None:
        """Re-deliver a received email to `to`, sent from our own verified `sender`.

        Resend has no server-side forward route. `resend.emails.receiving.forward()` in the
        Node SDK is a client-side composite -- it reads the received email, pulls its body
        and attachments, and posts them to the ordinary POST /emails send endpoint
        (resend-node src/emails/receiving/receiving.ts) -- and this mirrors it, sourcing the
        attachments from the receiving endpoints we already validate rather than from the
        raw .eml, so the download-URL host check still covers every byte we fetch.

        Reply-To carries the original sender, which is what lets the recipient answer the
        person who actually wrote in; the From has to be our own sending domain.
        """
        if not email_id or len(email_id) > 200:
            raise InvalidWebhookEvent("Inbound email ID is invalid")
        if not to or "@" not in to or len(to) > 320:
            raise ProviderRequestError("Forward destination is invalid")
        if not sender:
            raise ProviderRequestError("Forward sender is not configured")

        email = self.get_email(email_id)
        payload: dict[str, object] = {
            "from": sender,
            "to": [to],
            "subject": (SUPPORT_SUBJECT_PREFIX + email.subject)[:MAX_SUBJECT_LENGTH],
            "reply_to": [email.sender],
        }
        if email.html:
            payload["html"] = email.html
        if email.text or not email.html:
            # Resend rejects a send with neither body, and an empty forward is still worth
            # delivering: the headers and attachments are the message.
            payload["text"] = email.text or "(no message body)"
        attachments = self._forwardable_attachments(email_id)
        if attachments:
            payload["attachments"] = attachments

        with httpx.Client(
            base_url=RESEND_API_BASE_URL,
            headers={"Authorization": f"Bearer {self.api_key}", "User-Agent": USER_AGENT},
            timeout=httpx.Timeout(30.0, connect=5.0),
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
        ) as client:
            try:
                response = client.post("/emails", json=payload)
            except httpx.HTTPError as exc:
                # Never interpolate the payload: it is somebody's message to us.
                raise ProviderRequestError(f"Resend forward failed: {type(exc).__name__}") from exc
        if not 200 <= response.status_code < 300:
            raise ProviderRequestError(f"Resend forward returned HTTP {response.status_code}")

    def _forwardable_attachments(self, email_id: str) -> list[dict[str, str]]:
        """Every attachment of a received email, base64 encoded for POST /emails.

        Bounded by the same max_download_bytes budget the rest of the provider spends, so
        one forwarded message cannot pull an unbounded number of bytes through us. An
        attachment that does not fit is skipped rather than failing the whole forward --
        the recipient is better off with the message and most of its parts than with
        nothing at all.
        """
        forwarded: list[dict[str, str]] = []
        remaining = self.max_download_bytes
        for attachment in self.list_attachments(email_id):
            if attachment.size > remaining:
                LOGGER.warning(
                    "Skipped an oversize attachment while forwarding email_id=%s attachment_id=%s",
                    email_id,
                    attachment.id,
                )
                continue
            with self.download_chunks(attachment) as chunks:
                content = b"".join(chunks)
            if not content or len(content) > remaining:
                continue
            remaining -= len(content)
            entry = {
                "filename": attachment.filename,
                "content": base64.b64encode(content).decode("ascii"),
                "content_type": attachment.content_type,
            }
            # Inline images are referenced by cid: in the HTML, so the id has to survive
            # the round trip or the forwarded copy renders with broken images.
            content_id = attachment.content_id.strip().strip("<>")
            if content_id:
                entry["content_id"] = content_id
            forwarded.append(entry)
        return forwarded

    @contextmanager
    def download_chunks(self, attachment: InboundAttachment) -> Iterator[Iterable[bytes]]:
        self._validate_download_url(attachment.download_url)
        if attachment.size > self.max_download_bytes:
            raise EpubImportError("EPUB attachment exceeds the configured upload-size limit")
        with httpx.Client(
            timeout=httpx.Timeout(60.0, connect=5.0),
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
        ) as client:
            try:
                with client.stream(
                    "GET",
                    attachment.download_url,
                    headers={"User-Agent": USER_AGENT},
                ) as response:
                    if response.status_code != 200:
                        raise ProviderRequestError(f"Resend attachment download returned HTTP {response.status_code}")
                    content_length = response.headers.get("content-length")
                    if content_length:
                        try:
                            if int(content_length) > self.max_download_bytes:
                                raise EpubImportError("EPUB attachment exceeds the configured upload-size limit")
                        except ValueError as exc:
                            raise ProviderRequestError("Resend attachment download had an invalid length") from exc
                    yield response.iter_bytes(chunk_size=1024 * 1024)
            except httpx.HTTPError as exc:
                raise ProviderRequestError("Resend attachment download failed") from exc

    @staticmethod
    def _validate_download_url(download_url: str) -> None:
        parsed = urlsplit(download_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in RESEND_ATTACHMENT_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or parsed.fragment
        ):
            raise ProviderRequestError("Resend returned an unsafe attachment URL")


def _loggable_url(url: str) -> str:
    """Scheme, host and path only. Newsletter image URLs keep their query string so the
    fetch works, and that is exactly where publishers put per-subscriber tokens; a log line
    is not a place for those."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _normalize_address(value: object) -> str:
    if not isinstance(value, str) or len(value) > 320:
        return ""
    _, address = parseaddr(value, strict=True)
    if "@" not in address:
        return ""
    local, domain = address.rsplit("@", 1)
    if not local or not domain:
        return ""
    return f"{local}@{domain}".casefold()


def resolve_inbox_local(address: str, *, inbox_domain: str) -> str:
    """Return the inbox local part of an address on our inbox domain, else "".

    This is the whole of the routing decision: everything to the left of the @ is a
    candidate tenant inbox, and anything addressed elsewhere is not ours to deliver.
    """
    domain = inbox_domain.strip().strip(".").casefold()
    normalized = _normalize_address(address)
    if not domain or not normalized:
        return ""
    local, _, host = normalized.rpartition("@")
    return local if host == domain else ""


def _is_epub_candidate(attachment: InboundAttachment) -> bool:
    normalized_type = attachment.content_type.casefold().split(";", 1)[0].strip()
    return attachment.filename.casefold().endswith(".epub") or normalized_type == EPUB_MIME_TYPE


@dataclass(slots=True)
class _RemoteImageBudget:
    """What one delivery has left to spend on remote images.

    Mutable and shared: the closure handed to convert_newsletter draws from it image by
    image, and the cid: download path afterwards is seeded with what it spent, so remote
    and inline images together stay under one total.
    """

    remaining_bytes: int
    remaining_images: int
    # A monotonic instant, compared against the injected clock.
    deadline: float
    spent_bytes: int = 0


class InboundEmailService:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        storage: ItemStorage,
        provider: InboundEmailProvider | None,
        *,
        image_fetch: Callable[..., FetchedImage] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.database = database
        self.storage = storage
        self.provider = provider
        # Injected the same way the provider's transport is, so tests never resolve a
        # hostname or open a socket. None means the real SSRF-guarded fetcher.
        self.image_fetch = image_fetch
        # Monotonic, for the image time budget; injectable so a test can spend it.
        self._clock = clock
        # Read through the attribute rather than closing over the value, so the service's
        # one clock seam moves the reply window too.
        self._reply_limiter = RateLimiter(
            {REJECTION_REPLY_BUCKET: Policy(limit=REJECTION_REPLY_LIMIT, window_seconds=REJECTION_REPLY_WINDOW)},
            clock=lambda: self._clock(),
        )
        self._newsletter_lock = threading.Lock()

    def handle(self, raw_body: bytes, headers: Mapping[str, str]) -> InboundResult:
        if (
            self.provider is None
            or not self.settings.resend_api_key
            or not self.settings.resend_webhook_secret
            or not self.settings.inbox_domain
        ):
            raise InboundEmailDisabled("Resend inbound email is not fully configured")

        event = self.provider.verify_event(raw_body, headers)
        event_id = headers.get("svix-id", "")
        if not event_id or len(event_id) > 256:
            raise InvalidWebhookEvent("Webhook event ID is invalid")
        # Claimed before any work, not recorded after it. A delivery that outlives the
        # provider's patience is retried while the first attempt is still running, and a
        # claim made at the end let both attempts download and convert the same message.
        # A claim that fails is a replay, or that retry: either way the answer is the same.
        if not self.database.record_webhook_event(
            WEBHOOK_PROVIDER_NAME, event_id, datetime.now(UTC).isoformat(), PROCESSING_RESULT
        ):
            return InboundResult("duplicate_event", "Webhook event was already processed.")
        try:
            return self._handle_event(event_id, event)
        except BaseException:
            # A retry after a genuine failure -- provider down, disk full -- must be
            # processed, so the claim is handed back before the error reaches the webhook.
            self.database.release_webhook_event(WEBHOOK_PROVIDER_NAME, event_id)
            raise

    def _handle_event(self, event_id: str, event: Mapping[str, object]) -> InboundResult:
        assert self.provider is not None
        event_type = event.get("type")
        data = event.get("data")
        if event_type != "email.received" or not isinstance(data, dict):
            self._record(event_id, "ignored_event_type")
            return InboundResult("ignored", "Webhook event type was ignored.")

        tenant = self._resolve_tenant(data.get("to"))
        if tenant is None:
            # Resend delivers events for every address on the account's receiving domains,
            # so the one address we still care about here is the support address on the
            # apex. Everything else is not ours to deliver.
            forwarded = self._forward_to_support(event_id, data)
            if forwarded is not None:
                return forwarded
            # Discarded, not bounced and not an error: telling the sender that an address
            # does not exist would turn the webhook into an inbox-enumeration oracle.
            LOGGER.info("Discarded inbound email addressed to an unknown inbox")
            self._record(event_id, "unknown-inbox")
            return InboundResult("ignored", "Recipient does not match a known inbox.")

        sender = _normalize_address(data.get("from"))
        if not self.database.is_sender_allowed(tenant, sender):
            # Nothing is sent to anyone. A reply to the sender would make every inbox an
            # oracle; a reply to the owner per refused message would be the spam the
            # policy exists to stop. The account page shows the last few refusals instead.
            LOGGER.info("Refused inbound email for tenant=%s from a sender not on its list", tenant.id)
            if sender:
                self.database.record_refused_sender(tenant.id, sender, now=datetime.now(UTC).isoformat())
            self._record(event_id, "sender-refused")
            return InboundResult("ignored", "Sender is not allowed for this inbox.")

        email_id = data.get("email_id")
        if not isinstance(email_id, str) or not email_id or len(email_id) > 200:
            raise InvalidWebhookEvent("Inbound email ID is missing")

        scope = TenantScope(tenant.id)
        attachments = self.provider.list_attachments(email_id)
        candidates = [attachment for attachment in attachments if _is_epub_candidate(attachment)]

        # The product's central rule: an email carrying an EPUB is a book, an email
        # without one is an article. Nothing else about the message decides this.
        if not candidates:
            result = self.import_newsletter(scope, email_id, attachments=attachments)
            self._record(
                event_id,
                f"newsletter;imported={result.imported};duplicates={result.duplicates};rejected={result.rejected}",
            )
        else:
            result = self._import_books(scope, event_id, email_id, candidates)
        self._reply_to_rejection(tenant, result, subject=data.get("subject"))
        return result

    def _reply_to_rejection(self, tenant: Tenant, result: InboundResult, *, subject: object) -> None:
        """Tell the reader why something they sent did not arrive.

        The webhook's own result is seen by the provider and nobody else, so without this a
        refused delivery is indistinguishable from one that is still on its way. The reply
        goes to the account's registered address, never to the message's From: that header
        is whatever the sender wrote, and answering it would make every inbox a way to have
        us mail strangers. Best effort -- a reply that cannot be sent is logged, and the
        webhook result stands either way.
        """
        if not result.rejected or not self.settings.mail_from_address or not self.settings.resend_api_key:
            return
        # An address is guessable by design and the default policy accepts anyone, so a
        # stranger who sends rubbish to it makes us mail the owner once per message, from
        # our own domain. The cap turns that amplifier into a handful of messages an hour.
        # It counts every rejection, not only the ones from senders off the list: a direct
        # newsletter subscription is a listed sender and can be just as chatty.
        if not self._reply_limiter.allow(REJECTION_REPLY_BUCKET, tenant.id):
            LOGGER.info("Suppressed a rejection reply for tenant=%s: hourly cap reached", tenant.id)
            return
        subject_text = subject.strip() if isinstance(subject, str) else ""
        subject_text = " ".join(subject_text.split())[:200] or "your email"
        reasons = list(result.reasons) or [result.message]
        filed = ""
        if result.imported or result.duplicates:
            count = result.imported + result.duplicates
            noun, verb = ("items", "are") if count != 1 else ("item", "is")
            filed = f"\nThe other {count} {noun} from the same email {verb} in your library.\n"
        text = (
            f"Steepd could not file \"{subject_text}\".\n\n"
            + "".join(f"- {reason}\n" for reason in reasons)
            + filed
            + "\nNothing has been charged against your storage for it. If this looks wrong, reply to this "
            "email and a person will look.\n"
        )
        html = (
            '<!DOCTYPE html><html lang="en"><body>'
            f"<p>Steepd could not file <strong>{html_module.escape(subject_text)}</strong>.</p><ul>"
            + "".join(f"<li>{html_module.escape(reason)}</li>" for reason in reasons)
            + "</ul>"
            + (f"<p>{html_module.escape(filed.strip())}</p>" if filed else "")
            + "<p>Nothing has been charged against your storage for it. If this looks wrong, reply to "
            "this email and a person will look.</p></body></html>"
        )
        try:
            send_email(
                self.settings,
                to=tenant.email,
                subject=(REJECTION_SUBJECT_PREFIX + subject_text)[:MAX_SUBJECT_LENGTH],
                html=html,
                text=text,
            )
        except OutboundEmailError as exc:
            LOGGER.warning("Could not send a rejection reply reason=%s", type(exc).__name__)

    def _resolve_tenant(self, raw_recipients: object) -> Tenant | None:
        if not isinstance(raw_recipients, list):
            return None
        for recipient in raw_recipients[:100]:
            local = resolve_inbox_local(recipient, inbox_domain=self.settings.inbox_domain)
            if not local:
                continue
            tenant = self.database.tenant_by_inbox_local(local)
            if tenant is not None:
                return tenant
        return None

    def _addresses_tenant(self, scope: TenantScope, recipients: Sequence[str]) -> bool:
        for recipient in recipients:
            local = resolve_inbox_local(recipient, inbox_domain=self.settings.inbox_domain)
            if not local:
                continue
            tenant = self.database.tenant_by_inbox_local(local)
            if tenant is not None and tenant.id == scope.tenant_id:
                return True
        return False

    def _forward_to_support(self, event_id: str, data: Mapping[str, object]) -> InboundResult | None:
        """Relay mail addressed to the support address, or None if this is not support mail.

        None means "not handled" and leaves the caller's discard path untouched, which is
        what keeps the feature invisible while it is unconfigured.

        Loop safety: the forward goes out from our own MAIL_FROM_ADDRESS to the configured
        operator mailbox, so a bounce or auto-reply addressed back to the support address
        would be forwarded at most once more per inbound event, and the svix event-id dedup
        above stops a replayed event from amplifying. The actual loop breaker is the sender
        check below -- our own two addresses are never forwarded.
        """
        support_address = _normalize_address(self.settings.support_inbound_address)
        forward_address = self.settings.support_forward_address
        # Our own verified sending address. Config refuses to boot with support forwarding
        # configured and no MAIL_FROM_ADDRESS, so an empty one here means the whole feature
        # is off rather than half-configured.
        mail_from = self.settings.mail_from_address
        if not support_address or not forward_address or not mail_from:
            return None
        if not self._addresses_support(data.get("to"), support_address):
            return None

        email_id = data.get("email_id")
        if not isinstance(email_id, str) or not email_id or len(email_id) > 200:
            raise InvalidWebhookEvent("Inbound email ID is missing")

        # The webhook event carries the sender itself, so the loop check costs no provider
        # call: a message we generated is dropped before we ever read it back.
        loop_senders = {_normalize_address(forward_address), _normalize_address(mail_from)} - {""}
        sender = _normalize_address(data.get("from"))
        if sender and sender in loop_senders:
            LOGGER.warning("Dropped a support email sent from one of our own addresses email_id=%s", email_id)
            self._record(event_id, "support-loop-dropped")
            return InboundResult("ok", "Dropped a support email to avoid a mail loop.")

        assert self.provider is not None
        try:
            self.provider.forward_email(email_id, to=forward_address, sender=mail_from)
        except ProviderRequestError as exc:
            # str(exc) is safe to log: the provider keeps recipients, subjects and bodies
            # out of its messages. Returning success is deliberate -- a Resend retry would
            # re-forward the same message rather than fix the send.
            LOGGER.warning("Failed to forward a support email email_id=%s reason=%s", email_id, str(exc))
            self._record(event_id, "support-forward-failed")
            return InboundResult("ok", "Support email could not be forwarded.")

        LOGGER.info("Forwarded a support email to the operator mailbox email_id=%s", email_id)
        self._record(event_id, "support-forwarded")
        return InboundResult("ok", "Forwarded to support.")

    def _addresses_support(self, raw_recipients: object, support_address: str) -> bool:
        if not isinstance(raw_recipients, list):
            return False
        # The whole address, not the local part: "help@somewhere-else.example" is a
        # stranger's address that happens to share our local part, not our support inbox.
        return any(_normalize_address(recipient) == support_address for recipient in raw_recipients[:100])

    def _import_books(
        self,
        scope: TenantScope,
        event_id: str,
        email_id: str,
        candidates: Sequence[InboundAttachment],
    ) -> InboundResult:
        assert self.provider is not None
        imported = 0
        duplicates = 0
        rejected = 0
        reasons: list[str] = []
        for attachment in candidates:
            try:
                with self.provider.download_chunks(attachment) as chunks:
                    # store_chunks defaults to kind="book" -- the routing rule lives in that default.
                    result = self.storage.store_chunks(scope, chunks, filename=attachment.filename, source="resend")
                if result.duplicate:
                    duplicates += 1
                else:
                    imported += 1
            except EpubImportError as exc:
                rejected += 1
                reasons.append(f"{attachment.filename[:120]}: {exc}")
                LOGGER.warning("Rejected inbound EPUB attachment_id=%s reason=%s", attachment.id, str(exc))

        message = f"Imported {imported} EPUB{'s' if imported != 1 else ''} from inbound email."
        self._record(event_id, f"imported={imported};duplicates={duplicates};rejected={rejected}")
        LOGGER.info("%s email_id=%s duplicates=%d rejected=%d", message, email_id, duplicates, rejected)
        return InboundResult(
            "ok",
            message,
            imported=imported,
            duplicates=duplicates,
            rejected=rejected,
            tenant_id=scope.tenant_id,
            kind="book",
            reasons=tuple(reasons),
        )

    def import_newsletter(
        self,
        scope: TenantScope,
        email_id: str,
        *,
        attachments: Sequence[InboundAttachment] | None = None,
    ) -> InboundResult:
        if self.provider is None or not self.settings.resend_api_key or not self.settings.inbox_domain:
            raise InboundEmailDisabled("Inbound email is not fully configured")
        if not email_id or len(email_id) > 200:
            raise InvalidWebhookEvent("Inbound email ID is invalid")
        try:
            return self._import_newsletter(scope, email_id, attachments)
        except NewsletterConversionError as exc:
            LOGGER.warning("Rejected inbound newsletter email_id=%s reason=%s", email_id, str(exc))
            return InboundResult(
                "ok",
                "Newsletter could not be converted.",
                rejected=1,
                tenant_id=scope.tenant_id,
                kind="article",
                reasons=(str(exc),),
            )
        except EpubImportError as exc:
            # Storage refused the converted article: the quota is the realistic case. It is
            # a rejection like the one above, not an error -- a retry would meet the same
            # full account -- so it is recorded as done and the reader is told.
            LOGGER.warning("Could not store inbound newsletter email_id=%s reason=%s", email_id, str(exc))
            return InboundResult(
                "ok",
                "Newsletter could not be stored.",
                rejected=1,
                tenant_id=scope.tenant_id,
                kind="article",
                reasons=(str(exc),),
            )

    def _import_newsletter(
        self,
        scope: TenantScope,
        email_id: str,
        attachments: Sequence[InboundAttachment] | None,
    ) -> InboundResult:
        assert self.provider is not None
        email = self.provider.get_email(email_id)
        # Re-check the stored message against the tenant we resolved from the webhook. The
        # webhook payload and the stored email are two separate provider responses, and only
        # the stored one is what we actually convert.
        if not self._addresses_tenant(scope, email.recipients):
            raise InvalidWebhookEvent("Stored inbound email is not addressed to this tenant")
        tenant = self.database.tenant_by_id(scope.tenant_id)
        if tenant is None or not self.database.is_sender_allowed(tenant, _normalize_address(email.sender)):
            raise InvalidWebhookEvent("Stored inbound email is from a sender this inbox does not accept")

        if attachments is None:
            attachments = self.provider.list_attachments(email_id)
        inline_by_id: dict[str, InboundAttachment] = {}
        for attachment in attachments:
            content_id = normalize_content_id(attachment.content_id)
            content_type = attachment.content_type.casefold().split(";", 1)[0].strip()
            if content_id and content_type in SAFE_INLINE_IMAGE_TYPES:
                inline_by_id.setdefault(content_id, attachment)

        budget = _RemoteImageBudget(
            remaining_bytes=self.settings.newsletter_max_total_image_bytes,
            remaining_images=MAX_REMOTE_IMAGES_PER_NEWSLETTER,
            deadline=self._clock() + REMOTE_IMAGE_TIME_BUDGET_SECONDS,
        )
        document = convert_newsletter(
            email,
            public_base_url=self.settings.public_base_url,
            inline_image_types={key: value.content_type for key, value in inline_by_id.items()},
            max_output_bytes=self.settings.newsletter_max_body_bytes,
            fetch_remote_image=self._remote_image_fetcher(budget),
        )
        # Every remote image was fetched above, before this line, and must stay there: the
        # lock serialises deliveries across all tenants, so a slow
        # publisher CDN held inside it would stall every other tenant's mail.
        with self._newsletter_lock:
            if self.database.newsletter_delivery_exists(
                scope,
                NEWSLETTER_PROVIDER_NAME,
                email.id,
                email.message_id,
                document.content_sha256,
            ):
                return InboundResult(
                    "ok",
                    "Newsletter is already in your library.",
                    duplicates=1,
                    tenant_id=scope.tenant_id,
                    kind="article",
                )

            cid_resources = self._newsletter_resources(
                document,
                inline_by_id,
                initial_total_bytes=budget.spent_bytes,
            )
            # Order decides only the images/N numbering inside the archive; the two families
            # of placeholder location are distinct, so the anchored src rewrite in
            # publisher._package_resources cannot match across them.
            item_id = LocalNewsletterPublisher(self.storage, scope).publish(
                document,
                [*document.remote_resources, *cid_resources],
                (),
            )
            recorded = self.database.record_newsletter_delivery(
                scope,
                provider=NEWSLETTER_PROVIDER_NAME,
                email_id=email.id,
                message_id=email.message_id,
                content_sha256=document.content_sha256,
                source_url=document.source_url,
                item_id=item_id,
                forwarded_at=datetime.now(UTC).isoformat(),
            )
            if not recorded:
                raise NewsletterForwardingError("Newsletter delivery could not be recorded")

        LOGGER.info(
            "Imported newsletter into the library email_id=%s images=%d text_ratio=%.3f tables_flattened=%d "
            "remote_inlined=%d remote_failed=%d",
            email.id,
            document.stats.images_kept,
            document.stats.retained_text_ratio,
            document.stats.layout_tables_flattened,
            document.stats.remote_images_inlined,
            document.stats.remote_images_failed,
        )
        return InboundResult(
            "ok",
            "Imported 1 newsletter into your library.",
            imported=1,
            tenant_id=scope.tenant_id,
            kind="article",
        )

    def _remote_image_fetcher(self, budget: _RemoteImageBudget) -> RemoteImageFetcher:
        """The callable convert_newsletter drives to pull one remote image at a time.

        Its contract (newsletter.py) is that it returns None on any failure and never
        raises, because the converter treats None as "degrade this image to alt text" and
        has no other way to carry on. Only ImageFetchError is caught: that is the single
        error the fetcher raises for an image it cannot safely retrieve. Anything else is a
        bug in our own code, and swallowing it would file a silently image-less newsletter
        instead of failing the delivery, so it is left to propagate.
        """
        fetch = self.image_fetch if self.image_fetch is not None else fetch_remote_image

        def fetch_image(url: str) -> tuple[str, bytes] | None:
            if budget.remaining_images <= 0 or budget.remaining_bytes <= 0:
                return None
            if self._clock() >= budget.deadline:
                LOGGER.warning(
                    "Skipped remote newsletter image url=%s reason=delivery time budget spent", _loggable_url(url)
                )
                return None
            # Every attempt counts against the cap, not every success: the cap exists to
            # bound the outbound requests one webhook can make, and a failing fetch costs
            # the same connection as a successful one.
            budget.remaining_images -= 1
            max_bytes = min(self.settings.newsletter_max_image_bytes, budget.remaining_bytes)
            try:
                fetched = fetch(url, max_bytes=max_bytes)
            except ImageFetchError as exc:
                # Host and path only: the query string is where subscriber tokens live. The
                # response body never appears here either.
                LOGGER.warning("Skipped remote newsletter image url=%s reason=%s", _loggable_url(url), str(exc))
                return None
            if len(fetched.content) > max_bytes:
                # The real fetcher enforces max_bytes itself, so this only fires for a
                # fetcher that ignored it. Rejecting rather than trusting the payload is
                # what makes the byte arithmetic below true rather than hopeful.
                LOGGER.warning(
                    "Skipped remote newsletter image url=%s reason=exceeded the requested size", _loggable_url(url)
                )
                return None
            budget.remaining_bytes -= len(fetched.content)
            budget.spent_bytes += len(fetched.content)
            return fetched.content_type, fetched.content

        return fetch_image

    def _newsletter_resources(
        self,
        document: NewsletterDocument,
        inline_by_id: Mapping[str, InboundAttachment],
        *,
        initial_total_bytes: int = 0,
    ) -> list[NewsletterResource]:
        assert self.provider is not None
        resources: list[NewsletterResource] = []
        # Seeded with what the remote fetches already spent, so one newsletter cannot carry
        # 25MB of CDN images and another 25MB of cid: attachments.
        total_bytes = initial_total_bytes
        for reference in document.inline_images:
            attachment = inline_by_id.get(reference.content_id)
            if attachment is None:
                raise NewsletterConversionError("Referenced inline image is missing")
            if attachment.size <= 0 or attachment.size > self.settings.newsletter_max_image_bytes:
                raise NewsletterConversionError("Inline newsletter image exceeds the configured size limit")
            with self.provider.download_chunks(attachment) as chunks:
                content_parts: list[bytes] = []
                image_bytes = 0
                for chunk in chunks:
                    image_bytes += len(chunk)
                    total_bytes += len(chunk)
                    if image_bytes > self.settings.newsletter_max_image_bytes:
                        raise NewsletterConversionError("Inline newsletter image exceeds the configured size limit")
                    if total_bytes > self.settings.newsletter_max_total_image_bytes:
                        raise NewsletterConversionError("Newsletter images exceed the configured total-size limit")
                    content_parts.append(chunk)
            content = b"".join(content_parts)
            if not content:
                raise NewsletterConversionError("Inline newsletter image is empty")
            resources.append(
                NewsletterResource(
                    location=reference.location,
                    content_type=reference.content_type,
                    content=content,
                )
            )
        return resources

    def _record(self, event_id: str, result: str) -> None:
        """Replace the claim made in handle() with what the event came to."""
        self.database.update_webhook_event(WEBHOOK_PROVIDER_NAME, event_id, result)
