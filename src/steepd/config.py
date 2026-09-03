from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigurationError(RuntimeError):
    """Raised when deployment configuration is unsafe or incomplete."""


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigurationError(f"Missing required environment variable: {name}")
    return value


def _positive_int(name: str, default: int, *, maximum: int | None = None) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value <= 0 or (maximum is not None and value > maximum):
        suffix = f" no greater than {maximum}" if maximum is not None else ""
        raise ConfigurationError(f"{name} must be positive and{suffix}")
    return value


def _positive_float(name: str, default: float, *, maximum: float | None = None) -> float:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if value <= 0 or (maximum is not None and value > maximum):
        suffix = f" no greater than {maximum}" if maximum is not None else ""
        raise ConfigurationError(f"{name} must be positive and{suffix}")
    return value


def _base_url(name: str, default: str = "", *, required: bool = False) -> str:
    raw = _required(name) if required else os.getenv(name, default).strip()
    if not raw:
        return ""
    value = raw.rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
        raise ConfigurationError(f"{name} must be an absolute HTTP(S) base URL without a query or fragment")
    return value


def _https_url(name: str) -> str:
    """An optional absolute HTTPS URL, or "" when unset.

    HTTPS only, unlike _base_url: the one caller is a link rendered on a public page, and
    a plain-HTTP link there would be downgraded or blocked rather than followed. An unset
    value is not a failure -- the page simply omits the link -- but a set-and-malformed
    one is, because it would ship as a dead link nobody notices.
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return ""
    value = raw.rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ConfigurationError(f"{name} must be an absolute HTTPS URL")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    public_base_url: str
    app_environment: str = "development"
    max_upload_bytes: int = 50 * 1024 * 1024
    max_archive_bytes: int = 250 * 1024 * 1024
    max_archive_members: int = 5_000
    max_compression_ratio: float = 150.0
    service_check_timeout_seconds: float = 2.0
    webhook_max_bytes: int = 1024 * 1024
    # The domain every tenant inbox lives under, e.g. "read.steepd.app" for a.1@read.steepd.app.
    # An inbound recipient outside this domain never resolves to a tenant.
    inbox_domain: str = ""
    resend_api_key: str = ""
    resend_webhook_secret: str = ""
    # The Resend-verified sender address outbound mail is sent from, e.g.
    # "Steepd <noreply@steepd.app>". Empty disables outbound email entirely.
    mail_from_address: str = ""
    newsletter_max_body_bytes: int = 5 * 1024 * 1024
    newsletter_max_image_bytes: int = 10 * 1024 * 1024
    newsletter_max_total_image_bytes: int = 25 * 1024 * 1024
    # Both are rendered on the public pages only when set. Empty is the honest default:
    # a placeholder mailto or a link to a repository that does not exist yet is worse
    # than no link at all, so the pages omit the whole line instead.
    support_contact: str = ""
    source_repository_url: str = ""
    # Bearer token for GET /admin/stats. Empty keeps the route answering 404 to everyone;
    # the figures it serves are counts, not content, but they are nobody else's business.
    stats_token: str = ""
    # The address on our receiving domains whose mail is relayed to the operator, e.g.
    # "help@steepd.app". Resend delivers webhooks for every address on the account's
    # domains, not only tenant inboxes, so steepd forwards this one itself. Casefolded
    # because it is matched against normalized recipients. Both empty disables forwarding.
    support_inbound_address: str = ""
    # Where support_inbound_address is relayed to: the operator's real mailbox. Not
    # casefolded -- it is a delivery destination, and local parts are case-sensitive.
    support_forward_address: str = ""

    @classmethod
    def from_env(cls) -> Settings:
        environment = os.getenv("APP_ENVIRONMENT", "development").strip().lower() or "development"
        public_base_url = _base_url("PUBLIC_BASE_URL", "http://localhost:8000", required=True)
        if environment == "production" and not public_base_url.startswith("https://"):
            raise ConfigurationError("PUBLIC_BASE_URL must use HTTPS in production")

        inbox_domain = os.getenv("INBOX_DOMAIN", "").strip().strip(".").casefold()
        mail_from_address = os.getenv("MAIL_FROM_ADDRESS", "").strip()
        support_inbound_address = os.getenv("SUPPORT_INBOUND_ADDRESS", "").strip().casefold()
        support_forward_address = os.getenv("SUPPORT_FORWARD_ADDRESS", "").strip()
        # A forwarder with no destination, or a destination nothing forwards to, is a
        # half-applied deployment change rather than a choice worth honouring.
        if bool(support_inbound_address) != bool(support_forward_address):
            raise ConfigurationError("SUPPORT_INBOUND_ADDRESS and SUPPORT_FORWARD_ADDRESS must be set together")
        # A forward is an ordinary send from our own verified domain, so without a sender
        # address there is nothing to send it as.
        if support_inbound_address and not mail_from_address:
            raise ConfigurationError("SUPPORT_INBOUND_ADDRESS requires MAIL_FROM_ADDRESS")
        # Support has to live on a different domain from the tenant inboxes -- on
        # INBOX_DOMAIN a tenant whose inbox local part happened to be "help" would have
        # part of their mail silently relayed to the operator instead of their library.
        if inbox_domain and support_inbound_address.endswith(f"@{inbox_domain}"):
            raise ConfigurationError("SUPPORT_INBOUND_ADDRESS must not be on INBOX_DOMAIN")

        return cls(
            data_dir=Path(os.getenv("DATA_DIR", "./data")).expanduser().resolve(),
            public_base_url=public_base_url,
            app_environment=environment,
            max_upload_bytes=_positive_int("MAX_UPLOAD_BYTES", 50 * 1024 * 1024, maximum=500 * 1024 * 1024),
            max_archive_bytes=_positive_int(
                "MAX_ARCHIVE_UNCOMPRESSED_BYTES", 250 * 1024 * 1024, maximum=2 * 1024 * 1024 * 1024
            ),
            max_archive_members=_positive_int("MAX_ARCHIVE_MEMBERS", 5_000, maximum=50_000),
            max_compression_ratio=_positive_float("MAX_COMPRESSION_RATIO", 150.0, maximum=10_000.0),
            service_check_timeout_seconds=_positive_float("SERVICE_CHECK_TIMEOUT_SECONDS", 2.0, maximum=10.0),
            webhook_max_bytes=_positive_int("WEBHOOK_MAX_BYTES", 1024 * 1024, maximum=10 * 1024 * 1024),
            inbox_domain=inbox_domain,
            resend_api_key=os.getenv("RESEND_API_KEY", "").strip(),
            resend_webhook_secret=os.getenv("RESEND_WEBHOOK_SECRET", "").strip(),
            mail_from_address=mail_from_address,
            newsletter_max_body_bytes=_positive_int(
                "NEWSLETTER_MAX_BODY_BYTES", 5 * 1024 * 1024, maximum=25 * 1024 * 1024
            ),
            newsletter_max_image_bytes=_positive_int(
                "NEWSLETTER_MAX_IMAGE_BYTES", 10 * 1024 * 1024, maximum=50 * 1024 * 1024
            ),
            newsletter_max_total_image_bytes=_positive_int(
                "NEWSLETTER_MAX_TOTAL_IMAGE_BYTES", 25 * 1024 * 1024, maximum=100 * 1024 * 1024
            ),
            support_contact=os.getenv("SUPPORT_CONTACT", "").strip(),
            source_repository_url=_https_url("SOURCE_REPOSITORY_URL"),
            stats_token=os.getenv("STATS_TOKEN", "").strip(),
            support_inbound_address=support_inbound_address,
            support_forward_address=support_forward_address,
        )
