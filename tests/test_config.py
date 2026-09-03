"""Confirms the environment the README documents is actually enough to boot the service.

The four pre-tenant global basic-auth settings (BOOKS_ADMIN_USERNAME,
BOOKS_ADMIN_PASSWORD, BOOKS_OPDS_USERNAME, BOOKS_OPDS_PASSWORD) used to be required
here even though per-tenant device auth replaced them and nothing read them -- so the
README's own documented run command raised ConfigurationError. This test pins the
documented command as the contract: only the environment variables the README tells a
reader to set must be enough for Settings.from_env() to succeed.
"""

from __future__ import annotations

import pytest

from steepd.config import ConfigurationError, Settings

# Every environment variable Settings.from_env() looks at. Cleared before each test so
# a variable set in the runner's shell (or left over from another test) can't hide a
# newly-added required variable that the README doesn't yet document.
ALL_SETTINGS_ENV_VARS = (
    "APP_ENVIRONMENT",
    "PUBLIC_BASE_URL",
    "DATA_DIR",
    "MAX_UPLOAD_BYTES",
    "MAX_ARCHIVE_UNCOMPRESSED_BYTES",
    "MAX_ARCHIVE_MEMBERS",
    "MAX_COMPRESSION_RATIO",
    "SERVICE_CHECK_TIMEOUT_SECONDS",
    "WEBHOOK_MAX_BYTES",
    "INBOX_DOMAIN",
    "RESEND_API_KEY",
    "RESEND_WEBHOOK_SECRET",
    "NEWSLETTER_MAX_BODY_BYTES",
    "NEWSLETTER_MAX_IMAGE_BYTES",
    "NEWSLETTER_MAX_TOTAL_IMAGE_BYTES",
    "MAIL_FROM_ADDRESS",
    "SUPPORT_CONTACT",
    "SOURCE_REPOSITORY_URL",
    "SUPPORT_INBOUND_ADDRESS",
    "SUPPORT_FORWARD_ADDRESS",
    "STATS_TOKEN",
)


@pytest.fixture(autouse=True)
def _clean_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ALL_SETTINGS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_settings_boot_from_the_readme_documented_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """README.md's "Run the service" section documents exactly:

        PUBLIC_BASE_URL=http://localhost:8000 DATA_DIR=./.localdata python -m steepd

    A stranger following that command must get a running service, not a
    ConfigurationError about environment variables the README never mentioned.
    """
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("DATA_DIR", "./.localdata")

    settings = Settings.from_env()

    assert settings.public_base_url == "http://localhost:8000"
    assert str(settings.data_dir).endswith(".localdata")


def test_mail_from_address_defaults_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Outbound email must be off unless an operator explicitly sets a sender address -
    a blank MAIL_FROM_ADDRESS is how outbound.send_email() knows to refuse to send."""
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("DATA_DIR", "./.localdata")

    settings = Settings.from_env()

    assert settings.mail_from_address == ""


def test_mail_from_address_is_read_and_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Surrounding whitespace in the env var must not silently produce a broken sender
    address on outbound sends."""
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("DATA_DIR", "./.localdata")
    monkeypatch.setenv("MAIL_FROM_ADDRESS", "  Steepd <noreply@steepd.app>  ")

    settings = Settings.from_env()

    assert settings.mail_from_address == "Steepd <noreply@steepd.app>"


def _minimal_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("DATA_DIR", "./.localdata")


def test_the_public_page_links_default_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """The public pages render a support address and a source link only when they exist.
    Defaulting to a placeholder would ship a dead mailto and a 404 to a repository that
    has not been published yet."""
    _minimal_env(monkeypatch)

    settings = Settings.from_env()

    assert settings.support_contact == ""
    assert settings.source_repository_url == ""


def test_the_support_contact_is_read_and_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    _minimal_env(monkeypatch)
    monkeypatch.setenv("SUPPORT_CONTACT", "  hello@steepd.app  ")

    assert Settings.from_env().support_contact == "hello@steepd.app"


def test_the_source_repository_url_is_read_and_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    """The trailing slash goes so the rendered href matches what was configured."""
    _minimal_env(monkeypatch)
    monkeypatch.setenv("SOURCE_REPOSITORY_URL", "  https://code.example.test/steepd/  ")

    assert Settings.from_env().source_repository_url == "https://code.example.test/steepd"


@pytest.mark.parametrize(
    "value",
    ["http://code.example.test/steepd", "code.example.test/steepd", "https://", "ftp://example.test"],
)
def test_a_malformed_source_repository_url_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Set-but-wrong must fail loudly at start-up rather than render as a broken link.

    Plain HTTP is refused alongside the obviously-malformed cases: the link sits on an
    HTTPS marketing page, where a downgraded one is either blocked or a warning.
    """
    _minimal_env(monkeypatch)
    monkeypatch.setenv("SOURCE_REPOSITORY_URL", value)

    with pytest.raises(ConfigurationError, match="SOURCE_REPOSITORY_URL"):
        Settings.from_env()


def test_support_forwarding_defaults_to_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """No support address configured means inbound.py keeps discarding every message that
    does not resolve to a tenant inbox, exactly as it did before forwarding existed."""
    _minimal_env(monkeypatch)

    settings = Settings.from_env()

    assert settings.support_inbound_address == ""
    assert settings.support_forward_address == ""


def test_support_addresses_are_read_and_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    """The inbound address is casefolded because it is compared against normalized
    recipients; the forward address is only stripped, since it is a delivery destination
    and the local part of a real mailbox is case-sensitive."""
    _minimal_env(monkeypatch)
    monkeypatch.setenv("INBOX_DOMAIN", "read.steepd.app")
    monkeypatch.setenv("MAIL_FROM_ADDRESS", "Steepd <noreply@steepd.app>")
    monkeypatch.setenv("SUPPORT_INBOUND_ADDRESS", "  Help@Steepd.App  ")
    monkeypatch.setenv("SUPPORT_FORWARD_ADDRESS", "  Operator@example.com  ")

    settings = Settings.from_env()

    assert settings.support_inbound_address == "help@steepd.app"
    assert settings.support_forward_address == "Operator@example.com"


@pytest.mark.parametrize(
    ("inbound", "forward"),
    [("help@steepd.app", ""), ("", "operator@example.com")],
)
def test_half_configured_support_forwarding_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch, inbound: str, forward: str
) -> None:
    """A forwarder with no destination silently drops support mail, and a destination
    nothing forwards to is a mailbox nobody writes into. Both are half-applied deployment
    changes, so they fail at boot rather than at the first person asking for help."""
    _minimal_env(monkeypatch)
    monkeypatch.setenv("SUPPORT_INBOUND_ADDRESS", inbound)
    monkeypatch.setenv("SUPPORT_FORWARD_ADDRESS", forward)

    with pytest.raises(ConfigurationError, match="SUPPORT_INBOUND_ADDRESS"):
        Settings.from_env()


def test_a_support_address_on_the_inbox_domain_refuses_to_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Support must live on a different domain from the tenant inboxes. Sharing one, a
    tenant allocated the inbox local part "help" would have their deliveries relayed to
    the operator's mailbox instead of filed in their library."""
    _minimal_env(monkeypatch)
    monkeypatch.setenv("INBOX_DOMAIN", "read.steepd.app")
    monkeypatch.setenv("MAIL_FROM_ADDRESS", "Steepd <noreply@steepd.app>")
    monkeypatch.setenv("SUPPORT_INBOUND_ADDRESS", "help@read.steepd.app")
    monkeypatch.setenv("SUPPORT_FORWARD_ADDRESS", "operator@example.com")

    with pytest.raises(ConfigurationError, match="SUPPORT_INBOUND_ADDRESS"):
        Settings.from_env()


def test_support_forwarding_without_a_sending_address_refuses_to_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    """A forward is an ordinary send from our own verified domain. With no MAIL_FROM_ADDRESS
    there is nothing to send it as, and every support email would fail at the provider."""
    _minimal_env(monkeypatch)
    monkeypatch.setenv("SUPPORT_INBOUND_ADDRESS", "help@steepd.app")
    monkeypatch.setenv("SUPPORT_FORWARD_ADDRESS", "operator@example.com")

    with pytest.raises(ConfigurationError, match="MAIL_FROM_ADDRESS"):
        Settings.from_env()
