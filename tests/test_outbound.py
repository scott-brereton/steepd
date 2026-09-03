from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from steepd.config import Settings
from steepd.outbound import OutboundEmailDisabled, OutboundEmailError, send_email

API_KEY = "re_test_api_key"
FROM_ADDRESS = "Steepd <noreply@steepd.app>"
RECIPIENT = "reader@example.com"


def configured(settings: Settings) -> Settings:
    """Settings with outbound email enabled: a Resend API key and a sender address."""
    return replace(settings, resend_api_key=API_KEY, mail_from_address=FROM_ADDRESS)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return configured(Settings(data_dir=tmp_path, public_base_url="http://localhost:8000"))


def test_send_email_posts_the_expected_request_with_text(settings: Settings) -> None:
    """Pins the exact wire format: method, URL, bearer auth and JSON body Resend expects,
    including the optional text part when the caller supplies one."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"id": "email_123"})

    send_email(
        settings,
        to=RECIPIENT,
        subject="Your sign-in link",
        html="<p>Click to sign in.</p>",
        text="Click to sign in.",
        transport=httpx.MockTransport(handler),
    )

    assert len(captured) == 1
    request = captured[0]
    assert request.method == "POST"
    assert str(request.url) == "https://api.resend.com/emails"
    assert request.headers["Authorization"] == f"Bearer {API_KEY}"
    assert request.headers["User-Agent"] == "Steepd/0.1"
    body = json.loads(request.content)
    assert body == {
        "from": FROM_ADDRESS,
        "to": [RECIPIENT],
        "subject": "Your sign-in link",
        "html": "<p>Click to sign in.</p>",
        "text": "Click to sign in.",
    }


def test_send_email_omits_text_when_not_supplied(settings: Settings) -> None:
    """text is optional on the public API; the JSON body must not carry an empty text
    field Resend was never asked to send."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"id": "email_123"})

    send_email(
        settings,
        to=RECIPIENT,
        subject="Your sign-in link",
        html="<p>Click to sign in.</p>",
        transport=httpx.MockTransport(handler),
    )

    body = json.loads(captured[0].content)
    assert "text" not in body


def test_send_email_disabled_without_api_key(settings: Settings) -> None:
    """A tenant that never configured Resend must get a clear disabled signal, not a
    request sent with an empty bearer token."""
    with pytest.raises(OutboundEmailDisabled):
        send_email(
            replace(settings, resend_api_key=""),
            to=RECIPIENT,
            subject="Your sign-in link",
            html="<p>Click to sign in.</p>",
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )


def test_send_email_disabled_without_mail_from_address(settings: Settings) -> None:
    """Resend requires a verified sender; without one configured, sending must refuse
    up front rather than let Resend reject the request."""
    with pytest.raises(OutboundEmailDisabled):
        send_email(
            replace(settings, mail_from_address=""),
            to=RECIPIENT,
            subject="Your sign-in link",
            html="<p>Click to sign in.</p>",
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )


def test_send_email_raises_on_non_2xx_response(settings: Settings) -> None:
    """A Resend-side rejection (bad sender, rate limit, etc.) must surface as our own
    typed error, not succeed silently or leak an httpx exception type to callers."""
    with pytest.raises(OutboundEmailError):
        send_email(
            settings,
            to=RECIPIENT,
            subject="Your sign-in link",
            html="<p>Click to sign in.</p>",
            transport=httpx.MockTransport(lambda request: httpx.Response(500, text="oops")),
        )


def test_send_email_raises_on_connection_error(settings: Settings) -> None:
    """A network failure reaching Resend must not propagate as a raw httpx exception --
    callers only need to know the send failed."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(OutboundEmailError):
        send_email(
            settings,
            to=RECIPIENT,
            subject="Your sign-in link",
            html="<p>Click to sign in.</p>",
            transport=httpx.MockTransport(handler),
        )


def test_failed_send_exception_message_never_contains_the_recipient(settings: Settings) -> None:
    """Magic-link emails are credentials and recipients are PII: pins that neither ever
    ends up in the exception message a caller might log."""
    secret_recipient = "very-specific-reader@example.com"

    with pytest.raises(OutboundEmailError) as excinfo:
        send_email(
            settings,
            to=secret_recipient,
            subject="Your sign-in link",
            html="<p>Click to sign in.</p>",
            transport=httpx.MockTransport(lambda request: httpx.Response(500, text="oops")),
        )

    assert secret_recipient not in str(excinfo.value)


def test_send_email_rejects_recipient_without_at_sign(settings: Settings) -> None:
    """A malformed recipient must be caught before any request is made to Resend."""
    with pytest.raises(OutboundEmailError):
        send_email(
            settings,
            to="not-an-email",
            subject="Your sign-in link",
            html="<p>Click to sign in.</p>",
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )


def test_send_email_rejects_an_oversized_recipient(settings: Settings) -> None:
    """RFC 5321 caps a mailbox at 320 characters; anything longer is not a real address
    and must not be sent to Resend."""
    oversized = f"{'a' * 315}@example.com"
    assert len(oversized) > 320
    with pytest.raises(OutboundEmailError):
        send_email(
            settings,
            to=oversized,
            subject="Your sign-in link",
            html="<p>Click to sign in.</p>",
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )
