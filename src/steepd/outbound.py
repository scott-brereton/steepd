"""Outbound transactional email over Resend.

The service can receive email (inbound.py) but had no way to send any -- the web
sign-in layer needs to deliver magic-link emails, which are single-use credentials.
This module is deliberately minimal: one function, one provider, no queue or retry.
Recipient addresses, subjects and bodies are never included in raised exception
messages or logged, since a magic link in a log line would be a bearer credential
sitting in plaintext.
"""

from __future__ import annotations

import httpx

from steepd.config import Settings

RESEND_API_BASE_URL = "https://api.resend.com"
USER_AGENT = "Steepd/0.1"

MAX_RECIPIENT_LENGTH = 320
MAX_SUBJECT_LENGTH = 998


class OutboundEmailError(RuntimeError):
    pass


class OutboundEmailDisabled(OutboundEmailError):
    pass


def send_email(
    settings: Settings,
    *,
    to: str,
    subject: str,
    html: str,
    text: str = "",
    transport: httpx.BaseTransport | None = None,
) -> None:
    if not settings.resend_api_key or not settings.mail_from_address:
        raise OutboundEmailDisabled("Outbound email is not fully configured")
    if not to or "@" not in to or len(to) > MAX_RECIPIENT_LENGTH:
        raise OutboundEmailError("Outbound email recipient is invalid")
    if len(subject) > MAX_SUBJECT_LENGTH:
        raise OutboundEmailError("Outbound email subject is too long")

    payload: dict[str, object] = {
        "from": settings.mail_from_address,
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if text:
        payload["text"] = text

    with httpx.Client(
        timeout=httpx.Timeout(20.0, connect=5.0),
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        try:
            response = client.post(
                f"{RESEND_API_BASE_URL}/emails",
                json=payload,
                headers={
                    "Authorization": f"Bearer {settings.resend_api_key}",
                    "User-Agent": USER_AGENT,
                },
            )
        except httpx.HTTPError as exc:
            # Never interpolate the recipient, subject or body here: this message can
            # end up in logs, and a magic link is a credential.
            raise OutboundEmailError(f"Resend send failed: {type(exc).__name__}") from exc

    if not 200 <= response.status_code < 300:
        raise OutboundEmailError(f"Resend send returned HTTP {response.status_code}")
