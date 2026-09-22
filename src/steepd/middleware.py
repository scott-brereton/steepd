from __future__ import annotations

from starlette.responses import HTMLResponse, JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject bounded upload/webhook requests before framework body parsing."""

    def __init__(self, app: ASGIApp, *, route_limits: dict[str, int], html_paths: tuple[str, ...] = ()) -> None:
        self.app = app
        self.route_limits = route_limits
        self.html_paths = html_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        maximum = self.route_limits.get(path)
        if maximum is None:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > maximum:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > maximum:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("path") in self.html_paths:
            response = HTMLResponse(
                '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                '<title>Steepd — submission too large</title><style>'
                'body{margin:0;background:#F5F2ED;color:#1A1A2E;font:17px/1.6 system-ui,sans-serif}'
                'main{max-width:612px;margin:64px auto;padding:0 24px}h1{font-size:28px;line-height:1.2}'
                'a{color:#8B5E3C}</style></head><body><main><h1>That submission is too large.</h1>'
                '<p>Choose a smaller EPUB or a shorter article URL and try again.</p>'
                '<p><a href="/account#add">Back to your account</a></p></main></body></html>',
                status_code=413,
                headers={"Cache-Control": "private, no-store"},
            )
        else:
            response = JSONResponse({"detail": "Request body exceeds the configured limit"}, status_code=413)
        await response(scope, receive, send)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                        (
                            b"content-security-policy",
                            b"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                            b"base-uri 'none'; frame-ancestors 'none'",
                        ),
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, secure_send)
