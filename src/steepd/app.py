# No `from __future__ import annotations` here, deliberately. FastAPI resolves a route's
# annotations at registration time against module globals, and the Annotated dependency
# aliases below are locals of create_app -- they close over `database`, so they cannot be
# module-level. Under PEP 563 those annotations arrive as strings that never resolve, and
# every scoped route silently degrades into one expecting a query parameter (422).
import hmac
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.concurrency import run_in_threadpool

from steepd.auth import authenticate_device
from steepd.config import Settings
from steepd.db import Database
from steepd.epub import EPUB_MIME_TYPE, EpubImportError
from steepd.imagefetch import FetchedImage
from steepd.inbound import (
    InboundEmailDisabled,
    InboundEmailProvider,
    InboundEmailService,
    InvalidWebhookEvent,
    InvalidWebhookSignature,
    ProviderRequestError,
    ResendInboundProvider,
)
from steepd.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from steepd.models import Tenant
from steepd.newsletter import NewsletterForwardingError
from steepd.opds import (
    ACQUISITION_TYPE,
    ACTION_VERBS,
    NAVIGATION_TYPE,
    author_from_token,
    build_authors_catalog,
    build_item_menu,
    build_items_catalog,
    build_publication_catalog,
    build_publications_catalog,
    build_result_feed,
    build_root_catalog,
    build_site_catalog,
    build_sites_catalog,
)
from steepd.publications import Organizer, build_classifier, start_organizer_thread
from steepd.ratelimit import RateLimiter, RateLimitMiddleware
from steepd.retention import start_retention_thread
from steepd.stats import render_stats
from steepd.storage import TRASH_RETENTION, ItemStorage
from steepd.tenancy import TenantScope
from steepd.web import (
    FORM_ROUTE_LIMITS,
    SAVE_URL_PATH,
    UPLOAD_FORM_OVERHEAD,
    UPLOAD_PATH,
    build_web_router,
    is_site_host,
)

LOGGER = logging.getLogger("steepd.app")

BASIC_REALM = "Steepd"
WEBHOOK_PATH = "/webhooks/inbound-email"


def _xml_response(content: bytes, media_type: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Cache-Control": "private, no-store", "Content-Disposition": "inline"},
    )


def _unauthorized() -> HTTPException:
    # WWW-Authenticate is what makes an e-reader prompt for credentials rather than
    # silently show an empty library.
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid device credentials",
        headers={"WWW-Authenticate": f'Basic realm="{BASIC_REALM}", charset="UTF-8"'},
    )


def create_app(
    settings: Settings | None = None,
    *,
    inbound_provider: InboundEmailProvider | None = None,
    image_fetch: Callable[..., FetchedImage] | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()

    # Construct and initialize eagerly, before returning. Doing this in a lifespan handler
    # would leave app.state empty and the schema absent until the first startup event, and
    # a service that cannot open its database should fail here rather than on first request.
    database = Database(settings.data_dir / "steepd.sqlite3")
    storage = ItemStorage(settings, database)
    database.initialize()
    storage.initialize()

    # One instance serves everything, so the sweep is an in-process thread rather than
    # scheduler infrastructure. Production only: a test or a local run must not grow a
    # background thread that deletes the fixtures out from under it.
    if settings.app_environment == "production":
        start_retention_thread(database, storage)

    # The organizer is built either way, because the account pages read its status and
    # every manual correction works without it; only the thread that spends money is
    # gated. Same rule as the sweep: no test grows a background thread, and a deployment
    # without a key gets an organizer that simply never finds a classifier to use.
    organizer = Organizer(database, storage, settings, build_classifier(settings))
    if settings.app_environment == "production" and organizer.classifier is not None:
        start_organizer_thread(organizer)

    if (
        inbound_provider is None
        and settings.resend_api_key
        and settings.resend_webhook_secret
        and settings.inbox_domain
    ):
        inbound_provider = ResendInboundProvider(
            api_key=settings.resend_api_key,
            webhook_secret=settings.resend_webhook_secret,
            max_download_bytes=settings.max_upload_bytes,
        )
    inbound_service = InboundEmailService(settings, database, storage, inbound_provider, image_fetch=image_fetch)

    app = FastAPI(
        title="Steepd",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.storage = storage
    app.state.inbound_service = inbound_service
    app.state.organizer = organizer

    # Middleware is added innermost first, so this block reads inside-out: the finished
    # stack is SecurityHeaders -> RateLimit -> BodySizeLimit -> routes.
    #
    # SecurityHeadersMiddleware stays outermost so its headers are attached to responses
    # the inner two return without ever calling the app -- the 413 below and the 429
    # above it. RateLimitMiddleware sits above BodySizeLimitMiddleware so a refused
    # sign-up is answered before any body is read: the size limit works by wrapping
    # receive, and a limiter underneath it would only refuse after the upload had already
    # been pulled off the socket.
    app.add_middleware(
        BodySizeLimitMiddleware,
        route_limits={
            WEBHOOK_PATH: settings.webhook_max_bytes,
            **FORM_ROUTE_LIMITS,
            UPLOAD_PATH: settings.max_upload_bytes + UPLOAD_FORM_OVERHEAD,
        },
        html_paths=(UPLOAD_PATH, SAVE_URL_PATH),
    )
    # Held on app.state as well as inside the middleware: state is per app instance rather
    # than module-global, the same as database and storage, so two apps in one process
    # (which is what the test suite is) never share windows.
    app.state.rate_limiter = RateLimiter()
    app.add_middleware(RateLimitMiddleware, limiter=app.state.rate_limiter)
    app.add_middleware(SecurityHeadersMiddleware)

    # The browser layer. Built through a function because its routes need `database` and
    # `settings` the same way device_scope below does, and neither can be a module global.
    app.include_router(
        build_web_router(settings, database, storage, organizer, save_url_article=inbound_service.save_url_article)
    )

    basic = HTTPBasic(auto_error=False)

    def device_tenant(credentials: Annotated[HTTPBasicCredentials | None, Depends(basic)]) -> Tenant:
        """Resolve HTTP Basic credentials to the tenant every OPDS route reads through."""
        if credentials is None:
            raise _unauthorized()
        tenant = authenticate_device(database, credentials.username, credentials.password)
        if tenant is None:
            raise _unauthorized()
        return tenant

    DeviceTenant = Annotated[Tenant, Depends(device_tenant)]

    def device_scope(tenant: DeviceTenant) -> TenantScope:
        return TenantScope(tenant.id)

    # Named once so every OPDS route below takes the same scope the same way. There is no
    # route that reads items without one. FastAPI resolves device_tenant once per request,
    # so a route taking both pays for one password check.
    DeviceScope = Annotated[TenantScope, Depends(device_scope)]
    Page = Annotated[int, Query(ge=1)]

    def reader_actions_on(tenant: DeviceTenant) -> bool:
        return settings.reader_actions_enabled and tenant.reader_actions

    # Whether shelves list items as menus (steepd.opds) rather than direct downloads.
    Interactive = Annotated[bool, Depends(reader_actions_on)]

    def _items_feed(
        scope: TenantScope, *, title: str, feed_id: str, page: int, interactive: bool, **filters: str | bool | None
    ) -> Response:
        return _xml_response(
            build_items_catalog(
                database,
                scope,
                settings.public_base_url,
                title=title,
                feed_id=feed_id,
                page=page,
                interactive=interactive,
                **filters,
            ),
            ACQUISITION_TYPE,
        )

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        healthy = await run_in_threadpool(lambda: database.health() and storage.storage_is_healthy())
        if not healthy:
            return JSONResponse({"status": "error"}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        # Still 200: low is a warning for the uptime worker to relay, not an outage. The
        # worker keys on the "low" token, so the value is a fixed word rather than a number.
        if (await run_in_threadpool(storage.storage_report)).low:
            return JSONResponse({"status": "ok", "storage": "low"})
        return JSONResponse({"status": "ok"})

    @app.get("/admin/stats", include_in_schema=False)
    def admin_stats(request: Request) -> Response:
        # 404 for every failure, never 401 or 403: the route should not exist as far as
        # anyone without the token is concerned. Constant-time compare, and the token is
        # never logged (the access log carries only the path).
        expected = settings.stats_token
        offered = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not expected or not offered or not hmac.compare_digest(offered.encode(), expected.encode()):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
        return Response(
            render_stats(database, storage),
            media_type="text/plain; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    # -- OPDS ------------------------------------------------------------
    # Every path below is dictated by the hrefs steepd.opds already emits: the root feed's
    # navigation entries, and the self/previous/next links build_items_catalog derives as
    # /opds/{feed_id}. A feed_id that does not match its route leaves page 1 looking correct
    # and breaks every page after it, so the feed_id values here are not free choices.

    @app.get("/opds")
    @app.get("/opds/", include_in_schema=False)
    def opds_root(scope: DeviceScope, interactive: Interactive) -> Response:
        return _xml_response(
            build_root_catalog(database, scope, settings.public_base_url, interactive=interactive), NAVIGATION_TYPE
        )

    @app.get("/opds/recent")
    def opds_recent(scope: DeviceScope, interactive: Interactive, page: Page = 1) -> Response:
        return _items_feed(scope, title="Recent", feed_id="recent", page=page, interactive=interactive)

    @app.get("/opds/newsletters")
    def opds_newsletters(scope: DeviceScope, interactive: Interactive, page: Page = 1) -> Response:
        return _items_feed(
            scope,
            title="Newsletters",
            feed_id="newsletters",
            page=page,
            interactive=interactive,
            kind="article",
            source="newsletter",
        )

    @app.get("/opds/publications")
    def opds_publications(scope: DeviceScope, page: Page = 1) -> Response:
        return _xml_response(
            build_publications_catalog(database, scope, settings.public_base_url, page=page),
            NAVIGATION_TYPE,
        )

    @app.get("/opds/publications/{publication_id}")
    def opds_publication(
        scope: DeviceScope, interactive: Interactive, publication_id: str, page: Page = 1
    ) -> Response:
        feed = build_publication_catalog(
            database,
            scope,
            settings.public_base_url,
            publication_id=publication_id,
            page=page,
            interactive=interactive,
        )
        if feed is None:
            # Another tenant's id and one that never existed answer identically, so a feed
            # is never an oracle for what somebody else has.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such publication")
        return _xml_response(feed, ACQUISITION_TYPE)

    @app.get("/opds/saved")
    def opds_saved(scope: DeviceScope, interactive: Interactive, page: Page = 1) -> Response:
        return _items_feed(
            scope, title="Saved", feed_id="saved", page=page, interactive=interactive, kind="article", source="url"
        )

    @app.get("/opds/sites")
    def opds_sites(scope: DeviceScope, page: Page = 1) -> Response:
        return _xml_response(
            build_sites_catalog(database, scope, settings.public_base_url, page=page), NAVIGATION_TYPE
        )

    @app.get("/opds/sites/{host}")
    def opds_site(scope: DeviceScope, interactive: Interactive, host: str, page: Page = 1) -> Response:
        if not is_site_host(host):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such site")
        return _xml_response(
            build_site_catalog(
                database, scope, settings.public_base_url, host=host, page=page, interactive=interactive
            ),
            ACQUISITION_TYPE,
        )

    @app.get("/opds/books")
    def opds_books(scope: DeviceScope, interactive: Interactive, page: Page = 1) -> Response:
        return _items_feed(scope, title="Books", feed_id="books", page=page, interactive=interactive, kind="book")

    @app.get("/opds/starred")
    def opds_starred(scope: DeviceScope, interactive: Interactive, page: Page = 1) -> Response:
        return _items_feed(scope, title="Starred", feed_id="starred", page=page, interactive=interactive, starred=True)

    @app.get("/opds/search")
    def opds_search(
        scope: DeviceScope,
        interactive: Interactive,
        q: Annotated[str, Query(min_length=1, max_length=160)],
        page: Page = 1,
    ) -> Response:
        return _items_feed(
            scope, title=f"Search: {q}", feed_id="search", page=page, interactive=interactive, query=q
        )

    @app.get("/opds/authors")
    def opds_authors(scope: DeviceScope, page: Page = 1) -> Response:
        return _xml_response(
            build_authors_catalog(database, scope, settings.public_base_url, page=page),
            NAVIGATION_TYPE,
        )

    @app.get("/opds/authors/{token}")
    def opds_author(token: str, scope: DeviceScope, interactive: Interactive, page: Page = 1) -> Response:
        try:
            author = author_from_token(token)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Author not found") from exc
        # feed_id carries the token, not the plain name: self/previous/next are derived as
        # /opds/{feed_id}, so anything else would point pagination at a path with no route.
        return _items_feed(
            scope, title=author, feed_id=f"authors/{token}", page=page, interactive=interactive, author=author
        )

    @app.get("/opds/download/{item_id}.epub")
    def opds_download(item_id: str, scope: DeviceScope) -> FileResponse:
        item = database.get_item(scope, item_id)
        if item is None:
            # 404, never 403, and the same 404 whether the id is unknown or belongs to another
            # tenant. A 403 would confirm the id exists and turn this route into a
            # cross-tenant existence oracle.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
        path = storage.path_for(item)
        if not path.is_file():
            LOGGER.error("Item file missing for record id=%s", item.id)
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Item file is missing")
        response = FileResponse(path, media_type=EPUB_MIME_TYPE, filename=item.download_filename)
        response.headers["Cache-Control"] = "private, no-store"
        return response

    # -- reader actions --------------------------------------------------
    # Star, Unstar and Delete from Steepd are GET requests, because a reader can only follow
    # links. What makes that acceptable: they exist only for accounts that turned them on;
    # each sets a value rather than toggling one; each carries the revision its menu showed,
    # so a request replayed by Back after a later change does nothing; and Delete only moves
    # the item to Trash. A browser sending one cross-site is refused outright.

    def _actions_allowed(tenant: Tenant, request: Request) -> None:
        # 404 rather than 403 when off, so the routes look absent, and so a menu left open
        # on a reader cannot act after the owner or the operator turns them off.
        if not reader_actions_on(tenant):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
        if request.headers.get("sec-fetch-site", "") in ("cross-site", "same-site"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-site request refused")

    def _result(feed_id: str, title: str, rows: list[tuple[str, str]]) -> Response:
        return _xml_response(
            build_result_feed(
                settings.public_base_url,
                feed_id=feed_id,
                title=title,
                updated=datetime.now(UTC).isoformat(),
                rows=rows,
            ),
            NAVIGATION_TYPE,
        )

    trashed_row = (
        f"Deleted from Steepd. You can restore it on the website for {TRASH_RETENTION.days} days",
        "/opds",
    )

    @app.get("/opds/items/{item_id}")
    def opds_item(item_id: str, tenant: DeviceTenant, request: Request) -> Response:
        _actions_allowed(tenant, request)
        scope = TenantScope(tenant.id)
        item = database.get_item(scope, item_id)
        if item is not None:
            return _xml_response(build_item_menu(item, settings.public_base_url), NAVIGATION_TYPE)
        # Back from a Delete result lands here, so a trashed item gets a readable answer.
        if database.get_trashed_item(scope, item_id) is not None:
            return _result(f"{item_id}:trashed", "Deleted", [trashed_row])
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    @app.get("/opds/items/{item_id}/{verb}")
    def opds_item_action(
        item_id: str, verb: str, tenant: DeviceTenant, request: Request, rev: Annotated[int, Query(ge=0)]
    ) -> Response:
        _actions_allowed(tenant, request)
        if verb not in ACTION_VERBS:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
        scope = TenantScope(tenant.id)
        item_path = f"/opds/items/{item_id}"
        feed_id = f"{item_id}:{verb}"
        item = database.get_item(scope, item_id)
        if item is None:
            if database.get_trashed_item(scope, item_id) is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
            if verb == "trash":
                return _result(feed_id, "Deleted", [trashed_row])
            gone = ("Nothing changed. This item was deleted from Steepd", "/opds")
            return _result(feed_id, "Nothing changed", [gone])

        changed = _result(
            feed_id,
            "Nothing changed",
            [("Nothing changed. This item changed since you opened it. Reopen it", item_path)],
        )
        if verb == "trash":
            if item.revision == rev and storage.trash(scope, item_id, expected_revision=rev):
                LOGGER.info("Reader action trash: tenant=%s item=%s", tenant.id, item_id)
                return _result(feed_id, "Deleted", [trashed_row])
            return changed

        starred = verb == "star"
        label = "Starred" if starred else "Unstarred"
        done = _result(feed_id, label, [(f"{label}. Back to this item", item_path)])
        if (item.starred_at is not None) == starred and item.revision != rev:
            # Already so: most often Back fetching this same link again after it worked.
            return done
        now = datetime.now(UTC).isoformat()
        if item.revision == rev and database.set_starred(
            scope, item_id, starred=starred, expected_revision=rev, now=now
        ):
            LOGGER.info("Reader action %s: tenant=%s item=%s", verb, tenant.id, item_id)
            return done
        return changed

    # -- inbound email ---------------------------------------------------

    @app.post(WEBHOOK_PATH)
    async def inbound_email_webhook(request: Request) -> JSONResponse:
        raw_body = await request.body()
        headers = {key.casefold(): value for key, value in request.headers.items()}
        try:
            result = await run_in_threadpool(inbound_service.handle, raw_body, headers)
        except InboundEmailDisabled:
            # 503, not 500: an unconfigured deployment refuses webhooks loudly instead of
            # accepting mail it will silently discard.
            return JSONResponse(
                {"status": "disabled", "detail": "Inbound email is not configured"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except (InvalidWebhookSignature, InvalidWebhookEvent):
            return JSONResponse(
                {"status": "rejected", "detail": "Invalid webhook"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        except ProviderRequestError as exc:
            LOGGER.error("Inbound email provider request failed: %s", str(exc))
            return JSONResponse(
                {"status": "error", "detail": "Inbound email retrieval failed"},
                status_code=status.HTTP_502_BAD_GATEWAY,
            )
        except NewsletterForwardingError as exc:
            LOGGER.error("Newsletter filing failed: %s", str(exc))
            return JSONResponse(
                {"status": "error", "detail": "Newsletter could not be filed"},
                status_code=status.HTTP_502_BAD_GATEWAY,
            )
        except EpubImportError as exc:
            LOGGER.warning("Inbound email produced an unusable EPUB: %s", str(exc))
            return JSONResponse(
                {"status": "rejected", "detail": "Inbound EPUB was rejected"},
                status_code=exc.status_code,
            )
        return JSONResponse(result.as_dict(), headers={"Cache-Control": "no-store"})

    return app
