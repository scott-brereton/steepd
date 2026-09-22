"""Browser imports exercise real storage and conversion; only remote I/O is stubbed."""

from __future__ import annotations

import asyncio
import io
import zipfile
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from threading import Barrier, Event

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
from test_inbound import StubUrlConvert, _build_env
from test_urlarticle import FIXTURE_HTML

from steepd.app import create_app
from steepd.auth import issue_session
from steepd.config import Settings
from steepd.epub import ServiceStorageFull, inspect_epub
from steepd.epubgen import build_epub
from steepd.imagefetch import FetchedImage
from steepd.remotefetch import FetchedRemote, RemoteBodyTooLarge, RemoteFetchError
from steepd.tenancy import TenantScope
from steepd.urlarticle import convert_url_article
from steepd.web import FORM_MAX_BYTES, SAVE_URL_PATH, SESSION_COOKIE, UPLOAD_FORM_OVERHEAD, UPLOAD_PATH

BASE_URL = "http://localhost:8000"
URL = "https://publisher.example/story"


def _client(tmp_path, **overrides):
    app = create_app(Settings(data_dir=tmp_path, public_base_url=BASE_URL, **overrides))
    tenant, password = app.state.database.create_tenant_with_password(email="reader@example.test", inbox_local="reader")
    client = TestClient(app, base_url=BASE_URL)
    client.cookies.set(SESSION_COOKIE, issue_session(app.state.database, tenant.id))
    return client, tenant, password


@pytest.fixture
def imports(tmp_path, monkeypatch):
    def no_email(*args, **kwargs):
        pytest.fail("A browser import must not send email")

    monkeypatch.setattr("steepd.web.send_email", no_email)
    monkeypatch.setattr("steepd.inbound.send_email", no_email)
    return _client(tmp_path)


@pytest.fixture
def epub():
    return build_epub(
        title="A quiet book",
        author="Ada Writer",
        identifier="urn:test:web-import",
        language="en",
        body_html="<html><body><p>A book to read offline.</p></body></html>",
    )


def _upload(client, content, **kwargs):
    return client.post(UPLOAD_PATH, files={"epub": ("book.epub", content, "application/epub+zip")}, **kwargs)


def _html_error(response, code, field=None):
    assert response.status_code == code, response.text
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "private, no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    soup = BeautifulSoup(response.text, "html.parser")
    if field:
        assert soup.select_one("h1").text == "Your account"
        assert soup.select_one("#add h2").text == "Add to library"
        assert soup.select_one(f"#{field}-error[role=alert]")
    return soup


def _stub_page(client, *, error=None):
    def fetch(url, *, max_bytes):
        if error:
            raise error
        return FetchedRemote(content_type="text/html", content=FIXTURE_HTML, final_url=URL)

    client.app.state.inbound_service.url_convert = partial(convert_url_article, fetch_page=fetch)
    client.app.state.inbound_service.image_fetch = lambda *a, **kw: FetchedImage(
        "image/png", b"\x89PNG\r\n\x1a\nfixture"
    )


def test_upload_persists_epub_is_tenant_scoped_and_reaches_opds(imports, epub):
    client, tenant, password = imports
    scope = TenantScope(tenant.id)
    result = _upload(client, epub, follow_redirects=False)
    assert result.status_code == 303
    assert result.headers["location"] == "/account/library?shelf=books&notice=book"
    landing = client.get(result.headers["location"])
    assert "Added to Books." in landing.text and "A quiet book" in landing.text
    (item,) = client.app.state.database.list_items(scope)
    assert (item.kind, item.source) == ("book", "upload")
    stored = client.app.state.storage.path_for(item)
    assert stored.read_bytes() == epub
    assert inspect_epub(stored, client.app.state.settings, fallback_title="unused").title == "A quiet book"
    auth = (tenant.opds_username, password)
    assert "A quiet book" in client.get("/opds/books", auth=auth).text
    assert client.get(f"/opds/download/{item.id}.epub", auth=auth).content == epub
    other, other_pw = client.app.state.database.create_tenant_with_password(
        email="other@example.test", inbox_local="other"
    )
    assert client.get(f"/opds/download/{item.id}.epub", auth=(other.opds_username, other_pw)).status_code == 404
    client.cookies.set(SESSION_COOKIE, issue_session(client.app.state.database, other.id))
    assert "A quiet book" not in client.get("/account/library").text


def test_url_uses_real_conversion_without_email_configuration_and_refresh_is_safe(imports):
    client, tenant, password = imports
    _stub_page(client)
    assert client.app.state.inbound_service.provider is None
    assert not client.app.state.settings.inbox_domain
    for count in (1, 2):
        result = client.post(SAVE_URL_PATH, data={"url": f"  {URL}  ", "tenant_id": "foreign"}, follow_redirects=False)
        assert result.status_code == 303
        assert result.headers["location"] == "/account/library?shelf=saved&notice=article"
        for _ in range(2):
            assert "Added to Saved." in client.get(result.headers["location"]).text
        assert client.app.state.database.count_items(TenantScope(tenant.id)) == count
    items = client.app.state.database.list_items(TenantScope(tenant.id))
    assert {item.title for item in items} == {"A useful story", "A useful story (2)"}
    assert all((item.kind, item.source, item.source_url) == ("article", "url", URL) for item in items)
    assert "publisher.example" in client.get("/account/library?shelf=saved").text
    auth = (tenant.opds_username, password)
    download = client.get(f"/opds/download/{items[0].id}.epub", auth=auth)
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        chapters = " ".join(archive.read(name).decode() for name in archive.namelist() if name.endswith(".xhtml"))
        assert "central idea" in chapters and "Site navigation" not in chapters
        assert any(name.endswith(".png") for name in archive.namelist())
    with client.app.state.database._session() as connection:
        assert connection.execute("SELECT count(*) FROM webhook_events").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM newsletter_deliveries").fetchone()[0] == 0


@pytest.mark.parametrize(
    "kind,source,shelf",
    [
        ("book", "email", "books"),
        ("article", "url", "saved"),
        ("article", "newsletter", "newsletters"),
        ("article", "other", "recent"),
    ],
)
def test_duplicates_keep_existing_shelf_metadata_and_age_even_at_quota(tmp_path, epub, kind, source, shelf):
    client, tenant, _ = _client(tmp_path, free_quota_bytes=len(epub))
    scope = TenantScope(tenant.id)
    original = client.app.state.storage.store_bytes(
        scope, epub, filename="original.epub", kind=kind, source=source
    ).item
    response = _upload(client, epub, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/account/library?shelf={shelf}&notice=duplicate"
    assert "Already in your library." in client.get(response.headers["location"]).text
    assert client.app.state.database.list_items(scope) == [original]
    assert client.app.state.database.tenant_storage_bytes(scope) == len(epub)


@pytest.mark.parametrize("path", [UPLOAD_PATH, SAVE_URL_PATH])
def test_auth_and_origin_precede_body_parsing(imports, monkeypatch, path):
    client, _, _ = imports

    async def forbidden_body(self):
        pytest.fail("Body read before authentication/origin check")
        yield b""

    monkeypatch.setattr("starlette.requests.Request.stream", forbidden_body)
    assert client.post(path, headers={"Origin": "https://other.example"}).status_code == 403
    client.cookies.clear()
    response = client.post(path, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/signin"
    pending = client.app.state.database.create_pending_tenant(email="pending@example.test")
    client.cookies.set(SESSION_COOKIE, issue_session(client.app.state.database, pending.id))
    response = client.post(path, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/account/address"


@pytest.mark.parametrize("value", ["", "example.com", "https://one.example https://two.example", '<script>"&'])
def test_bad_url_is_escaped_and_stays_in_the_form(imports, value):
    client, _, _ = imports
    response = client.post(SAVE_URL_PATH, data={"url": value})
    soup = _html_error(response, 400, "url")
    assert soup.select_one("input[name=url]")["value"] == value
    assert soup.select_one("script") is None


@pytest.mark.parametrize("error,code", [(RemoteFetchError("private details"), 422), (RemoteBodyTooLarge("size"), 413)])
def test_url_fetch_failures_preserve_the_input_without_partial_items(imports, error, code):
    client, tenant, _ = imports
    _stub_page(client, error=error)
    response = client.post(SAVE_URL_PATH, data={"url": URL})
    soup = _html_error(response, code, "url")
    assert soup.select_one("input[name=url]")["value"] == URL
    assert "private details" not in response.text
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0


def test_private_url_is_rejected_by_the_shared_fetcher(imports):
    client, tenant, _ = imports
    response = client.post(SAVE_URL_PATH, data={"url": "http://127.0.0.1/private"})
    _html_error(response, 422, "url")
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0


@pytest.fixture
def spools(monkeypatch):
    from starlette import formparsers

    created = []
    factory = formparsers.SpooledTemporaryFile

    def track(*args, **kwargs):
        spool = factory(*args, **kwargs)
        created.append(spool)
        return spool

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", track)
    yield created
    assert all(spool.closed for spool in created), "Every upload spool must close explicitly"


def _part(content=b"data", *, name="epub", filename="book.epub"):
    return (
        f'--boundary\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n\r\n'.encode()
        + content
        + b"\r\n"
    )


@pytest.mark.parametrize(
    "body,content_type",
    [
        (b"", "multipart/form-data"),
        (b"broken boundary\r\n", "multipart/form-data; boundary=boundary"),
        (b"--boundary\r\nBad\x00Header: value\r\n\r\n", "multipart/form-data; boundary=boundary"),
        (_part(), "multipart/form-data; boundary=boundary"),
        (_part() + b"--boundary\r\nContent-Dispos", "multipart/form-data; boundary=boundary"),
        (_part() + _part() + b"--boundary--\r\n", "multipart/form-data; boundary=boundary"),
        (_part(name="wrong") + b"--boundary--\r\n", "multipart/form-data; boundary=boundary"),
        (_part(filename="") + b"--boundary--\r\n", "multipart/form-data; boundary=boundary"),
        (_part(content=b"") + b"--boundary--\r\n", "multipart/form-data; boundary=boundary"),
        (
            b'--boundary\r\nContent-Disposition: form-data; name="text"\r\n\r\ndata\r\n--boundary--\r\n',
            "multipart/form-data; boundary=boundary",
        ),
    ],
)
def test_malformed_and_incomplete_uploads_are_html_400_and_close_spools(
    imports, spools, monkeypatch, body, content_type
):
    client, tenant, _ = imports
    monkeypatch.setattr(client.app.state.storage, "store_chunks", lambda *a, **kw: pytest.fail("Invalid upload stored"))
    response = client.post(UPLOAD_PATH, content=body, headers={"Content-Type": content_type})
    _html_error(response, 400, "epub")
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0


def test_spools_close_on_success_validation_and_storage_failure(imports, epub, spools, monkeypatch):
    client, tenant, _ = imports
    assert _upload(client, epub, follow_redirects=False).status_code == 303
    _html_error(_upload(client, b"not an epub"), 422, "epub")

    def full(*args, **kwargs):
        raise ServiceStorageFull("disk full")

    monkeypatch.setattr(client.app.state.storage, "store_chunks", full)
    _html_error(_upload(client, epub), 507, "epub")
    assert len(spools) == 3 and all(spool.closed for spool in spools)
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 1
    assert not list(client.app.state.storage.temp_dir.iterdir())


@pytest.mark.parametrize("path", [UPLOAD_PATH, SAVE_URL_PATH])
def test_real_quota_failure_is_actionable(tmp_path, epub, path):
    client, tenant, _ = _client(tmp_path, free_quota_bytes=1)
    _stub_page(client)
    response = _upload(client, epub) if path == UPLOAD_PATH else client.post(path, data={"url": URL})
    _html_error(response, 413, "epub" if path == UPLOAD_PATH else "url")
    assert "Delete something from your library" in response.text
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0
    assert not list(client.app.state.storage.temp_dir.iterdir())


def test_exact_epub_size_limit_is_distinct_from_request_limit(tmp_path, epub, spools):
    client, tenant, _ = _client(tmp_path, max_upload_bytes=len(epub) - 1)
    _html_error(_upload(client, epub), 413, "epub")
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0
    assert not list(client.app.state.storage.temp_dir.iterdir())


async def _chunked_post(client, path, chunks, content_type):
    messages = []
    bodies = iter(chunks)

    async def receive():
        body = next(bodies, None)
        return {"type": "http.request", "body": body or b"", "more_body": body is not None}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "server": ("localhost", 8000),
        "client": ("127.0.0.1", 1234),
        "headers": [
            (b"content-type", content_type.encode()),
            (b"cookie", f"{SESSION_COOKIE}={client.cookies.get(SESSION_COOKIE)}".encode()),
        ],
    }
    await client.app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in messages)
    return start, body


def test_chunked_body_limit_mid_upload_closes_already_created_spool(tmp_path, spools):
    client, tenant, _ = _client(tmp_path, max_upload_bytes=1024)
    start, body = asyncio.run(
        _chunked_post(
            client,
            UPLOAD_PATH,
            [_part(), b"x" * (1024 + UPLOAD_FORM_OVERHEAD)],
            "multipart/form-data; boundary=boundary",
        )
    )
    assert start["status"] == 413
    assert b"Back to your account" in body
    assert len(spools) == 1 and spools[0].closed
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0


@pytest.mark.parametrize("path,limit", [(SAVE_URL_PATH, FORM_MAX_BYTES), (UPLOAD_PATH, 1024 + UPLOAD_FORM_OVERHEAD)])
def test_known_and_unknown_body_lengths_get_html_limits(tmp_path, path, limit):
    client, _, _ = _client(tmp_path, max_upload_bytes=1024)
    _html_error(client.post(path, content=b"x" * (limit + 1)), 413)
    content_type = (
        "multipart/form-data; boundary=boundary" if path == UPLOAD_PATH else "application/x-www-form-urlencoded"
    )
    start, body = asyncio.run(_chunked_post(client, path, [b"x" * (limit + 1)], content_type))
    assert start["status"] == 413 and b"Back to your account" in body


def test_rate_limit_is_shared_by_routes_and_sessions_but_not_accounts(imports):
    client, tenant, _ = imports
    ticks = [100.0]
    client.app.state.rate_limiter.clock = lambda: ticks[0]
    for index in range(30):
        response = client.post(UPLOAD_PATH if index % 2 else SAVE_URL_PATH)
        assert response.status_code == 400
    client.cookies.set(SESSION_COOKIE, issue_session(client.app.state.database, tenant.id))
    for path in (UPLOAD_PATH, SAVE_URL_PATH):
        response = client.post(path)
        _html_error(response, 429, "epub" if path == UPLOAD_PATH else "url")
        assert response.headers["Retry-After"] == "3600"
    other = client.app.state.database.create_tenant(email="other@example.test", inbox_local="other")
    client.cookies.set(SESSION_COOKIE, issue_session(client.app.state.database, other.id))
    assert client.post(SAVE_URL_PATH).status_code == 400
    client.cookies.set(SESSION_COOKIE, issue_session(client.app.state.database, tenant.id))
    ticks[0] += 3600
    assert client.post(SAVE_URL_PATH).status_code == 400


def test_forms_live_on_the_account_page_and_notice_codes_are_allowlisted(imports, epub):
    client, _, _ = imports
    account = BeautifulSoup(client.get("/account").text, "html.parser")
    section = account.select_one("section#add")
    assert section.select_one("h2").text == "Add to library"
    assert {form["action"] for form in section.select("form")} == {UPLOAD_PATH, SAVE_URL_PATH}
    assert section.select_one("input[name=url]") and section.select_one("input[name=epub][type=file]")
    assert account.select_one("details#add") is None
    for query in ("", "?shelf=saved", "?q=missing"):
        page = BeautifulSoup(client.get("/account/library" + query).text, "html.parser")
        assert page.select_one("#add") is None and page.select_one("form[enctype]") is None
    assert "/account#add" in client.get("/account/library").text
    _upload(client, epub)
    assert "/account#add" not in client.get("/account/library?shelf=books").text
    soup = BeautifulSoup(client.get("/account/library?notice=untrusted").text, "html.parser")
    assert soup.select_one(".notice") is None


def test_email_and_browser_operation_share_title_allocation_under_overlap(tmp_path):
    barrier = Barrier(2)
    converter = StubUrlConvert(title="Shared story")

    def overlap(*args, **kwargs):
        result = converter(*args, **kwargs)
        barrier.wait(timeout=5)
        return result

    _, database, _, service, tenants, _ = _build_env(tmp_path, ["a.1"], url_convert=overlap)
    scope = TenantScope(tenants[0].id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        browser = pool.submit(service.save_url_article, scope, URL)
        email = pool.submit(service.import_url_article, scope, "email-1", URL)
        assert browser.result(timeout=10)
        assert email.result(timeout=10).imported == 1
    assert {item.title for item in database.list_items(scope)} == {"Shared story", "Shared story (2)"}


def test_slow_capture_keeps_the_app_responsive_and_reports_success_only_after_storage(imports):
    client, tenant, _ = imports
    fetching, release = Event(), Event()

    def slow_page(url, *, max_bytes):
        fetching.set()
        assert release.wait(timeout=5)
        return FetchedRemote(
            content_type="text/html", content=FIXTURE_HTML.replace(b"<img", b"<ignored"), final_url=URL
        )

    client.app.state.inbound_service.url_convert = partial(convert_url_article, fetch_page=slow_page)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.post, SAVE_URL_PATH, data={"url": URL}, follow_redirects=False)
        try:
            assert fetching.wait(timeout=5)
            assert not pending.done()
            assert client.get("/healthz").status_code == 200
            assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0
        finally:
            release.set()
        assert pending.result(timeout=5).status_code == 303
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 1


def test_unexpected_storage_error_propagates_and_still_closes_upload(imports, epub, spools, monkeypatch):
    client, tenant, _ = imports

    def broken(*args, **kwargs):
        raise RuntimeError("unexpected storage failure")

    monkeypatch.setattr(client.app.state.storage, "store_chunks", broken)
    with pytest.raises(RuntimeError, match="unexpected storage failure"):
        _upload(client, epub)
    assert len(spools) == 1 and spools[0].closed
    assert client.app.state.database.count_items(TenantScope(tenant.id)) == 0


@pytest.mark.parametrize("budget_seconds,expected_fetches", [(None, 2), (5.0, 1)])
def test_image_deadline_parameter_bounds_one_save(tmp_path, budget_seconds, expected_fetches):
    """Each image fetch costs six ticks; a five-second budget therefore allows exactly one."""
    ticks = {"now": 1_000.0}
    fetched = []
    two_images = FIXTURE_HTML.replace(
        b'<img src="/images/chart.png" alt="A useful chart">',
        b'<img src="/images/one.png" alt="One chart"> <img src="/images/two.png" alt="Two chart">',
    )

    def fetch_page(url, *, max_bytes):
        return FetchedRemote(content_type="text/html", content=two_images, final_url=URL)

    def fetch_image(url, *, max_bytes):
        fetched.append(url)
        ticks["now"] += 6.0
        return FetchedImage("image/png", b"\x89PNG\r\n\x1a\nfixture")

    _, database, _, service, tenants, _ = _build_env(
        tmp_path, ["a.1"], image_fetch=fetch_image, url_convert=partial(convert_url_article, fetch_page=fetch_page)
    )
    service._clock = lambda: ticks["now"]
    scope = TenantScope(tenants[0].id)
    kwargs = {} if budget_seconds is None else {"image_time_budget_seconds": budget_seconds}
    assert service.save_url_article(scope, URL, **kwargs)
    assert len(fetched) == expected_fetches
    assert database.count_items(scope) == 1
