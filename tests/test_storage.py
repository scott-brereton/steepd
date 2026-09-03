import io
import zipfile
from collections.abc import Callable, Iterator, Sequence

import pytest

from steepd.config import Settings
from steepd.db import Database
from steepd.epub import ServiceStorageFull, StorageQuotaExceeded, UnsafeEpub, UploadTooLarge
from steepd.epubgen import build_epub
from steepd.models import Item
from steepd.plans import FREE_QUOTA_BYTES, PAID_PLAN, PAID_QUOTA_BYTES
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope


@pytest.fixture
def storage(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url="http://localhost:8000")
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    store = ItemStorage(settings, database)
    store.initialize()
    return settings, database, store


def _epub(title: str) -> bytes:
    return build_epub(title=title, author="Author", language="en",
                      identifier=f"urn:uuid:{title}", body_html="<p>hi</p>")


def _repack_epub(
    payload: bytes,
    *,
    rewrite: Callable[[str, bytes], bytes] | None = None,
    extra_members: Sequence[tuple[str, bytes]] = (),
) -> bytes:
    """Rebuild a valid EPUB archive with hostile edits applied.

    Member order and compression are copied from the original so that "mimetype" stays the
    first stored entry -- inspect_epub rejects an archive that fails that check first, which
    would make these tests pass for the wrong reason.
    """
    target = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(payload)) as original, zipfile.ZipFile(target, "w") as rebuilt:
        for info in original.infolist():
            data = original.read(info)
            if rewrite is not None:
                data = rewrite(info.filename, data)
            rebuilt.writestr(zipfile.ZipInfo(info.filename), data, compress_type=info.compress_type)
        for name, data in extra_members:
            rebuilt.writestr(zipfile.ZipInfo(name), data, compress_type=zipfile.ZIP_DEFLATED)
    return target.getvalue()


def _epub_with_spine_href(payload: bytes, href: str) -> bytes:
    marker = b'href="index.xhtml"'

    def rewrite(name: str, data: bytes) -> bytes:
        if not name.endswith(".opf"):
            return data
        assert marker in data, "the package document no longer declares the manifest href this test rewrites"
        return data.replace(marker, f'href="{href}"'.encode())

    return _repack_epub(payload, rewrite=rewrite)


def _epub_with_mimetype_last_and_deflated(payload: bytes) -> bytes:
    """The specification's packaging rule broken both ways: `mimetype` is the last member
    and it is compressed. Every reader opens such a file; the check only ever cost the user
    a book, silently."""
    target = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(payload)) as original, zipfile.ZipFile(target, "w") as rebuilt:
        members = [(info.filename, original.read(info)) for info in original.infolist()]
        for name, data in sorted(members, key=lambda member: member[0] == "mimetype"):
            rebuilt.writestr(zipfile.ZipInfo(name), data, compress_type=zipfile.ZIP_DEFLATED)
    return target.getvalue()


def test_an_epub_whose_mimetype_is_not_first_or_stored_is_still_accepted(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    payload = _epub_with_mimetype_last_and_deflated(_epub("Loose"))
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert archive.infolist()[-1].filename == "mimetype"

    result = store.store_bytes(TenantScope(tenant.id), payload, filename="loose.epub", kind="book", source="email")

    assert result.item.title == "Loose"


def test_a_zip_with_the_wrong_mimetype_is_still_refused(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    payload = _repack_epub(_epub("Bad"), rewrite=lambda name, data: b"text/plain" if name == "mimetype" else data)

    with pytest.raises(UnsafeEpub):
        store.store_bytes(TenantScope(tenant.id), payload, filename="bad.epub", kind="book", source="email")


def test_stores_an_article_and_returns_an_item(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)

    result = store.store_bytes(
        scope, _epub("News"), filename="news.epub", kind="article",
        source="newsletter", source_url="https://example.com/post", title="News", author="Author",
    )

    assert result.duplicate is False
    assert result.item.kind == "article"
    assert result.item.tenant_id == tenant.id
    assert store.path_for(result.item).exists()
    assert database.get_item(scope, result.item.id) is not None


def test_second_identical_file_is_a_duplicate_for_the_same_tenant(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    payload = _epub("Same")

    first = store.store_bytes(scope, payload, filename="s.epub", kind="book", source="email", title="Same")
    second = store.store_bytes(scope, payload, filename="s.epub", kind="book", source="email", title="Same")

    assert second.duplicate is True
    assert second.item.id == first.item.id
    assert database.count_items(scope) == 1


def test_files_are_partitioned_by_tenant(storage):
    _, database, store = storage
    alice = database.create_tenant(email="a@example.com", inbox_local="a.1")
    bob = database.create_tenant(email="b@example.com", inbox_local="b.2")
    payload = _epub("Shared")

    a_item = store.store_bytes(TenantScope(alice.id), payload, filename="x.epub", kind="book",
                               source="email", title="Shared")
    b_item = store.store_bytes(TenantScope(bob.id), payload, filename="x.epub", kind="book",
                               source="email", title="Shared")

    assert b_item.duplicate is False
    assert alice.id in str(store.path_for(a_item.item))
    assert bob.id in str(store.path_for(b_item.item))
    assert store.path_for(a_item.item) != store.path_for(b_item.item)


def test_delete_is_scoped(storage):
    _, database, store = storage
    alice = database.create_tenant(email="a@example.com", inbox_local="a.1")
    bob = database.create_tenant(email="b@example.com", inbox_local="b.2")
    item = store.store_bytes(TenantScope(alice.id), _epub("Mine"), filename="m.epub",
                             kind="book", source="email", title="Mine").item

    assert store.delete(TenantScope(bob.id), item.id) is False
    assert store.path_for(item).exists()
    assert store.delete(TenantScope(alice.id), item.id) is True
    assert not store.path_for(item).exists()


def test_delete_all_for_tenant_removes_every_file_and_row(storage):
    """Account deletion goes through delete() per item rather than an rm -rf of the tenant
    directory, so each file is trash-staged and the matching row goes with it. A bulk
    directory removal would leave rows pointing at files that no longer exist."""
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    items = [
        store.store_bytes(scope, _epub(f"Book {index}"), filename=f"b{index}.epub",
                          kind="book", source="email", title=f"Book {index}").item
        for index in range(3)
    ]
    paths = [store.path_for(item) for item in items]
    assert all(path.exists() for path in paths)

    assert store.delete_all_for_tenant(scope) == 3

    assert not any(path.exists() for path in paths)
    assert database.count_items(scope) == 0
    assert list(store.trash_dir.iterdir()) == []


def test_delete_all_for_tenant_pages_past_the_default_list_limit(storage):
    # list_items defaults to 50 rows. A single unpaged read would silently leave everything
    # past the first page on disk, and the caller would see a plausible-looking count.
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    for index in range(55):
        store.store_bytes(scope, _epub(f"Book {index}"), filename=f"b{index}.epub",
                          kind="book", source="email", title=f"Book {index}")

    assert store.delete_all_for_tenant(scope) == 55
    assert database.count_items(scope) == 0


def test_delete_all_for_tenant_leaves_another_tenant_untouched(storage):
    _, database, store = storage
    alice = database.create_tenant(email="a@example.com", inbox_local="a.1")
    bob = database.create_tenant(email="b@example.com", inbox_local="b.2")
    payload = _epub("Shared")
    a_item = store.store_bytes(TenantScope(alice.id), payload, filename="x.epub", kind="book",
                               source="email", title="Shared").item
    b_item = store.store_bytes(TenantScope(bob.id), payload, filename="x.epub", kind="book",
                               source="email", title="Shared").item

    assert store.delete_all_for_tenant(TenantScope(alice.id)) == 1

    assert not store.path_for(a_item).exists()
    assert store.path_for(b_item).exists()
    assert database.count_items(TenantScope(bob.id)) == 1


def test_delete_all_for_tenant_on_an_empty_library_is_a_no_op(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    assert store.delete_all_for_tenant(TenantScope(tenant.id)) == 0


def test_path_for_rejects_a_forged_tenant_id_that_would_escape_items_dir(storage):
    _, _, store = storage
    item_id = "deadbeef"
    forged = Item(
        id=item_id,
        tenant_id="../../etc",
        kind="book",
        sha256="0" * 64,
        storage_name=f"{item_id}.epub",
        download_filename="x.epub",
        title="x",
        author="",
        language="",
        identifier="",
        source_url="",
        size_bytes=1,
        created_at="2026-01-01T00:00:00+00:00",
        expires_at=None,
        source="test",
    )

    with pytest.raises(UnsafeEpub):
        store.path_for(forged)

    # Prove the guard is load-bearing: naively joining the forged tenant_id (what path_for
    # would do without the check) really does escape items_dir.
    naive = (store.items_dir / forged.tenant_id / forged.storage_name).resolve()
    assert not naive.is_relative_to(store.items_dir.resolve())


def test_epub_containing_a_path_traversal_member_is_rejected(storage):
    """An archive member named "../evil.txt" must be refused at the door.

    The service itself never extracts an uploaded EPUB, so nothing here escapes our own data
    directory -- but the file is handed on verbatim to the reader's e-reader, which does
    extract it. Storing an archive that writes outside its own unpack root would make us the
    delivery mechanism for that attack.
    """
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    hostile = _repack_epub(_epub("Traversal"), extra_members=(("../evil.txt", b"pwned"),))

    with pytest.raises(UnsafeEpub, match="path-traversal"):
        store.store_bytes(scope, hostile, filename="t.epub", kind="book", source="email")

    assert database.count_items(scope) == 0
    assert list(store.temp_dir.iterdir()) == []


@pytest.mark.parametrize("href", ["https://attacker.example/x.xhtml", "https:index.xhtml"])
def test_epub_whose_spine_points_at_a_remote_resource_is_rejected(storage, href):
    """A spine entry must resolve to a file inside the archive, never to a URL.

    A remote href turns opening the book into an outbound request from the reader's device,
    which both leaks that they opened it and lets the sender swap the content afterwards. The
    scheme-only form ("https:index.xhtml") is the interesting one: it resolves to a member
    that really exists, so nothing else in the validation chain notices it.
    """
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    hostile = _epub_with_spine_href(_epub("Remote"), href)

    with pytest.raises(UnsafeEpub, match="remote resource"):
        store.store_bytes(scope, hostile, filename="r.epub", kind="book", source="email")

    assert database.count_items(scope) == 0


def test_stream_longer_than_the_upload_limit_is_rejected_while_streaming(tmp_path):
    """The upload limit is enforced on bytes actually written, not on a declared size.

    Every upstream caller learns the size from something the sender controls -- a
    Content-Length header or MIME metadata -- so the running total kept while the stream is
    consumed is the only check that stops a body which understates its own length.
    """
    payload = _epub("Oversized")
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)

    def store_with_limit(limit: int) -> ItemStorage:
        settings = Settings(data_dir=tmp_path, public_base_url="http://localhost:8000", max_upload_bytes=limit)
        store = ItemStorage(settings, database)
        store.initialize()
        return store

    def chunks() -> Iterator[bytes]:
        for start in range(0, len(payload), 512):
            yield payload[start:start + 512]

    strict = store_with_limit(len(payload) - 1)
    with pytest.raises(UploadTooLarge):
        strict.store_chunks(scope, chunks(), filename="big.epub", source="email")

    assert database.count_items(scope) == 0
    assert list(strict.temp_dir.iterdir()) == []

    # The same bytes through a limit that fits are stored, so the rejection above was the size
    # check and not some other objection to the payload.
    permissive = store_with_limit(len(payload))
    assert permissive.store_chunks(scope, chunks(), filename="big.epub", source="email").duplicate is False


# -- plan storage quotas ---------------------------------------------------
# Usage is inflated by inserting item rows with a large size_bytes rather than by storing
# real files: the quota comes from steepd.plans, not from Settings, so there is no small
# limit to configure, and a fixture that actually wrote 100MB would be a 100MB fixture.


def _charge(database, scope, size_bytes, *, item_id="filler", sha="filler-sha"):
    database.insert_item(
        scope,
        Item(
            id=item_id,
            tenant_id=scope.tenant_id,
            kind="book",
            sha256=sha,
            storage_name=f"{item_id}.epub",
            download_filename="filler.epub",
            title="Already stored",
            author="Author",
            language="en",
            identifier="",
            source_url="",
            size_bytes=size_bytes,
            created_at="2026-01-01T00:00:00+00:00",
            expires_at=None,
            source="email",
        ),
    )


def test_store_over_the_free_quota_is_rejected_and_leaves_no_temp_file(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    _charge(database, scope, FREE_QUOTA_BYTES)

    with pytest.raises(StorageQuotaExceeded) as excinfo:
        store.store_bytes(scope, _epub("Over"), filename="over.epub", kind="book", source="email")

    # 413 so the webhook handler, which dispatches on EpubImportError.status_code, reports a
    # full account the same way it reports an oversized upload.
    assert excinfo.value.status_code == 413
    assert database.count_items(scope) == 1
    assert list(store.temp_dir.iterdir()) == []


def test_a_store_that_exactly_fills_the_free_quota_is_accepted(storage):
    """The cap is what may be stored, not what may be approached: usage + size == quota
    fits. Kills the off-by-one that would reject the item that exactly fills the account."""
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    payload = _epub("Exact")
    _charge(database, scope, FREE_QUOTA_BYTES - len(payload))

    assert store.store_bytes(scope, payload, filename="e.epub", kind="book", source="email").duplicate is False


def test_the_same_store_is_accepted_on_the_paid_plan(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    _charge(database, scope, FREE_QUOTA_BYTES)
    assert database.set_tenant_plan(tenant.id, PAID_PLAN) is True

    result = store.store_bytes(scope, _epub("Room"), filename="room.epub", kind="book", source="email")

    assert result.duplicate is False
    assert database.count_items(scope) == 2


def test_a_paid_tenant_is_still_capped_at_the_paid_quota(storage):
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    _charge(database, scope, PAID_QUOTA_BYTES)
    database.set_tenant_plan(tenant.id, PAID_PLAN)

    with pytest.raises(StorageQuotaExceeded):
        store.store_bytes(scope, _epub("Too much"), filename="t.epub", kind="book", source="email")


def test_re_sending_a_file_already_stored_stays_a_duplicate_over_quota(storage):
    """A duplicate adds no bytes, so it must not be rejected once the account is full --
    otherwise a device that re-sends on every sync starts failing at the cap. Pins the
    order of the two checks inside _store.
    """
    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    payload = _epub("Resent")
    first = store.store_bytes(scope, payload, filename="r.epub", kind="book", source="email")
    _charge(database, scope, FREE_QUOTA_BYTES)

    second = store.store_bytes(scope, payload, filename="r.epub", kind="book", source="email")

    assert second.duplicate is True
    assert second.item.id == first.item.id


def test_one_tenants_usage_does_not_fill_anothers_quota(storage):
    _, database, store = storage
    alice = database.create_tenant(email="a@example.com", inbox_local="a.1")
    bob = database.create_tenant(email="b@example.com", inbox_local="b.2")
    _charge(database, TenantScope(alice.id), FREE_QUOTA_BYTES)

    result = store.store_bytes(TenantScope(bob.id), _epub("Bob's"), filename="b.epub", kind="book", source="email")

    assert result.duplicate is False


def _disk(monkeypatch, *, total: int, free: int) -> None:
    """Pin what the volume reports, without needing a full disk to test against."""
    monkeypatch.setattr("steepd.storage.shutil.disk_usage", lambda path: shutil_usage(total, total - free, free))


def shutil_usage(total, used, free):
    from collections import namedtuple

    return namedtuple("usage", "total used free")(total, used, free)


def test_a_store_is_refused_below_the_disk_floor_and_says_it_is_our_problem(storage, monkeypatch):
    """The account is nowhere near its allowance; the volume is nearly full. The refusal
    is a 507 with wording that blames the service, and nothing is left on disk."""
    from steepd.storage import DISK_FREE_FLOOR_BYTES

    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    _disk(monkeypatch, total=5 * 1024**3, free=DISK_FREE_FLOOR_BYTES - 1)

    with pytest.raises(ServiceStorageFull) as excinfo:
        store.store_bytes(scope, _epub("Full"), filename="full.epub", kind="book", source="email")

    assert excinfo.value.status_code == 507
    assert "our problem" in str(excinfo.value)
    assert database.count_items(scope) == 0
    assert list(store.temp_dir.iterdir()) == []


def test_a_full_account_is_told_it_is_full_before_the_disk_is_blamed(storage, monkeypatch):
    from steepd.storage import DISK_FREE_FLOOR_BYTES

    _, database, store = storage
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    _charge(database, scope, FREE_QUOTA_BYTES)
    _disk(monkeypatch, total=5 * 1024**3, free=DISK_FREE_FLOOR_BYTES - 1)

    with pytest.raises(StorageQuotaExceeded):
        store.store_bytes(scope, _epub("Over"), filename="over.epub", kind="book", source="email")


def test_the_storage_report_flags_low_at_ten_percent_or_the_floor_whichever_is_larger(storage, monkeypatch):
    from steepd.storage import DISK_FREE_FLOOR_BYTES

    _, _, store = storage
    gigabyte = 1024**3
    _disk(monkeypatch, total=5 * gigabyte, free=int(0.11 * 5 * gigabyte))
    assert store.storage_report().low is False
    _disk(monkeypatch, total=5 * gigabyte, free=int(0.09 * 5 * gigabyte))
    assert store.storage_report().low is True
    # A tiny volume: ten percent is below the floor, so the floor decides.
    _disk(monkeypatch, total=1 * gigabyte, free=DISK_FREE_FLOOR_BYTES - 1)
    assert store.storage_report().low is True
