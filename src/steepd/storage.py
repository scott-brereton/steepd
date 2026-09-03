from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import threading
import uuid
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from steepd.config import Settings
from steepd.db import Database
from steepd.epub import (
    ServiceStorageFull,
    StorageQuotaExceeded,
    UnsafeEpub,
    UploadTooLarge,
    inspect_epub,
    sanitize_filename,
)
from steepd.models import Item
from steepd.plans import FREE_PLAN, quota_bytes
from steepd.tenancy import TenantScope

# Item stores are refused while less than this is free on the volume. It is headroom for
# everything else that writes: SQLite's journal, sign-in tokens, sessions, and the retention
# sweep's own deletes. Items stop landing a little early so the service keeps working, and
# tells people why, while the volume is grown.
DISK_FREE_FLOOR_BYTES = 250 * 1024 * 1024

# Below this share of the volume, /healthz reports storage as low so the uptime worker can
# say so before the floor above is reached.
DISK_LOW_FRACTION = 0.10


@dataclass(frozen=True, slots=True)
class StoreResult:
    item: Item
    duplicate: bool


@dataclass(frozen=True, slots=True)
class StorageReport:
    total_bytes: int
    free_bytes: int

    @property
    def low(self) -> bool:
        return self.free_bytes < max(DISK_FREE_FLOOR_BYTES, int(self.total_bytes * DISK_LOW_FRACTION))


class ItemStorage:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self.items_dir = settings.data_dir / "items"
        self.temp_dir = settings.data_dir / "tmp"
        self.trash_dir = settings.data_dir / "trash"
        self._lock = threading.RLock()

    def initialize(self) -> None:
        for directory in (self.items_dir, self.temp_dir, self.trash_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def _tenant_dir(self, tenant_id: str) -> Path:
        return self.items_dir / tenant_id

    def path_for(self, item: Item) -> Path:
        # storage_name must be derived only from the random item id (see the invariant in
        # Task 5's brief): sha256 is unique per tenant, not globally, so a content- or
        # filename-derived name would let one tenant's insert collide with another's.
        expected = f"{item.id}.epub"
        if item.storage_name != expected:
            raise UnsafeEpub("Stored item path is inconsistent")
        # tenant_id must be a single, safe path segment. It is always DB-generated today, but
        # this is a structural guard on the path -- not an authorization check -- so that a
        # stray path bug degrades to a missing file rather than escaping items_dir.
        if not item.tenant_id or item.tenant_id in {".", ".."} or "/" in item.tenant_id or "\\" in item.tenant_id:
            raise UnsafeEpub("Stored item tenant_id is unsafe")
        tenant_dir = self._tenant_dir(item.tenant_id)
        path = tenant_dir / expected
        if path.parent != tenant_dir:
            raise UnsafeEpub("Stored item path is unsafe")
        return path

    def store_bytes(
        self,
        scope: TenantScope,
        payload: bytes,
        *,
        filename: str,
        kind: str,
        source: str,
        source_url: str = "",
        title: str = "",
        author: str = "",
    ) -> StoreResult:
        return self._store(
            scope,
            [payload],
            filename=filename,
            kind=kind,
            source=source,
            source_url=source_url,
            title=title,
            author=author,
        )

    def store_chunks(
        self,
        scope: TenantScope,
        chunks: Iterable[bytes],
        *,
        filename: str,
        source: str,
        kind: str = "book",
    ) -> StoreResult:
        return self._store(scope, chunks, filename=filename, kind=kind, source=source)

    def _store(
        self,
        scope: TenantScope,
        chunks: Iterable[bytes],
        *,
        filename: str,
        kind: str,
        source: str,
        source_url: str = "",
        title: str = "",
        author: str = "",
    ) -> StoreResult:
        fallback_title = Path(sanitize_filename(filename)).stem
        digest = hashlib.sha256()
        total = 0
        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                prefix="upload-",
                suffix=".tmp",
                dir=self.temp_dir,
                delete=False,
            ) as output:
                temporary_path = Path(output.name)
                for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise UnsafeEpub("Attachment stream returned invalid data")
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > self.settings.max_upload_bytes:
                        raise UploadTooLarge("EPUB exceeds the configured upload-size limit")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())

            if total == 0:
                raise UnsafeEpub("Uploaded EPUB is empty")

            sha256 = digest.hexdigest()
            # Always inspected, even when title/author are already known (store_bytes callers),
            # so generated and uploaded files take the same validation path and so language and
            # identifier -- which callers never supply -- come from the file itself.
            metadata = inspect_epub(temporary_path, self.settings, fallback_title=fallback_title)
            download_filename = sanitize_filename(filename, fallback_title=metadata.title)

            with self._lock:
                existing = self.database.item_by_sha256(scope, sha256)
                if existing is not None:
                    temporary_path.unlink(missing_ok=True)
                    temporary_path = None
                    return StoreResult(item=existing, duplicate=True)

                # After the duplicate check, so re-sending a file the tenant already has
                # stays a duplicate rather than becoming a quota error -- it adds no bytes.
                # Inside the lock, so two concurrent stores read a usage figure that already
                # includes whichever of them landed first.
                self._enforce_quota(scope, total)

                tenant_dir = self._tenant_dir(scope.tenant_id)
                tenant_dir.mkdir(parents=True, exist_ok=True)

                item_id = uuid.uuid4().hex
                item = Item(
                    id=item_id,
                    tenant_id=scope.tenant_id,
                    kind=kind,
                    sha256=sha256,
                    storage_name=f"{item_id}.epub",
                    download_filename=download_filename,
                    title=title or metadata.title,
                    author=author or metadata.author,
                    language=metadata.language,
                    identifier=metadata.identifier,
                    source_url=source_url,
                    size_bytes=total,
                    created_at=datetime.now(UTC).isoformat(),
                    expires_at=None,
                    source=source,
                )
                destination = self.path_for(item)
                if destination.exists():
                    raise UnsafeEpub("A conflicting stored item already exists")
                os.replace(temporary_path, destination)
                temporary_path = None
                self._fsync_directory(tenant_dir)
                try:
                    self.database.insert_item(scope, item)
                except Exception:
                    destination.unlink(missing_ok=True)
                    self._fsync_directory(tenant_dir)
                    raise
                return StoreResult(item=item, duplicate=False)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def _enforce_quota(self, scope: TenantScope, incoming_bytes: int) -> None:
        """Refuse a store that would put the tenant over their plan's allowance.

        The plan is read here rather than cached anywhere: an upgrade must take effect on
        the next upload, not on the next restart. An unknown tenant id -- which insert_item
        would reject moments later anyway -- is charged the free allowance rather than
        skipping the check.
        """
        tenant = self.database.tenant_by_id(scope.tenant_id)
        allowance = quota_bytes(tenant.plan if tenant is not None else FREE_PLAN)
        if self.database.tenant_storage_bytes(scope) + incoming_bytes > allowance:
            raise StorageQuotaExceeded("Storing this item would exceed the plan's storage limit")
        # The whole volume, not this account. Checked after the allowance so a full account
        # is still told it is full rather than that we are; the wording of each reaches the
        # reader in the rejection reply.
        if self.storage_report().free_bytes - incoming_bytes < DISK_FREE_FLOOR_BYTES:
            raise ServiceStorageFull(
                "Steepd is out of storage space, so nothing was stored. This is our problem, not your "
                "account's; try again later"
            )

    def delete(self, scope: TenantScope, item_id: str) -> bool:
        with self._lock:
            item = self.database.get_item(scope, item_id)
            if item is None:
                return False
            source = self.path_for(item)
            staged = self.trash_dir / f"{item.id}.epub"
            if source.exists():
                os.replace(source, staged)
            try:
                if not self.database.delete_item(scope, item_id):
                    if staged.exists():
                        os.replace(staged, source)
                    return False
            except Exception:
                if staged.exists():
                    os.replace(staged, source)
                raise
            staged.unlink(missing_ok=True)
            self._fsync_directory(self._tenant_dir(item.tenant_id))
            return True

    def delete_all_for_tenant(self, scope: TenantScope) -> int:
        """Delete every one of the tenant's items and return how many went.

        Each one goes through delete(), so every file takes the same trash-staged, fsynced
        path as a single deletion and a failure part-way through leaves the rest consistent
        rather than half-orphaned. The loop re-reads page zero each time instead of walking
        an offset: a successful delete removes the row it just read, so the next page starts
        where the last one did. `progressed` is the termination guard -- a page whose items
        all refuse to delete would otherwise be re-read forever.
        """
        deleted = 0
        while True:
            items = self.database.list_items(scope, limit=100)
            progressed = False
            for item in items:
                if self.delete(scope, item.id):
                    deleted += 1
                    progressed = True
            if not progressed:
                break
        with suppress(OSError):
            # Fails while anything is left in it, which is the check we want: an empty
            # per-tenant directory still records that the tenant existed.
            self._tenant_dir(scope.tenant_id).rmdir()
        return deleted

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        try:
            descriptor = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def storage_report(self) -> StorageReport:
        usage = shutil.disk_usage(self.settings.data_dir)
        return StorageReport(total_bytes=usage.total, free_bytes=usage.free)

    def storage_is_healthy(self) -> bool:
        try:
            if not all(directory.is_dir() for directory in (self.items_dir, self.temp_dir, self.trash_dir)):
                return False
            return self.storage_report().free_bytes > 0
        except OSError:
            return False
