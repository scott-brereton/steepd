from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

ItemKind = Literal["book", "article"]


@dataclass(frozen=True, slots=True)
class Tenant:
    id: str
    email: str
    inbox_local: str
    opds_username: str
    opds_password_hash: str
    plan: str
    created_at: str
    # NULL until the owner chose their address on first sign-in. While NULL the
    # inbox_local is a placeholder nothing routes to. See steepd.inboxnames.
    inbox_confirmed_at: str | None = None
    # "anyone" or "listed". Anything else reads as "anyone".
    sender_policy: str = "anyone"


@dataclass(frozen=True, slots=True)
class RefusedSender:
    address: str
    count: int
    last_seen_at: str


@dataclass(frozen=True, slots=True)
class Item:
    id: str
    tenant_id: str
    kind: ItemKind
    sha256: str
    storage_name: str
    download_filename: str
    title: str
    author: str
    language: str
    identifier: str
    source_url: str
    size_bytes: int
    created_at: str
    expires_at: str | None
    source: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AuthorSummary:
    name: str
    item_count: int
    updated_at: str
