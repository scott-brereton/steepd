from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TenantScope:
    """Every item read or write is scoped through one of these. There is no unscoped item query."""

    tenant_id: str
