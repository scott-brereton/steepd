"""Tests for the create-tenant command. It is the only onboarding path for plan (a),
so it must actually persist the tenant and print the one-time password it claims to."""

from __future__ import annotations

import logging

from steepd.__main__ import AccessLogPathFilter, create_tenant, stats
from steepd.db import Database


def _configure(monkeypatch, tmp_path):
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INBOX_DOMAIN", "read.example.test")


def test_create_tenant_persists_and_prints_working_credentials(monkeypatch, tmp_path, capsys):
    _configure(monkeypatch, tmp_path)
    assert create_tenant("ada@example.com", "ada.1") == 0
    output = capsys.readouterr().out
    assert "ada.1@read.example.test" in output
    assert "Device username: ada.1" in output

    printed_password = next(
        line.split("Device password:")[1].strip() for line in output.splitlines() if "Device password:" in line
    )
    database = Database(tmp_path / "steepd.sqlite3")
    tenant = database.tenant_by_opds_username("ada.1")
    assert tenant is not None and tenant.email == "ada@example.com"
    # The printed password must be the one whose hash was stored, or onboarding hands
    # out credentials that can never log in.
    from steepd.auth import verify_password

    assert verify_password(printed_password, tenant.opds_password_hash)


def test_create_tenant_rejects_a_duplicate_inbox(monkeypatch, tmp_path, capsys):
    _configure(monkeypatch, tmp_path)
    assert create_tenant("ada@example.com", "ada.1") == 0
    assert create_tenant("other@example.com", "ada.1") == 1
    assert "already exists" in capsys.readouterr().err


def _access_record(path: str, *, args=None) -> logging.LogRecord:
    """A record shaped the way uvicorn's access logger emits one."""
    return logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
        args if args is not None else ("203.0.113.9:4000", "GET", path, "1.1", 303), None,
    )


def test_sign_in_links_are_kept_out_of_the_access_log():
    """The magic link is a bearer credential and the request line is the one place it
    would otherwise be written down. Every other request is logged as before, and a record
    of an unexpected shape is passed through rather than silenced."""
    keep = AccessLogPathFilter()
    assert keep.filter(_access_record("/auth/abc123?x=1")) is False
    assert keep.filter(_access_record("/account")) is True
    assert keep.filter(_access_record("/authors")) is True
    assert keep.filter(_access_record("", args=("only", "two"))) is True


def test_create_tenant_refuses_a_malformed_or_reserved_name(monkeypatch, tmp_path, capsys):
    _configure(monkeypatch, tmp_path)
    assert create_tenant("ada@example.com", "Hello") == 1
    assert "reserved" in capsys.readouterr().err
    assert create_tenant("ada@example.com", ".ada") == 1
    assert Database(tmp_path / "steepd.sqlite3").tenant_by_email("ada@example.com") is None


def test_create_tenant_refuses_a_retired_name(monkeypatch, tmp_path, capsys):
    _configure(monkeypatch, tmp_path)
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    gone = database.create_tenant(email="gone@example.com", inbox_local="ada")
    database.delete_tenant(gone.id)
    assert create_tenant("ada@example.com", "ada") == 1
    assert "already exists" in capsys.readouterr().err


def test_a_cli_tenant_is_confirmed_immediately(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    assert create_tenant("ada@example.com", "ada.1") == 0
    tenant = Database(tmp_path / "steepd.sqlite3").tenant_by_inbox_local("ada.1")
    assert tenant is not None and tenant.inbox_confirmed_at is not None


def test_stats_prints_accounts_items_inbound_and_volume(monkeypatch, tmp_path, capsys):
    from datetime import UTC, datetime

    from steepd.epubgen import build_epub
    from steepd.storage import ItemStorage
    from steepd.tenancy import TenantScope

    _configure(monkeypatch, tmp_path)
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    confirmed = database.create_tenant(email="ada@example.com", inbox_local="ada")
    database.create_pending_tenant(email="new@example.com")
    database.set_tenant_plan(confirmed.id, "paid")
    from steepd.config import Settings

    storage = ItemStorage(Settings.from_env(), database)
    storage.initialize()
    payload = build_epub(title="Book", author="A", language="en", identifier="urn:uuid:b", body_html="<p>hi</p>")
    storage.store_bytes(TenantScope(confirmed.id), payload, filename="b.epub", kind="book", source="email")
    now = datetime.now(UTC).isoformat()
    database.record_webhook_event("resend", "e1", now, "imported=1;duplicates=0;rejected=0")
    database.record_webhook_event("resend", "e2", now, "newsletter;imported=0;duplicates=0;rejected=1")
    database.record_webhook_event("resend", "e3", now, "unknown-inbox")
    database.record_webhook_event("resend", "e4", now, "sender-refused")
    database.record_webhook_event("resend", "old", "2020-01-01T00:00:00+00:00", "unknown-inbox")

    assert stats() == 0
    out = capsys.readouterr().out
    assert "Accounts:       2 (1 confirmed, 1 pending); 0 free, 1 paid" in out
    assert "Items:          1 (1 books, 0 articles)" in out
    assert "Inbound (30d):  4 emails; 1 filed, 1 rejected, 1 to unknown inboxes, 1 refused by sender policy" in out
    assert "Volume:" in out and "free" in out
