from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import sys

import uvicorn

from steepd.app import create_app
from steepd.config import Settings
from steepd.db import Database
from steepd.inboxnames import normalize_inbox_local, validate_inbox_local_format
from steepd.stats import render_stats
from steepd.storage import ItemStorage

# Paths whose request line must never reach the access log. A sign-in link is a bearer
# credential: it travels only by email, and a log line holding it -- retained by the host,
# readable by anyone with the dashboard -- would be a second copy nobody sent.
_UNLOGGED_PATH_PREFIXES = ("/auth/",)


class AccessLogPathFilter(logging.Filter):
    """Drop uvicorn access-log records for paths that carry a credential.

    uvicorn's access logger formats `%s - "%s %s HTTP/%s" %d` from a five-tuple of args,
    the third of which is the path with its query string. That is the only shape it emits,
    so anything else passes through untouched rather than being silenced by accident.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            return not args[2].startswith(_UNLOGGED_PATH_PREFIXES)
        return True


def serve() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # httpx logs every request URL at INFO. Newsletter image URLs can carry per-subscriber
    # tokens and Resend attachment URLs are signed; neither belongs in the log stream.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").addFilter(AccessLogPathFilter())
    settings = Settings.from_env()
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(
        create_app(settings),
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
        forwarded_allow_ips="*",
        server_header=False,
        access_log=True,
    )


def create_tenant(email: str, inbox_local: str) -> int:
    """Onboard one tenant and print the only copy of their device password.

    The password is shown once and never stored -- only its hash lands in the
    database -- so this output is the moment to copy it into the reader.
    """
    settings = Settings.from_env()
    database = Database(settings.data_dir / "steepd.sqlite3")
    database.initialize()

    # The same two rules the address page applies, so an operator cannot hand out a name the
    # web form would have refused. inbox_local_available also covers retired names, which the
    # UNIQUE constraint below would not catch.
    name = normalize_inbox_local(inbox_local)
    reason = validate_inbox_local_format(name)
    if reason is not None:
        print(f"Inbox address {inbox_local!r} is not usable: {reason}", file=sys.stderr)
        return 1
    if not database.inbox_local_available(name):
        print("A tenant with that email or inbox address already exists.", file=sys.stderr)
        return 1

    try:
        tenant, device_password = database.create_tenant_with_password(email=email, inbox_local=name)
    except sqlite3.IntegrityError:
        print("A tenant with that email or inbox address already exists.", file=sys.stderr)
        return 1

    inbox = f"{tenant.inbox_local}@{settings.inbox_domain}" if settings.inbox_domain else tenant.inbox_local
    print(f"Tenant created for {tenant.email}")
    print(f"  Inbox address:   {inbox}")
    print(f"  OPDS catalogue:  {settings.public_base_url}/opds")
    print(f"  Device username: {tenant.opds_username}")
    print(f"  Device password: {device_password}")
    print("The password is shown only this once; it is not stored and cannot be recovered.")
    return 0


def stats() -> int:
    """Print the operator's figures. The same text `GET /admin/stats` serves, for a shell
    on the box (a Railway ssh session, or a local run against a copied volume)."""
    settings = Settings.from_env()
    database = Database(settings.data_dir / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    print(render_stats(database, storage), end="")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="steepd", description="Steepd hosted reader service")
    subparsers = parser.add_subparsers(dest="command")
    create = subparsers.add_parser("create-tenant", help="Onboard a tenant and print their one-time device password")
    create.add_argument("email", help="The tenant's own email address (identity, not the inbox)")
    create.add_argument("inbox_local", help="Local part of the tenant's private inbox, e.g. 'ada.1'")
    subparsers.add_parser("stats", help="Print account, item, inbound-mail and volume counts")
    arguments = parser.parse_args()

    if arguments.command == "create-tenant":
        raise SystemExit(create_tenant(arguments.email, arguments.inbox_local))
    if arguments.command == "stats":
        raise SystemExit(stats())
    serve()


if __name__ == "__main__":
    main()
