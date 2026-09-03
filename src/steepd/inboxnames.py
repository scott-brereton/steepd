"""Rules for an inbox local part, which is also the OPDS device username.

Pure functions only: uniqueness against live and retired names is the database's
business (Database.inbox_local_available). Everything that decides whether a string is
an acceptable name lives here so the address page, the CLI and the tests agree.
"""

from __future__ import annotations

import re
import secrets
import string

PLACEHOLDER_PREFIX = "pending."
MIN_LENGTH = 2
MAX_LENGTH = 24

# Names that would collide with a role address, mislead, or look like ours.
RESERVED_INBOX_LOCALS = frozenset(
    {
        "abuse",
        "admin",
        "help",
        "hello",
        "info",
        "login",
        "mail",
        "no-reply",
        "noreply",
        "pending",
        "postmaster",
        "root",
        "steepd",
        "support",
    }
)

_SEPARATORS = (".", "-")
_STEM_ALPHABET = frozenset(string.ascii_lowercase + string.digits)
_FORMAT = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")


def normalize_inbox_local(name: str) -> str:
    return name.strip().casefold()


def placeholder_inbox_local() -> str:
    """A name a pending account holds until its owner chooses one. Never shown anywhere."""
    return f"{PLACEHOLDER_PREFIX}{secrets.token_hex(8)}"


def is_placeholder(name: str) -> bool:
    return name.startswith(PLACEHOLDER_PREFIX)


def _separator_out_of_place(name: str) -> bool:
    """True when a dot or hyphen leads, trails, or sits beside another one."""
    if name.startswith(_SEPARATORS) or name.endswith(_SEPARATORS):
        return True
    pairs = zip(name, name[1:], strict=False)
    return any(first in _SEPARATORS and second in _SEPARATORS for first, second in pairs)


def is_reserved_inbox_local(name: str) -> bool:
    """Whether the name is one nobody may hold: a role address the service answers for
    itself, or a pending account's placeholder. Separate from the format rules so a page
    can tell someone their name is reserved rather than merely taken."""
    return name in RESERVED_INBOX_LOCALS or is_placeholder(name)


def validate_inbox_local_format(name: str) -> str | None:
    """The reason this name cannot be an address, or None if its shape is fine."""
    if len(name) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if len(name) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    # Before the alphabet rule, so a doubled dot reports the dot problem rather than the alphabet.
    if _separator_out_of_place(name):
        return "Dots and hyphens can only sit between letters or digits, not at the start or end."
    if not _FORMAT.fullmatch(name):
        return "Use lowercase letters, digits, dots and hyphens only."
    if is_reserved_inbox_local(name):
        return "That name is reserved."
    return None


def email_stem(email: str) -> str:
    """A starting suggestion drawn from an email address: its letters and digits, or "reader"."""
    local = email.partition("@")[0].casefold()
    stem = "".join(character for character in local if character in _STEM_ALPHABET)
    return stem[:MAX_LENGTH] or "reader"
