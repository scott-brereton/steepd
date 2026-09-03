from __future__ import annotations

import pytest

from steepd.inboxnames import (
    PLACEHOLDER_PREFIX,
    RESERVED_INBOX_LOCALS,
    email_stem,
    is_placeholder,
    normalize_inbox_local,
    placeholder_inbox_local,
    validate_inbox_local_format,
)


@pytest.mark.parametrize("name", ["ines", "ab", "ines.b", "a-b", "reader42", "x" * 24])
def test_acceptable_names(name):
    assert validate_inbox_local_format(name) is None


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("a", "at least 2"),
        ("x" * 25, "at most 24"),
        ("Ines", "lowercase"),
        ("sc ott", "lowercase"),
        ("ines_b", "lowercase"),
        (".ines", "start or end"),
        ("ines-", "start or end"),
        ("sc..ott", "start or end"),
        ("hello", "reserved"),
        ("no-reply", "reserved"),
        ("pending", "reserved"),
        ("pending.abc", "reserved"),
        ("", "at least 2"),
    ],
)
def test_rejected_names_say_why(name, fragment):
    reason = validate_inbox_local_format(name)
    assert reason is not None and fragment in reason, reason


def test_every_reserved_word_is_itself_well_formed_so_the_list_is_the_only_reason():
    for word in RESERVED_INBOX_LOCALS:
        assert validate_inbox_local_format(word) is not None


def test_placeholders_are_random_prefixed_and_recognised():
    one, two = placeholder_inbox_local(), placeholder_inbox_local()
    assert one != two
    assert one.startswith(PLACEHOLDER_PREFIX) and len(one) == len(PLACEHOLDER_PREFIX) + 16
    assert is_placeholder(one) and not is_placeholder("ines")
    assert validate_inbox_local_format(one) is not None


def test_normalize_trims_and_casefolds():
    assert normalize_inbox_local("  Ines.B ") == "ines.b"


@pytest.mark.parametrize(
    ("email", "stem"),
    [
        ("ines@example.com", "ines"),
        ("Ada.Lovelace+news@example.com", "adalovelacenews"),
        ("李@example.com", "reader"),
        ("averyveryverylongname.indeed.yes@example.com", "averyveryverylongnameind"),
    ],
)
def test_email_stem(email, stem):
    assert email_stem(email) == stem
