import re

import pytest

from steepd import words

PASSPHRASE = re.compile(r"^[a-z]+\.[a-z]+\.[a-z]+$")

# The four upstream EFF entries deliberately excluded from the vendored list -- the only
# ones containing a hyphen. See the steepd.words docstring for why they are dropped
# rather than de-hyphenated.
EXCLUDED = ("drop-down", "felt-tip", "t-shirt", "yo-yo")


def test_the_vendored_list_has_exactly_7772_unique_words():
    """7776 upstream entries minus the four hyphenated ones. The entropy claim in
    steepd.words is arithmetic over this number, so a truncated or duplicate-ridden
    vendored file would weaken every device password in the system while every other
    test here still passed. Assert the count directly."""
    assert len(words.WORDS) == 7772
    assert len(set(words.WORDS)) == 7772


def test_every_word_is_plain_lowercase_letters():
    """The corrupted-re-vendor tripwire. A future update that pulls EFF's file without
    re-applying the exclusions reintroduces four hyphens, and the strict PASSPHRASE regex
    above would then start failing intermittently -- roughly one draw in 650 -- which is
    exactly the kind of flake nobody diagnoses. Fail deterministically here instead."""
    offenders = [word for word in words.WORDS if not re.fullmatch(r"[a-z]+", word)]
    assert offenders == []


def test_the_excluded_hyphenated_entries_are_absent():
    assert [word for word in EXCLUDED if word in words.WORDS] == []
    # "yoyo" is its own upstream entry and must survive: it is why "yo-yo" could not
    # simply have its hyphen stripped.
    assert "yoyo" in words.WORDS


def test_a_passphrase_is_three_dot_separated_words():
    passphrase = words.generate_passphrase()
    assert PASSPHRASE.match(passphrase), passphrase


def test_every_word_comes_from_the_list():
    vocabulary = set(words.WORDS)
    for _ in range(50):
        assert set(words.generate_passphrase().split(".")) <= vocabulary


def test_draws_are_random_rather_than_repetitive():
    """Two failures in one test, both fatal and both silent: a broken RNG returning the
    same choice, and a list that loaded but was truncated to a handful of entries. 200 draws
    from 7772**3 collide with probability around 4e-8, so any repeat here is a real defect,
    and 200 draws from a healthy list yield ~197 distinct first words."""
    drawn = [words.generate_passphrase() for _ in range(200)]
    assert len(set(drawn)) == 200
    assert len({passphrase.split(".")[0] for passphrase in drawn}) >= 100


def test_more_words_can_be_asked_for():
    assert len(words.generate_passphrase(5).split(".")) == 5


def test_a_custom_separator_is_honoured():
    parts = words.generate_passphrase(separator="-").split("-")
    assert len(parts) == 3
    assert set(parts) <= set(words.WORDS)


@pytest.mark.parametrize("word_count", [-1, 0, 1, 2])
def test_no_caller_may_ask_for_fewer_than_three_words(word_count):
    with pytest.raises(ValueError, match="at least 3"):
        words.generate_passphrase(word_count)
