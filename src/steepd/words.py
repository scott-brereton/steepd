"""Human-typeable passphrases for device passwords.

The wordlist is the EFF "large" wordlist (eff_large_wordlist.txt), published by the
Electronic Frontier Foundation in 2016 at https://www.eff.org/dice and licensed
CC BY 3.0 US (https://creativecommons.org/licenses/by/3.0/us/). It is vendored as
wordlist.txt: the upstream file's leading five-digit dice indices are stripped, and
what remains is one word per line, in upstream order. There is deliberately no header
or comment in that file -- every line is a candidate word, so a comment would become
one.

The vendored list is upstream's 7776 entries minus exactly four:

    drop-down    felt-tip    t-shirt    yo-yo

which are the only upstream entries containing a hyphen. That is the whole diff
against EFF's file, so a reviewer can reconstruct it. They are excluded rather than
de-hyphenated because "yo-yo" would collapse onto the list's own separate "yoyo"
entry; excluding them keeps every word a uniform [a-z]+.

Uniformity is the point. These passphrases are read off one screen and typed into
another, and a dot-separated phrase containing a hyphenated word (say
"maple.drop-down.lantern") makes the reader guess which separator they are looking
at. Dropping those four costs 0.0022 bits of entropy, which is nothing, and buys a
password that transcribes cleanly every time.
"""

from __future__ import annotations

import secrets
from importlib.resources import files

# Three words drawn from 7772 is 7772**3 == 469_459_763_648 possibilities, or about
# 2**38.77. That is not enough to stand alone against an offline attacker, and it is not
# asked to: the plaintext is never stored, only a scrypt hash (n=2**14, r=8, p=1 -- see
# steepd.auth.hash_password), and online guessing is to be rate limited before launch.
# Three was chosen over four as a typing-effort tradeoff -- these passwords are entered
# on e-ink keyboards, one slow character at a time -- and is judged proportionate to what
# it guards: a personal reading library, not money or identity.
MINIMUM_WORD_COUNT = 3


def _load_words() -> tuple[str, ...]:
    """Read the vendored list once, at import.

    importlib.resources rather than a path relative to __file__ so this works the same
    whether steepd is an editable install pointing into src/ or the wheel the Dockerfile
    builds and pip-installs into site-packages.
    """
    text = files(__package__).joinpath("wordlist.txt").read_text(encoding="utf-8")
    return tuple(text.split())


WORDS = _load_words()


def generate_passphrase(word_count: int = 3, *, separator: str = ".") -> str:
    """A random passphrase such as "maple.otter.lantern".

    Raises ValueError below MINIMUM_WORD_COUNT words. Callers may ask for more, never
    fewer: the floor is the security property, and a caller that could pass 1 or 2 could
    weaken every device password in the system without the change being visible here.
    """
    if word_count < MINIMUM_WORD_COUNT:
        raise ValueError(f"word_count must be at least {MINIMUM_WORD_COUNT}, got {word_count}")
    return separator.join(secrets.choice(WORDS) for _ in range(word_count))
