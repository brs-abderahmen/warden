"""Remember text from untrusted tools and spot it in later tool calls.

Matching is on text, so a rewritten secret will not match. Strict approval mode covers that case.
"""

import re

TOKEN = re.compile(r"[^\W_]+(?:[-@.][^\W_]+)*")
DOMAIN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}")
SHINGLE_WORDS = 4


def tokens(text: str) -> list[str]:
    return [token.lower() for token in TOKEN.findall(text)]


def is_identifier(token: str) -> bool:
    """Addresses, domains and codes are distinctive enough to match on a single token."""
    return (
        "@" in token
        or bool(DOMAIN.fullmatch(token))
        or (len(token) >= 6 and any(char.isdigit() for char in token))
    )


def shingles(words: list[str]) -> set[tuple[str, ...]]:
    return {
        tuple(words[index : index + SHINGLE_WORDS])
        for index in range(len(words) - SHINGLE_WORDS + 1)
    }


class UntrustedData:
    def __init__(self):
        self.seen = False
        self.identifiers: set[str] = set()
        self.shingles: set[tuple[str, ...]] = set()

    def add(self, text: str) -> None:
        self.seen = True
        words = tokens(text)
        self.identifiers.update(word for word in words if is_identifier(word))
        self.shingles.update(shingles(words))

    def overlaps(self, text: str) -> bool:
        words = tokens(text)
        return bool(self.identifiers.intersection(words)) or bool(
            self.shingles.intersection(shingles(words))
        )
