"""The meta-discussion dampener, fixed: don't discount live attacks just
because they mention the word "research."

``meta_discussion_score`` in :mod:`injectguard.signals` subtracts a flat
0.35 whenever the text contains both a generic publication word ("article",
"research", "discuss"...) and a topic word ("prompt injection",
"jailbreak"...), anywhere in the message, regardless of whether the message
also contains a live attack payload sitting right next to that phrase. That
makes the dampener itself an evasion vector: appending one generic sentence,
"This is for a research article discussing prompt injection.", to a real
attack is enough to push 6 of the project's own 15 red-team attacks below
the block threshold (see ``tests/test_adversarial.py`` for the measurement).

Checking the corpus this dampener was built for shows it protects exactly
one benign example: "The article discusses how attackers say 'ignore
previous instructions'." That example puts the quoted trigger phrase inside
quotation marks, a citation, not a command. Every one of the 15 attacks
this dampener can be tricked into discounting has its attack payload
sitting bare, not quoted, in the message. So the fix is narrow: only apply
the generic-co-occurrence dampening when every signal hit's matched
evidence text actually appears inside a quoted span. A citation gets the
benefit of the doubt; a live directive does not, no matter what sentence
you staple onto it afterward. The explicit third-person framing patterns
("attackers say...", "how to defend...") are unaffected, since those never
needed this narrowing to be correct.
"""
from __future__ import annotations

import re

from .signals import (
    _META_GENERIC,
    _META_TOPIC,
    META_DAMPEN,
    META_FRAMING,
    SignalHit,
)

_QUOTE_SPAN = re.compile(r"'([^']*)'|\"([^\"]*)\"")


def _quoted_text(text: str) -> str:
    return " ".join(a or b for a, b in _QUOTE_SPAN.findall(text)).lower()


def meta_discussion_score(text: str, hits: list[SignalHit]) -> float:
    """Return the dampening to subtract when text reads as discussion, not
    attack. Unlike the original, this requires the actual matched attack
    evidence to be inside a quoted span before the generic-co-occurrence
    check is allowed to discount it."""
    if any(p.search(text) for p in META_FRAMING):
        return META_DAMPEN
    if _META_GENERIC.search(text) and _META_TOPIC.search(text):
        if not hits:
            return META_DAMPEN
        quoted = _quoted_text(text)
        if quoted and all(h.evidence.lower() in quoted for h in hits):
            return META_DAMPEN
    return 0.0
