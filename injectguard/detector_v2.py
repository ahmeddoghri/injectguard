"""Detector wired to the fixed meta-discussion dampener (signals_v2).

Same scoring logic as :class:`injectguard.detector.Detector`, but the
dampener requires quoted evidence before it discounts a match (see
:mod:`injectguard.signals_v2`). Kept as a parallel class rather than a
change to ``detector.py`` so ``injectguard.eval``'s and
``injectguard.external_eval``'s published baselines keep reproducing
exactly.
"""
from __future__ import annotations

from .detector import Verdict
from .signals import SIGNALS, Signal
from .signals_v2 import meta_discussion_score


class DetectorV2:
    def __init__(self, threshold: float = 0.5, signals: list[Signal] | None = None) -> None:
        self.threshold = threshold
        self.signals = signals if signals is not None else SIGNALS

    def scan(self, text: str) -> Verdict:
        hits = []
        for sig in self.signals:
            hit = sig.check(text)
            if hit is not None:
                hits.append(hit)
        score = sum(h.weight for h in hits)
        score -= meta_discussion_score(text, hits)
        score = max(0.0, min(score, 1.0))
        return Verdict(
            blocked=score >= self.threshold,
            score=score,
            threshold=self.threshold,
            hits=hits,
        )

    def is_safe(self, text: str) -> bool:
        return not self.scan(text).blocked
