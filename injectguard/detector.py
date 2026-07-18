"""The detector: run every signal, sum the weights, return a verdict with
the reasons attached.

The design goal is transparency. A blocked message always comes back with the
exact signals that fired and the text that triggered them, so you can tune the
threshold or whitelist a false positive instead of arguing with a mystery score.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from injectguard.signals import SIGNALS, Signal, SignalHit, meta_discussion_score


@dataclass
class Verdict:
    blocked: bool
    score: float
    threshold: float
    hits: list[SignalHit] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [h.signal for h in self.hits]

    def explain(self) -> str:
        if not self.hits:
            return "clean: no injection signals fired"
        parts = [f"{h.signal} (+{h.weight:.2f}) -> {h.evidence!r}" for h in self.hits]
        state = "BLOCKED" if self.blocked else "allowed"
        return f"{state} score={self.score:.2f}/{self.threshold:.2f}\n  " + "\n  ".join(parts)


class Detector:
    """Score text for prompt-injection and jailbreak signals.

    ``threshold`` is the score at or above which text is blocked. The default of
    0.5 means any single strong signal (instruction override, jailbreak persona)
    blocks on its own, while weak signals need company. Tune it against your own
    traffic using the benchmark.
    """

    def __init__(self, threshold: float = 0.5, signals: list[Signal] | None = None) -> None:
        self.threshold = threshold
        self.signals = signals if signals is not None else SIGNALS

    def scan(self, text: str) -> Verdict:
        hits: list[SignalHit] = []
        for sig in self.signals:
            hit = sig.check(text)
            if hit is not None:
                hits.append(hit)
        score = sum(h.weight for h in hits)
        # dampen text that reads as discussion of attacks rather than an attack
        score -= meta_discussion_score(text)
        # clamp to [0, 1] so it reads like a probability-ish number
        score = max(0.0, min(score, 1.0))
        return Verdict(
            blocked=score >= self.threshold,
            score=score,
            threshold=self.threshold,
            hits=hits,
        )

    def is_safe(self, text: str) -> bool:
        return not self.scan(text).blocked
