"""Run the detector against someone else's benchmark.

The internal corpus in ``corpus.py`` is useful for development, but a detector
graded only on its author's own test set has told you nothing yet. This module
runs the stock :class:`~injectguard.detector.Detector` against the
deepset/prompt-injections dataset (662 labeled prompts, Apache 2.0, embedded
verbatim under ``injectguard/data/``) and reports precision, recall, and F1 for
the injection class, overall and per language.

Run it::

    python -m injectguard.external_eval

No network, no dependencies, deterministic. The numbers it prints are the
numbers in the README.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources

from injectguard.detector import Detector

DATASET = "deepset_prompt_injections.json"


def load_rows() -> list[dict]:
    """Load the embedded corpus (text, label, split, lang per row)."""
    path = resources.files("injectguard").joinpath("data", DATASET)
    with path.open(encoding="utf-8") as f:
        return json.load(f)["rows"]


@dataclass
class Scores:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def evaluate(detector: Detector | None = None) -> dict[str, Scores]:
    """Score the detector on the external corpus.

    Returns scores keyed by group: ``all``, ``en``, ``de``.
    """
    det = detector or Detector()
    groups: dict[str, Scores] = {"all": Scores(), "en": Scores(), "de": Scores()}
    for row in load_rows():
        blocked = det.scan(row["text"]).blocked
        for key in ("all", row["lang"]):
            s = groups[key]
            if row["label"] == 1 and blocked:
                s.tp += 1
            elif row["label"] == 1:
                s.fn += 1
            elif blocked:
                s.fp += 1
            else:
                s.tn += 1
    return groups


def sample_misses(detector: Detector | None = None, k: int = 5) -> dict[str, list[str]]:
    """A few example false negatives and false positives, for the README."""
    det = detector or Detector()
    fns: list[str] = []
    fps: list[str] = []
    for row in load_rows():
        blocked = det.scan(row["text"]).blocked
        if row["label"] == 1 and not blocked and len(fns) < k:
            fns.append(row["text"])
        elif row["label"] == 0 and blocked and len(fps) < k:
            fps.append(row["text"])
    return {"false_negatives": fns, "false_positives": fps}


def main() -> None:
    groups = evaluate()
    print("external benchmark: deepset/prompt-injections (662 prompts, Apache 2.0)")
    print()
    print(f"{'group':<8}{'n':>6}{'precision':>11}{'recall':>9}{'f1':>7}")
    for name, s in groups.items():
        n = s.tp + s.fp + s.fn + s.tn
        print(f"{name:<8}{n:>6}{s.precision:>11.2f}{s.recall:>9.2f}{s.f1:>7.2f}")
    print()
    misses = sample_misses(k=3)
    print("example misses (false negatives):")
    for t in misses["false_negatives"]:
        print(f"  * {t[:100].replace(chr(10), ' ')}")
    print("example false alarms (false positives):")
    for t in misses["false_positives"]:
        print(f"  * {t[:100].replace(chr(10), ' ')}")


if __name__ == "__main__":
    main()
