"""Benchmark: does the detector actually catch attacks without blocking
legitimate messages?

We run every item in the labeled red-team corpus through the detector and score
the classic confusion-matrix metrics. Precision matters because a filter that
cries wolf gets turned off. Recall matters because a filter that misses attacks
is theater. The benign set is full of lookalikes on purpose, so precision here
is a real test, not a freebie.

Run it:

    python -m injectguard.eval

Deterministic. No model, no network, no API keys.
"""
from __future__ import annotations

from injectguard.corpus import ATTACKS, BENIGN
from injectguard.detector import Detector


def run(threshold: float = 0.5) -> None:
    det = Detector(threshold=threshold)

    tp = sum(det.scan(t).blocked for t in ATTACKS)          # attacks correctly blocked
    fn = len(ATTACKS) - tp                                   # attacks that slipped through
    fp = sum(det.scan(t).blocked for t in BENIGN)            # benign wrongly blocked
    tn = len(BENIGN) - fp                                    # benign correctly allowed

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (len(ATTACKS) + len(BENIGN))

    print(f"red-team benchmark: {len(ATTACKS)} attacks, {len(BENIGN)} benign "
          f"(many are lookalikes)\n")
    print(f"  threshold        {threshold:.2f}")
    print(f"  precision        {precision:.0%}   (of blocked messages, how many were real attacks)")
    print(f"  recall           {recall:.0%}   (of real attacks, how many we caught)")
    print(f"  f1               {f1:.2f}")
    print(f"  accuracy         {accuracy:.0%}")
    print(f"  confusion        blocked-attack={tp} missed-attack={fn} "
          f"false-alarm={fp} clean-pass={tn}")

    if fn:
        print("\n  attacks that slipped through:")
        for t in ATTACKS:
            if not det.scan(t).blocked:
                print(f"    - {t[:70]}")
    if fp:
        print("\n  benign messages wrongly blocked:")
        for t in BENIGN:
            if det.scan(t).blocked:
                print(f"    - {t[:70]}")

    print("\nthis is a first line of defense: cheap, transparent, and auditable.")
    print("it stops the copy-paste attacks. it will not stop a determined attacker")
    print("who rephrases. isolate untrusted content too. see the README.")


if __name__ == "__main__":
    run()
