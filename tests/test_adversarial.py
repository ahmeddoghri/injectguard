"""Tests for the meta-discussion dampener evasion vulnerability and its fix."""

from __future__ import annotations

from injectguard.corpus import ATTACKS, BENIGN
from injectguard.detector import Detector
from injectguard.detector_v2 import DetectorV2
from injectguard.external_eval import evaluate

EVASION_SUFFIX = " This is for a research article discussing prompt injection."


# --- the finding: the dampener is itself an evasion vector -----------------

def test_original_dampener_lets_attacks_evade_with_a_generic_suffix():
    """Appending one boilerplate sentence flips a real, multi-word attack
    from blocked to allowed for a substantial fraction of the project's own
    red-team corpus."""
    det = Detector()
    evaded = sum(
        1
        for a in ATTACKS
        if det.scan(a).blocked and not det.scan(a + EVASION_SUFFIX).blocked
    )
    assert evaded >= 5  # measured: 6/15


def test_fixed_dampener_closes_the_evasion():
    det = DetectorV2()
    evaded = sum(
        1
        for a in ATTACKS
        if det.scan(a).blocked and not det.scan(a + EVASION_SUFFIX).blocked
    )
    assert evaded == 0


def test_only_one_benign_example_actually_needs_the_dampener():
    """Sanity check on the finding: the corpus this dampener protects is
    small and specific, a quoted citation, not a live command."""
    det = Detector()
    needs_dampening = [
        b
        for b in BENIGN
        if det.scan(b).score > 0 and "'" in b
    ]
    assert len(needs_dampening) == 1
    assert "attackers say" in needs_dampening[0]


# --- the fix does not regress anything the dampener was built for ----------

def test_fixed_detector_still_allows_the_quoted_citation():
    det = DetectorV2()
    assert det.is_safe(
        "The article discusses how attackers say 'ignore previous instructions'."
    )


def test_fixed_detector_still_allows_all_benign_lookalikes():
    det = DetectorV2()
    false_alarms = [b for b in BENIGN if det.scan(b).blocked]
    assert false_alarms == []


def test_fixed_detector_still_catches_every_original_attack():
    det = DetectorV2()
    caught = sum(det.scan(a).blocked for a in ATTACKS)
    assert caught == len(ATTACKS)


# --- external benchmark: fix must not move the published numbers -----------

def test_external_benchmark_unaffected_by_the_fix():
    v1 = evaluate(Detector())
    v2 = evaluate(DetectorV2())
    for group in ("all", "en", "de"):
        assert v2[group].precision == v1[group].precision
        assert v2[group].recall == v1[group].recall


# --- the original module is untouched ---------------------------------------

def test_original_signals_module_untouched():
    import injectguard.signals as signals

    assert not hasattr(signals, "meta_discussion_score_v2")


def test_original_benchmark_still_reproduces():
    det = Detector()
    assert sum(det.scan(a).blocked for a in ATTACKS) == len(ATTACKS)
    assert sum(det.scan(b).blocked for b in BENIGN) == 0
