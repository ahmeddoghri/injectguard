"""The individual injection/jailbreak signals.

Each signal is a small, named, interpretable rule. Keeping them separate is the
whole point: when the detector blocks something, it can tell you which signals
fired, so you can audit false positives instead of staring at a black-box score.

These patterns cover the common, well-documented attack shapes. They are not
exhaustive and they are not a substitute for real isolation of untrusted content.
See the README for the honest limits.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SignalHit:
    signal: str
    weight: float
    evidence: str


@dataclass
class Signal:
    name: str
    weight: float
    patterns: list[str]
    _compiled: list[re.Pattern] = None

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def check(self, text: str) -> SignalHit | None:
        for pat in self._compiled:
            m = pat.search(text)
            if m:
                return SignalHit(self.name, self.weight, m.group(0)[:80])
        return None


# The signal set. Weights are calibrated so that any single strong signal, or a
# couple of weak ones together, crosses the default threshold.
SIGNALS: list[Signal] = [
    Signal(
        "instruction_override",
        weight=0.6,
        patterns=[
            r"ignore (all|any|the|your)?\s*(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)",
            r"ignore (your|the|all|any)\s+(guidelines?|guardrails?|rules?|restrictions?|safety)",
            r"disregard (all|any|the|your)?\s*(previous|prior|above|earlier)",
            r"forget (everything|all|what|the)\s+(you|above|previous|prior)",
            r"do not (follow|obey|listen to)\s+(the|your|any|previous)",
        ],
    ),
    Signal(
        "role_reassignment",
        weight=0.5,
        patterns=[
            r"you are (now|actually|really)\s+(a|an|the|no longer)",
            r"you are no longer (bound|restricted|limited|subject)",
            r"from now on,? you",
            r"pretend (to be|you are|that you)",
            r"act as (if|though|a|an)\b",
            r"new (system )?(prompt|instructions?|rules?):",
        ],
    ),
    Signal(
        "jailbreak_persona",
        weight=0.6,
        patterns=[
            r"\bDAN\b.{0,40}(mode|jailbreak|do anything)",
            r"do anything now",
            r"developer mode",
            r"(enable|activate|switch to)\s+.{0,20}(unrestricted|unfiltered|jailbreak)",
            r"you have no (restrictions?|guidelines?|filters?|rules?)",
        ],
    ),
    Signal(
        "system_prompt_exfiltration",
        weight=0.55,
        patterns=[
            r"(reveal|show|print|repeat|output|tell me)\s+(your|the)\s+(original\s+|initial\s+|system\s+)*(prompt|instructions?|rules?)",
            r"what (are|were) your (original |initial |system )?(instructions?|rules?)",
            r"repeat the (words|text) above",
        ],
    ),
    Signal(
        "delimiter_injection",
        weight=0.4,
        patterns=[
            r"</?(system|user|assistant|instructions?)>",
            r"\[/?(INST|SYS|system|user)\]",
            r"###\s*(system|instruction|new prompt)",
            r"<\|(im_start|im_end|system|endoftext)\|>",
        ],
    ),
    Signal(
        "override_urgency",
        weight=0.25,
        patterns=[
            r"this is (very )?(important|urgent|critical|a test)",
            r"(you must|it is imperative that you)\s+(comply|obey|do|ignore)",
        ],
    ),
    Signal(
        "encoding_evasion",
        weight=0.5,
        patterns=[
            r"(decode|base64|rot13|reverse) (the|this|following)",
            r"respond only in (base64|rot13|hex)",
            r"(so|so that|because) the (safety )?filter (cannot|can't|won't|will not) (read|see|detect)",
        ],
    ),
]

# Meta-discussion framing: text that talks ABOUT attacks rather than performing
# one. When these appear, the payload is very likely quoted or illustrative, so
# we dampen the score. A genuine multi-signal attack still clears the threshold;
# a single-signal message that is really an article or a research question does
# not. This is a deliberate precision/recall trade, documented in the README.
META_FRAMING = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(article|blog|post|paper|research(ing|er)?|study|example|discuss(es|ing)?)\b",
        r"attackers? (say|use|write|craft|send)",
        r"how (to )?(defend|protect|prevent|detect)",
        r"what (is|are) (a |an )?(prompt injection|jailbreak)",
    ]
]
META_DAMPEN = 0.35


def meta_discussion_score(text: str) -> float:
    """Return the dampening to subtract when text reads as discussion, not attack."""
    return META_DAMPEN if any(p.search(text) for p in META_FRAMING) else 0.0
