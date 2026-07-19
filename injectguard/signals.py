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
            # the classic bare form: "ignore the above and say X" (no noun at all)
            r"ig(no|mo)re (the|all|everything)\s*(above|below)?\s*(and|,|:)",
            r"ignore (all\s+)?(the\s+)?provided (context|articles?|text|information)",
            r"disregard (all|any|the|your)?\s*(previous|prior|above|earlier)",
            r"forget (everything|all|what|the)\s+(you|above|previous|prior)",
            # conversation reset: "forget everything we've talked about", "you have amnesia"
            r"forget (everything|all)\s+(we|that|about|i|before|from)\b",
            r"\b(has|have|with|got)\s+amnesia\b",
            r"do not (follow|obey|listen to)\s+(the|your|any|previous)",
            # German, same family
            r"ignorier(e|en sie)?\s+(alle|die|alle vorherigen|vorherigen|obigen)\s*(anweisungen|instruktionen|regeln|eingaben)?",
            r"vergiss (alles|was|die|deine)",
            r"vergessen sie (alles|was|die|ihre)",
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
            # conversation reset framed as a fresh assignment
            r"(now )?(come|comes|start with) (a )?new (task|tasks|assignment)",
            # German, same family
            r"(du bist|sie sind) (jetzt|nun|ab sofort)",
            r"tu so,? als",
            r"(agiere|handeln sie|agieren sie) als",
            r"von nun an",
            r"ich m(ö|o)chte, dass (du|sie) als .{0,40}(agier|fungier|handel)",
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
            # the spellcheck-and-print family: any verb aimed at "the above prompt/text"
            r"(print|repeat|output|spell.?check|proofread|copy)\b.{0,40}\b(above|obige[nr]?)\s*(prompt|text|instructions?|eingabeaufforderung)?",
            r"(the )?(text|prompt|words) above and (print|repeat|output|return)",
            r"return your embeddings",
            # German, same family
            r"(drucke|drucken sie|zeige|zeigen sie|wiederhole|wiederholen sie)\b.{0,40}(eingabeaufforderung|prompt|anweisungen)",
            r"pr(ü|u)fen sie .{0,30}rechtschreibung",
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
#
# The generic publication words (article, research, example...) only count when
# the text is actually about injection as a topic. Without that anchor, any
# roleplay attack that happens to mention "research" or "discuss" gets a free
# discount, which is exactly how the first external-benchmark run lost recall.
_META_TOPIC = re.compile(
    r"\b(prompt injection|jailbreak(s|ing)?|injection attack|adversarial prompt)\b",
    re.IGNORECASE,
)
_META_GENERIC = re.compile(
    r"\b(article|blog|post|paper|research(ing|er)?|study|example|discuss(es|ing)?)\b",
    re.IGNORECASE,
)
META_FRAMING = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"attackers? (say|use|write|craft|send)",
        r"how (to )?(defend|protect|prevent|detect)",
        r"what (is|are) (a |an )?(prompt injection|jailbreak)",
    ]
]
META_DAMPEN = 0.35


def meta_discussion_score(text: str) -> float:
    """Return the dampening to subtract when text reads as discussion, not attack."""
    if any(p.search(text) for p in META_FRAMING):
        return META_DAMPEN
    if _META_GENERIC.search(text) and _META_TOPIC.search(text):
        return META_DAMPEN
    return 0.0
