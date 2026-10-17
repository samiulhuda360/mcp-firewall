"""Rules layer for prompt-injection detection.

Each rule is a regular expression with a weight. A text's score is the sum of the weights of the rules that match
(each rule counts once). A score of 1.0 or more is treated as an injection. Scores between 0.5 and 1.0 are
"suspicious": the optional classifier makes the final call on those (and on everything else the rules let through).

The rules look for the shape of an attack rather than for known strings: an instruction that tries to override the
agent's task, text addressed to "the AI/assistant", directives to call tools or send data somewhere, requests to hide
something from the user, chat-template markers, and hiding tricks (zero-width characters, HTML comments, base64).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field

THRESHOLD = 1.0
SUSPICIOUS = 0.5

ZERO_WIDTH = re.compile("[\u200b‌‍⁠﻿­]")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
TAG_CHARS = re.compile("[󠀀-󠁿]+")  # invisible Unicode "tag" characters that can spell out ASCII

_I = re.I


@dataclass(frozen=True)
class Rule:
    id: str
    weight: float
    pattern: re.Pattern[str]
    description: str


def _r(rule_id: str, weight: float, pattern: str, description: str, flags: int = 0) -> Rule:
    return Rule(rule_id, weight, re.compile(pattern, _I | flags), description)


AGENT_WORDS = r"(?:ai|a\.i\.|llm|assistant|agent|chat ?bot|language model|model|copilot|gpt|gemini)"

RULES: list[Rule] = [
    _r(
        "override",
        1.0,
        r"\b(?:ignore|disregard|forget|override|bypass|skip|drop|abandon|don'?t follow|do not follow)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|former|all|any|your|the|system|original|initial)\b[^.\n]{0,30}?"
        r"\b(?:instructions?|directions?|directives?|prompts?|rules|guidelines|orders|tasks?|assignments?|requests?|context|restrictions?|commands?)\b",
        "tries to cancel the agent's existing instructions",
    ),
    _r(
        "forget_everything",
        1.0,
        r"\b(?:forget|disregard|ignore)\s+(?:everything|all of (?:that|this|the above))\b",
        "tries to wipe the agent's context",
    ),
    _r(
        "new_task",
        0.6,
        r"\b(?:new|updated|revised|real|actual|additional|secret|hidden|supplement(?:ary)?)\s+(?:instructions?|tasks?|directives?|objectives?|rules?|assignments?)\b\s*(?:[:\-]|follows?|are|is)",
        "announces replacement instructions",
    ),
    _r(
        "now_focus",
        0.6,
        r"\bnow\b[^.\n]{0,20}\b(?:focus on|your (?:new |next )?task|perform a different task|we will start over)\b",
        "switches the agent to a new task",
    ),
    _r("from_now_on", 0.4, r"\bfrom now on\b", "changes behaviour for the rest of the session"),
    _r(
        "you_are_now",
        0.6,
        r"\byou (?:are|will be) (?:now|no longer|henceforth)\b|\byou now take instructions\b",
        "redefines the agent's identity",
    ),
    _r(
        "act_as",
        0.4,
        r"\b(?:act|behave|pretend|roleplay|role-play)\s+(?:as|like|to be|you are)\b|\bpretend\b[^.\n]{0,15}\byou\b",
        "asks the agent to play a role",
    ),
    _r(
        "jailbreak_mode",
        1.0,
        r"\b(?:developer|god|dan|jailbreak|unrestricted|admin)\s+mode\b|\bdo anything now\b",
        "known jailbreak framing",
    ),
    _r(
        "addressed_to_agent",
        1.0,
        r"\b(?:note|message|instructions?|reminder|memo|directive|attention)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?"
        + AGENT_WORDS
        + r"s?\b"
        r"|\bif you are an?\s+" + AGENT_WORDS + r"\b"
        r"|\b(?:dear|hey|hello|attention)\s+(?:the\s+)?" + AGENT_WORDS + r"\b",
        "text written to the AI rather than to a person",
    ),
    _r(
        "agent_must",
        0.6,
        r"\b(?:the|any|this|an?)\s+"
        + AGENT_WORDS
        + r"s?\b[^.\n]{0,40}\b(?:must|should|shall|needs? to|is (?:required|instructed|authori[sz]ed)|will now|has to)\b",
        "tells the AI what it must do",
    ),
    _r(
        "tool_directive",
        0.6,
        r"\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[`'\"]?[a-z]+(?:_{1,2}[a-z]+)+[`'\"]?(?:\s+(?:tool|function|command))?\b"
        r"|\b(?:call|invoke|use)\s+the\s+[a-z]+\s+(?:tool|function)\b",
        "directs the agent to call a tool",
    ),
    _r(
        "exfil_destination",
        0.6,
        r"\b(?:send|forward|e-?mail|post|upload|transmit|copy|leak|share|deliver|cc|bcc)\b[^.\n]{0,80}?\b(?:to|at|into)\s+"
        r"(?:[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://\S+)",
        "asks for data to be sent to an address or URL",
    ),
    _r("markdown_exfil", 1.0, r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=", "markdown image whose URL can carry data out"),
    _r(
        "data_in_url",
        0.6,
        r"\b(?:include|append|add|encode|put)\b[^.\n]{0,50}\b(?:in|into|to|as)\s+(?:the\s+)?(?:url|link|query string|query parameter|image (?:url|link))\b",
        "asks for data to be packed into a URL",
    ),
    _r(
        "hide_from_user",
        0.8,
        r"\b(?:do not|don'?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|show(?:ing)?|alert(?:ing)?|notify(?:ing)?|ask(?:ing)?)\b"
        r"[^.\n]{0,30}\b(?:the\s+)?(?:user|human|anyone|operator|customer|requester)\b",
        "asks the agent to hide its actions",
    ),
    _r("silently", 0.3, r"\b(?:silently|quietly|secretly|covertly)\b", "secrecy wording"),
    _r(
        "prompt_leak",
        0.8,
        r"\b(?:reveal|show|print|output|repeat|tell me|give me|list|translate|spell|write out|respond with)\b[^.\n]{0,40}?"
        r"\b(?:system prompt|(?:your|the)\s+(?:initial\s+|original\s+|hidden\s+|complete\s+|full\s+)?(?:instructions|prompt(?: text)?|rules|guidelines)|the (?:pass ?word|pass ?phrase|secret key)|prompt texts?)\b"
        r"|\b(?:beginning|start|top) of (?:this|the|your) (?:prompt|conversation|instructions)\b",
        "asks the agent to reveal its prompt or secrets",
    ),
    _r(
        "chat_markup",
        1.0,
        r"<\|?(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|?>|\[/?(?:INST|SYS)\]|<</?SYS>>|^\s*#{2,}\s*(?:system|instruction)s?\b|^\s*(?:system|assistant)\s*:",
        "chat-template or role markers inside data",
        re.M,
    ),
    _r("end_of_context", 0.6, r"\b(?:end of (?:document|input|context|data|file)|=+\s*end\b|-{3,}\s*end\b)", "pretends the data has ended"),
    _r("urgent_imperative", 0.3, r"\b(?:important|urgent|attention|warning|critical)\b\s*[:!-]", "urgency marker"),
    _r(
        "credential_request",
        0.6,
        r"\b(?:send|share|give|provide|paste|reply with|include)\b[^.\n]{0,40}\b(?:api keys?|passwords?|credentials|tokens?|secrets?|private keys?)\b",
        "asks for credentials",
    ),
]


@dataclass
class InjectionVerdict:
    score: float
    rules: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)

    @property
    def is_injection(self) -> bool:
        return self.score >= THRESHOLD

    @property
    def suspicious(self) -> bool:
        return self.score >= SUSPICIOUS


def normalise(text: str) -> tuple[str, list[str]]:
    """NFKC-folds look-alike characters, unescapes HTML, removes zero-width characters and appends decoded base64."""
    signals: list[str] = []
    if TAG_CHARS.search(text):
        signals.append("unicode_tags")
        text = TAG_CHARS.sub(
            lambda m: " " + "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0x20 <= ord(c) - 0xE0000 < 0x7F) + " ", text
        )
    if ZERO_WIDTH.search(text):
        signals.append("zero_width")
    out = ZERO_WIDTH.sub("", text)
    folded = unicodedata.normalize("NFKC", out)
    if folded != out:
        signals.append("unicode_folded")
    out = html.unescape(folded)
    extra: list[str] = []
    for blob in BASE64_BLOB.findall(out)[:5]:
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(ch.isprintable() or ch.isspace() for ch in decoded) >= 0.95 * len(decoded) and " " in decoded:
            extra.append(decoded)
            signals.append("base64_text")
    if extra:
        out = out + "\n" + "\n".join(extra)
    return out, signals


def scan(text: str) -> InjectionVerdict:
    """Scores one text with the rules layer."""
    norm, signals = normalise(text)
    verdict = InjectionVerdict(score=0.0, signals=signals)
    for rule in RULES:
        if rule.pattern.search(norm):
            verdict.rules.append(rule.id)
            verdict.score += rule.weight
    # Hiding tricks only count when the text also contains something instruction-like.
    if verdict.rules:
        if "zero_width" in signals:
            verdict.score += 0.4
            verdict.rules.append("zero_width")
        if "unicode_tags" in signals:
            verdict.score += 0.6
            verdict.rules.append("hidden_unicode_tags")
        if "base64_text" in signals:
            verdict.score += 0.4
            verdict.rules.append("base64_payload")
        for comment in HTML_COMMENT.findall(norm):
            if re.search(r"\b(?:you|ignore|send|call|assistant|agent|ai)\b", comment, re.I):
                verdict.score += 0.6
                verdict.rules.append("html_comment_directive")
                break
    verdict.score = round(verdict.score, 2)
    return verdict
