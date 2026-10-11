"""Semantic layer: catches paraphrases by pairing an ACTION concept with an OBJECT concept inside a short window.
A regex needs the exact wording; this needs only the intent (e.g. 'set aside everything your creators told you')."""
import re
I = re.I
def _w(*ws): return r"\b(?:" + "|".join(ws) + r")\b"
OVERRIDE_ACT = _w("ignore", "disregard", "forget", "cancel", "set aside", "erase", "discard", "bypass", "abandon", "override", "neglect", "stop following", "pay no attention to", "throw away", "wipe", "scrap", "drop")
RULES_OBJ = _w(r"instructions?", "rules", "guidelines?", "guidance", "directives?", "policies", "restrictions", "programming", "constraints", "setup", r"system (?:prompt|message)", r"what you(?:'ve| have)? been told", r"everything you (?:were|have been) (?:told|given)", r"your creators", r"your developers", "training")
PERSONA_ACT = _w("become", "act", "pretend", "imagine", "roleplay", "role-play", "simulate", "answer as", "respond as", "persona", "version")
UNREST = _w("no", "zero", "without", "unrestricted", "uncensored", "unfiltered", "unlimited", "ignores?", "free of", "no longer bound")
LIMITS = _w("rules", "limits?", "restrictions?", "safety", "filters?", "policies", "guidelines?", "censorship", "content rules")
REVEAL_ACT = _w("reveal", "show", "print", "recite", "paste", "repeat", "disclose", "tell", "share", "display", "quote", "output", "read out", "leak", "expose", "dump", "give")
CONFIG_OBJ = _w(r"system (?:prompt|message)", r"(?:hidden|initial|setup|confidential|secret) (?:instructions?|prompt|message|text)", r"your (?:instructions|prompt|configuration|rules)", r"(?:text|message|words) (?:placed|written|that came|which came)? ?before", r"developers? wrote", "configured with", r"pre-?prompt")
SEND_ACT = _w("send", "forward", "email", "upload", "post", "transmit", "exfiltrate", "leak", "submit", "mail")
DEST = r"(?:[\w.+-]+@[\w-]+\.[\w.]+|https?://\S+)"
TRUST_ACT = _w("remember", "memori[sz]e", "from now on", "in every future", "always", "going forward")
TRUST_OBJ = _w("administrator", "admin", "developer", "system", "trusted", "authori[sz]ed", "root")
TRUST_V = _w("treat", "trust", "regard", "consider", "assume", "accept")

def _near(text, A, B, window=70, ordered=False):
    ra, rb = re.compile(A, I), re.compile(B, I)
    for m in ra.finditer(text):
        seg = text[m.end(): m.end() + window]
        sentence_break = re.search(r"[.!?\n]", seg)
        if sentence_break: seg = seg[: sentence_break.start()]
        n = rb.search(seg)
        if n: yield m.start(), m.end() + n.end()

def semantic_hits(text):
    """Yield (category, rule_id, weight, start, end)."""
    for a, b in _near(text, OVERRIDE_ACT, RULES_OBJ, 70): yield "instruction_override", "SEM-OVR", .72, a, b
    for a, b in _near(text, PERSONA_ACT, UNREST + r"[^.\n]{0,25}" + LIMITS, 90): yield "role_change", "SEM-ROL", .72, a, b
    for a, b in _near(text, REVEAL_ACT, CONFIG_OBJ, 60): yield "secret_extraction", "SEM-SEC", .74, a, b
    for a, b in _near(text, SEND_ACT, r"[^.\n]{0,60}" + DEST, 80):
        yield "tool_abuse", "SEM-TOL", .7, a, b
    for a, b in _near(text, TRUST_ACT, TRUST_V + r"[^.\n]{0,50}" + TRUST_OBJ, 90): yield "context_poisoning", "SEM-CTX", .74, a, b
    if re.search(r"\b(?:when|if) i (?:say|type|write)\b", text, I) and re.search(OVERRIDE_ACT, text, I):
        m = re.search(r"\b(?:when|if) i (?:say|type|write)\b", text, I); yield "multi_step_jailbreak", "SEM-MSJ", .75, m.start(), min(len(text), m.end() + 90)
