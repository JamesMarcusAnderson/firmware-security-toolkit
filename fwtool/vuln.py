"""Pattern-based flagging of suspicious strings.

Findings are de-duplicated: a single string that matches two needles in the
same pattern is one finding, not two. Patterns are deliberately anchored so
ordinary text does not trip them.
"""
import re

PATTERNS = [
    # (label, compiled patterns)
    ("hardcoded password", [
        re.compile(r"(?i)\bpassword\s*[=:]\s*\S+"),
        # (?<![/\w]) keeps a filesystem path like "/root:/usr/bin" from matching:
        # a bare \b sits between "/" and "r", so it would fire on the path.
        re.compile(r"(?<![/\w])admin:\S+"),
        re.compile(r"(?<![/\w])root:\S+"),
    ]),
    ("private key", [
        re.compile(r"BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    ]),
    ("debug interface", [
        re.compile(r"\bDEBUG\s*=\s*1\b"),
        re.compile(r"\bdebug_uart\b"),
        re.compile(r"\bconsole_enable\b"),
    ]),
    ("known-bad RNG", [
        re.compile(r"\bsrand\s*\(\s*time\b"),
        re.compile(r"(?<![\w.])rand\s*\(\s*\)"),
    ]),
]


def scan(strings):
    """Scan extracted strings and return de-duplicated findings."""
    hits = []
    seen = set()
    for s in strings:
        text = s["string"]
        for label, patterns in PATTERNS:
            for pat in patterns:
                m = pat.search(text)
                if not m:
                    continue
                key = (s["offset"], label)
                if key in seen:
                    break                     # already reported for this string
                seen.add(key)
                hits.append({
                    "offset": s["offset"],
                    "pattern": label,
                    "match": m.group(0),
                    "context": text,
                })
                break
    return hits
