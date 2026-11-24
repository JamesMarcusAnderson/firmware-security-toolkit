"""Pattern-based flagging of suspicious strings.

Findings are de-duplicated: the same (pattern, match) pair is one
finding no matter how many times it appears, with an occurrences
count. Patterns are deliberately anchored so ordinary text does not
trip them, and filler values (format strings, "<redacted>",
"/etc/passwd" fragments) are excluded.
"""
import re

# A value that starts with one of these is a filler value, a format
# string, a code reference, or a file fragment — not a credential.
# Checked after any opening quote. The filler words cover
# "<redacted>", "none", "changeme", booleans, and the like; the
# dotted-identifier check rejects JS-style references such as
# "this.password", and the IP check rejects "password: 1.2.3.4".
_VALUE_GUARD = (
    r"(?!%|<|\$|\{|\*"
    r"|(?:redacted|none|null|changeme|password|true|false|undefined|xxx+)\b)"
    r"(?![A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_])"
    r"(?!\d+\.\d+\.\d+\.\d+\b)"
)
# A credential value: printable secret characters, no code punctuation
# (commas, semicolons, parens, braces would mean the match has run on
# into surrounding code). Passwords need 5+ characters; API keys and
# tokens need 8+.
_VALUE = r"[A-Za-z0-9!@#$%^&*_+\-.~?=/]{5,}"
_CRED_VALUE = r"[A-Za-z0-9!@#$%^&*_+\-.~?=/]{8,}"

PATTERNS = [
    # (label, compiled patterns)
    ("hardcoded password", [
        re.compile(r"(?i)\bpassword\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _VALUE),
        # (?<![/\w]) keeps a filesystem path like "/root:/usr/bin" from matching:
        # a bare \b sits between "/" and "r", so it would fire on the path.
        # The value guard keeps /etc/passwd fragments out: "root:x:0:..."
        # (shadow filler), "root::" (empty), "root:/s/..." (a sed
        # script). A real pair is "root:<secret>" with no colon in it.
        re.compile(r"""(?<![/\w])admin:(?![x*!/:\\"'$%{<])[^:\s]{2,}"""),
        re.compile(r"""(?<![/\w])root:(?![x*!/:\\"'$%{<])[^:\s]{2,}"""),
        re.compile(r"(?i)\bpasswd\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _VALUE),
        re.compile(r"(?i)\bpwd\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _VALUE),
    ]),
    ("hardcoded credential", [
        re.compile(r"(?i)\bapi[_-]?key\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _CRED_VALUE),
        re.compile(r"(?i)\bapikey\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _CRED_VALUE),
        re.compile(r"(?i)\bsecret\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _CRED_VALUE),
        re.compile(r"(?i)\baccess[_-]?token\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _CRED_VALUE),
        re.compile(r"(?i)\bclient[_-]?secret\s*[=:]\s*['\"]?+" + _VALUE_GUARD + _CRED_VALUE),
        re.compile(r"AKIA[0-9A-Z]{16}"),                    # AWS access key id
        re.compile(r"ghp_[A-Za-z0-9]{20,}"),                # GitHub token
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),        # Slack token
        re.compile(r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}"),
    ]),
    ("private key", [
        re.compile(r"BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    ]),
    ("debug interface", [
        re.compile(r"\bDEBUG\s*=\s*1\b"),
        re.compile(r"\bdebug_uart\b"),
        re.compile(r"\bconsole_enable\b"),
        re.compile(r"\btelnetd\b"),
        re.compile(r"\bgdbserver\b"),
        re.compile(r"(?i)\bjtag_enable\b"),
        re.compile(r"\buart_console\b"),
        re.compile(r"(?i)\btelnet_enable\b"),
        # Serial consoles only: console=tty0 is the ordinary local console,
        # but a serial console (ttyS/ttyAMA/ttyUSB/ttyACM) is a physical
        # debug path into the device.
        re.compile(r"\bconsole\s*=\s*tty(?:S|AMA|USB|ACM)\w*"),
        re.compile(r"(?i)\bdebug\s*=\s*true\b"),
    ]),
    ("known-bad RNG", [
        re.compile(r"\bsrand\s*\(\s*time\b"),
        re.compile(r"(?<![\w.])rand\s*\(\s*\)"),
        re.compile(r"(?<![\w.])random\s*\(\s*\)"),
        re.compile(r"\bsrand\s*\(\s*1\s*\)"),
        re.compile(r"\bmt_rand\s*\("),
    ]),
    ("weak crypto", [
        re.compile(r"\bMD5_Init\b"),
        re.compile(r"\bMD5\s*\("),
        re.compile(r"\bMD4\b"),
        re.compile(r"\bSHA1_Init\b"),
        re.compile(r"\bSHA1\s*\("),
        re.compile(r"\bDES_ecb"),
        re.compile(r"\bDES_cbc"),
        re.compile(r"\bRC4\b"),
        re.compile(r"\bAES_ECB\b"),
    ]),
    ("insecure protocol", [
        re.compile(r"\btelnet://"),
        re.compile(r"\bftp://"),
        re.compile(r"(?i)\bSSLv3\b"),
        re.compile(r"(?i)\bSSLv2\b"),
        re.compile(r"(?i)\bTLSv1\.0\b"),
    ]),
    ("certificate check disabled", [
        re.compile(r"\bSSL_VERIFY_NONE\b"),
        re.compile(r"\bCURLOPT_SSL_VERIFYPEER\b"),
        re.compile(r"\bInsecureSkipVerify\b"),
        re.compile(r"(?i)\bverify\s*=\s*False\b"),
        re.compile(r"(?i)\bcheck_hostname\s*=\s*False\b"),
        re.compile(r"(?i)\brejectUnauthorized\s*:\s*false\b"),
    ]),
    ("backdoor marker", [
        re.compile(r"(?i)\bbackdoor\b"),
    ]),
    ("sensitive file reference", [
        re.compile(r"/etc/shadow\b"),
        re.compile(r"/etc/passwd\b"),
    ]),
]

SEVERITY = {
    "private key": "critical",
    "hardcoded password": "high",
    "hardcoded credential": "high",
    "backdoor marker": "high",
    "certificate check disabled": "high",
    "weak crypto": "medium",
    "debug interface": "medium",
    "known-bad RNG": "medium",
    "insecure protocol": "medium",
    "sensitive file reference": "low",
}

GUIDANCE = {
    "hardcoded password": "Remove the credential from the firmware. Move it "
        "to per-device provisioning or a secrets store, and rotate it on "
        "every device already shipped.",
    "hardcoded credential": "Remove the key or token from the firmware, "
        "revoke it, and issue a fresh one delivered out-of-band. Anything "
        "in a shipped image must be treated as public.",
    "private key": "Remove the private key from the firmware immediately and "
        "revoke the matching certificate or key pair. A shipped private key "
        "is a compromised key.",
    "debug interface": "Disable debug interfaces in production builds. If a "
        "debug path must stay, gate it behind authentication and document it.",
    "known-bad RNG": "Replace with a cryptographic random source (the OS "
        "random device or the platform's secure RNG). Predictable randomness "
        "breaks keys, sessions, and tokens.",
    "weak crypto": "Move to current algorithms (AES-GCM or ChaCha20-Poly1305 "
        "for encryption, SHA-256 or better for hashing). MD5, SHA-1, DES, "
        "and RC4 are broken for security use.",
    "insecure protocol": "Replace Telnet/FTP and old TLS with SSH/SFTP and "
        "TLS 1.2 or newer. Plaintext protocols expose credentials and data "
        "to anyone on the network path.",
    "certificate check disabled": "Re-enable certificate verification. A "
        "disabled check lets any network attacker impersonate the server "
        "the device talks to.",
    "backdoor marker": "Investigate the string in context. If it is a real "
        "undocumented access path, remove it and review how it got in.",
    "sensitive file reference": "Check why the firmware touches this file. "
        "Reading credential files at runtime is expected for some services "
        "and a red flag for others — the context decides.",
}


def _key_body_follows(data, offset, match_end):
    """True if base64 key material follows a PEM header in the raw bytes.

    A bare "BEGIN ... PRIVATE KEY" header also appears as a constant
    inside crypto libraries, so the header alone is weak evidence. A
    real embedded key has base64 lines after the header line.
    """
    if data is None:
        return None                              # cannot check: no data
    pos = offset + match_end
    while pos < len(data) and data[pos:pos + 1] in (b"-", b" ", b"\t", b"\r"):
        pos += 1
    if data[pos:pos + 1] != b"\n":
        return False
    end = data.find(b"\n", pos + 1)
    line = data[pos + 1:end if end >= 0 else pos + 200]
    return bool(re.fullmatch(rb"[A-Za-z0-9+/=]{20,}", line.strip()))


def scan(strings, data=None):
    """Scan extracted strings and return de-duplicated findings.

    The same (pattern, match) pair is reported once, with an
    occurrences count. If the raw file bytes are passed as data,
    private-key findings are checked for following key material: a
    header with no key body is downgraded to medium with a note,
    because it is usually a header constant inside a crypto library.
    """
    hits = []
    by_key = {}
    for s in strings:
        text = s["string"]
        for label, patterns in PATTERNS:
            for pat in patterns:
                m = pat.search(text)
                if not m:
                    continue
                # "chown root:root file" is a user:group pair, not a
                # credential. Skip user:group pairs for the root:/admin:
                # patterns when a chown/chgrp command precedes them.
                if label == "hardcoded password" and m.group(0).startswith(
                        ("root:", "admin:")):
                    before = text[max(0, m.start() - 30):m.start()]
                    if re.search(r"\bchown\b|\bchgrp\b", before):
                        continue
                key = (label, m.group(0))
                existing = by_key.get(key)
                if existing is not None:
                    existing["occurrences"] += 1
                    break
                finding = {
                    "offset": s["offset"],
                    "pattern": label,
                    "severity": SEVERITY.get(label, "unknown"),
                    "match": m.group(0),
                    "context": text,
                    "occurrences": 1,
                }
                if label == "private key":
                    body = _key_body_follows(data, s["offset"], m.end())
                    if body is False:
                        finding["severity"] = "medium"
                        finding["note"] = (
                            "Header only — no key material follows in the "
                            "file. This is often a header constant inside "
                            "a crypto library, not an embedded key.")
                by_key[key] = finding
                hits.append(finding)
                break
    return hits
