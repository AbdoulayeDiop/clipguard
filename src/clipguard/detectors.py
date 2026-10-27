"""Detection engine: decides whether a piece of text looks sensitive.

Each detector returns zero or more Finding objects. Detectors combine
regular expressions with validation (Luhn checksum for cards, mod-97 for
IBANs, Shannon entropy for generic secrets) to keep false positives low.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, Iterable

# Severity levels, ordered.
LOW, MEDIUM, HIGH = "low", "medium", "high"
SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}


@dataclass(frozen=True)
class Finding:
    detector: str      # machine id, e.g. "aws_access_key"
    label: str         # human label, e.g. "AWS access key"
    severity: str      # low / medium / high
    match: str         # the matched text (never shown unmasked)
    start: int
    end: int

    @property
    def masked(self) -> str:
        return mask(self.match)


def mask(value: str, keep: int | None = None) -> str:
    """Mask a secret for display, keeping only a few leading characters.

    Long values (API keys) keep 4 characters so you can tell which key it is;
    short ones (passwords) keep fewer so the hint doesn't give much away.
    """
    value = value.strip()
    if keep is None:
        keep = 4 if len(value) >= 20 else 2 if len(value) >= 10 else 0
    if len(value) <= keep + 2:
        return "*" * len(value)
    return value[:keep] + "…" + "*" * min(8, len(value) - keep)


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------

def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(iban: str) -> bool:
    iban = re.sub(r"\s+", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", iban):
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def nir_valid(nir: str) -> bool:
    """French NIR: the 2-digit key equals 97 - (first 13 digits mod 97).

    Corsican departments 2A and 2B are replaced by 19 and 18 for the computation.
    """
    s = nir.replace(" ", "").upper()
    if len(s) != 15:
        return False
    body, key = s[:13], s[13:]
    body = body[:5] + body[5:7].replace("2A", "19").replace("2B", "18") + body[7:]
    if not body.isdigit() or not key.isdigit():
        return False
    return 97 - int(body) % 97 == int(key)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def _looks_like_password(token: str) -> bool:
    """Heuristic for a strong, random-looking password/secret."""
    if not 12 <= len(token) <= 128:
        return False
    classes = sum([
        any(c.islower() for c in token),
        any(c.isupper() for c in token),
        any(c.isdigit() for c in token),
        any(not c.isalnum() for c in token),
    ])
    if classes < 3:
        return False
    # Exclude obvious non-secrets: URLs, paths, emails.
    if re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*://|www\.|/|~/|[A-Za-z]:\\)", token):
        return False
    if re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", token):
        return False
    return shannon_entropy(token) >= 3.5


# --------------------------------------------------------------------------
# Pattern table
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Pattern:
    id: str
    label: str
    severity: str
    regex: re.Pattern
    validate: Callable[[str], bool] | None = None
    group: int = 0


def _p(id, label, severity, regex, validate=None, flags=0, group=0):
    return Pattern(id, label, severity, re.compile(regex, flags), validate, group)


PATTERNS: list[Pattern] = [
    # --- Cloud & API keys -------------------------------------------------
    _p("aws_access_key", "AWS access key", HIGH,
       r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _p("aws_secret_key", "AWS secret key", HIGH,
       r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"=:\s]([A-Za-z0-9/+=]{40})\b",
       group=1),
    _p("github_token", "GitHub token", HIGH,
       r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    _p("gitlab_token", "GitLab token", HIGH, r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    _p("openai_key", "OpenAI API key", HIGH,
       r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"
       r"|\bsk-proj-[A-Za-z0-9_\-]{40,}\b"),
    _p("anthropic_key", "Anthropic API key", HIGH,
       r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b"),
    _p("google_api_key", "Google API key", HIGH, r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("stripe_key", "Stripe secret key", HIGH,
       r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b"),
    _p("slack_token", "Slack token", HIGH, r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),
    _p("slack_webhook", "Slack webhook URL", MEDIUM,
       r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"),
    _p("twilio_key", "Twilio API key", HIGH, r"\bSK[0-9a-fA-F]{32}\b"),
    _p("sendgrid_key", "SendGrid API key", HIGH,
       r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    _p("npm_token", "npm token", HIGH, r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("hf_token", "Hugging Face token", HIGH, r"\bhf_[A-Za-z]{34}\b"),
    # Matches the whole block (header to footer) so that masking hides the key body.
    _p("private_key", "Private key", HIGH,
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
       r"[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)"),
    _p("jwt", "JSON Web Token", MEDIUM,
       r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    # Reports only the password part, so masking keeps the rest of the URL readable.
    _p("db_url", "Database URL with password", HIGH,
       r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:([^\s@/]+)@[^\s]+",
       group=1),
    _p("password_assignment", "Password in text", HIGH,
       r"(?i)\b(?:password|passwd|pwd|pass|secret|api[_-]?key|token)\s*[:=]\s*['\"]?([^\s'\"]{6,})",
       validate=lambda v: len(v) >= 16 or any(not c.isalpha() for c in v),
       group=1),

    # --- Financial --------------------------------------------------------
    _p("credit_card", "Credit card number", HIGH,
       r"\b(?:\d[ \-]?){12,18}\d\b", validate=luhn_valid),
    _p("iban", "IBAN", MEDIUM,
       r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b",
       validate=iban_valid),

    # --- Personal identifiers ----------------------------------------------
    _p("us_ssn", "US Social Security number", HIGH,
       r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    _p("fr_nir", "French social security number (NIR)", HIGH,
       r"\b[12][ ]?\d{2}[ ]?(?:0[1-9]|1[0-2]|[2-9]\d)[ ]?(?:\d{2}|2[AB])[ ]?\d{3}[ ]?\d{3}[ ]?\d{2}\b",
       validate=lambda v: nir_valid(v)),
    _p("email", "Email address", LOW,
       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    _p("phone", "Phone number", LOW,
       r"(?<![\w+])(?:\+\d{1,3}[ .\-]?)?(?:\(?\d{1,4}\)?[ .\-]?){2,5}\d{2,4}(?!\w)",
       validate=lambda s: 9 <= sum(c.isdigit() for c in s) <= 15),
]


def _password_findings(text: str) -> Iterable[Finding]:
    # Only treat short single-token clipboards as potential passwords.
    stripped = text.strip()
    if "\n" in stripped or " " in stripped:
        return []
    if _looks_like_password(stripped):
        start = text.index(stripped)
        return [Finding("high_entropy", "Password or secret (high entropy)",
                        MEDIUM, stripped, start, start + len(stripped))]
    return []


def scan(
    text: str,
    min_severity: str = LOW,
    disabled: Iterable[str] = (),
    max_chars: int = 200_000,
) -> list[Finding]:
    """Scan text and return findings, highest severity first, de-duplicated."""
    if not text:
        return []
    text = text[:max_chars]
    disabled = set(disabled)
    floor = SEVERITY_RANK[min_severity]
    findings: list[Finding] = []

    for pat in PATTERNS:
        if pat.id in disabled or SEVERITY_RANK[pat.severity] < floor:
            continue
        for m in pat.regex.finditer(text):
            value = m.group(pat.group)
            if not value:
                continue
            if pat.validate and not pat.validate(value):
                continue
            findings.append(Finding(pat.id, pat.label, pat.severity, value,
                                    m.start(pat.group), m.end(pat.group)))

    if "high_entropy" not in disabled and SEVERITY_RANK[MEDIUM] >= floor:
        findings.extend(_password_findings(text))

    return _dedupe(findings)


def redact_value(f: Finding) -> str:
    """Replacement text for one finding when pasting a masked version."""
    v = f.match
    if f.detector == "private_key":
        return "[PRIVATE KEY REDACTED]"
    if f.detector == "credit_card":
        # Keep the layout and the last 4 digits: **** **** **** 1111
        digits_seen, total = 0, sum(c.isdigit() for c in v)
        out = []
        for c in v:
            if c.isdigit():
                digits_seen += 1
                out.append(c if digits_seen > total - 4 else "*")
            else:
                out.append(c)
        return "".join(out)
    if f.detector == "iban":
        compact = v.replace(" ", "")
        return compact[:4] + " **** " + compact[-4:]
    if f.detector == "email":
        user, _, domain = v.partition("@")
        return (user[:1] + "***@" + domain) if user else v
    if f.detector == "phone":
        return "*" * 6 + "".join(c for c in v if c.isdigit())[-2:]
    keep = 4 if len(v) >= 12 else 0
    return v[:keep] + "*" * 8


def redact(text: str, findings: list[Finding]) -> str:
    """Return text with every finding replaced by its masked form."""
    spans: list[Finding] = []
    for f in sorted(findings, key=lambda f: (f.start, -(f.end - f.start))):
        if spans and f.start < spans[-1].end:
            continue  # overlaps a span we're already masking
        spans.append(f)
    out, pos = [], 0
    for f in spans:
        out.append(text[pos:f.start])
        out.append(redact_value(f))
        pos = f.end
    out.append(text[pos:])
    return "".join(out)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop findings that overlap a higher-or-equal severity finding.

    Example: in postgres://admin:pw@db.example.com the password (high) wins over
    the "pw@db.example.com" email match (low).
    """
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    for f in findings:
        if any(f.start < k.end and k.start < f.end for k in kept):
            continue
        kept.append(f)
    return kept
