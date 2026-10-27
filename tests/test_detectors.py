"""Detector tests.

Fake secrets are assembled at runtime so that no realistic-looking token
appears literally in the source (keeps GitHub secret scanning quiet).
"""

import pytest

from clipguard.detectors import iban_valid, luhn_valid, mask, scan


def ids(text, **kw):
    return {f.detector for f in scan(text, **kw)}


def j(*parts):
    return "".join(parts)


AWS_KEY = j("AKIA", "Q3EXAMPLE7ZZ4XQW")
GITHUB = j("ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
STRIPE = j("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc")
GOOGLE = j("AIza", "SyD-EXAMPLEexampleEXAMPLEexample123")
SLACK = j("xox", "b-123456789012-abcdefABCDEF")
ANTHROPIC = j("sk-ant-", "api03-", "x" * 90)
JWT = j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")


@pytest.mark.parametrize("text,expected", [
    (f"key={AWS_KEY}", "aws_access_key"),
    (GITHUB, "github_token"),
    (STRIPE, "stripe_key"),
    (GOOGLE, "google_api_key"),
    (SLACK, "slack_token"),
    (ANTHROPIC, "anthropic_key"),
    (JWT, "jwt"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private_key"),
    ("postgres://admin:hunter2pass@db.example.com:5432/app", "db_url"),
    ("password: Tr0ub4dor&3", "password_assignment"),
    ("Card: 4111 1111 1111 1111", "credit_card"),
    ("4111-1111-1111-1111", "credit_card"),
    ("FR76 3000 6000 0112 3456 7890 189", "iban"),
    ("GB82WEST12345698765432", "iban"),
    ("SSN 123-45-6789", "us_ssn"),
    ("1 85 05 78 006 084 36", "fr_nir"),
])
def test_detects(text, expected):
    assert expected in ids(text)


@pytest.mark.parametrize("text", [
    "Hello, how are you today?",
    "The meeting is at 3pm in room 204.",
    "https://example.com/some/long/path?query=value",
    "4111 1111 1111 1112",            # fails Luhn
    "FR76 3000 6000 0112 3456 7890 188",  # fails mod-97
    "def main():\n    return 42\n",
    "Order #12345 shipped",
])
def test_no_false_positives(text):
    assert ids(text, min_severity="medium") == set()


def test_high_entropy_password():
    assert "high_entropy" in ids("Xq9#vL2!mZ7@pR4$")


def test_plain_word_not_password():
    assert "high_entropy" not in ids("Supercalifragilistic")


def test_low_severity_pii():
    found = ids("Contact jane.doe@example.com or +33 6 12 34 56 78", min_severity="low")
    assert {"email", "phone"} <= found
    assert ids("jane.doe@example.com", min_severity="medium") == set()


def test_disabled_detectors():
    assert "credit_card" not in ids("4111 1111 1111 1111", disabled=["credit_card"])


def test_dedupe_contained_matches():
    findings = scan("postgres://admin:hunter2pass@db.example.com/app")
    assert len(findings) == 1


def test_highest_severity_first():
    findings = scan(f"mail me at a@b.co, key {AWS_KEY}")
    assert findings[0].severity == "high"


def test_mask_hides_secret():
    m = mask(STRIPE)
    assert STRIPE not in m and m.startswith("sk_l")


def test_validators():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("1234")
    assert iban_valid("DE89 3704 0044 0532 0130 00")
    assert not iban_valid("DE00 3704 0044 0532 0130 00")
