import pytest

from demo.fakes import FAKES
from mcp_firewall.inspect.redact import ird_ok, luhn_ok, redact


@pytest.mark.parametrize(
    ("number", "ok"),
    [
        ("49091850", True),
        ("35901981", True),
        ("49098576", True),
        ("136410132", True),
        ("136410133", False),
        ("9125568", False),
        ("150000001", False),
    ],
)
def test_ird_checksum(number, ok):
    assert ird_ok(number) is ok


def test_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


@pytest.mark.parametrize(
    "name", ["AWS_KEY", "GITHUB_TOKEN", "STRIPE_KEY", "SLACK_TOKEN", "OPENAI_KEY", "GOOGLE_KEY", "JWT", "DB_URL", "PEM_KEY"]
)
def test_secret_patterns(name):
    value = FAKES[name]
    out = redact(f"value: {value} end", ["secret"])
    assert value not in out.text
    assert out.counts["secret"] >= 1


def test_secret_assignment_keeps_name():
    value = "".join(["abcd", "EFGH", "1234", "/abcd", "+efgh"])
    out = redact("aws_secret_access_key = " + value, ["secret"])
    assert out.text == "aws_secret_access_key = [REDACTED:secret]"


def test_cards_need_luhn():
    out = redact("card 4111 1111 1111 1111 and order 4111 1111 1111 1112", ["card"])
    assert out.counts["card"] == 1
    assert "1112" in out.text


def test_ird_needs_format_or_context():
    assert redact("IRD 49-091-850", ["ird"]).counts["ird"] == 1
    assert redact("tax number 136410132", ["ird"]).counts["ird"] == 1
    assert redact("order 136410132 shipped", ["ird"]).counts["ird"] == 0


def test_nz_phones():
    out = redact("021 555 0134, +64 9 555 0199, 0800 555 010, version 1.0.2", ["phone"])
    assert out.counts["phone"] == 3
    assert "version 1.0.2" in out.text


def test_email_keep_domain():
    out = redact("tom@acme-outdoor.example and x@evil.example", ["email"], ["acme-outdoor.example"])
    assert "tom@acme-outdoor.example" in out.text
    assert "x@evil.example" not in out.text


def test_only_requested_kinds():
    out = redact("mail x@evil.example", ["secret"])
    assert out.text == "mail x@evil.example"
