from logscrub import scrub
from logscrub.cli import main


def test_openai_key():
    r = scrub("OPENAI_KEY=sk-" + "A" * 40)
    assert "[REDACTED:openai_key]" in r.text
    assert "sk-AAAA" not in r.text


def test_github_token():
    r = scrub("token ghp_" + "b" * 36)
    assert r.text == "token [REDACTED:github_token]"


def test_aws_and_google():
    r = scrub("AKIAIOSFODNN7EXAMPLE and AIza" + "c" * 35)
    assert r.findings["aws_access_key"] == 1
    assert r.findings["google_api_key"] == 1


def test_stripe_twilio_sendgrid():
    r = scrub("stripe sk_live_" + "a" * 24)
    assert r.findings["stripe_key"] == 1 and "sk_live_aaaa" not in r.text
    r = scrub("twilio SK" + "0" * 32)
    assert r.findings["twilio_key"] == 1
    r = scrub("sendgrid SG." + "x" * 22 + "." + "y" * 30)
    assert r.findings["sendgrid_key"] == 1


def test_stripe_does_not_clash_with_openai():
    # openai uses sk- (hyphen); stripe uses sk_ (underscore) — keep them distinct
    r = scrub("sk-" + "A" * 40)
    assert r.findings["openai_key"] == 1
    assert "stripe_key" not in r.findings


def test_jwt_and_bearer():
    jwt = "eyJhbGciOi.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT4"
    r = scrub(f"Authorization: Bearer {jwt}")
    # the bearer detector wins; either way the token is gone
    assert jwt not in r.text
    assert "REDACTED" in r.text


def test_private_key_block():
    block = ("-----BEGIN RSA PRIVATE KEY-----\nMIIBxxxx\nyyyy\n"
             "-----END RSA PRIVATE KEY-----")
    r = scrub("key:\n" + block)
    assert "[REDACTED:private_key]" in r.text
    assert "MIIBxxxx" not in r.text


def test_email_and_ip():
    r = scrub("contact me@example.com from 192.168.1.10")
    assert "[REDACTED:email]" in r.text
    assert "[REDACTED:ip]" in r.text


def test_ip_octet_validation_no_false_positive():
    # 999.1.1.1 is not a valid IP and must NOT be redacted
    r = scrub("version 999.1.1.1 build")
    assert "999.1.1.1" in r.text
    assert r.findings.get("ip", 0) == 0


def test_credit_card_luhn():
    r = scrub("card 4111 1111 1111 1111 here")        # valid Luhn
    assert "[REDACTED:credit_card]" in r.text
    r2 = scrub("id 1234 5678 9012 3456 ref")          # invalid Luhn
    assert "1234 5678 9012 3456" in r2.text


def test_generic_assignment_redacts_value_keeps_key():
    r = scrub('password = "hunter2secret"')
    assert "password" in r.text                        # key kept
    assert "hunter2secret" not in r.text               # value gone
    assert "[REDACTED:secret_assignment]" in r.text


def test_keep_option():
    r = scrub("me@example.com", keep={"email"})
    assert r.text == "me@example.com"


def test_counts():
    r = scrub("a@b.com c@d.com")
    assert r.findings["email"] == 2
    assert r.total == 2


def test_cli_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("key ghp_" + "z" * 36))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[REDACTED:github_token]" in out
