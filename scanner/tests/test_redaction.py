import pytest

from sentinel_scanner.redaction import (
    REDACTED,
    is_sensitive_name,
    redact_headers,
    redact_text,
    redact_url,
)


def test_sensitive_headers_are_redacted() -> None:
    headers = [
        ("Authorization", "Bearer abc.def.ghi"),
        ("Proxy-Authorization", "Basic dXNlcjpwdw=="),
        ("Cookie", "session=abc"),
        ("X-API-Key", "k-123"),
        ("X-Auth-Token", "t-456"),
        ("X-CSRF-Token", "c-789"),
        ("WWW-Authenticate", 'Basic realm="x"'),
        ("Content-Type", "text/html"),
        ("Server", "nginx"),
        ("Keep-Alive", "timeout=5"),
    ]
    redacted, names = redact_headers(headers)
    values = dict(redacted)
    for name in ("Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "X-Auth-Token"):
        assert values[name] == REDACTED
    assert values["Content-Type"] == "text/html"
    assert values["Server"] == "nginx"
    assert values["Keep-Alive"] == "timeout=5"
    assert "Server" not in names


def test_set_cookie_keeps_name_and_flags_but_not_value() -> None:
    redacted, names = redact_headers(
        [("Set-Cookie", "session=s3cr3t-value; Path=/; HttpOnly; Secure; SameSite=Lax")]
    )
    assert redacted == [
        ("Set-Cookie", f"session={REDACTED}; Path=/; HttpOnly; Secure; SameSite=Lax")
    ]
    assert names == ["Set-Cookie"]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://lab.test/a?token=abc&page=2", f"http://lab.test/a?token={REDACTED}&page=2"),
        (
            "http://lab.test/a?api_key=k&sessionid=s",
            f"http://lab.test/a?api_key={REDACTED}&sessionid={REDACTED}",
        ),
        ("http://u:pw@lab.test/a", f"http://{REDACTED}@lab.test/a"),
        ("http://lab.test/a?q=search", "http://lab.test/a?q=search"),
        ("http://lab.test/a?token=", "http://lab.test/a?token="),
    ],
)
def test_url_redaction(url: str, expected: str) -> None:
    assert redact_url(url)[0].replace("%5BREDACTED%5D", REDACTED) == expected


@pytest.mark.parametrize(
    ("text", "secret", "kind"),
    [
        (
            "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl",
            "eyJhbGciOiJIUzI1NiJ9",
            "jwt",
        ),
        ("Authorization: Bearer s3cr3tT0kenValue123", "s3cr3tT0kenValue123", "bearer"),
        ("aws AKIAABCDEFGHIJKLMNOP here", "AKIAABCDEFGHIJKLMNOP", "aws_access_key"),
        ("password=hunter2&user=bob", "hunter2", "assignment"),
        ('{"api_key": "live_123456"}', "live_123456", "assignment"),
        (
            '<input type="hidden" name="csrf_token" value="CSRF-VALUE-1">',
            "CSRF-VALUE-1",
            "hidden_input_value",
        ),
        (
            '<input value="CSRF-VALUE-2" type="hidden" name="authenticity_token">',
            "CSRF-VALUE-2",
            "hidden_input_value",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
            "MIIEow",
            "private_key",
        ),
    ],
)
def test_body_secrets_are_redacted(text: str, secret: str, kind: str) -> None:
    redacted, kinds = redact_text(text)
    assert secret not in redacted
    assert REDACTED in redacted
    assert kind in kinds


def test_ordinary_text_is_untouched() -> None:
    text = '<input name="email" value="a@b.test"><p>Reset your keyboard settings</p>'
    assert redact_text(text) == (text, [])


@pytest.mark.parametrize("name", ["X-Session-Id", "csrftoken", "jwt", "client_secret", "PASSWORD"])
def test_sensitive_names(name: str) -> None:
    assert is_sensitive_name(name)
