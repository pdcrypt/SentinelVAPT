import ipaddress

import pytest

from sentinel_scanner.errors import ScopeViolation
from sentinel_scanner.scope import ScopePolicy, canonical_path


@pytest.fixture
def policy() -> ScopePolicy:
    return ScopePolicy(
        hosts=("lab.test", "::1"),
        ports=(80, 8080),
        path_prefixes=("/app", "/static/"),
        excluded_paths=("/app/admin",),
        lab_only=True,
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://lab.test/app", "http://lab.test/app"),
        ("HTTP://LAB.TEST:80/app/", "http://lab.test/app/"),
        ("http://lab.test.:8080/app/x", "http://lab.test:8080/app/x"),
        ("http://lab.test/app/x?a=1#frag", "http://lab.test/app/x?a=1"),
        ("http://[::1]:8080/static/a.css", "http://[::1]:8080/static/a.css"),
        ("http://lab.test/app/./x/../y", "http://lab.test/app/y"),
        ("http://lab.test/app//x", "http://lab.test/app/x"),
        ("http://lab.test/%61pp/x", "http://lab.test/app/x"),  # %61 = 'a'
        ("http://lab.test/app/caf%c3%a9", "http://lab.test/app/caf%C3%A9"),
    ],
)
def test_allowed_urls_are_canonicalized(policy: ScopePolicy, url: str, expected: str) -> None:
    assert policy.check_url(url).url == expected


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://lab.test/app", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("javascript:alert(1)", "scheme_not_allowed"),
        ("http://evil.test/app", "host_out_of_scope"),  # valid lab name, not in scope
        ("http://other.local/app", "host_out_of_scope"),
        ("http://lab.test.evil.com/app", "not_lab_host"),
        ("http://lab.test@evil.test/app", "credentials_in_url"),
        ("http://u:p@lab.test/app", "credentials_in_url"),
        ("http://lab.test:81/app", "port_not_allowed"),
        ("https://lab.test/app", "port_not_allowed"),  # 443 not allowed
        ("http://lab.test:0/app", "port_not_allowed"),
        ("http://lab.test:99999/app", "invalid_url"),
        ("http://lab.test/", "path_out_of_scope"),
        ("http://lab.test/application", "path_out_of_scope"),  # segment boundary
        ("http://lab.test/app/../secret", "path_out_of_scope"),
        ("http://lab.test/app/%2e%2e/secret", "path_out_of_scope"),  # encoded traversal
        ("http://lab.test/app/%2E%2E/%2e%2e/etc", "path_out_of_scope"),
        ("http://lab.test/app/admin", "path_excluded"),
        ("http://lab.test/app/admin/users", "path_excluded"),
        ("http://lab.test/app/ADMIN", "path_excluded"),  # case-insensitive servers
        ("http://lab.test/app/admin;jsessionid=1", "path_excluded"),  # path parameters
        ("http://lab.test/app//admin", "path_excluded"),  # collapsed slashes
        ("http://lab.test/app/x/../admin", "path_excluded"),
        ("http://lab.test/app/%61dmin", "path_excluded"),  # encoded letters
        ("http://lab.test/app%2fadmin", "ambiguous_path"),  # encoded slash
        ("http://lab.test/app%5cadmin", "ambiguous_path"),  # encoded backslash
        ("http://lab.test/app%00", "ambiguous_path"),
        ("http://169.254.169.254/app", "forbidden_address"),
        ("http://0xa9fea9fe/app", "numeric_host"),
        ("http://[::ffff:a9fe:a9fe]/app", "forbidden_address"),
        ("http:///app", "invalid_url"),
    ],
)
def test_out_of_scope_urls_are_rejected(policy: ScopePolicy, url: str, code: str) -> None:
    with pytest.raises(ScopeViolation) as exc:
        policy.check_url(url)
    assert exc.value.code == code


def test_check_address(policy: ScopePolicy) -> None:
    policy.check_address(ipaddress.ip_address("127.0.0.1"), "lab.test")
    unspecified = "0.0.0.0"  # noqa: S104  # an input that must be rejected, not a bind
    for bad in ("169.254.169.254", "8.8.8.8", "::ffff:169.254.169.254", unspecified):
        with pytest.raises(ScopeViolation) as exc:
            policy.check_address(ipaddress.ip_address(bad), "lab.test")
        assert exc.value.code == "forbidden_address"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", "/"),
        ("/", "/"),
        ("/a/b/", "/a/b/"),
        ("/a/./b", "/a/b"),
        ("/a/b/..", "/a/"),
        ("/../../a", "/a"),
        ("/a/%2E%2e/b", "/b"),
        ("/%7euser", "/~user"),
        ("/a%20b", "/a%20b"),
    ],
)
def test_canonical_path(raw: str, expected: str) -> None:
    assert canonical_path(raw) == expected


def test_scope_itself_is_revalidated() -> None:
    with pytest.raises(ScopeViolation):
        ScopePolicy(
            hosts=("example.com",),
            ports=(80,),
            path_prefixes=("/",),
            excluded_paths=(),
            lab_only=True,
        )
    with pytest.raises(ScopeViolation):
        ScopePolicy(
            hosts=("lab.test",), ports=(), path_prefixes=("/",), excluded_paths=(), lab_only=True
        )
