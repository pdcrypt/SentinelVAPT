"""Redirects are never followed automatically; each hop is a fully checked
request, and a hop that leaves the scope is blocked before it is sent."""

import pytest
from tests.conftest import LabServer, SpyConnector, lab_resolver, make_client

from sentinel_scanner.errors import ScopeViolation
from sentinel_scanner.limits import ScanLimits
from sentinel_scanner.transport import HttpMethod


def test_in_scope_redirects_are_followed(lab: LabServer) -> None:
    lab.redirect("/a", "/b", 301)
    lab.redirect("/b", lab.url("/c"), 307)
    lab.html("/c", "<title>C</title>")
    result = make_client(lab).fetch(HttpMethod.GET, lab.url("/a"))
    assert [r.status for r in result.responses] == [301, 307, 200]
    assert result.final.url == lab.url("/c")
    assert lab.paths() == ["/a", "/b", "/c"]
    assert result.blocked_redirect is None


@pytest.mark.parametrize(
    ("location", "code"),
    [
        ("http://evil.test:{port}/x", "host_out_of_scope"),
        ("//evil.test:{port}/x", "host_out_of_scope"),  # protocol-relative
        ("http://lab.test:{port}@evil.test:{port}/x", "credentials_in_url"),
        ("http://lab.test:1/x", "port_not_allowed"),
        ("https://lab.test/x", "port_not_allowed"),  # scheme switch to default 443
        ("http://169.254.169.254/latest/meta-data/", "forbidden_address"),
        ("http://0xa9fea9fe/", "numeric_host"),
        ("http://[::ffff:a9fe:a9fe]/", "forbidden_address"),
        ("/admin/panel", "path_excluded"),
        ("/%2e%2e/admin/panel", "path_excluded"),
        ("/ADMIN", "path_excluded"),
        ("/admin%2fpanel", "ambiguous_path"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("gopher://lab.test/", "scheme_not_allowed"),
    ],
)
def test_redirects_leaving_scope_are_blocked(
    lab: LabServer, spy: SpyConnector, location: str, code: str
) -> None:
    lab.redirect("/start", location.format(port=lab.port))
    client = make_client(lab, connector=spy, excluded_paths=("/admin",))
    result = client.fetch(HttpMethod.GET, lab.url("/start"))

    assert result.blocked_redirect is not None
    assert result.blocked_redirect.code == code
    assert [r.status for r in result.responses] == [302]
    # Only the first request ever reached the network.
    assert lab.paths() == ["/start"]
    assert lab.hosts_seen == {"lab.test"}
    assert len(spy.opened) == 1
    assert client.requests_sent == 1


def test_redirect_loops_stop_at_the_hop_limit(lab: LabServer) -> None:
    lab.redirect("/loop", "/loop")
    client = make_client(lab, limits=ScanLimits(max_redirects=3, max_requests_per_second=20))
    result = client.fetch(HttpMethod.GET, lab.url("/loop"))
    assert result.redirect_limit_reached
    assert len(result.responses) == 4  # the request plus 3 hops
    assert client.requests_sent == 4


def test_redirects_can_be_disabled(lab: LabServer) -> None:
    lab.redirect("/a", "/b")
    client = make_client(lab, limits=ScanLimits(max_redirects=0, max_requests_per_second=20))
    result = client.fetch(HttpMethod.GET, lab.url("/a"))
    assert result.redirect_limit_reached
    assert lab.paths() == ["/a"]


def test_303_switches_to_get_but_head_stays_head(lab: LabServer) -> None:
    lab.redirect("/form", "/done", 303)
    lab.html("/done", "")
    client = make_client(lab)
    client.fetch(HttpMethod.OPTIONS, lab.url("/form"))
    client.fetch(HttpMethod.HEAD, lab.url("/form"))
    assert [(r.method, r.path) for r in lab.requests] == [
        ("OPTIONS", "/form"),
        ("GET", "/done"),
        ("HEAD", "/form"),
        ("HEAD", "/done"),
    ]


@pytest.mark.parametrize(
    "addresses",
    [
        ["169.254.169.254"],  # name now points at the metadata service
        ["8.8.8.8"],  # or at a public host
        ["127.0.0.1", "169.254.169.254"],  # one good address is not enough
        ["::ffff:169.254.169.254"],
        ["2002:a9fe:a9fe::1"],
    ],
)
def test_dns_answers_are_checked_before_connecting(
    lab: LabServer, spy: SpyConnector, addresses: list[str]
) -> None:
    """DNS rebinding: the hostname is in scope, but what it resolves to is not."""
    client = make_client(lab, connector=spy, resolver=lab_resolver(lab_test=addresses))
    with pytest.raises(ScopeViolation) as exc:
        client.request(HttpMethod.GET, lab.url("/"))
    assert exc.value.code == "forbidden_address"
    assert spy.opened == []
    assert lab.requests == []


def test_connection_goes_to_the_checked_address(lab: LabServer, spy: SpyConnector) -> None:
    lab.html("/", "")
    make_client(lab, connector=spy).request(HttpMethod.GET, lab.url("/"))
    [connection] = spy.opened
    assert (connection.ip, connection.port, connection.server_hostname) == (
        "127.0.0.1",
        lab.port,
        "lab.test",
    )
