"""Over a whole scan, the only connections opened are to checked, in-scope
addresses, and blocked requests never reach the connector."""

import pytest
from tests.conftest import FakeTime, LabServer, SpyConnector, make_client
from tests.test_discovery import build_site, scan

from sentinel_scanner.errors import ScopeViolation
from sentinel_scanner.transport import HttpMethod


def test_full_scan_only_connects_to_checked_addresses(
    lab: LabServer, fake_time: FakeTime, spy: SpyConnector
) -> None:
    build_site(lab)
    result = scan(lab, fake_time, spy=spy)
    assert len(spy.opened) == result.requests_sent == len(lab.requests)
    assert {(c.ip, c.port, c.server_hostname) for c in spy.opened} == {
        ("127.0.0.1", lab.port, "lab.test")
    }


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.test/",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",  # an IP that is not the listed host
        "http://localhost/",
        "http://lab.test:22/",
        "http://lab.test/admin",
    ],
)
def test_blocked_requests_never_reach_the_connector(
    lab: LabServer, spy: SpyConnector, url: str
) -> None:
    client = make_client(lab, connector=spy, excluded_paths=("/admin",))
    with pytest.raises(ScopeViolation):
        client.request(HttpMethod.GET, url.replace("lab.test/", f"lab.test:{lab.port}/"))
    assert spy.opened == []
    assert lab.requests == []
