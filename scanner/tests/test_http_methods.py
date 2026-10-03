"""Only GET, HEAD and OPTIONS exist; requests carry no body, cookies,
credentials or proxy routing."""

import inspect

import pytest
from tests.conftest import LabServer, make_client

from sentinel_scanner.transport import REQUEST_HEADERS, HttpMethod, SafeHttpClient


@pytest.mark.parametrize("method", list(HttpMethod))
def test_safe_methods_are_sent_as_is(lab: LabServer, method: HttpMethod) -> None:
    lab.html("/", "<title>x</title>")
    response = make_client(lab).request(method, lab.url("/"))
    assert response.status == 200
    assert [r.method for r in lab.requests] == [method.value]
    if method is HttpMethod.HEAD:
        assert response.body == b""


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "get"])
def test_unsafe_methods_are_refused_before_sending(lab: LabServer, method: str) -> None:
    client = make_client(lab)
    with pytest.raises(ValueError, match="not allowed"):
        client.request(method, lab.url("/"))  # type: ignore[arg-type]
    assert lab.requests == []
    assert client.requests_sent == 0


def test_the_api_has_no_way_to_send_a_body() -> None:
    assert list(inspect.signature(SafeHttpClient.request).parameters) == ["self", "method", "url"]
    assert list(inspect.signature(SafeHttpClient.fetch).parameters) == ["self", "method", "url"]


def test_request_headers_are_fixed_and_minimal(lab: LabServer) -> None:
    lab.html("/", "")
    make_client(lab).request(HttpMethod.GET, lab.url("/"))
    sent = lab.requests[0].headers
    assert sent["host"] == f"lab.test:{lab.port}"
    assert sent["user-agent"].startswith("SentinelVAPT/")
    assert "authorized-assessment" in sent["user-agent"]
    assert sent["accept-encoding"] == "identity"
    for absent in ("cookie", "authorization", "proxy-authorization"):
        assert absent not in sent
    assert {k.lower() for k, _ in REQUEST_HEADERS} | {"host"} == set(sent)


def test_cookies_are_never_sent_back(lab: LabServer) -> None:
    lab.html("/", "", headers=[("Set-Cookie", "session=abc123; Path=/")])
    client = make_client(lab)
    client.request(HttpMethod.GET, lab.url("/"))
    client.request(HttpMethod.GET, lab.url("/"))
    assert all("cookie" not in r.headers for r in lab.requests)


def test_proxy_environment_variables_are_ignored(
    lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")  # discard port: would fail if used
    lab.html("/", "")
    assert make_client(lab).request(HttpMethod.GET, lab.url("/")).status == 200


def test_compressed_bodies_are_not_decompressed(lab: LabServer) -> None:
    lab.route("/", body=b"\x1f\x8b\x08\x00not-really-gzip", headers=[("Content-Encoding", "gzip")])
    response = make_client(lab).request(HttpMethod.GET, lab.url("/"))
    assert response.body.startswith(b"\x1f\x8b")
