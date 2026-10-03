import ipaddress

import pytest

from sentinel_scanner.netaddr import address_problem, embedded_ipv4


def ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(text)


def teredo(server: str, client: str) -> str:
    value = (
        (0x20010000 << 96)
        | (int(ipaddress.IPv4Address(server)) << 64)
        | (int(ipaddress.IPv4Address(client)) ^ 0xFFFFFFFF)
    )
    return str(ipaddress.IPv6Address(value))


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "127.8.9.10", "10.0.0.5", "172.16.3.4", "192.168.1.20", "::1", "fd00::5"],
)
def test_lab_allows_loopback_and_private(address: str) -> None:
    assert address_problem(ip(address), lab_only=True) is None


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "100.64.0.1"])
def test_lab_blocks_public_addresses(address: str) -> None:
    assert address_problem(ip(address), lab_only=True) is not None
    if address != "100.64.0.1":  # CGNAT is neither private nor public; lab-only blocks it
        assert address_problem(ip(address), lab_only=False) is None


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",  # cloud metadata
        "169.254.0.1",
        "fe80::1",
        "0.0.0.0",  # noqa: S104  # an input that must be rejected, not a bind
        "0.1.2.3",  # 'this network'
        "::",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "240.0.0.1",
        "::ffff:169.254.169.254",  # IPv4-mapped
        "2002:a9fe:a9fe::1",  # 6to4 wrapping the metadata address
        "64:ff9b::a9fe:a9fe",  # NAT64
        "64:ff9b:1::a9fe:a9fe",  # local-use NAT64
    ],
)
@pytest.mark.parametrize("lab_only", [True, False])
def test_always_blocked(address: str, lab_only: bool) -> None:
    assert address_problem(ip(address), lab_only=lab_only) is not None


def test_teredo_embedding_is_decoded() -> None:
    disguised = ip(teredo("8.8.8.8", "169.254.169.254"))
    assert ipaddress.IPv4Address("169.254.169.254") in embedded_ipv4(disguised)  # type: ignore[arg-type]
    problem = address_problem(disguised, lab_only=False)
    assert problem is not None and "169.254.169.254" in problem


def test_embedded_public_address_blocked_for_lab() -> None:
    # Transition addresses never count as lab addresses, even when they wrap a
    # private IPv4 address; IPv4-mapped is judged by the address it maps.
    assert address_problem(ip("2002:0a00:0001::1"), lab_only=True) is not None
    assert address_problem(ip("::ffff:8.8.8.8"), lab_only=True) is not None
    assert address_problem(ip("::ffff:10.0.0.1"), lab_only=True) is None


def test_zone_ids_rejected() -> None:
    assert address_problem(ip("fe80::1%eth0"), lab_only=False) is not None
    assert address_problem(ip("fd00::1%1"), lab_only=True) == "IPv6 zone IDs are not allowed"
