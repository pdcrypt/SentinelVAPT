"""IP address policy. Pure and offline.

Used twice: on IP literals in the scope, and on every address a hostname
resolves to just before connecting. IPv6 forms that carry an IPv4 address
(IPv4-mapped, 6to4, Teredo, NAT64) are decoded so the embedded address is held
to the same rules.
"""

import ipaddress

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# "This network": on several platforms 0.x.x.x reaches the local host.
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_NAT64_PREFIXES = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


def parse_ip(text: str) -> IPAddress | None:
    """Parse a canonical IP literal (brackets allowed for IPv6); None if not an IP."""
    host = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def embedded_ipv4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses carried inside an IPv6 address."""
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)  # (server, client)
    if any(ip in net for net in _NAT64_PREFIXES):
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


def _basic_problem(ip: IPAddress) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None:
        return "IPv6 zone IDs are not allowed"
    if ip.is_unspecified or (isinstance(ip, ipaddress.IPv4Address) and ip in _THIS_NETWORK):
        return "unspecified / 'this network' address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_link_local:
        return "link-local address (includes cloud metadata endpoints)"
    if ip.is_reserved and not ip.is_loopback:
        return "reserved address"
    return None


def address_problem(ip: IPAddress, *, lab_only: bool) -> str | None:
    """Why this address must not be contacted, or None if it may be.

    lab_only: the address must be loopback or private (Phase 2 only supports
    local_lab targets).
    """
    problem = _basic_problem(ip)
    if problem:
        return problem
    if isinstance(ip, ipaddress.IPv6Address):
        # 6to4, Teredo and NAT64 addresses are reached through relays, never on
        # a lab network. (IPv4-mapped is just another spelling of the IPv4
        # address and is judged by it below.)
        is_transition = (
            ip.sixtofour is not None
            or ip.teredo is not None
            or any(ip in net for net in _NAT64_PREFIXES)
        )
        if lab_only and is_transition:
            return "6to4/Teredo/NAT64 transition address; not a lab address"
        for inner in embedded_ipv4(ip):
            inner_problem = _basic_problem(inner)
            if inner_problem:
                return f"embeds {inner}: {inner_problem}"
            if lab_only and not (inner.is_loopback or inner.is_private):
                return f"embeds public address {inner}"
    if lab_only and not (ip.is_loopback or ip.is_private):
        return "public address; local_lab scans may only reach loopback or private addresses"
    return None
