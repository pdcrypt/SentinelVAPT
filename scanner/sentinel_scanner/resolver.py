"""Hostname resolution. Every resolved address is checked by ScopePolicy before
the transport connects, and the transport connects to that checked address
(it never resolves the name a second time), which defeats DNS rebinding."""

import socket
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Protocol

from sentinel_scanner.errors import RequestFailed
from sentinel_scanner.netaddr import IPAddress, parse_ip


class Resolver(Protocol):
    def resolve(self, host: str, port: int, timeout: float) -> list[IPAddress]: ...


class SystemResolver:
    """Uses the operating system resolver (getaddrinfo), bounded by a timeout."""

    def __init__(self) -> None:
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sentinel-dns")

    def resolve(self, host: str, port: int, timeout: float) -> list[IPAddress]:
        literal = parse_ip(host)
        if literal is not None:
            return [literal]
        future = self._pool.submit(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
        try:
            infos = future.result(timeout=timeout)
        except FutureTimeout:
            raise RequestFailed("dns_timeout", f"resolving '{host}' timed out") from None
        except OSError as exc:
            raise RequestFailed("dns_failure", f"could not resolve '{host}': {exc}") from None
        addresses: list[IPAddress] = []
        for *_, sockaddr in infos:
            ip = parse_ip(str(sockaddr[0]))
            if ip is not None and ip not in addresses:
                addresses.append(ip)
        if not addresses:
            raise RequestFailed("dns_failure", f"'{host}' did not resolve")
        return addresses


class StaticResolver:
    """Fixed name -> addresses mapping, for tests and controlled environments."""

    def __init__(self, mapping: Mapping[str, Sequence[str]]) -> None:
        self._mapping = {
            name.lower(): [parse_ip(a) for a in addrs] for name, addrs in mapping.items()
        }

    def resolve(self, host: str, port: int, timeout: float) -> list[IPAddress]:
        literal = parse_ip(host)
        if literal is not None:
            return [literal]
        addresses = [a for a in self._mapping.get(host.lower(), []) if a is not None]
        if not addresses:
            raise RequestFailed("dns_failure", f"'{host}' did not resolve")
        return addresses
