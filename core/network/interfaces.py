"""Local IPv4 discovery without requiring an Internet connection.

The UDP route probe does not send application data; connect() on a UDP socket
only asks the local OS routing table which source address would be used.
If no default route exists, active interface addresses and hostname resolution
are used as fallbacks.
"""

from __future__ import annotations

import ipaddress
import socket


def _usable_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        isinstance(address, ipaddress.IPv4Address)
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_unspecified
        and not address.is_multicast
    )


def _route_probe() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        # UDP connect does not establish a connection or transmit a packet.
        sock.connect(("8.8.8.8", 80))
        address = sock.getsockname()[0]
        return address if _usable_ipv4(address) else None
    except OSError:
        return None
    finally:
        sock.close()


def _psutil_addresses() -> list[str]:
    """Read addresses from active interfaces when psutil is installed."""
    try:
        import psutil  # Optional dependency; stdlib fallback remains available.
    except ImportError:
        return []

    found = []
    try:
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
    except (OSError, RuntimeError):
        return []

    for interface, entries in addresses.items():
        state = stats.get(interface)
        if state is not None and not state.isup:
            continue
        for entry in entries:
            if entry.family == socket.AF_INET and _usable_ipv4(entry.address):
                found.append(entry.address)

    # Stable order makes selection predictable between runs.
    return sorted(set(found), key=lambda value: (
        not ipaddress.ip_address(value).is_private, value
    ))


def _hostname_addresses() -> list[str]:
    found = set()
    try:
        records = socket.getaddrinfo(
            socket.gethostname(), None, family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
    except OSError:
        records = []

    for record in records:
        address = record[4][0]
        if _usable_ipv4(address):
            found.add(address)

    try:
        _hostname, _aliases, addresses = socket.gethostbyname_ex(socket.gethostname())
    except OSError:
        addresses = []

    found.update(address for address in addresses if _usable_ipv4(address))
    return sorted(found, key=lambda value: (
        not ipaddress.ip_address(value).is_private, value
    ))


def get_local_ipv4() -> str:
    """Return a usable local IPv4 address, or 127.0.0.1 when offline."""
    route_address = _route_probe()
    if route_address:
        return route_address

    for address in _psutil_addresses():
        return address

    for address in _hostname_addresses():
        return address

    return "127.0.0.1"
