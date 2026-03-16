"""Response signatures for identifying likely LFI disclosures."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: str
    confidence_weight: float = 0.7
    flags: int = re.IGNORECASE


SIGNATURES = [
    Signature("etc_passwd", r"root:x:0:0:"),
    Signature("etc_shadow", r"root:[*$!x]:"),
    Signature("windows_win_ini", r"\[fonts\]|\[extensions\]"),
    Signature("windows_boot_ini", r"\[boot loader\]|multi\(0\)disk\(0\)"),
    Signature("php_warning_include", r"warning:\s+include\("),
    Signature("php_warning_fopen", r"warning:\s+fopen\("),
    Signature("path_leak_unix", r"/(var|srv|home|usr)/[\w\-./]+", confidence_weight=0.4),
    Signature("path_leak_windows", r"[A-Z]:\\\\[\w\-.\\\\ ]+", confidence_weight=0.4),
    Signature("proc_environ", r"(?:HTTP_USER_AGENT|DOCUMENT_ROOT)=", confidence_weight=0.8),
]


def match_signatures(text: str) -> List[dict]:
    """Return matched signatures with confidence weights."""
    hits = []
    for signature in SIGNATURES:
        if re.search(signature.pattern, text, flags=signature.flags):
            hits.append(
                {
                    "name": signature.name,
                    "pattern": signature.pattern,
                    "weight": signature.confidence_weight,
                }
            )
    return hits


def compute_confidence(signature_hits: List[dict]) -> float:
    """Bounded confidence score [0,1] based on unique signature hits."""
    total = sum(hit["weight"] for hit in signature_hits)
    return round(min(total, 1.0), 2)
