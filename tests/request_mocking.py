"""Tiny request-mocking helper for urllib-based code under test."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from unittest.mock import patch


@dataclass
class MockHTTPResponse:
    status_code: int
    body: str

    def read(self) -> bytes:
        return self.body.encode("utf-8")

    def getcode(self) -> int:
        return self.status_code

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class URLOpenMock:
    """Request-mocking library helper for patching urllib `urlopen` handlers in tests."""

    def __init__(self, target: str, responder: Callable):
        self._target = target
        self._responder = responder
        self._patch = patch(target, side_effect=self._side_effect)

    def _side_effect(self, request, timeout=10.0):
        status_code, body = self._responder(request, timeout)
        return MockHTTPResponse(status_code=status_code, body=body)

    def __enter__(self):
        return self._patch.__enter__()

    def __exit__(self, exc_type, exc, tb):
        return self._patch.__exit__(exc_type, exc, tb)
