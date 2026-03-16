"""Core LFI scanning engine."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .payloads import iter_payloads
from .signatures import compute_confidence, match_signatures

TRANSIENT_STATUS = {429, 500, 502, 503, 504}


@dataclass
class ScanConfig:
    url: str
    param: str
    candidate_params: Optional[List[str]] = None
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    cookie: Optional[str] = None
    timeout: float = 10.0
    rate_limit: float = 5.0
    concurrency: int = 5
    retries: int = 2
    backoff_base: float = 0.5
    payload_items: Optional[List[Tuple[str, str]]] = None


class LfiScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._headers = dict(config.headers or {})
        if config.cookie:
            self._headers["Cookie"] = config.cookie
        self._rate_lock = threading.Lock()
        self._last_request_at = 0.0

    def _apply_rate_limit(self) -> None:
        if self.config.rate_limit <= 0:
            return
        min_interval = 1.0 / self.config.rate_limit
        with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_at
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_request_at = time.monotonic()

    def _inject_payload(self, param: str, payload: str) -> tuple[str, Dict[str, str], Optional[str]]:
        method = self.config.method.upper()
        if method == "GET":
            parts = urlsplit(self.config.url)
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            query[param] = payload
            updated_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment))
            return updated_url, {}, self._build_poc_request(updated_url, None)

        data = {param: payload}
        return self.config.url, data, self._build_poc_request(self.config.url, data)

    def _build_poc_request(self, url: str, data: Optional[Dict[str, str]]) -> str:
        method = self.config.method.upper()
        headers = " ".join([f"-H {json.dumps(f'{k}: {v}')}" for k, v in (self.config.headers or {}).items()])
        cookie = f" --cookie {json.dumps(self.config.cookie)}" if self.config.cookie else ""
        data_flag = f" --data {json.dumps(urlencode(data))}" if data else ""
        return f"curl -i -X {method} {headers}{cookie}{data_flag} {json.dumps(url)}".strip()

    def _request_once(self, url: str, data: Dict[str, str]) -> tuple[int, str]:
        body = urlencode(data).encode("utf-8") if data else None
        request = Request(url=url, method=self.config.method.upper(), headers=self._headers, data=body)
        try:
            with urlopen(request, timeout=self.config.timeout) as response:
                content = response.read().decode("utf-8", errors="replace")
                return response.getcode(), content
        except HTTPError as exc:
            content = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return exc.code, content

    def _send_with_retries(self, url: str, data: Dict[str, str]) -> tuple[int, str]:
        last_error: Optional[Exception] = None
        for attempt in range(self.config.retries + 1):
            self._apply_rate_limit()
            try:
                status_code, content = self._request_once(url, data)
                if status_code in TRANSIENT_STATUS and attempt < self.config.retries:
                    time.sleep(self.config.backoff_base * (2**attempt))
                    continue
                return status_code, content
            except (URLError, TimeoutError) as exc:
                last_error = exc
                if attempt < self.config.retries:
                    time.sleep(self.config.backoff_base * (2**attempt))
                    continue
                raise

        if last_error:
            raise last_error
        raise RuntimeError("Unexpected request state")

    def _scan_payload(self, param: str, payload: str, payload_set: str) -> dict:
        url, data, poc = self._inject_payload(param, payload)
        try:
            status_code, body = self._send_with_retries(url, data)
            hits = match_signatures(body)
            confidence = compute_confidence(hits)
            snippet = body[:300].replace("\n", "\\n")
            return {
                "payload": payload,
                "param": param,
                "payload_set": payload_set,
                "method": self.config.method.upper(),
                "url": url,
                "status_code": status_code,
                "response_snippet": snippet,
                "signature_hits": hits,
                "confidence": confidence,
                "poc_request": poc,
            }
        except Exception as exc:
            return {
                "payload": payload,
                "param": param,
                "payload_set": payload_set,
                "method": self.config.method.upper(),
                "url": url,
                "status_code": None,
                "response_snippet": "",
                "signature_hits": [],
                "confidence": 0.0,
                "poc_request": poc,
                "error": str(exc),
            }

    def run(self) -> dict:
        params = self.config.candidate_params or [self.config.param]
        payload_items = list(self.config.payload_items or iter_payloads())
        attempts = [(param, payload, payload_set) for param in params for payload, payload_set in payload_items]
        results: List[dict] = []

        executor = ThreadPoolExecutor(max_workers=max(1, self.config.concurrency))
        futures = [executor.submit(self._scan_payload, param, payload, payload_set) for param, payload, payload_set in attempts]
        try:
            for future in as_completed(futures):
                results.append(future.result())
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)

        findings = sorted(
            [r for r in results if r.get("confidence", 0) > 0],
            key=lambda item: item["confidence"],
            reverse=True,
        )
        return {
            "config": asdict(self.config),
            "total_payloads": len(attempts),
            "findings": findings,
            "results": results,
        }
