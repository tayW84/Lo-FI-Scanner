"""Command-line interface for Lo-FI scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

from .scanner import LfiScanner, ScanConfig


def _parse_headers(header_values: list[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in header_values:
        if ":" not in item:
            raise ValueError(f"Invalid header format: {item!r}. Expected 'Key: Value'.")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lo-FI Scanner - Local File Inclusion scanner")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--param", required=True, help="Potentially vulnerable parameter name")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    parser.add_argument("--headers", action="append", default=[], help="Repeatable header in 'Key: Value' format")
    parser.add_argument("--cookie", default=None, help="Raw Cookie header value")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Requests per second")
    parser.add_argument("--max-requests", type=int, default=50, help="Maximum payload requests to send")
    parser.add_argument("--output", default=None, help="Optional output JSON report path")
    parser.add_argument("--concurrency", type=int, default=5, help="Worker thread count (default: 5)")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        headers = _parse_headers(args.headers)
    except ValueError as exc:
        parser.error(str(exc))

    config = ScanConfig(
        url=args.url,
        param=args.param,
        method=args.method,
        headers=headers,
        cookie=args.cookie,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        max_requests=args.max_requests,
        concurrency=args.concurrency,
    )

    report = LfiScanner(config).run()

    findings = report["findings"]
    print(f"[+] Scan complete. Payloads tested: {report['total_payloads']}")
    print(f"[+] Findings with confidence > 0: {len(findings)}")

    if findings:
        print("\nTop findings:")
        for index, finding in enumerate(findings[:10], start=1):
            hit_names = ", ".join(hit["name"] for hit in finding["signature_hits"]) or "none"
            print(
                f"  {index}. payload={finding['payload']!r} status={finding['status_code']} "
                f"confidence={finding['confidence']} signatures={hit_names}"
            )
            print(f"     poc: {finding['poc_request']}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] JSON report written to {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
