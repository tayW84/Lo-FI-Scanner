"""Command-line interface for Lo-FI scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from .exploit import AuthorizationError, ExploitConfig, LfiExploit
from .scanner import LfiScanner, ScanConfig


def _parse_headers(header_values: list[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in header_values:
        if ":" not in item:
            raise ValueError(f"Invalid header format: {item!r}. Expected 'Key: Value'.")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def _load_wordlist(path: str) -> List[str]:
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        raise ValueError(f"Parameter wordlist does not exist: {wordlist_path}")

    values: List[str] = []
    for line in wordlist_path.read_text(encoding="utf-8").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        values.append(candidate)

    if not values:
        raise ValueError(f"Parameter wordlist is empty: {wordlist_path}")
    return values


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lo-FI Scanner - Local File Inclusion scanner")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--param", default=None, help="Potentially vulnerable parameter name")
    parser.add_argument("--param-wordlist", default=None, help="Path to newline-delimited parameter names to test")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    parser.add_argument("--headers", action="append", default=[], help="Repeatable header in 'Key: Value' format")
    parser.add_argument("--cookie", default=None, help="Raw Cookie header value")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Requests per second")
    parser.add_argument("--max-requests", type=int, default=50, help="Maximum payload requests to send")
    parser.add_argument("--output", default=None, help="Optional output JSON report path")
    parser.add_argument("--concurrency", type=int, default=5, help="Worker thread count (default: 5)")
    parser.add_argument("--exploit", action="store_true", help="Send one explicit payload instead of scanner corpus")
    parser.add_argument("--payload", default=None, help="Payload to use in exploit mode")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Required gate for exploit mode. You must have explicit written permission.",
    )
    return parser


def _resolve_scan_params(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[str, List[str] | None]:
    candidate_params: List[str] = []
    if args.param:
        candidate_params.append(args.param)
    if args.param_wordlist:
        candidate_params.extend(_load_wordlist(args.param_wordlist))

    unique_params = list(dict.fromkeys(candidate_params))
    if not unique_params:
        parser.error("scan mode requires --param and/or --param-wordlist")

    return unique_params[0], unique_params


def _run_scan(args: argparse.Namespace, headers: Dict[str, str], parser: argparse.ArgumentParser) -> int:
    param, candidate_params = _resolve_scan_params(args, parser)
    config = ScanConfig(
        url=args.url,
        param=param,
        candidate_params=candidate_params,
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
                f"  {index}. param={finding['param']!r} payload={finding['payload']!r} "
                f"status={finding['status_code']} confidence={finding['confidence']} signatures={hit_names}"
            )
            print(f"     poc: {finding['poc_request']}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] JSON report written to {output_path}")

    return 0


def _run_exploit(args: argparse.Namespace, headers: Dict[str, str], parser: argparse.ArgumentParser) -> int:
    if not args.param:
        parser.error("--param is required when --exploit is set")
    if args.param_wordlist:
        parser.error("--param-wordlist is not supported with --exploit")
    if not args.payload:
        parser.error("--payload is required when --exploit is set")

    config = ExploitConfig(
        url=args.url,
        param=args.param,
        payload=args.payload,
        method=args.method,
        headers=headers,
        cookie=args.cookie,
        timeout=args.timeout,
        authorized=args.i_have_authorization,
    )

    exploit = LfiExploit(config)
    try:
        report = exploit.run()
    except AuthorizationError as exc:
        parser.error(str(exc))

    print(f"[+] Exploit request sent. Status: {report['response']['status_code']}")
    print(f"[+] Reproduction: {report['request']['curl']}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Exploit report written to {output_path}")

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        headers = _parse_headers(args.headers)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        if args.exploit:
            return _run_exploit(args, headers, parser)
        return _run_scan(args, headers, parser)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
