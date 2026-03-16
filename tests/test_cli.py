from pathlib import Path

import pytest

from lofi_scanner.cli import _load_wordlist, _resolve_scan_params, build_parser


def test_load_wordlist_skips_comments_and_blanks(tmp_path: Path):
    wordlist = tmp_path / "params.txt"
    wordlist.write_text("\n# common names\nfile\npage\n\n", encoding="utf-8")

    params = _load_wordlist(str(wordlist))

    assert params == ["file", "page"]


def test_resolve_scan_params_deduplicates(tmp_path: Path):
    wordlist = tmp_path / "params.txt"
    wordlist.write_text("page\nfile\n", encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(["--url", "https://target.local/view", "--param", "file", "--param-wordlist", str(wordlist)])

    primary, candidates = _resolve_scan_params(args, parser)

    assert primary == "file"
    assert candidates == ["file", "page"]


def test_resolve_scan_params_requires_any_input():
    parser = build_parser()
    args = parser.parse_args(["--url", "https://target.local/view"])

    with pytest.raises(SystemExit):
        _resolve_scan_params(args, parser)
