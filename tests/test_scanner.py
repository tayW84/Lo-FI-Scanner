from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from lofi_scanner.scanner import LfiScanner, ScanConfig

from .request_mocking import URLOpenMock


def _fixture(name: str) -> str:
    return (Path(__file__).parent / "fixtures" / name).read_text(encoding="utf-8")


def test_payload_injection_and_signature_detection():
    body = _fixture("true_positive_response.txt")

    def responder(request, _timeout):
        parsed = urlsplit(request.full_url)
        payload_value = parse_qs(parsed.query)["file"][0]
        assert payload_value
        return 200, body

    scanner = LfiScanner(
        ScanConfig(
            url="https://target.local/view",
            param="file",
            method="GET",
            concurrency=1,
            retries=0,
            rate_limit=0,
        )
    )

    with patch("lofi_scanner.scanner.iter_payloads", return_value=iter([("../../../../etc/passwd", "test")])):
        with URLOpenMock("lofi_scanner.scanner.urlopen", responder):
            report = scanner.run()

    assert report["total_payloads"] == 1
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["param"] == "file"
    assert finding["signature_hits"]
    assert any(hit["name"] == "etc_passwd" for hit in finding["signature_hits"])


def test_false_positive_content_not_reported():
    def responder(_request, _timeout):
        return 200, _fixture("false_positive_response.txt")

    scanner = LfiScanner(
        ScanConfig(
            url="https://target.local/view",
            param="file",
            method="GET",
            concurrency=1,
            retries=0,
            rate_limit=0,
        )
    )

    with patch("lofi_scanner.scanner.iter_payloads", return_value=iter([("../../../../etc/passwd", "test")])):
        with URLOpenMock("lofi_scanner.scanner.urlopen", responder):
            report = scanner.run()

    assert report["total_payloads"] == 1
    assert report["findings"] == []


def test_candidate_params_are_scanned_from_config():
    def responder(request, _timeout):
        parsed = urlsplit(request.full_url)
        params = parse_qs(parsed.query)
        if "page" in params:
            return 200, _fixture("true_positive_response.txt")
        return 200, _fixture("false_positive_response.txt")

    scanner = LfiScanner(
        ScanConfig(
            url="https://target.local/view",
            param="file",
            candidate_params=["file", "page"],
            method="GET",
            concurrency=1,
            retries=0,
            rate_limit=0,
        )
    )

    with patch("lofi_scanner.scanner.iter_payloads", return_value=iter([("../../../../etc/passwd", "test")])):
        with URLOpenMock("lofi_scanner.scanner.urlopen", responder):
            report = scanner.run()

    assert report["total_payloads"] == 2
    assert len(report["findings"]) == 1
    assert report["findings"][0]["param"] == "page"


def test_custom_payload_items_override_builtin_payloads():
    seen_payloads = []

    def responder(request, _timeout):
        parsed = urlsplit(request.full_url)
        payload_value = parse_qs(parsed.query)["file"][0]
        seen_payloads.append(payload_value)
        return 200, _fixture("false_positive_response.txt")

    scanner = LfiScanner(
        ScanConfig(
            url="https://target.local/view",
            param="file",
            method="GET",
            concurrency=1,
            retries=0,
            rate_limit=0,
            payload_items=[("../../../../etc/hosts", "custom-wordlist")],
        )
    )

    with URLOpenMock("lofi_scanner.scanner.urlopen", responder):
        report = scanner.run()

    assert report["total_payloads"] == 1
    assert seen_payloads == ["../../../../etc/hosts"]
    assert report["results"][0]["payload_set"] == "custom-wordlist"


def test_keyboard_interrupt_cancels_pending_futures():
    class DummyFuture:
        def __init__(self):
            self.cancelled = False

        def cancel(self):
            self.cancelled = True

    class DummyExecutor:
        instance = None

        def __init__(self, max_workers):
            self.max_workers = max_workers
            self.futures = []
            self.shutdown_calls = []
            DummyExecutor.instance = self

        def submit(self, fn, *args):
            future = DummyFuture()
            self.futures.append(future)
            return future

        def shutdown(self, wait=True, cancel_futures=False):
            self.shutdown_calls.append((wait, cancel_futures))

    scanner = LfiScanner(
        ScanConfig(
            url="https://target.local/view",
            param="file",
            method="GET",
            concurrency=2,
            retries=0,
            rate_limit=0,
        )
    )

    with patch("lofi_scanner.scanner.iter_payloads", return_value=iter([('a', 'test'), ('b', 'test')])):
        with patch("lofi_scanner.scanner.ThreadPoolExecutor", DummyExecutor):
            with patch("lofi_scanner.scanner.as_completed", side_effect=KeyboardInterrupt):
                with patch.object(scanner, "_scan_payload", return_value={}):
                    try:
                        scanner.run()
                    except KeyboardInterrupt:
                        pass
                    else:
                        raise AssertionError("Expected KeyboardInterrupt")

    executor = DummyExecutor.instance
    assert executor is not None
    assert executor.shutdown_calls == [(False, True)]
    assert all(future.cancelled for future in executor.futures)
