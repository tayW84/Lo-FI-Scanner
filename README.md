# Lo-FI-Scanner

Lo-FI-Scanner is a Python CLI for **Local File Inclusion (LFI)** assessment workflows. It supports:

- multi-payload scan mode with signature-based detection
- controlled exploit mode for a single explicit payload
- JSON reporting for automation and triage

## Responsible use (read first)

This tool can generate intrusive traffic and retrieve sensitive file contents if a target is vulnerable.

- You must have **explicit written permission** from the target owner before scanning.
- You must have **explicit written permission** before using exploit mode.
- Unauthorized scanning or exploitation may violate law, policy, and contracts.

Exploit mode includes a built-in authorization gate (`--i-have-authorization`) to reinforce this requirement.

## Installation

### From source

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

The package installs the `lofi-scanner` console command via `pyproject.toml`.

## Quick-start scan example

```bash
lofi-scanner \
  --url "https://example.com/download" \
  --param "file" \
  --param-wordlist params.txt \
  --method GET \
  --rate-limit 3 \
  --output report.scan.json
```

What this does:

1. injects built-in LFI payloads into one or more parameters (`--param` and/or `--param-wordlist`)
2. sends requests with retry/backoff behavior for transient server errors
3. applies response signatures (e.g., `/etc/passwd`, Windows INI markers)
4. writes findings and full per-payload results to JSON


## Parameter discovery with a wordlist

Use `--param-wordlist` to test multiple potential parameter names in scan mode.

- The wordlist format is one parameter per line.
- Empty lines and lines starting with `#` are ignored.
- You can combine `--param` and `--param-wordlist`; duplicates are automatically removed.

```bash
lofi-scanner \
  --url "https://example.com/download" \
  --param "file" \
  --param-wordlist params.txt \
```


## Automated scanning workflow (parameter + payload + file discovery)

You can now automate the full sequence: discover parameters, run LFI payload corpora, and pivot to server-file discovery with custom wordlists.

### 1) Fuzz parameter names

```bash
lofi-scanner \
  --url "http://target.local/index.php" \
  --param-wordlist /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  --method GET \
  --output report.params.json
```

### 2) Test common LFI payloads for discovered params

```bash
lofi-scanner \
  --url "http://target.local/index.php" \
  --param "language" \
  --payload-wordlist /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  --method GET \
  --output report.lfi.json
```

### 3) Fuzz webroot candidates (append `/index.php`)

```bash
lofi-scanner \
  --url "http://target.local/index.php" \
  --param "language" \
  --payload-wordlist /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt \
  --payload-prefix "../../../../" \
  --payload-suffix "/index.php" \
  --method GET \
  --output report.webroot.json
```

### 4) Fuzz server configs/logs with path prefixing

```bash
lofi-scanner \
  --url "http://target.local/index.php" \
  --param "language" \
  --payload-wordlist ./LFI-WordList-Linux \
  --payload-prefix "../../../../" \
  --method GET \
  --output report.files.json
```

`--payload-wordlist` entries are newline-delimited (comments starting with `#` are ignored). Use `--payload-prefix`/`--payload-suffix` to transform each entry into the exact payload style required by the target application.

## Exploit mode example (legal warning)

> ⚠️ **Legal warning:** exploit mode must only be used against systems you are explicitly authorized to test.

```bash
lofi-scanner \
  --exploit \
  --i-have-authorization \
  --url "https://example.com/download" \
  --param "file" \
  --payload "../../../../etc/passwd" \
  --method GET \
  --output report.exploit.json
```

Exploit mode sends one controlled request and returns:

- exact request metadata
- reproducible `curl` command
- raw response body/status

## JSON output schema

### Scan report

```json
{
  "config": {
    "url": "string",
    "param": "string",
    "candidate_params": ["string"],
    "method": "GET|POST",
    "headers": {"string": "string"},
    "cookie": "string|null",
    "timeout": 10.0,
    "rate_limit": 5.0,
    "concurrency": 5,
    "retries": 2,
    "backoff_base": 0.5
  },
  "total_payloads": 120,
  "findings": [
    {
      "payload": "string",
      "param": "string",
      "payload_set": "string",
      "method": "GET|POST",
      "url": "string",
      "status_code": 200,
      "response_snippet": "string",
      "signature_hits": [
        {"name": "string", "pattern": "string", "weight": 0.7}
      ],
      "confidence": 1.0,
      "poc_request": "curl ..."
    }
  ],
  "results": ["all payload attempts including non-findings/errors"]
}
```

### Exploit report

```json
{
  "config": {
    "url": "string",
    "param": "string",
    "payload": "string",
    "method": "GET|POST",
    "headers": {"string": "string"},
    "cookie": "string|null",
    "timeout": 10.0,
    "authorized": true
  },
  "request": {
    "method": "GET|POST",
    "url": "string",
    "body": {"param": "payload"},
    "curl": "curl ..."
  },
  "response": {
    "status_code": 200,
    "body": "string"
  }
}
```

## Limitations and false-positive guidance

- Signature matching is heuristic and content-based; it does not prove exploitability alone.
- Some endpoints echo user input or static docs that resemble signatures.
- Confidence is bounded and additive by signature weight, not a full risk score.
- WAFs, anti-automation logic, and custom error pages can hide true positives.
- High concurrency can produce noisy results on unstable targets.

Recommended triage:

1. validate findings manually with the provided PoC `curl`
2. compare behavior across multiple payload families
3. capture server-side evidence (logs, stack traces) when available
4. document exact authorization scope and test window in your report
