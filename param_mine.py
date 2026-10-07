#!/usr/bin/env python3
"""Find query parameters that change an authorized HTTP endpoint's response."""

import argparse
import hashlib
import http.client
import json
import math
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

WORDLIST = [
    "id", "user", "username", "email", "token", "key", "api", "secret",
    "password", "debug", "test", "admin", "action", "type", "mode", "page",
    "url", "redirect", "return", "next", "back", "file", "path", "dir", "src",
    "source", "dest", "destination", "target", "to", "from", "ref", "referrer",
    "lang", "locale", "format", "output", "callback", "jsonp", "config",
    "settings", "option", "search", "query", "q", "filter", "sort", "order",
    "limit", "offset", "size", "count", "start", "end", "date", "time",
    "version", "v", "auth", "access", "session", "cookie", "csrf", "nonce",
    "hash", "sig", "sign", "signature", "hmac", "method", "cmd", "command",
    "exec", "run", "eval", "load", "import", "include", "require", "module",
    "class", "function", "host", "ip", "port", "proxy", "server", "endpoint",
    "base", "domain", "subdomain", "zone", "region", "bucket", "prefix",
    "name", "title",
]

MAX_THREADS = 20
MAX_PARAMS = 1000
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TIMEOUT = 120.0
MAX_REQUESTS_PER_SECOND = 100.0
MAX_WORDLIST_BYTES = 1024 * 1024
MAX_PARAM_LENGTH = 256
MAX_URL_LENGTH = 8192


@dataclass(frozen=True)
class ResponseFingerprint:
    status: int
    length: int
    body_sha256: str
    truncated: bool


class ScanError(Exception):
    """Raised when the scan cannot be safely started or its baseline fails."""


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.interval = 1.0 / requests_per_second
        self.next_request_at = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_request_at)
            self.next_request_at = slot + self.interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP_OPENER = urllib.request.build_opener(NoRedirectHandler())


def normalize_target_url(url: str) -> str:
    if len(url) > MAX_URL_LENGTH:
        raise ScanError(f"target URL exceeds {MAX_URL_LENGTH} characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ScanError(f"invalid target URL: {exc}") from exc
    if parsed.scheme.lower() not in ("http", "https") or not hostname:
        raise ScanError("target must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ScanError("credentials in the target URL are not allowed")
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ScanError("target URL must not contain control characters")
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
    )


def sanitize_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted_query = urllib.parse.urlencode(
        [(name, "<redacted>") for name, _ in query]
    )
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, redacted_query, "")
    )


def build_probe_url(url: str, param: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(name, value) for name, value in query if name != param]
    query.append((param, "FUZZ"))
    return urllib.parse.urlunsplit(
        parsed._replace(query=urllib.parse.urlencode(query))
    )


def load_parameters(path: str | None, max_params: int) -> list[str]:
    parameters = []
    seen = set()

    def add_parameter(param: str) -> None:
        param = param.strip()
        if not param or any(ord(char) < 32 or ord(char) == 127 for char in param):
            raise ScanError("wordlist contains an empty or invalid parameter name")
        if len(param) > MAX_PARAM_LENGTH:
            raise ScanError(
                f"parameter names must not exceed {MAX_PARAM_LENGTH} characters"
            )
        if param not in seen:
            seen.add(param)
            parameters.append(param)
            if len(parameters) > max_params:
                raise ScanError(
                    f"wordlist has more than the configured limit of {max_params} "
                    "unique parameters"
                )

    if path is None:
        for param in WORDLIST:
            add_parameter(param)
    else:
        with open(path, encoding="utf-8") as wordlist_file:
            if os.fstat(wordlist_file.fileno()).st_size > MAX_WORDLIST_BYTES:
                raise ScanError(
                    f"wordlist file exceeds the {MAX_WORDLIST_BYTES}-byte limit"
                )
            for line in wordlist_file:
                if line.strip() and not line.lstrip().startswith("#"):
                    add_parameter(line)

    if not parameters:
        raise ScanError("wordlist contains no parameter names")
    return parameters


def validate_headers(values: list[str]) -> dict[str, str]:
    headers = {}
    for value in values:
        name, separator, contents = value.partition(":")
        name = name.strip()
        contents = contents.strip()
        if not separator or not name or any(char in name for char in "\r\n:"):
            raise ScanError(f"invalid header; expected 'Name: value': {value!r}")
        if any(char in contents for char in "\r\n"):
            raise ScanError(f"header value contains a newline: {name!r}")
        headers[name] = contents
    return headers


def fetch_response(
    url: str,
    headers: dict[str, str],
    timeout: float,
    limiter: RateLimiter,
) -> ResponseFingerprint:
    request = urllib.request.Request(url, method="GET")
    for name, value in headers.items():
        request.add_header(name, value)

    limiter.wait()
    try:
        response = HTTP_OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error

    try:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        truncated = len(body) > MAX_RESPONSE_BYTES
        body = body[:MAX_RESPONSE_BYTES]
        return ResponseFingerprint(
            status=response.getcode(),
            length=len(body),
            body_sha256=hashlib.sha256(body).hexdigest(),
            truncated=truncated,
        )
    finally:
        response.close()


def compare_response(
    param: str,
    response: ResponseFingerprint,
    baselines: list[ResponseFingerprint],
    stable_baseline: bool,
    probe_url: str,
) -> dict | None:
    baseline = baselines[0]
    status_changed = (
        response.status != baseline.status
        if stable_baseline
        else response.status not in {item.status for item in baselines}
    )
    body_changed = (
        response.length != baseline.length
        or response.body_sha256 != baseline.body_sha256
        or response.truncated != baseline.truncated
    )
    length_changed = (
        response.length != baseline.length
        if stable_baseline
        else response.length not in {item.length for item in baselines}
    )
    if not stable_baseline:
        body_changed = (
            response.length != baseline.length
            or response.body_sha256
            not in {item.body_sha256 for item in baselines}
            or response.truncated != baseline.truncated
        )

    if not status_changed and not length_changed and (
        not stable_baseline or not body_changed
    ):
        return None

    differences = []
    if status_changed:
        baseline_statuses = " / ".join(str(item.status) for item in baselines)
        differences.append(f"status={baseline_statuses}->{response.status}")
    if length_changed:
        baseline_lengths = " / ".join(str(item.length) for item in baselines)
        differences.append(f"length={baseline_lengths}->{response.length}")
    if stable_baseline and body_changed:
        differences.append("body changed")
    return {
        "param": param,
        "status": response.status,
        "length": response.length,
        "url": sanitize_url(probe_url),
        "diff": ", ".join(differences),
        "body_changed": body_changed,
        "truncated": response.truncated,
    }


def scan(
    url: str,
    parameters: list[str],
    headers: dict[str, str],
    threads: int,
    timeout: float,
    requests_per_second: float,
) -> tuple[list[dict], list[tuple[str, str]], bool]:
    limiter = RateLimiter(requests_per_second)
    try:
        baselines = [
            fetch_response(url, headers, timeout, limiter),
            fetch_response(url, headers, timeout, limiter),
        ]
    except (http.client.HTTPException, OSError, TimeoutError, urllib.error.URLError) as exc:
        raise ScanError(f"baseline request failed ({error_message(exc)})") from exc
    stable_baseline = baselines[0] == baselines[1]

    findings_by_param = {}
    errors_by_param = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                fetch_response,
                build_probe_url(url, param),
                headers,
                timeout,
                limiter,
            ): param
            for param in parameters
        }
        for future in as_completed(futures):
            param = futures[future]
            try:
                response = future.result()
            except (http.client.HTTPException, OSError, TimeoutError, urllib.error.URLError) as exc:
                errors_by_param[param] = error_message(exc)
                continue
            finding = compare_response(
                param,
                response,
                baselines,
                stable_baseline,
                build_probe_url(url, param),
            )
            if finding:
                findings_by_param[param] = finding

    findings = [
        findings_by_param[param]
        for param in parameters
        if param in findings_by_param
    ]
    errors = [(param, errors_by_param[param]) for param in parameters if param in errors_by_param]
    return findings, errors, stable_baseline


def error_message(error: Exception) -> str:
    if isinstance(error, urllib.error.URLError):
        reason = error.reason
        detail = reason if isinstance(reason, str) else f"{type(reason).__name__}: {reason}"
        return f"URLError: {detail}"
    return f"{type(error).__name__}: {error}"


def bounded_int(minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be an integer") from exc
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(
                f"must be between {minimum} and {maximum}"
            )
        return number

    return parse


def bounded_float(minimum: float, maximum: float):
    def parse(value: str) -> float:
        try:
            number = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be a number") from exc
        if not math.isfinite(number) or not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(
                f"must be between {minimum} and {maximum}"
            )
        return number

    return parse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Discover query parameters that change one authorized HTTP endpoint. "
            "No crawling or redirect following is performed."
        ),
        epilog="Authorized security testing only.",
    )
    parser.add_argument("url", help="Single target URL (HTTP or HTTPS)")
    parser.add_argument("--wordlist", help="UTF-8 file containing parameter names")
    parser.add_argument("--method", choices=("GET",), default="GET")
    parser.add_argument(
        "--threads", type=bounded_int(1, MAX_THREADS), default=5,
        help=f"Concurrent requests (1-{MAX_THREADS}; default: 5)",
    )
    parser.add_argument(
        "--timeout", type=bounded_float(0.1, MAX_TIMEOUT), default=8.0,
        help=f"Per-request socket timeout in seconds (0.1-{MAX_TIMEOUT}; default: 8)",
    )
    parser.add_argument(
        "--rate-limit", type=bounded_float(0.1, MAX_REQUESTS_PER_SECOND), default=5.0,
        help=f"Maximum aggregate requests per second (0.1-{MAX_REQUESTS_PER_SECOND}; default: 5)",
    )
    parser.add_argument(
        "--max-params", type=bounded_int(1, MAX_PARAMS), default=500,
        help=f"Maximum unique wordlist entries (1-{MAX_PARAMS}; default: 500)",
    )
    parser.add_argument(
        "--header", action="append", default=[],
        help="Request header in 'Name: value' form; repeat for multiple headers",
    )
    parser.add_argument("--out", help="Write findings as a JSON array")
    args = parser.parse_args(argv)

    try:
        target_url = normalize_target_url(args.url)
        parameters = load_parameters(args.wordlist, args.max_params)
        headers = validate_headers(args.header)
    except (OSError, UnicodeError, ScanError) as exc:
        parser.error(str(exc))

    print(f"[*] Getting two baseline responses for {sanitize_url(target_url)} ...")
    try:
        findings, errors, stable_baseline = scan(
            target_url,
            parameters,
            headers,
            args.threads,
            args.timeout,
            args.rate_limit,
        )
    except ScanError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if stable_baseline:
        print("[+] Baseline responses are stable")
    else:
        print(
            "[!] Baseline responses differ; body-only changes will not be reported",
            file=sys.stderr,
        )
    print(
        f"[*] Testing {len(parameters)} unique parameters "
        f"(up to {args.threads} workers, {args.rate_limit:g} requests/second) ..."
    )
    for result in findings:
        print(
            f"  [+] param={result['param']:20s} status={result['status']} "
            f"len={result['length']} {result['diff']}"
        )
    for param, message in errors:
        print(f"  [!] param={param}: request failed ({message})", file=sys.stderr)

    print(f"\n[*] {len(findings)} potentially interesting parameters found")
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as output_file:
                json.dump(findings, output_file, indent=2, ensure_ascii=False)
                output_file.write("\n")
        except OSError as exc:
            print(f"[!] Could not write results to {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"[*] Results saved to {args.out}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
