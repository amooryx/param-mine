<div align="center">
  <img src="./banner.svg" alt="param-mine" width="800">
</div>

# param-mine

`param-mine` tests whether candidate **query parameter names** change the HTTP
response from one endpoint. A response difference is only a lead for manual
review; it does not prove a vulnerability.

> **Authorized security testing only.** Scan only endpoints you own or have
> explicit permission to test.

## Install

Requires Python 3.10 or newer. The tool has no runtime dependencies.

```bash
python -m pip install .
param-mine --help
```

To run from a checkout without installing:

```bash
python param_mine.py --help
```

## Usage

```bash
param-mine "https://example.test/search?lang=en" --wordlist params.txt --threads 5 --rate-limit 5 --timeout 8 --out findings.json
```

The scan makes two baseline GET requests and then one GET request per unique
wordlist entry. It preserves existing query parameters, replacing any existing
value for the candidate name with the benign marker `FUZZ`. The default list is
built in; a custom wordlist is UTF-8 text with one name per line, optional
blank lines, and full-line comments beginning with `#`.

`--header "Name: value"` may be repeated for authenticated testing. Treat
credentials in command history and output files as sensitive.

## Scope and limits

- Only one absolute HTTP(S) URL is scanned. The tool does not crawl or follow
  redirects, so it will not expand scope to another endpoint or host.
- Requests use GET only. No payloads beyond the literal `FUZZ` value are sent.
- Aggregate request rate defaults to 5 requests/second and is configurable
  from 0.1 to 100. Concurrency defaults to 5 and is capped at 20.
- Per-request timeout defaults to 8 seconds and is capped at 120 seconds.
- At most 500 unique parameter names are tested by default. `--max-params` can
  raise this to 1,000. Wordlists are limited to 1 MiB and parameter names to
  256 characters. Response comparisons capture at most 1 MiB per request.
- Existing query values are redacted in printed target URLs and JSON findings.
  Header values are not included in findings.
- Stable baselines permit body-hash comparisons. If the two baseline responses
  differ, body-only changes are ignored to reduce noise; status or response
  length changes outside the baseline observations are still reported.

Findings include the parameter, response status and captured body length, a
brief difference description, whether the body changed, and whether its capture
was truncated. Network failures are printed per parameter and cause exit code
1. A failed baseline or output write exits with code 2; otherwise the tool exits
0, whether or not it found differences.

## Development

Run the standard-library regression suite with:

```bash
python -m unittest discover -s tests -v
```

## Disclaimer

Use only for authorized testing and comply with the target's rules of
engagement.

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) |
[@amooryx](https://github.com/amooryx)
