#!/usr/bin/env python3
"""
Param Mine — Hidden Parameter Discovery via Wordlist Fuzzing
Discovers undocumented query parameters on web endpoints.
Author: Omar Khalid (amooryx) | github.com/amooryx/param-mine
AUTHORIZED USE ONLY.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

WORDLIST = [
    "id","user","username","email","token","key","api","secret","password",
    "debug","test","admin","action","type","mode","page","url","redirect",
    "return","next","back","file","path","dir","src","source","dest",
    "destination","target","to","from","ref","referrer","lang","locale",
    "format","output","callback","jsonp","config","settings","option",
    "search","query","q","filter","sort","order","limit","offset","page",
    "size","count","start","end","date","time","version","v","auth",
    "access","session","cookie","csrf","nonce","hash","sig","sign",
    "signature","hmac","method","cmd","command","exec","run","eval",
    "load","import","include","require","module","class","function",
    "host","ip","port","proxy","server","endpoint","base","domain",
    "subdomain","zone","region","bucket","prefix","name","title",
]

def get_baseline(url: str, method: str, extra_headers: dict, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, method=method)
    for k, v in extra_headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192)
            return resp.status, hashlib.md5(body).hexdigest()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""

def test_param(url: str, param: str, method: str, extra_headers: dict,
               baseline: tuple[int, str], timeout: float) -> dict | None:
    parsed  = urllib.parse.urlparse(url)
    qs      = urllib.parse.parse_qs(parsed.query)
    qs[param] = ["FUZZ"]
    new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
    req     = urllib.request.Request(new_url, method=method)
    for k, v in extra_headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body   = resp.read(8192)
            status = resp.status
            bhash  = hashlib.md5(body).hexdigest()
            if status != baseline[0] or bhash != baseline[1]:
                return {"param": param, "status": status, "length": len(body),
                        "url": new_url, "diff": f"status={baseline[0]}->{status}"}
    except urllib.error.HTTPError as e:
        if e.code != baseline[0]:
            return {"param": param, "status": e.code, "length": 0, "url": new_url,
                    "diff": f"status={baseline[0]}->{e.code}"}
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Param Mine — Hidden Parameter Discovery (Authorized use only)",
    )
    parser.add_argument("url",         help="Target URL")
    parser.add_argument("--wordlist",  help="Parameter wordlist file")
    parser.add_argument("--method",    default="GET", help="HTTP method")
    parser.add_argument("--threads",   type=int, default=20)
    parser.add_argument("--timeout",   type=float, default=8)
    parser.add_argument("--header",    nargs="*", help="Extra headers: 'Key: Value'")
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            if ": " in h:
                k, v = h.split(": ", 1)
                headers[k] = v

    wordlist = WORDLIST
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]

    print(f"[*] Getting baseline for {args.url} ...")
    baseline = get_baseline(args.url, args.method, headers, args.timeout)
    print(f"  [+] Baseline: status={baseline[0]}, md5={baseline[1][:8]}...")
    print(f"[*] Testing {len(wordlist)} parameters ...")

    findings = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(test_param, args.url, p, args.method, headers, baseline, args.timeout): p
                   for p in wordlist}
        for fut in futures:
            result = fut.result()
            if result:
                print(f"  [+] param={result['param']:20s} status={result['status']} len={result['length']}  {result.get('diff','')}")
                findings.append(result)

    print(f"\n[*] {len(findings)} potentially interesting parameters found")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
