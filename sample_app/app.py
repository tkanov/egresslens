#!/usr/bin/env python3
"""Small sample app: DNS resolving and crt.sh queries.

Usage:
  python app.py dns example.com    # DNS records
  python app.py crt example.com    # crt.sh entries (JSON)
  python app.py all example.com    # both
"""

import argparse
import json
import sys

import requests
import dns.resolver


def resolve(domain, timeout=5.0):
    resolver = dns.resolver.Resolver()
    out = {"A": [], "AAAA": [], "MX": []}
    for rtype in ("A", "AAAA", "MX"):
        try:
            answers = resolver.resolve(domain, rtype, lifetime=timeout)
            if rtype == "MX":
                for r in answers:
                    out["MX"].append({"preference": int(r.preference), "exchange": str(r.exchange).rstrip('.')})
            else:
                for r in answers:
                    out[rtype].append(str(r))
        except Exception:
            # keep going even if one record type fails
            continue
    return out


def query_crtsh(domain, timeout=10.0):
    url = f"https://crt.sh/?q=%25{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "sample-app/1.0"})
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return []
        return []
    except requests.RequestException:
        return []


def main():
    parser = argparse.ArgumentParser(description="Sample DNS + crt.sh utility")
    parser.add_argument("command", choices=["dns", "crt", "all"], help="Command to run")
    parser.add_argument("domain", help="Domain to query")
    args = parser.parse_args()

    if args.command == "dns":
        out = resolve(args.domain)
        print(json.dumps(out, indent=2))
    elif args.command == "crt":
        out = query_crtsh(args.domain)
        print(json.dumps(out, indent=2))
    else:  # all
        out = {"domain": args.domain, "dns": resolve(args.domain), "crt": query_crtsh(args.domain)}
        print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
