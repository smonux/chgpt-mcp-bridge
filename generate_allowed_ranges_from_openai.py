#!/usr/bin/env python3
"""
Fetch OpenAI's published IPv4 ranges from the source used in gpt-mcp-filter
(spec.md -> https://openai.com/chatgpt-actions.json) and write a file that is
compatible with the proxy's allowed-ranges format (one CIDR per line).

Usage:
  python generate_allowed_ranges_from_openai.py --output allowed-ranges.txt

Exit codes:
  0 = success
  1 = fetch/parse error
  2 = no IPv4 CIDRs found
"""

import argparse
import json
import re
import sys
from urllib.request import urlopen, Request

SOURCE_URL = 'https://openai.com/chatgpt-actions.json'
CIDR_RE = re.compile(r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}/(?:3[0-2]|[12]?\d)\b')


def extract_ipv4_cidrs(obj):
    """Recursively walk any JSON structure and collect IPv4 CIDR strings."""
    found = set()
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str):
            for m in CIDR_RE.findall(x):
                found.add(m)
    walk(obj)
    return sorted(found)


def fetch_json(url: str):
    req = Request(url, headers={'User-Agent': 'cidr-fetch/1.0'})
    with urlopen(req, timeout=15) as resp:
        if getattr(resp, 'status', 200) != 200:
            raise RuntimeError(f'HTTP {getattr(resp, 'status', 'unknown')}')
        data = resp.read()
    return json.loads(data.decode('utf-8', errors='replace'))


def main():
    p = argparse.ArgumentParser(description='Generate allowed-ranges file from OpenAI published IPv4 ranges')
    p.add_argument('-o', '--output', default='allowed-ranges.txt', help='Output path (default: allowed-ranges.txt)')
    args = p.parse_args()

    try:
        obj = fetch_json(SOURCE_URL)
        cidrs = extract_ipv4_cidrs(obj)
    except Exception as e:
        print(f'Failed to fetch/parse {SOURCE_URL}: {e}', file=sys.stderr)
        sys.exit(1)

    if not cidrs:
        print('No IPv4 CIDRs found in JSON.', file=sys.stderr)
        sys.exit(2)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(f'# Auto-generated from {SOURCE_URL}\n')
        for c in cidrs:
            f.write(c + '\n')

    print(f'Wrote {len(cidrs)} ranges to {args.output}')

if __name__ == '__main__':
    main()
