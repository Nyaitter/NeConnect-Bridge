#!/usr/bin/env python3
"""広告ブロックの一覧を配布元から取り寄せ、1つの圧縮ファイルにまとめる。

使い方:
    python3 client/internal/adblock/tools/build_lists.py

書き出すのは client/internal/adblock/lists/domains.txt.gz。
中の各行は「domain」（止める）か「@@domain」（通す）で、接続のたびに読む形にそろえてある。
走査の対象は公開されている次の一覧:
  - AdGuard DNS filter (AdGuardSDNSFilter)
  - AdGuard Japanese filter の広告配信元 (adservers.txt)
  - OISD small (domainswild)

一覧はそれぞれの配布元の条件に従う。詳しくは同じフォルダの SOURCES.md を見ること。
"""

import gzip
import re
import sys
import urllib.request
from pathlib import Path

SOURCES = [
    ("AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
    (
        "AdGuard Japanese filter (adservers)",
        "https://adguardteam.github.io/AdguardFilters/JapaneseFilter/sections/adservers.txt",
    ),
    ("OISD small", "https://small.oisd.nl/domainswild"),
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
HERE = Path(__file__).resolve().parent.parent
OUT = HERE / "lists" / "domains.txt.gz"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as resp:
        return resp.read().decode("utf-8", "replace")


def valid_domain(raw):
    d = raw.strip().lower().rstrip(".")
    if not d or len(d) > 253:
        return None
    if any(ch in d for ch in "*/\\?#@=[]:% "):
        return None
    if not re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+", d):
        return None
    tld = d.rsplit(".", 1)[-1]
    if len(tld) < 2:
        return None
    if not (tld.startswith("xn--") or re.fullmatch(r"[a-z]{2,}", tld)):
        return None
    return d


def host_from_rule(body):
    body = re.split(r"[\^$]", body, 1)[0]
    if "/" in body:
        return None
    return valid_domain(body[2:] if body.startswith("*.") else body)


def parse(text):
    blocked, allowed = set(), set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "!#[;" or s.startswith("# "):
            continue
        allow = False
        if s.startswith("@@"):
            allow = True
            s = s[2:].strip()
        if not s:
            continue
        if s.startswith("||"):
            d = host_from_rule(s[2:])
            if d:
                (allowed if allow else blocked).add(d)
            continue
        fields = s.split()
        if len(fields) >= 2:
            if fields[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                d = valid_domain(fields[1])
                if d:
                    (allowed if allow else blocked).add(d)
            continue
        if s.startswith("*."):
            d = valid_domain(s[2:])
        elif s.startswith("|") or s.startswith("/"):
            continue
        else:
            d = valid_domain(s)
        if d:
            (allowed if allow else blocked).add(d)
    return blocked, allowed


def main():
    blocked, allowed = set(), set()
    report = []
    for name, url in SOURCES:
        try:
            text = fetch(url)
        except Exception as exc:  # 取れない一覧は飛ばし、残りで組み立てる
            report.append((name, url, 0, f"取得できず: {exc}"))
            continue
        b, a = parse(text)
        blocked |= b
        allowed |= a
        report.append((name, url, len(b), f"通す指定 {len(a)}"))
    if len(blocked) < 10000:
        print("一覧が小さすぎます。取得状況を確認してください。", file=sys.stderr)
        return 1
    allowed -= blocked
    lines = [f"||{d}^" for d in sorted(blocked)] + [f"@@||{d}^" for d in sorted(allowed)]
    body = "\n".join(lines) + "\n"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(gzip.compress(body.encode("utf-8"), 9))
    print(f"{OUT} に {len(blocked)} 件（通す {len(allowed)} 件）を書き出しました "
          f"({OUT.stat().st_size} bytes)")
    sources = ["# 一覧の出どころ", "", "| 一覧 | URL | 止める件数 | 備考 |", "| --- | --- | --- | --- |"]
    for name, url, count, note in report:
        sources.append(f"| {name} | {url} | {count} | {note} |")
    (HERE / "lists" / "SOURCES.md").write_text("\n".join(sources) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
