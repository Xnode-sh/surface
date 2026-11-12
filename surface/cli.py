# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""surface — Android attack surface mapper for Termux (no root, no adb)."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import apk, risk

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _scan(packages):
    results = []
    for pkg in packages:
        surface = apk.inspect(pkg)
        findings = [] if surface.error else risk.analyze(surface)
        results.append({
            "package": surface.package,
            "label": surface.label,
            "version": surface.version_name,
            "target_sdk": surface.target_sdk,
            "score": risk.score(findings),
            "findings": sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9)),
            "components": [
                {"kind": c.kind, "name": c.name, "exported": c.exported,
                 "permission": c.permission, "deep_links": c.deep_links}
                for c in surface.components
            ],
            "error": surface.error,
            "apk": surface.apk_path,
        })
    return results


def _counts(findings):
    out = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f["severity"] in out:
            out[f["severity"]] += 1
    return out


def _print_table(results, verbose=False):
    print(f"{'SCORE':>5}  {'H':>2} {'M':>2} {'L':>2}  PACKAGE")
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        if r["error"]:
            print(f"{'--':>5}  {' ':>2} {' ':>2} {' ':>2}  {r['package']}  (error: {r['error']})")
            continue
        c = _counts(r["findings"])
        print(f"{r['score']:>5}  {c['high']:>2} {c['medium']:>2} {c['low']:>2}  {r['package']}")
        if verbose:
            for f in r["findings"]:
                if f["severity"] == "info":
                    continue
                print(f"         [{f['severity']}] {f['title']} — {f['detail']}")


def _write_json(path, results):
    payload = {
        "tool": "surface",
        "generated": datetime.now(timezone.utc).isoformat(),
        "apps": results,
    }
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_markdown(path, results):
    lines = ["# Android attack surface report", "",
             f"Generated: {datetime.now(timezone.utc).isoformat()}", "",
             "| Score | High | Medium | Low | Package |", "|---|---|---|---|---|"]
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        c = _counts(r["findings"])
        lines.append(f"| {r['score']} | {c['high']} | {c['medium']} | {c['low']} | `{r['package']}` |")
    lines.append("")
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        if r["error"] or not r["findings"]:
            continue
        lines.append(f"## {r['package']} (score {r['score']})")
        for f in r["findings"]:
            if f["severity"] == "info":
                continue
            lines.append(f"- **{f['severity']}** {f['title']}: {f['detail']}")
        lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="surface", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list installed packages")

    scan = sub.add_parser("scan", help="map attack surface of installed apps")
    scan.add_argument("-p", "--package", action="append", default=[], help="package to scan (repeatable)")
    scan.add_argument("-n", "--limit", type=int, default=0, help="max packages to scan (0 = all)")
    scan.add_argument("--json", metavar="FILE", help="write JSON report")
    scan.add_argument("--md", metavar="FILE", help="write Markdown report")
    scan.add_argument("-v", "--verbose", action="store_true", help="show findings per app")
    scan.add_argument("--min-score", type=int, default=0, help="only show apps at/above this score")

    args = parser.parse_args(argv)

    if args.cmd == "list":
        for pkg in apk.installed_packages():
            print(pkg)
        return 0

    packages = args.package or apk.installed_packages()
    if args.limit:
        packages = packages[: args.limit]
    if not packages:
        print("no packages found", file=sys.stderr)
        return 1

    results = _scan(packages)
    shown = [r for r in results if r["score"] >= args.min_score]
    _print_table(shown, verbose=args.verbose)

    if args.json:
        _write_json(args.json, results)
        print(f"\nJSON: {args.json}")
    if args.md:
        _write_markdown(args.md, results)
        print(f"Markdown: {args.md}")

    high = sum(_counts(r["findings"])["high"] for r in results)
    medium = sum(_counts(r["findings"])["medium"] for r in results)
    print(f"\napps: {len(results)} · high: {high} · medium: {medium}")
    return 0
