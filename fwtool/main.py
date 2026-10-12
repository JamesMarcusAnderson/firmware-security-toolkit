#!/usr/bin/env python3
import argparse
import json
import sys

from . import detect, sections, strings, vuln

MAX_STRINGS_SHOWN = 200


def build_report(path, want_strings=False, want_sections=False, want_vulns=False):
    with open(path, "rb") as f:
        head = f.read(4096)

    report = {"file": path, "identify": detect.identify(path, head)}

    if want_sections:
        report["sections"] = sections.elf_sections(path)

    if want_strings or want_vulns:
        found = strings.extract(path)
        report["strings_found"] = len(found)
        if want_strings:
            report["strings"] = found[:MAX_STRINGS_SHOWN]
            report["strings_truncated"] = len(found) > MAX_STRINGS_SHOWN
        if want_vulns:
            report["vulnerabilities"] = vuln.scan(found)

    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--sections", action="store_true")
    ap.add_argument("--vulns", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        report = build_report(args.firmware, args.strings, args.sections, args.vulns)
    except FileNotFoundError:
        print(f"error: no such file: {args.firmware}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"error: not a file: {args.firmware}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"file: {report['file']}")
    print(f"format: {report['identify']['format']}")
    print(f"size: {report['identify']['size']} bytes "
          f"(chip markers scanned in first {report['identify']['marker_scan_bytes']})")
    print(f"chips: {', '.join(report['identify']['chip_markers']) or 'none'}")
    if "sections" in report:
        named = [s for s in (report["sections"] or []) if s.get("name")]
        print(f"sections: {len(report['sections'] or [])} "
              f"({len(named)} named)")
    if "strings_found" in report:
        note = " (truncated)" if report.get("strings_truncated") else ""
        print(f"strings: {len(report.get('strings', []))} shown "
              f"of {report['strings_found']}{note}")
    if "vulnerabilities" in report:
        if not report["vulnerabilities"]:
            print("vulnerabilities: none")
        for v in report["vulnerabilities"]:
            print(f"  [{v['pattern']}] {v['match']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
