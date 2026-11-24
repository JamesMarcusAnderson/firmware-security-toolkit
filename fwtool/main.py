#!/usr/bin/env python3
"""fwtool — firmware security analysis CLI.

Scans a firmware image and reports: format and chip family, ELF
sections, printable strings, vulnerability patterns, identified
software components with versions, public CVEs for those versions,
and a software bill of materials (SBOM).

Honest limits, printed in every report: v1 does not extract
filesystems and does not run the firmware, so it cannot see inside
compressed parts of the image. The SBOM is component-fingerprint-
based, not a full extracted-filesystem SBOM.
"""
import argparse
import datetime
import json
import os
import sys

from . import __version__, cve, detect, fingerprint, htmlreport, sbom, sections, strings, vuln

MAX_STRINGS_SHOWN = 200

LIMITS = [
    "No filesystem extraction: compressed or packed parts of the image "
    "(SquashFS, gzip, xz, …) are identified, not unpacked, so components "
    "inside them are only visible if their strings or banners leak into "
    "the raw image.",
    "The SBOM is component-fingerprint-based: it lists components found "
    "via ELF dynamic-section libraries and version-banner strings. It is "
    "not a full inventory of an extracted filesystem.",
    "CVE findings are version matches against public NVD data. A CVE "
    "listed for a component version means that version is recorded as "
    "affected; it does not prove the vulnerable code path is reachable "
    "in this firmware.",
    "Pattern findings are string matches. Every finding shows its "
    "evidence — check the evidence in context before acting.",
    "Chip markers are searched in the first 64 KiB only; the window "
    "actually scanned is reported in the output.",
]


def build_report(path, want_strings=False, want_sections=False,
                 want_vulns=False, want_components=False, want_cve=False,
                 cache_dir=None, api_key=None):
    with open(path, "rb") as f:
        head = f.read(4096)

    report = {
        "file": path,
        "tool": {"name": "fwtool", "version": __version__},
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "identify": detect.identify(path, head),
        "limits": LIMITS,
    }

    if want_sections:
        report["sections"] = sections.elf_sections(path)

    if want_strings or want_vulns or want_components or want_cve:
        found = strings.extract(path)
        report["strings_found"] = len(found)
        if want_strings:
            report["strings"] = found[:MAX_STRINGS_SHOWN]
            report["strings_truncated"] = len(found) > MAX_STRINGS_SHOWN
        if want_vulns:
            # Raw bytes let the scanner verify private-key findings
            # (header alone vs. header + key material).
            with open(path, "rb") as f:
                data = f.read()
            report["vulnerabilities"] = vuln.scan(found, data=data)
        if want_components or want_cve:
            report["components"] = fingerprint.fingerprint(path, found)
        if want_cve:
            result = cve.lookup(report["components"], cache_dir=cache_dir,
                                api_key=api_key)
            report["cve_findings"] = result["findings"]
            report["cve_status"] = {
                "components_queried": result["queried"],
                "components_with_versions": sum(
                    1 for fp in report["components"] if fp.get("version")),
                "components_without_versions": sum(
                    1 for fp in report["components"] if not fp.get("version")),
                "errors": result["errors"],
            }

    return report


def _print_text(report):
    print(f"file: {report['file']}")
    print(f"format: {report['identify']['format']}")
    if report["identify"].get("architecture"):
        print(f"architecture: {report['identify']['architecture']}")
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
    if "components" in report:
        print(f"components: {len(report['components'])} identified")
        for fp in report["components"]:
            print(f"  {fp['name']} {fp.get('version') or '(version unknown)'}"
                  f" — {fp.get('evidence_source')}")
    if "vulnerabilities" in report:
        if not report["vulnerabilities"]:
            print("vulnerabilities: none")
        for v in report["vulnerabilities"]:
            print(f"  [{v['severity']}] [{v['pattern']}] {v['match']}")
    if "cve_findings" in report:
        status = report["cve_status"]
        print(f"cves: {len(report['cve_findings'])} findings "
              f"({status['components_queried']} components queried)")
        for finding in report["cve_findings"][:20]:
            score = finding["cvss"]["score"]
            print(f"  [{finding['severity']}] {finding['id']} "
                  f"({finding['component']} {finding['component_version']})"
                  f" CVSS {score if score is not None else 'n/a'}")
        if len(report["cve_findings"]) > 20:
            print(f"  ... and {len(report['cve_findings']) - 20} more "
                  f"(see the JSON or HTML report)")
        for err in status["errors"]:
            print(f"  ! CVE lookup failed for {err['component']}: {err['error']}",
                  file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fwtool",
        description="Firmware security analysis: identify, flag, fingerprint, "
                    "and check CVEs for a firmware image.")
    ap.add_argument("firmware", nargs="?",
                    help="firmware image to scan")
    ap.add_argument("--strings", action="store_true",
                    help="include printable strings in the report")
    ap.add_argument("--sections", action="store_true",
                    help="include ELF section headers in the report")
    ap.add_argument("--vulns", action="store_true",
                    help="flag vulnerability patterns in the strings")
    ap.add_argument("--components", action="store_true",
                    help="identify software components and versions")
    ap.add_argument("--cve", action="store_true",
                    help="look up CVEs for identified components (needs "
                         "network; results cached for 7 days). Implies "
                         "--components.")
    ap.add_argument("--all", action="store_true",
                    help="run every analysis: --strings --sections --vulns "
                         "--components --cve")
    ap.add_argument("--json", action="store_true",
                    help="print the full report as JSON")
    ap.add_argument("--out", metavar="FILE",
                    help="write the JSON report to FILE")
    ap.add_argument("--html", metavar="FILE",
                    help="write a readable HTML report to FILE")
    ap.add_argument("--sbom-cyclonedx", metavar="FILE",
                    help="write a CycloneDX SBOM (JSON) to FILE. Implies "
                         "--components. Fingerprint-based, not a full "
                         "extracted-filesystem SBOM.")
    ap.add_argument("--sbom-spdx", metavar="FILE",
                    help="write an SPDX SBOM (JSON) to FILE. Implies "
                         "--components. Fingerprint-based, not a full "
                         "extracted-filesystem SBOM.")
    ap.add_argument("--cache-dir", metavar="DIR",
                    help="directory for cached NVD results "
                         "(default: ~/.cache/fwtool/nvd)")
    ap.add_argument("--api-key", metavar="KEY",
                    help="NVD API key (or set NVD_API_KEY). Raises the "
                         "rate limit from 5 to 50 requests per 30 seconds.")
    ap.add_argument("--version", action="version",
                    version="fwtool %s" % __version__)
    args = ap.parse_args(argv)

    if not args.firmware:
        ap.print_usage(sys.stderr)
        print("fwtool: error: a firmware image is required", file=sys.stderr)
        return 2

    want_cve = args.cve or args.all
    want_components = (args.components or want_cve or args.all
                       or args.sbom_cyclonedx or args.sbom_spdx)
    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    try:
        report = build_report(
            args.firmware,
            want_strings=args.strings or args.all,
            want_sections=args.sections or args.all,
            want_vulns=args.vulns or args.all,
            want_components=bool(want_components),
            want_cve=want_cve,
            cache_dir=args.cache_dir,
            api_key=api_key,
        )
    except FileNotFoundError:
        print(f"error: no such file: {args.firmware}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"error: not a file: {args.firmware}", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"error: cannot read: {args.firmware}", file=sys.stderr)
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"wrote {args.out}", file=sys.stderr)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(htmlreport.render(report, __version__))
        print(f"wrote {args.html}", file=sys.stderr)
    if args.sbom_cyclonedx:
        with open(args.sbom_cyclonedx, "w", encoding="utf-8") as f:
            json.dump(sbom.cyclonedx(report, __version__), f, indent=2)
        print(f"wrote {args.sbom_cyclonedx}", file=sys.stderr)
    if args.sbom_spdx:
        with open(args.sbom_spdx, "w", encoding="utf-8") as f:
            json.dump(sbom.spdx(report, __version__), f, indent=2)
        print(f"wrote {args.sbom_spdx}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
