"""Readable HTML report: one self-contained file, no JavaScript, no
external resources. Written for a non-expert reader: what was scanned,
what was found, how bad it is, and what to do about it.
"""
import html

from . import vuln

SEVERITY_ORDER = ["critical", "high", "medium", "low", "none", "unknown"]

CSS = """
body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  max-width: 900px; margin: 2em auto; padding: 0 1.5em; color: #1a1a1a;
  line-height: 1.5; }
h1 { font-size: 1.6em; border-bottom: 3px solid #222; padding-bottom: .3em; }
h2 { font-size: 1.25em; margin-top: 1.8em; border-bottom: 1px solid #ccc;
  padding-bottom: .2em; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; font-size: .92em; }
th, td { border: 1px solid #ddd; padding: .45em .6em; text-align: left;
  vertical-align: top; }
th { background: #f2f2f2; }
code { background: #f4f4f4; padding: .1em .3em; border-radius: 3px;
  font-size: .88em; word-break: break-all; }
.sev { display: inline-block; padding: .1em .55em; border-radius: 3px;
  color: #fff; font-weight: 600; font-size: .85em; }
.critical { background: #b00020; } .high { background: #d32f2f; }
.medium { background: #ef6c00; } .low { background: #f9a825; color: #222; }
.none { background: #757575; } .unknown { background: #9e9e9e; }
.note { background: #fff8e1; border-left: 4px solid #f9a825; padding: .8em 1em;
  margin: 1em 0; }
.good { background: #e8f5e9; border-left: 4px solid #43a047; padding: .8em 1em;
  margin: 1em 0; }
.meta { color: #555; }
footer { margin-top: 2.5em; padding-top: 1em; border-top: 1px solid #ccc;
  color: #666; font-size: .85em; }
"""


def _esc(value):
    return html.escape("" if value is None else str(value))


def _sev_badge(severity):
    sev = (severity or "unknown").lower()
    if sev not in SEVERITY_ORDER:
        sev = "unknown"
    return '<span class="sev %s">%s</span>' % (sev, _esc(sev.upper()))


def _counts(findings, key="severity"):
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        sev = (finding.get(key) or "unknown").lower()
        counts[sev if sev in counts else "unknown"] += 1
    return counts


def render(report, tool_version):
    identify = report["identify"]
    patterns = report.get("vulnerabilities", [])
    cve_findings = report.get("cve_findings", [])
    components = report.get("components", [])
    cve_status = report.get("cve_status", {})

    pattern_counts = _counts(patterns)
    cve_counts = _counts(cve_findings)
    total = len(patterns) + len(cve_findings)

    parts = []
    parts.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                 "<title>Firmware security report — %s</title>\n"
                 "<style>%s</style>\n</head>\n<body>\n" % (_esc(report["file"]), CSS))
    parts.append("<h1>Firmware security report</h1>\n")
    parts.append("<p class=\"meta\">Scanned <code>%s</code> on %s with "
                 "firmwarescope %s.</p>\n" % (_esc(report["file"]),
                                       _esc(report.get("scanned_at", "")),
                                       _esc(tool_version)))

    parts.append("<h2>What was scanned</h2>\n<table>\n"
                 "<tr><th>File</th><td><code>%s</code></td></tr>\n"
                 "<tr><th>Format</th><td>%s</td></tr>\n"
                 "<tr><th>Size</th><td>%s bytes</td></tr>\n"
                 "<tr><th>Architecture</th><td>%s</td></tr>\n"
                 "<tr><th>Chip markers</th><td>%s</td></tr>\n"
                 "<tr><th>Strings found</th><td>%s</td></tr>\n"
                 "<tr><th>Components identified</th><td>%s</td></tr>\n"
                 "</table>\n" % (
                     _esc(report["file"]),
                     _esc(identify.get("format")),
                     _esc(identify.get("size")),
                     _esc(identify.get("architecture") or "not detected"),
                     _esc(", ".join(identify.get("chip_markers") or []) or "none"),
                     _esc(report.get("strings_found", "not scanned")),
                     _esc(len(components))))

    parts.append("<div class=\"note\"><strong>What this report can and "
                 "cannot say.</strong> Findings come from patterns in the "
                 "image's strings, from component version banners, and "
                 "from public CVE data for those versions. This tool does "
                 "not extract filesystems and does not run the firmware, "
                 "so it cannot see inside compressed parts of the image "
                 "and cannot prove a finding is reachable. Every finding "
                 "shows its evidence — check the evidence before acting."
                 "</div>\n")

    parts.append("<h2>Summary</h2>\n")
    if total == 0:
        parts.append("<div class=\"good\"><strong>No findings.</strong> "
                     "No vulnerability patterns matched and no CVEs were "
                     "found for the identified components. That is not a "
                     "guarantee the firmware is safe — see the note above."
                     "</div>\n")
    else:
        parts.append("<p><strong>%d finding(s)</strong>: %d pattern "
                     "finding(s) and %d CVE finding(s).</p>\n" % (
                         total, len(patterns), len(cve_findings)))
        parts.append("<table>\n<tr><th>Severity</th><th>Pattern findings</th>"
                     "<th>CVE findings</th></tr>\n")
        for sev in SEVERITY_ORDER:
            if pattern_counts[sev] or cve_counts[sev]:
                parts.append("<tr><td>%s</td><td>%d</td><td>%d</td></tr>\n" % (
                    _sev_badge(sev), pattern_counts[sev], cve_counts[sev]))
        parts.append("</table>\n")

    if patterns:
        parts.append("<h2>Pattern findings</h2>\n"
                     "<p>Matches in the image's strings. Each one shows "
                     "the matched text, where it sits in the file, and "
                     "what to do about it.</p>\n<table>\n"
                     "<tr><th>Severity</th><th>Finding</th><th>Match</th>"
                     "<th>Offset</th><th>What to do</th></tr>\n")
        for finding in sorted(patterns, key=lambda f: SEVERITY_ORDER.index(
                (f.get("severity") or "unknown").lower()
                if (f.get("severity") or "unknown").lower() in SEVERITY_ORDER
                else "unknown")):
            label = finding["pattern"]
            occurrences = finding.get("occurrences", 1)
            note = finding.get("note", "")
            match_cell = "<code>%s</code>" % _esc(finding["match"])
            if occurrences > 1:
                match_cell += " <br>(%d occurrences)" % occurrences
            if note:
                match_cell += "<br><em>%s</em>" % _esc(note)
            parts.append("<tr><td>%s</td><td>%s</td><td>%s</td>"
                         "<td>0x%x</td><td>%s</td></tr>\n" % (
                             _sev_badge(finding.get("severity")),
                             _esc(label), match_cell,
                             finding["offset"],
                             _esc(vuln.GUIDANCE.get(label, ""))))
        parts.append("</table>\n")

    if components:
        parts.append("<h2>Components identified</h2>\n"
                     "<p>From ELF dynamic-section libraries and version "
                     "banners. A component with no version was seen but "
                     "its release version could not be determined, so no "
                     "CVE lookup was run for it.</p>\n<table>\n"
                     "<tr><th>Component</th><th>Version</th><th>Evidence</th>"
                     "<th>Source</th></tr>\n")
        for fp in components:
            parts.append("<tr><td>%s</td><td>%s</td><td><code>%s</code></td>"
                         "<td>%s</td></tr>\n" % (
                             _esc(fp["name"]),
                             _esc(fp.get("version") or "unknown"),
                             _esc(fp.get("evidence") or ""),
                             _esc(fp.get("evidence_source") or "")))
        parts.append("</table>\n")

    if cve_findings:
        parts.append("<h2>CVE findings</h2>\n"
                     "<p>Public CVEs for the identified component "
                     "versions, from the National Vulnerability Database. "
                     "Each finding shows the match basis: the component, "
                     "its version, the evidence string, and the CPE name "
                     "that was queried.</p>\n<table>\n"
                     "<tr><th>CVE</th><th>Severity</th><th>CVSS</th>"
                     "<th>Component</th><th>Description</th>"
                     "<th>Match basis</th></tr>\n")
        for finding in cve_findings:
            basis = finding.get("match_basis", {})
            score = finding.get("cvss", {}).get("score")
            parts.append("<tr><td><a href=\"%s\">%s</a></td><td>%s</td>"
                         "<td>%s</td><td>%s %s</td><td>%s</td>"
                         "<td><code>%s</code><br>evidence: <code>%s</code>"
                         " (%s)</td></tr>\n" % (
                             _esc(finding.get("url", "")),
                             _esc(finding.get("id")),
                             _sev_badge(finding.get("severity")),
                             _esc(score if score is not None else "—"),
                             _esc(finding.get("component")),
                             _esc(finding.get("component_version") or ""),
                             _esc(finding.get("description")),
                             _esc(basis.get("cpe")),
                             _esc(basis.get("evidence")),
                             _esc(basis.get("evidence_source"))))
        parts.append("</table>\n")

    if cve_status.get("errors"):
        parts.append("<div class=\"note\"><strong>CVE lookup problems."
                     "</strong> Some components could not be checked:\n<ul>\n")
        for err in cve_status["errors"]:
            parts.append("<li>%s %s — %s</li>\n" % (
                _esc(err.get("component")), _esc(err.get("version") or ""),
                _esc(err.get("error"))))
        parts.append("</ul></div>\n")

    parts.append("<h2>Honest limits</h2>\n<ul>\n")
    for limit in report.get("limits", []):
        parts.append("<li>%s</li>\n" % _esc(limit))
    parts.append("</ul>\n")

    parts.append("<footer>Generated by firmwarescope %s. CVE data: National "
                 "Vulnerability Database (public data). This report is a "
                 "triage aid, not a security certification.</footer>\n"
                 "</body>\n</html>\n" % _esc(tool_version))
    return "".join(parts)
