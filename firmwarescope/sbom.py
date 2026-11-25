"""SBOM export: CycloneDX 1.6 JSON and SPDX 2.3 JSON.

Both documents are built from the component fingerprints, following
the published CycloneDX and SPDX specifications. Scope, stated in
every document: this SBOM is component-fingerprint-based. v1 does
not extract filesystems, so components that leave no version banner
and no dynamic-library trace in the image are not listed. The SBOM
says what was found and how — it does not claim to be a complete
inventory of an extracted filesystem.
"""
import datetime
import re
import uuid

SCOPE_NOTE = ("Component-fingerprint-based SBOM: components were identified "
              "from ELF dynamic-section libraries and version-banner strings "
              "in the firmware image. This tool version does not extract "
              "filesystems, so the inventory is limited to components that "
              "leave such a trace. It is not a full extracted-filesystem SBOM.")


def _timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _purl(name, version):
    base = "pkg:generic/" + re.sub(r"[^A-Za-z0-9._+-]", "-", name.lower())
    return base + ("@" + version if version else "")


def _spdx_id(name):
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def cyclonedx(report, tool_version):
    """Build a CycloneDX 1.6 SBOM document (as a dict) from a report."""
    identify = report["identify"]
    components = []
    for fp in report.get("components", []):
        entry = {
            "type": "library",
            "bom-ref": str(uuid.uuid5(uuid.NAMESPACE_URL,
                                      "firmwarescope-component:%s:%s" % (
                                          fp["name"], fp.get("version") or ""))),
            "name": fp["name"],
            "purl": _purl(fp["name"], fp.get("version")),
            "properties": [
                {"name": "firmwarescope:evidence",
                 "value": fp.get("evidence") or ""},
                {"name": "firmwarescope:evidence-source",
                 "value": fp.get("evidence_source") or ""},
                {"name": "firmwarescope:sbom-scope",
                 "value": "component-fingerprint-based"},
            ],
        }
        if fp.get("version"):
            entry["version"] = fp["version"]
        if fp.get("cpe"):
            entry["cpe"] = fp["cpe"]
        components.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": [{"vendor": "James Marcus Anderson",
                       "name": "firmwarescope",
                       "version": tool_version}],
            "component": {
                "type": "firmware",
                "bom-ref": str(uuid.uuid5(uuid.NAMESPACE_URL,
                                          "firmwarescope-image:%s" % report["file"])),
                "name": report["file"],
                "properties": [
                    {"name": "firmwarescope:format", "value": identify.get("format", "")},
                    {"name": "firmwarescope:size-bytes",
                     "value": str(identify.get("size", ""))},
                    {"name": "firmwarescope:sbom-scope", "value": SCOPE_NOTE},
                ],
            },
            "properties": [
                {"name": "firmwarescope:sbom-scope", "value": SCOPE_NOTE},
            ],
        },
        "components": components,
    }


def spdx(report, tool_version):
    """Build an SPDX 2.3 SBOM document (as a dict) from a report."""
    packages = []
    for fp in report.get("components", []):
        entry = {
            "SPDXID": _spdx_id(fp["name"]),
            "name": fp["name"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "description": "Evidence: %s (source: %s). %s" % (
                fp.get("evidence") or "none",
                fp.get("evidence_source") or "unknown",
                "Component-fingerprint-based SBOM; no filesystem extraction."),
        }
        if fp.get("version"):
            entry["versionInfo"] = fp["version"]
        if fp.get("cpe"):
            entry["externalRefs"] = [{
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": fp["cpe"],
            }]
        packages.append(entry)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "firmwarescope SBOM for %s" % report["file"],
        "documentNamespace": "https://firmwarescope.invalid/spdx/%s" % uuid.uuid4(),
        "comment": SCOPE_NOTE,
        "creationInfo": {
            "created": _timestamp(),
            "creators": ["Tool: firmwarescope-%s" % tool_version],
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": _spdx_id(fp["name"]),
            }
            for fp in report.get("components", [])
        ],
    }
