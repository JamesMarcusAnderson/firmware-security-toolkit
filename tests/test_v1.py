"""Tests for the v1 packaging build: fingerprinting, CVE lookup, SBOM
export, HTML report, expanded patterns, and expanded detection.

All tests run offline. The CVE tests use a canned NVD payload and a
mocked HTTP layer — no network calls are made.
"""
import json
import pathlib
import struct
import subprocess
import sys

import pytest

from fwtool import cve, detect, fingerprint, htmlreport, sbom, strings, vuln
from fwtool.main import build_report

REPO = pathlib.Path(__file__).parent.parent
FIXTURES = pathlib.Path(__file__).parent / "fixtures"

jsonschema = pytest.importorskip("jsonschema")


def _strings(*texts):
    return [{"offset": i * 100, "string": t} for i, t in enumerate(texts)]


# ---------------------------------------------------------------- fingerprint

def test_version_banners_are_fingerprinted(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00" * 64)
    found = fingerprint.fingerprint(str(p), _strings(
        "OpenSSL 1.1.1k  25 Mar 2021",
        "BusyBox v1.35.0 (2022-01-01) multi-call binary.",
        "Linux version 5.10.146 (builder@host) (gcc) #0",
        "Dropbear sshd v2019.78",
        "dnsmasq-2.85",
        "U-Boot 2021.10 (Jan 01 2022)",
    ))
    by_name = {fp["name"]: fp for fp in found}
    assert by_name["OpenSSL"]["version"] == "1.1.1k"
    assert by_name["BusyBox"]["version"] == "1.35.0"
    assert by_name["Linux kernel"]["version"] == "5.10.146"
    assert by_name["Dropbear"]["version"] == "2019.78"
    assert by_name["dnsmasq"]["version"] == "2.85"
    assert by_name["U-Boot"]["version"] == "2021.10"
    assert all(fp["evidence"] for fp in found)
    assert all(fp["evidence_source"] == "version-string" for fp in found)


def test_cpe_names_are_built_correctly():
    assert fingerprint.cpe_name({"name": "OpenSSL", "version": "1.1.1k"}) == \
        "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    assert fingerprint.cpe_name({"name": "Linux kernel", "version": "5.10.146"}) == \
        "cpe:2.3:o:linux:linux_kernel:5.10.146:*:*:*:*:*:*:*"
    # OpenSSH 8.4p1 splits into version 8.4 + update p1.
    assert fingerprint.cpe_name({"name": "OpenSSH", "version": "8.4",
                                 "update": "p1"}) == \
        "cpe:2.3:a:openbsd:openssh:8.4:p1:*:*:*:*:*:*"
    assert fingerprint.cpe_name({"name": "OpenSSL", "version": None}) is None
    assert fingerprint.cpe_name({"name": "Unknown Thing", "version": "1.0"}) is None


def test_openssh_update_suffix_is_parsed(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00" * 64)
    found = fingerprint.fingerprint(str(p), _strings("SSH-2.0-OpenSSH_8.4p1"))
    assert len(found) == 1
    assert found[0]["version"] == "8.4"
    assert found[0]["update"] == "p1"
    assert found[0]["cpe"] == "cpe:2.3:a:openbsd:openssh:8.4:p1:*:*:*:*:*:*"


def test_glibc_keeps_highest_symbol_version(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00" * 64)
    found = fingerprint.fingerprint(str(p), _strings(
        "GLIBC_2.2.5", "GLIBC_2.17", "GLIBC_2.35", "GLIBC_2.34"))
    assert len(found) == 1
    assert found[0]["name"] == "glibc"
    assert found[0]["version"] == "2.35"
    assert found[0]["evidence_source"] == "symbol-version"


def test_glibc_banner_beats_symbol_version(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00" * 64)
    found = fingerprint.fingerprint(str(p), _strings(
        "GLIBC_2.35",
        "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3) stable release version 2.35.",
    ))
    assert len(found) == 1
    assert found[0]["version"] == "2.35"
    assert found[0]["evidence_source"] == "version-string"


def _synthetic_elf64_with_dynamic():
    """Minimal ELF64 with PT_LOAD + PT_DYNAMIC + a string table."""
    dyn_off = 64 + 2 * 56
    strtab = b"\x00libssl.so.1.1\x00libz.so.1\x00"
    strtab_off = dyn_off + 5 * 16
    vbase = 0x400000
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        2, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0,
    )
    assert len(header) == 64
    total = strtab_off + len(strtab)
    ph_load = struct.pack("<IIQQQQQQ", 1, 5, 0, vbase, 0, total, total, 0x1000)
    ph_dyn = struct.pack("<IIQQQQQQ", 2, 6, dyn_off, vbase + dyn_off, 0,
                         5 * 16, 5 * 16, 8)

    def dyn(tag, val):
        return struct.pack("<qQ", tag, val)

    body = header + ph_load + ph_dyn
    body += dyn(1, 1)                       # DT_NEEDED libssl.so.1.1
    body += dyn(1, 15)                      # DT_NEEDED libz.so.1
    body += dyn(5, vbase + strtab_off)      # DT_STRTAB
    body += dyn(10, len(strtab))            # DT_STRSZ
    body += dyn(0, 0)                       # DT_NULL
    body += strtab
    assert len(body) == total
    return body


def test_elf_dynamic_sonames_are_fingerprinted(tmp_path):
    p = tmp_path / "dyn.elf"
    p.write_bytes(_synthetic_elf64_with_dynamic())
    assert fingerprint._parse_elf_dynamic(p.read_bytes()) == \
        ["libssl.so.1.1", "libz.so.1"]
    found = fingerprint.fingerprint(str(p), [])
    by_name = {fp["name"]: fp for fp in found}
    # Sonames prove presence only: no release version is claimed.
    assert by_name["OpenSSL"]["version"] is None
    assert by_name["OpenSSL"]["evidence"] == "libssl.so.1.1"
    assert by_name["OpenSSL"]["evidence_source"] == "elf-dynamic"
    assert by_name["OpenSSL"]["cpe"] is None
    assert by_name["zlib"]["version"] is None


def test_banner_version_upgrades_soname_record(tmp_path):
    p = tmp_path / "dyn.elf"
    p.write_bytes(_synthetic_elf64_with_dynamic())
    found = fingerprint.fingerprint(str(p), _strings("OpenSSL 3.0.2 15 Mar 2022"))
    by_name = {fp["name"]: fp for fp in found}
    assert by_name["OpenSSL"]["version"] == "3.0.2"
    assert by_name["OpenSSL"]["evidence_source"] == "version-string"
    assert by_name["OpenSSL"]["sightings"] == 2


def test_real_binary_dynamic_section_matches_readelf():
    """Cross-check against the system readelf on /bin/ls."""
    data = pathlib.Path("/bin/ls").read_bytes()
    assert fingerprint._parse_elf_dynamic(data) == \
        ["libselinux.so.1", "libc.so.6"]


# ------------------------------------------------------------------------ cve

NVD_PAYLOAD = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2023-0001",
            "descriptions": [{"lang": "en", "value": "A test flaw."}],
            "published": "2023-01-01T00:00:00.000",
            "lastModified": "2023-01-02T00:00:00.000",
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "references": [{"url": "https://example.invalid/x"}],
        }},
        {"cve": {
            "id": "CVE-2023-0002",
            "descriptions": [{"lang": "en", "value": "An older flaw."}],
            "published": "2023-01-01T00:00:00.000",
            "lastModified": "2023-01-02T00:00:00.000",
            "metrics": {"cvssMetricV2": [{"cvssData": {
                "version": "2.0", "baseScore": 5.0, "baseSeverity": "MEDIUM",
                "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"}}]},
            "references": [],
        }},
    ],
}


def test_parse_nvd_response_prefers_cvss_v31_and_sorts():
    parsed = cve.parse_nvd_response(NVD_PAYLOAD)
    assert [c["id"] for c in parsed] == ["CVE-2023-0001", "CVE-2023-0002"]
    assert parsed[0]["cvss"]["score"] == 9.8
    assert parsed[0]["severity"] == "critical"
    assert parsed[0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"
    assert parsed[1]["cvss"]["version"] == "2.0"
    assert parsed[1]["severity"] == "medium"


def test_severity_bands():
    assert cve.severity_for_score(9.8) == "critical"
    assert cve.severity_for_score(7.5) == "high"
    assert cve.severity_for_score(5.0) == "medium"
    assert cve.severity_for_score(2.0) == "low"
    assert cve.severity_for_score(0.0) == "none"
    assert cve.severity_for_score(None) == "unknown"


class _FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_query_cpe_uses_cache_and_reports_match_basis(monkeypatch, tmp_path):
    cache_dir = tmp_path / "nvd"
    calls = []

    def fake_urlopen(request, timeout=None):
        calls.append(request.full_url)
        return _FakeResponse(NVD_PAYLOAD)

    monkeypatch.setattr(cve.urllib.request, "urlopen", fake_urlopen)
    throttle = cve.Throttle(0)
    cpe_name = "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    first = cve.query_cpe(cpe_name, cache_dir=str(cache_dir), throttle=throttle)
    assert first["error"] is None
    assert len(first["cves"]) == 2
    assert first["from_cache"] is False
    assert "cpeName=" in calls[0]

    # Second call must hit the cache and make no HTTP request.
    monkeypatch.setattr(cve.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used")))
    second = cve.query_cpe(cpe_name, cache_dir=str(cache_dir), throttle=throttle)
    assert second["from_cache"] is True
    assert second["cves"] == first["cves"]


def test_lookup_skips_versionless_components(monkeypatch, tmp_path):
    cache_dir = tmp_path / "nvd"
    monkeypatch.setattr(cve.urllib.request, "urlopen",
                        lambda *a, **k: _FakeResponse(NVD_PAYLOAD))
    components = [
        {"name": "OpenSSL", "version": "1.1.1k", "evidence": "OpenSSL 1.1.1k",
         "evidence_source": "version-string", "offset": 10,
         "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
        {"name": "zlib", "version": None, "evidence": "libz.so.1",
         "evidence_source": "elf-dynamic", "offset": None, "cpe": None},
    ]
    result = cve.lookup(components, cache_dir=str(cache_dir))
    assert result["queried"] == 1
    assert len(result["findings"]) == 2
    assert result["findings"][0]["component"] == "OpenSSL"
    assert result["findings"][0]["match_basis"]["cpe"].startswith("cpe:2.3:a:openssl")
    assert result["findings"][0]["match_basis"]["evidence"] == "OpenSSL 1.1.1k"


def test_lookup_failure_is_recorded_not_raised(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise cve.urllib.error.URLError("no network")

    monkeypatch.setattr(cve.urllib.request, "urlopen", boom)
    components = [{"name": "OpenSSL", "version": "1.1.1k",
                   "evidence": "OpenSSL 1.1.1k", "evidence_source": "version-string",
                   "offset": 10,
                   "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"}]
    result = cve.lookup(components, cache_dir=str(tmp_path / "nvd"))
    assert result["findings"] == []
    assert len(result["errors"]) == 1
    assert "no network" in result["errors"][0]["error"]


# ----------------------------------------------------------------------- sbom

def _sample_report():
    return {
        "file": "demo.bin",
        "identify": {"format": "raw", "size": 1234, "chip_markers": []},
        "components": [
            {"name": "OpenSSL", "version": "1.1.1k",
             "evidence": "OpenSSL 1.1.1k  25 Mar 2021",
             "evidence_source": "version-string", "offset": 10,
             "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
            {"name": "zlib", "version": None, "evidence": "libz.so.1",
             "evidence_source": "elf-dynamic", "offset": None, "cpe": None},
        ],
    }


def test_cyclonedx_structure_and_scope_note():
    doc = sbom.cyclonedx(_sample_report(), "1.0.0")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["metadata"]["component"]["type"] == "firmware"
    assert len(doc["components"]) == 2
    openssl = doc["components"][0]
    assert openssl["version"] == "1.1.1k"
    assert openssl["cpe"].startswith("cpe:2.3:a:openssl")
    assert openssl["purl"] == "pkg:generic/openssl@1.1.1k"
    zlib = doc["components"][1]
    assert "version" not in zlib          # versionless: no version claimed
    assert "cpe" not in zlib
    scope = json.dumps(doc)
    assert "component-fingerprint-based" in scope
    assert "does not extract filesystems" in scope


def test_spdx_structure_and_scope_note():
    doc = sbom.spdx(_sample_report(), "1.0.0")
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(doc["packages"]) == 2
    assert doc["packages"][0]["versionInfo"] == "1.1.1k"
    assert "versionInfo" not in doc["packages"][1]
    assert all(p["filesAnalyzed"] is False for p in doc["packages"])
    assert len(doc["relationships"]) == 2
    assert "does not extract filesystems" in doc["comment"]


def test_sbom_documents_validate_against_official_schemas():
    report = _sample_report()
    cdx_schema = json.loads((FIXTURES / "bom-1.6.schema.json").read_text())
    spdx_schema = json.loads((FIXTURES / "spdx-schema.json").read_text())
    jsonschema.validate(sbom.cyclonedx(report, "1.0.0"), cdx_schema)
    jsonschema.validate(sbom.spdx(report, "1.0.0"), spdx_schema)


# ------------------------------------------------------------------ html report

def _full_report():
    report = _sample_report()
    report.update({
        "scanned_at": "2026-11-17T00:00:00Z",
        "strings_found": 42,
        "vulnerabilities": [
            {"offset": 100, "pattern": "private key", "severity": "critical",
             "match": "BEGIN RSA PRIVATE KEY", "context": "x"},
        ],
        "cve_findings": [
            {"id": "CVE-2023-0001", "description": "A test flaw.",
             "published": "2023-01-01", "modified": "2023-01-02",
             "cvss": {"version": "3.1", "score": 9.8, "severity": "CRITICAL",
                      "vector": "CVSS:3.1/AV:N"},
             "severity": "critical", "references": [],
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
             "component": "OpenSSL", "component_version": "1.1.1k",
             "match_basis": {"cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
                             "evidence": "OpenSSL 1.1.1k  25 Mar 2021",
                             "evidence_source": "version-string", "offset": 10}},
        ],
        "cve_status": {"components_queried": 1, "errors": []},
        "limits": ["No filesystem extraction."],
    })
    return report


def test_html_report_renders_and_escapes():
    out = htmlreport.render(_full_report(), "1.0.0")
    assert "<!DOCTYPE html>" in out
    assert "demo.bin" in out
    assert "CVE-2023-0001" in out
    assert "BEGIN RSA PRIVATE KEY" in out
    assert "cpe:2.3:a:openssl" in out
    assert "No filesystem extraction." in out
    assert "CRITICAL" in out
    # Evidence is escaped, never injected raw.
    report = _full_report()
    report["components"][0]["evidence"] = "<script>alert(1)</script>"
    out = htmlreport.render(report, "1.0.0")
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


# ----------------------------------------------------------------------- vuln

@pytest.mark.parametrize("text,label", [
    ("api_key=AKIAIOSFODNN7EXAMPLE", "hardcoded credential"),
    ("api-key: sk_live_abcdefghijklmnop", "hardcoded credential"),
    ("secret=Sup3rSecretValue123", "hardcoded credential"),
    ("AKIAIOSFODNN7EXAMPLE", "hardcoded credential"),
    ("ghp_abcdefghij1234567890", "hardcoded credential"),
    ("Authorization: Basic YWRtaW46cGFzc3dvcmQ=", "hardcoded credential"),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "private key"),
    ("telnetd -l /bin/sh", "debug interface"),
    ("gdbserver :1234 ./app", "debug interface"),
    ("jtag_enable=1", "debug interface"),
    ("random();", "known-bad RNG"),
    ("srand(1);", "known-bad RNG"),
    ("MD5_Init(&ctx);", "weak crypto"),
    ("SHA1(data, len, out);", "weak crypto"),
    ("DES_ecb_encrypt(&in, &out, &ks, 1);", "weak crypto"),
    ("RC4(&key, len, in, out);", "weak crypto"),
    ("telnet://192.168.1.1", "insecure protocol"),
    ("ftp://user@host/file", "insecure protocol"),
    ("SSLv3 handshake failed", "insecure protocol"),
    ("ctx.verify = SSL_VERIFY_NONE", "certificate check disabled"),
    ("InsecureSkipVerify: true", "certificate check disabled"),
    ("requests.get(url, verify=False)", "certificate check disabled"),
    ("backdoor account enabled", "backdoor marker"),
    ("open /etc/shadow failed", "sensitive file reference"),
    ("cat /etc/passwd", "sensitive file reference"),
])
def test_new_patterns_match(text, label):
    hits = vuln.scan([{"offset": 0, "string": text}])
    assert [h["pattern"] for h in hits] == [label]
    assert hits[0]["severity"] == vuln.SEVERITY[label]
    assert label in vuln.GUIDANCE


@pytest.mark.parametrize("text", [
    "password",                       # the word alone is not a credential
    "this string mentions MD5 sums",  # MD5 as a word, not a call
    "the random forest model",        # 'random' as an adjective
    "/root:/usr/bin:/bin",            # filesystem path, not a credential
    "root:",                          # no secret present
    "api key documentation page",     # no value assigned
    "password: %s",                   # format string, not a credential
    "password='<redacted>'",          # filler value, not a credential
    "password=<password>",            # filler value, not a credential
    "password: <none>",               # filler value, not a credential
    "root:x:0:0:root:/root:/bin/ash",  # /etc/passwd line, not a credential
    "root:::0:99999:7:::",            # /etc/shadow line, not a credential
    "root:/s/^root:\\([^:]*\\):.*$/\\1/p",  # sed script, not a credential
    "console=tty0",                   # ordinary local console, not serial
    "password:this.password,optional:this.optional",  # JS code, not a credential
    "password:false},options);},render:function(){var",  # JS code
    "password: pass,",                # JS variable, too short to be a secret
    "password: 1.2.3.4",              # an IP address, not a credential
    "Authorization: Basic %s",        # format string, not a credential
    'chown root:root "$1.tmp"',       # user:group pair, not a credential
    "chown -R admin:admin /srv/www",  # user:group pair, not a credential
])
def test_new_patterns_do_not_fire_on_ordinary_text(text):
    assert vuln.scan([{"offset": 0, "string": text}]) == []


@pytest.mark.parametrize("text", [
    "root:root",                      # real default credential
    "root:s3cret",                    # real user:password pair
    "admin:changeme123",              # real pair (changeme + suffix)
    "console=ttyS0,115200",           # serial console: a real debug path
    "console=ttyAMA0",                # serial console on ARM boards
])
def test_real_credentials_and_serial_consoles_still_match(text):
    assert vuln.scan([{"offset": 0, "string": text}]) != []


def test_identical_matches_collapse_with_occurrences():
    found = [{"offset": i * 100, "string": "/etc/passwd"}
             for i in range(5)]
    hits = vuln.scan(found)
    assert len(hits) == 1
    assert hits[0]["pattern"] == "sensitive file reference"
    assert hits[0]["occurrences"] == 5
    assert hits[0]["offset"] == 0


def test_private_key_header_without_body_is_downgraded(tmp_path):
    # A header constant inside a binary: NUL-terminated, no key material.
    data = b"-----BEGIN RSA PRIVATE KEY-----\x00\x01\x02\x03"
    p = tmp_path / "lib.bin"
    p.write_bytes(data)
    found = strings.extract(str(p))
    hits = vuln.scan(found, data=data)
    assert len(hits) == 1
    assert hits[0]["severity"] == "medium"
    assert "Header only" in hits[0]["note"]


def test_private_key_with_body_stays_critical(tmp_path):
    body = (b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n"
            b"-----END RSA PRIVATE KEY-----\n")
    p = tmp_path / "key.pem"
    p.write_bytes(body)
    found = strings.extract(str(p))
    hits = vuln.scan(found, data=body)
    assert len(hits) == 1
    assert hits[0]["severity"] == "critical"
    assert "note" not in hits[0]


def test_versioned_soname_paths_are_fingerprinted(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00" * 64)
    found = fingerprint.fingerprint(str(p), _strings(
        "/usr/lib/libmbedtls.so.2.28.9",
        "/usr/lib/libz.so.1.2.13",
        "/usr/lib/libmbedtls.so.14",      # API version only: no fingerprint
    ))
    by_name = {fp["name"]: fp for fp in found}
    assert by_name["mbedTLS"]["version"] == "2.28.9"
    assert by_name["zlib"]["version"] == "1.2.13"


# --------------------------------------------------------------------- detect

@pytest.mark.parametrize("head,fmt", [
    (b"hsqs" + b"\x00" * 60, "SquashFS"),
    (b"\x85\x19" + b"\x00" * 60, "JFFS2"),
    (b"HDR0" + b"\x00" * 60, "TRX"),
    (b"\xd0\x0d\xfe\xed" + b"\x00" * 60, "FIT image / device tree"),
    (b"PK\x03\x04" + b"\x00" * 60, "ZIP"),
    (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 60, "7-Zip"),
    (b"\x28\xb5\x2f\xfd" + b"\x00" * 60, "Zstandard"),
    (b"MZ" + b"\x00" * 60, "PE executable"),
])
def test_new_format_magic(tmp_path, head, fmt):
    p = tmp_path / "f.bin"
    p.write_bytes(head)
    assert detect.identify(str(p), head)["format"] == fmt


@pytest.mark.parametrize("machine,arch", [
    (62, "x86-64"), (3, "x86 (32-bit)"), (40, "ARM"), (183, "AArch64"),
    (8, "MIPS"), (243, "RISC-V"), (999, "e_machine 999"),
])
def test_elf_architecture(machine, arch):
    # e_type at 16, e_machine at 18.
    head = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
            + struct.pack("<HH", 2, machine))
    assert detect.elf_architecture(head) == arch


def test_elf_architecture_rejects_non_elf():
    assert detect.elf_architecture(b"not an elf file at all....") is None


def test_new_chip_markers(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"nRF52840 Allwinner H616 Rockchip RK3568\x00" + b"\x00" * 100)
    with open(p, "rb") as f:
        head = f.read(4096)
    markers = detect.identify(str(p), head)["chip_markers"]
    assert "Nordic nRF52" in markers
    assert "Allwinner" in markers
    assert "Rockchip" in markers


# ----------------------------------------------------------------------- main

def test_cli_version():
    r = subprocess.run([sys.executable, "-m", "fwtool", "--version"],
                       cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0
    assert r.stdout.strip() == "fwtool 1.0.0"


def test_cli_writes_html_and_sboms_offline(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"OpenSSL 1.1.1k  25 Mar 2021\x00admin:hunter2\x00")
    html_path = tmp_path / "report.html"
    cdx_path = tmp_path / "sbom.cdx.json"
    spdx_path = tmp_path / "sbom.spdx.json"
    r = subprocess.run(
        [sys.executable, "-m", "fwtool", str(src), "--vulns",
         "--html", str(html_path),
         "--sbom-cyclonedx", str(cdx_path),
         "--sbom-spdx", str(spdx_path)],
        cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    html = html_path.read_text()
    assert "OpenSSL" in html and "admin:hunter2" in html
    cdx = json.loads(cdx_path.read_text())
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["components"][0]["version"] == "1.1.1k"
    spdx = json.loads(spdx_path.read_text())
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["packages"][0]["versionInfo"] == "1.1.1k"


def test_build_report_carries_limits_and_tool_version(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello\x00")
    report = build_report(str(p))
    assert report["tool"] == {"name": "fwtool", "version": "1.0.0"}
    assert report["scanned_at"]
    assert any("does not extract filesystems" in item.lower()
               or "No filesystem extraction" in item for item in report["limits"])
