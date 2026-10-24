import json
import pathlib
import subprocess
import sys

import pytest

from fwtool import detect, sections, strings, vuln

REPO = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(REPO / "tools"))


@pytest.fixture
def sample(tmp_path):
    """Generate the sample image the same way the README tells users to."""
    out = tmp_path / "sample.bin"
    subprocess.run([sys.executable, str(REPO / "tools" / "make_sample.py"), str(out)],
                   check=True, capture_output=True)
    return out


def test_identify_detects_format_and_chip(sample):
    with open(sample, "rb") as f:
        head = f.read(4096)
    info = detect.identify(str(sample), head)
    assert info["format"] == "raw"
    assert "ST STM32" in info["chip_markers"]
    assert info["size"] == sample.stat().st_size
    assert info["marker_scan_bytes"] == info["size"]


def test_identify_reports_scan_window_for_large_files(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * (128 * 1024))
    with open(p, "rb") as f:
        head = f.read(4096)
    assert detect.identify(str(p), head)["marker_scan_bytes"] == 64 * 1024


def test_missing_file_raises_filenotfounderror():
    with pytest.raises(FileNotFoundError):
        detect.identify("/nonexistent/nope.bin", b"")


def test_elf_magic_is_detected(tmp_path):
    p = tmp_path / "f.elf"
    p.write_bytes(b"\x7fELF" + b"\x02" + b"\x00" * 60)
    with open(p, "rb") as f:
        head = f.read(4096)
    assert detect.identify(str(p), head)["format"] == "ELF"


def test_elf_sections_are_named_on_a_real_binary():
    """The regression this fixes: names must be resolved, not just offsets."""
    target = "/bin/ls"
    result = sections.elf_sections(target)
    assert result is not None
    names = [s["name"] for s in result]
    assert ".text" in names
    assert ".shstrtab" in names
    assert all(s["name"] is not None for s in result)
    assert result[0]["name"] == ""          # section 0 is always NULL


def test_elf_sections_rejects_non_elf(tmp_path):
    p = tmp_path / "raw.bin"
    p.write_bytes(b"\x00" * 64)
    assert sections.elf_sections(str(p)) is None


def test_strings_extraction(sample):
    found = strings.extract(str(sample))
    text = " ".join(s["string"] for s in found)
    assert "STM32F407VG bootloader v1.3.2" in text
    assert all(s["offset"] >= 0 for s in found)


def test_no_duplicate_findings_for_one_string(sample):
    """srand(time(NULL)) and rand() sit in the same string: one finding."""
    found = strings.extract(str(sample))
    hits = vuln.scan(found)
    rng = [h for h in hits if h["pattern"] == "known-bad RNG"]
    assert len(rng) == 1
    offsets = [(h["offset"], h["pattern"]) for h in hits]
    assert len(offsets) == len(set(offsets))


def test_credential_is_captured_whole(sample):
    found = strings.extract(str(sample))
    matches = {h["match"] for h in vuln.scan(found) if h["pattern"] == "hardcoded password"}
    assert "admin:hunter2" in matches
    assert "password=Sup3rSecret!" in matches


@pytest.mark.parametrize("text,should_match", [
    ("/root:/usr/bin:/bin", False),        # a filesystem path, not a credential
    ("root:s3cret", True),
    ("admin:hunter2", True),
    ("root:", False),                      # no secret present
])
def test_root_path_is_not_a_credential(tmp_path, text, should_match):
    p = tmp_path / "t.bin"
    p.write_bytes(text.encode() + b"\x00")
    hits = vuln.scan(strings.extract(str(p)))
    assert bool(hits) is should_match


def test_private_key_is_flagged(tmp_path):
    p = tmp_path / "k.bin"
    p.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\x00")
    hits = vuln.scan(strings.extract(str(p)))
    assert [h["pattern"] for h in hits] == ["private key"]


def test_cli_exits_2_on_missing_file():
    r = subprocess.run([sys.executable, "-m", "fwtool.main", "/nonexistent/x.bin"],
                       cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 2
    assert "no such file" in r.stderr


def test_cli_json_output_is_valid(sample):
    r = subprocess.run([sys.executable, "-m", "fwtool.main", str(sample),
                        "--vulns", "--strings", "--json"],
                       cwd=REPO, capture_output=True, text=True, check=True)
    report = json.loads(r.stdout)
    assert report["identify"]["chip_markers"] == ["ST STM32"]
    assert report["vulnerabilities"]
    assert report["strings_found"] >= len(report["strings"])


def test_cli_reports_truncation(tmp_path):
    p = tmp_path / "many.bin"
    p.write_bytes(b"".join(b"STR%04d_padding_data\x00" % i for i in range(300)))
    r = subprocess.run([sys.executable, "-m", "fwtool.main", str(p), "--strings", "--json"],
                       cwd=REPO, capture_output=True, text=True, check=True)
    report = json.loads(r.stdout)
    assert report["strings_truncated"] is True
    assert len(report["strings"]) == 200
    assert report["strings_found"] == 300


def test_committed_sample_report_is_reproducible(sample):
    """docs/sample-report.json must be output this code can actually produce."""
    from fwtool.main import build_report
    report = build_report(str(sample), want_vulns=True)
    committed = json.loads((REPO / "docs" / "sample-report.json").read_text())

    assert report["identify"]["format"] == committed["identify"]["format"]
    assert report["identify"]["chip_markers"] == committed["identify"]["chip_markers"]
    assert [v["pattern"] for v in report["vulnerabilities"]] == \
           [v["pattern"] for v in committed["vulnerabilities"]]
    assert [v["match"] for v in report["vulnerabilities"]] == \
           [v["match"] for v in committed["vulnerabilities"]]


def test_elf_sections_parse_32_bit_elf(tmp_path):
    """New additive support: 32-bit ELF sections must be named, not []."""
    import struct

    shstrtab = b"\x00.text\x00.shstrtab\x00"
    e_shoff = 52
    # ELF32 header: ident(16) + type, machine, version, entry, phoff,
    # shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8,
        2, 3, 1, 0, 0, e_shoff, 0, 52, 0, 0, 40, 3, 2,
    )
    assert len(header) == 52

    def shdr(name, typ, flags, addr, offset, size):
        # ELF32 section header is 10 x 4-byte fields = 40 bytes
        return struct.pack("<IIIIIIIIII", name, typ, flags, addr, offset, size,
                           0, 0, 0, 0)

    body = header
    body += shdr(0, 0, 0, 0, 0, 0)
    body += shdr(1, 1, 6, 0, 0, 0)
    body += shdr(7, 3, 0, 0, e_shoff + 120, len(shstrtab))
    body += shstrtab

    p = tmp_path / "test32.elf"
    p.write_bytes(body)
    result = sections.elf_sections(str(p))
    assert result is not None
    assert [s["name"] for s in result] == ["", ".text", ".shstrtab"]
