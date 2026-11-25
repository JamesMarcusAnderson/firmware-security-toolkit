# fwtool — firmware security analysis

**Version 1.0.0.** One command turns a firmware image into a readable
security report: what is in it, what is wrong with it, which public
CVEs affect its components, and a software bill of materials (SBOM).

```bash
fwtool router-firmware.bin --all --html report.html --sbom-cyclonedx sbom.json
```

No Python needed for the download: the Linux release is a one-file
executable. Windows and macOS binaries ship with the first release.
From source, the tool is standard-library-only Python 3.11+ —
nothing to install.

## What it does

- **Identifies** the image: container format (ELF, uImage, SquashFS,
  JFFS2, TRX, gzip/xz, ZIP, PE, Mach-O, and more), CPU architecture
  for ELF files, and chip-family markers (ESP32, STM32, nRF52,
  Allwinner, Rockchip, and 44 others).
- **Maps ELF sections** with resolved names — 32-bit and 64-bit.
- **Flags vulnerability patterns** in the image's strings: hardcoded
  passwords and credentials, private keys, debug interfaces, weak
  crypto (MD5, SHA-1, DES, RC4), insecure protocols, disabled
  certificate checks, bad random-number generation, and more.
  Patterns are anchored and ignore filler values, so `/etc/passwd`
  lines, `chown root:root` commands, and JS code do not trip them.
  A private-key header with no key material after it is downgraded
  and labelled — it is usually a header constant inside a crypto
  library, not an embedded key.
- **Fingerprints components and versions** from ELF dynamic-section
  libraries and version banners (BusyBox, OpenSSL, mbedTLS, Linux
  kernel, Dropbear, dnsmasq, U-Boot, and 37 more). Every
  fingerprint shows its evidence.
- **Looks up CVEs** for each versioned component against the public
  National Vulnerability Database (NVD) API — no key needed, results
  cached for 7 days. Every CVE finding shows its match basis:
  component, version, evidence string, and the CPE name queried.
  Components without a known version are never queried, because a
  versionless query would return every CVE ever filed against the
  product.
- **Writes SBOMs** in CycloneDX 1.6 and SPDX 2.3 JSON, validated
  against the official schemas.
- **Writes a readable HTML report** a non-expert can follow: what
  was scanned, what was found, how bad it is, and what to do about
  it — alongside the full JSON report.
## See it before you buy it

`docs/demo/` holds a real scan of a real public firmware image
OpenWrt 23.05.5 (x86-64), downloaded from the OpenWrt download site and verified
by SHA-256, with the HTML report, JSON report, and both SBOMs.
That scan found BusyBox 1.36.1 and mbedTLS 2.28.9, 23 CVE findings
for those versions, and 14 pattern findings. The demo README
records the exact download URL, date, checksum, and command so you
can reproduce it.

Buy the tool (one-time purchase, all three platforms) at the fwtool product site: https://jamesmarcusanderson.github.io/fwtool/

## Install

**Download (easiest):** get the one-file executable for your system
from [the releases page](https://github.com/JamesMarcusAnderson/firmware-security-toolkit/releases), and run it. Nothing else to install.

- Linux x86-64: `fwtool-1.0.0-linux-x86_64` (available now)
- Windows x86-64: `fwtool-1.0.0-windows-x86_64.exe` (ships with the
  first release)
- macOS Apple Silicon: `fwtool-1.0.0-macos-arm64` (ships with the
  first release; Intel Macs: run from source below.)

**From source:** Python 3.11+ and nothing else.

```bash
python -m fwtool firmware.bin --all
```

## Quickstart

```bash
# Make a demo image and scan it
python tools/make_sample.py sample.bin
fwtool sample.bin --vulns --sections

# Full scan: everything, with all outputs
fwtool firmware.bin --all --html report.html \
  --sbom-cyclonedx sbom.cyclonedx.json --sbom-spdx sbom.spdx.json

# Just the CVE check (implies component fingerprinting)
fwtool firmware.bin --cve --json

# Just the SBOM (implies component fingerprinting)
fwtool firmware.bin --sbom-cyclonedx sbom.json
```

Full options and worked examples: `docs/USER-GUIDE.md`.
`fwtool --help` lists every flag.

## Honest limits

- **No filesystem extraction (yet).** Compressed or packed parts of
  an image (SquashFS, gzip, xz) are identified, not unpacked. The
  tool sees what is visible in the raw image: strings, banners, and
  library names. Components hidden inside compressed parts are not
  found. Filesystem extraction is a later phase, not v1.
- **The SBOM is component-fingerprint-based.** It lists components
  found via ELF dynamic-section libraries and version banners. It
  is not a full inventory of an extracted filesystem, and every
  SBOM says so.
- **CVE findings are version matches against public NVD data.** A
  CVE listed for a component version means NVD records that version
  as affected. It does not prove the vulnerable code path is
  reachable in this firmware. Check the match basis on each finding.
- **Pattern findings are string matches.** Every finding shows its
  evidence — check the evidence in context before acting.
- **Chip markers are searched in the first 64 KiB only.** The
  window actually scanned is reported in the output.
- **CVE lookup needs network** (the public NVD API, no key). Without
  network, the lookup fails per component and the failure is recorded
  in the report — the rest of the scan still runs. Without an API key
  the NVD allows 5 requests per 30 seconds, so the tool waits ~6
  seconds between lookups; set `NVD_API_KEY` for the faster limit.
  Results are cached for 7 days.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q
```

111 tests, all offline (the CVE tests use a canned NVD response).
The suite includes schema validation of both SBOM formats against
the official CycloneDX 1.6 and SPDX 2.3 JSON Schemas.

## License

MIT — see `LICENSE`.
