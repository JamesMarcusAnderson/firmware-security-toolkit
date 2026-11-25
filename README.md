# FirmwareScope — firmware security analysis

Renamed from fwtool on 2026-11-24.

**Version 1.0.0.** One command turns a firmware image into a readable
security report: what is in it, what is wrong with it, which public
CVEs affect its components, and a software bill of materials (SBOM).

```bash
firmwarescope router-firmware.bin --all --html report.html --sbom-cyclonedx sbom.json
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

## Why firmware analysis matters now

Three November 2026 developments show why opaque firmware needs
independent analysis — and where this tool's limits are.

**Baseboard management controllers are the firmware most people never
audit.** runZero's "Lights Out" project, disclosed in waves from
September to October 2026, reported about 40 flaws across eight
vendors' BMC platforms. The Supermicro wave (advisory Oct 26, 2026)
is headlined by CVE-2026-18450 (CVSS 9.8): the BMC does not enforce
the integrity and encryption a negotiated RMCP+ session requires, so
crafted packets can run arbitrary IPMI commands on an active session.
It affects 402 Supermicro products. runZero's internet scan found
more than 86,000 publicly exposed BMCs, over half of them carrying
one or more critical vulnerabilities. A BMC is a separate processor
with its own firmware and network stack and full authority over its
host — and its firmware is exactly the kind of opaque binary
FirmwareScope is built to open: format detection, ELF sections,
component fingerprints, SBOM, CVE lookup. Supermicro reported no
known malicious use, and none of the CVEs was in CISA's Known
Exploited Vulnerabilities catalog as of Oct 31, 2026, so this is a
call to audit, not a claim of active exploitation.

**Some flaws no SBOM or static scan can catch — and this tool says
so.** Researchers at Technische Universität Berlin disclosed "Hello
Again" in November 2026: a physical attack that defeats the
firmware-TPM lockout protecting Windows Hello and BitLocker PINs.
The flaw tracked as CVE-2026-43613 (CVSS 5.1, AMD bulletin
AMD-SN-7079) is that AMD Secure Processor firmware never verifies
that a replay-protected monotonic counter (RPMC) actually increased,
so an interposer board can block the update and report success. In
the lab, a 4-digit Windows Hello PIN fell in 57 minutes (worst case
40 hours, against 69 days with the lockout working) and a 6-digit
BitLocker PIN in under 7 minutes. No SBOM lists a flaw in the
platform security processor's RPMC handling, and no string scan
finds it — the defect is in how firmware behaves, not in what the
image contains. FirmwareScope's CVE lookup only covers versioned
components with public NVD records; it cannot audit a security
processor's counter logic. AMD plans firmware fixes for most
affected chips between November 2026 and February 2027.

**The same month showed the limit below the firmware layer.**
Trezor confirmed in November 2026 that three Safe 5 wallets sold by
reseller CryptoBilis contained an extra circuit board between the
main board and the display that copied recovery phrases and sent
them over a mobile network — without touching the wallet firmware or
Secure Element, so every software integrity check passed. Firmware
analysis of the wallet's own image would have found nothing wrong,
because nothing in the firmware was wrong. Physical provenance
matters alongside firmware analysis.

**SBOMs are now measured against a 2026 baseline — here is how this
tool scores.** CISA's 2026 SBOM Minimum Elements v2.1 (July 29,
2026) replaced the 2021 NTIA baseline with 17 data fields, and names
SPDX and CycloneDX as the two formats. FirmwareScope emits both
(CycloneDX 1.6, SPDX 2.3). Checked against the tool's own SBOM code
(`firmwarescope/sbom.py`), the coverage is:

| CISA 2026 field | FirmwareScope output |
|---|---|
| SBOM Data Format Name | Covered, both formats: CycloneDX `bomFormat`, SPDX `spdxVersion` |
| SBOM Data Format Version | Covered, both formats: CycloneDX 1.6, SPDX 2.3 |
| SBOM Timestamp | Covered, both formats: CycloneDX `metadata.timestamp`, SPDX `creationInfo.created` |
| SBOM Tool Name | Covered, both formats: `firmwarescope` |
| SBOM Tool Version | Covered, both formats |
| SBOM Version | Partial: CycloneDX carries `version: 1`; SPDX has no numeric SBOM-version field (its `documentNamespace` is a unique UUID, not a version) |
| SBOM Generation Context | Partial: the scope is documented in prose — every SBOM states it is component-fingerprint-based with no filesystem extraction — but there is no standard lifecycle-phase value |
| SBOM Author | Not covered: the CycloneDX tool entry names a vendor, and SPDX creators list only the tool; neither names an SBOM author |
| SBOM Author Signature | Not covered: no signature is emitted. Signing is a separate step after generation, not part of it |
| Component Name | Covered, both formats |
| Component Version | Covered where a version was fingerprinted; unversioned components are listed without one, by design |
| Component Identifiers | Covered: a Package-URL for every component, plus a CPE where one is known |
| Component Producer | Not covered: SPDX records `supplier: NOASSERTION` and CycloneDX emits no per-component producer |
| Component License | Not covered: SPDX records `licenseConcluded: NOASSERTION` and CycloneDX emits no license field |
| Component Hash Algorithm | Not covered: no hashes are emitted |
| Component Hash Value | Not covered: no hashes are emitted |
| Component Dependency Relationship | Not covered: no component-to-component dependency graph is emitted (the SPDX `DESCRIBES` links are document-to-package, not dependencies) |

That is 8 fields covered, 2 partial, 7 not covered. Two of the gaps
are honest scope limits, not oversights: the SBOM is
component-fingerprint-based (components are found from ELF
dynamic-section libraries and version banners, not from an extracted
filesystem), so it cannot hash files it never extracted or name
producers and licenses it never observed; and an author signature
belongs to whoever signs the finished SBOM, not to the tool that
generated it.

Sources: runZero, "Lights Out" — https://www.runzero.com/blog/lights-out-exposed/ ;
Supermicro BMC advisory, Oct 26, 2026 — https://www.supermicro.com/de-de/support/security_BMC_IPMI_Oct_2026_1 ;
The Hacker News, "Hello Again", Nov 18, 2026 — https://thehackernews.com/2026/11/flash-chip-attack-bypasses-tpm-lockout.html ;
The Hacker News, Trezor Safe 5 implants, Nov 13, 2026 — https://thehackernews.com/2026/11/trezor-confirms-hidden-hardware.html ;
CISA 2026 SBOM Minimum Elements v2.1, July 29, 2026 — field list as
summarised by Cybeats, https://www.cybeats.com/blog/sbom-minimum-elements-building-on-a-strong-foundation ,
and SoftWSP, https://softwsp.com/guides/sbom-minimum-elements/ .

## See it before you buy it

`docs/demo/` holds a real scan of a real public firmware image
OpenWrt 23.05.5 (x86-64), downloaded from the OpenWrt download site and verified
by SHA-256, with the HTML report, JSON report, and both SBOMs.
That scan found BusyBox 1.36.1 and mbedTLS 2.28.9, 23 CVE findings
for those versions, and 14 pattern findings. The demo README
records the exact download URL, date, checksum, and command so you
can reproduce it.

Buy the tool (one-time purchase, all three platforms) at the FirmwareScope product site: https://jamesmarcusanderson.github.io/firmwarescope/

## Install

**Download (easiest):** get the one-file executable for your system
from [the releases page](https://github.com/JamesMarcusAnderson/firmware-security-toolkit/releases), and run it. Nothing else to install.

- Linux x86-64: `firmwarescope-1.0.0-linux-x86_64` (available now)
- Windows x86-64: `firmwarescope-1.0.0-windows-x86_64.exe` (ships with the
  first release)
- macOS Apple Silicon: `firmwarescope-1.0.0-macos-arm64` (ships with the
  first release; Intel Macs: run from source below.)

**From source:** Python 3.11+ and nothing else.

```bash
python -m firmwarescope firmware.bin --all
```

## Quickstart

```bash
# Make a demo image and scan it
python tools/make_sample.py sample.bin
firmwarescope sample.bin --vulns --sections

# Full scan: everything, with all outputs
firmwarescope firmware.bin --all --html report.html \
  --sbom-cyclonedx sbom.cyclonedx.json --sbom-spdx sbom.spdx.json

# Just the CVE check (implies component fingerprinting)
firmwarescope firmware.bin --cve --json

# Just the SBOM (implies component fingerprinting)
firmwarescope firmware.bin --sbom-cyclonedx sbom.json
```

Full options and worked examples: `docs/USER-GUIDE.md`.
`firmwarescope --help` lists every flag.

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
