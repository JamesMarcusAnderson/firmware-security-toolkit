# Changelog

## Note — 2026-11-24

Product renamed to FirmwareScope. The Python module, the binary,
and the release assets are now `firmwarescope`; version stays
1.0.0 and the price is unchanged.

## 1.0.0 — 2026-11-17

First sale-ready release. Built from the 0.x demo CLI
(format/chip identification, strings, 64-bit ELF sections, four
pattern categories).

### Added

- **CVE lookup.** Component/version fingerprinting from ELF
  dynamic-section libraries and version banners (44 components),
  matched against the public NVD API with no key required. Every
  CVE finding shows its match basis (component, version, evidence
  string, CPE queried). Results cached 7 days; rate-limit-aware
  throttling (6 s between requests without a key, 0.6 s with
  `NVD_API_KEY`). Versionless components are never queried.
- **SBOM export.** CycloneDX 1.6 and SPDX 2.3 JSON, validated
  against the official schemas. Honestly scoped: the SBOM is
  component-fingerprint-based, not a full extracted-filesystem
  SBOM, and every document says so.
- **Readable HTML report.** Self-contained, no JavaScript: what
  was scanned, summary by severity, pattern findings with
  recommendations, components with evidence, CVE findings with
  match basis, and the honest-limits list.
- **Expanded patterns.** 10 categories, 53 anchored patterns:
  hardcoded passwords, hardcoded credentials (API keys, tokens,
  cloud keys), private keys, debug interfaces, weak crypto,
  insecure protocols, disabled certificate checks, bad RNG,
  backdoor markers, sensitive file references. Severities and
  plain-language guidance on every finding. Ignores filler values:
  `/etc/passwd` fragments, `chown` user:group pairs, format
  strings, and code references no longer trip the credential
  patterns. Private-key headers with no following key material
  are downgraded and labelled. Identical matches collapse to one
  finding with an occurrence count.
- **Expanded detection.** 25+ container formats (SquashFS, JFFS2,
  TRX, FIT/device tree, ZIP, 7-Zip, Zstandard, PE, Mach-O, …),
  49 chip markers, and ELF CPU-architecture detection.
- **32-bit ELF section parsing.** The code already parsed 32-bit
  ELF sections; the README wrongly said it did not. The docs now
  say what the code does. (Found while fact-checking the audit's
  build-readiness list — see PACKAGING-REPORT.md.)
- **Packaging.** One-file executables via PyInstaller
  (`firmwarescope.spec`); Linux binary built and verified here.
  GitHub Actions workflow (`.github/workflows/release.yml`)
  builds Linux, Windows, and macOS binaries on push and publishes
  them on version tags.
- **Proof artifact.** `docs/demo/`: a real scan of OpenWrt
  23.05.5 (x86-64), with HTML + JSON reports and both SBOMs,
  download URL, date, and SHA-256 recorded for reproduction.
- **Docs.** New README, `docs/USER-GUIDE.md`, this changelog.

### Changed

- CLI: `--version`, `--components`, `--cve`, `--all`, `--out`,
  `--html`, `--sbom-cyclonedx`, `--sbom-spdx`, `--cache-dir`,
  `--api-key`. Existing flags (`--strings`, `--sections`,
  `--vulns`, `--json`) work as before.
- JSON report now carries `tool` (name + version), `scanned_at`,
  and the `limits` list on every run.
- Tests: 111 (was 19), all offline, including SBOM schema
  validation against the official CycloneDX 1.6 and SPDX 2.3
  JSON Schemas.

### Not in v1 (honest)

- No filesystem extraction. Compressed/packed parts of an image
  are identified, not unpacked.
- No emulation, no dynamic analysis, no reachability proof for
  CVE findings.
- No Windows/macOS binaries yet — they are built by CI on push
  (see PACKAGING-REPORT.md for the exact steps). The macOS build
  is Apple Silicon only; Intel Macs run from source.
