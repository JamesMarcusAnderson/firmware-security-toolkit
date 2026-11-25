# Demo scan — OpenWrt 23.05.5 (x86-64)

A real scan of a real public firmware image, so you can see what
FirmwareScope's output looks like before paying for it.

## What was scanned

- **Image:** OpenWrt 23.05.5, x86-64 generic ext4 combined image
- **Downloaded from:**
  https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64-generic-ext4-combined.img.gz
- **Downloaded:** 2026-11-17
- **SHA-256 of the download** (verified against OpenWrt's published
  `sha256sums` in the same directory):
  `f5c77659a33bd43cba105cf2f75e56d054fa9e0b9a73dc9f2a5bcb0e126ff7d5`
- **Scanned file:** the gunzipped image,
  `openwrt-23.05.5-x86-64-generic-ext4-combined.img`
  (126,353,408 bytes). FirmwareScope v1 identifies gzip containers but does
  not unpack them, so the image was gunzipped before scanning — that
  is the documented v1 boundary, not a hidden step.
- **Command:**
  `firmwarescope openwrt-23.05.5-x86-64-generic-ext4-combined.img --all`
  (run 2026-11-17, FirmwareScope v1.0.0)

## What it found

- **2 components identified:** BusyBox 1.36.1, mbedTLS 2.28.9
  (from version banners and versioned library paths in the image).
- **23 CVE findings** for those two versions, from the public NVD
  data — 3 critical, 6 high, 13 medium, 1 low. Each finding shows
  its match basis (component, version, evidence string, CPE queried).
  Spot-check: CVE-2022-48174 (BusyBox, CVSS 9.8) was verified
  against NVD's own configuration data, which lists BusyBox
  versions through 1.36.1 as affected.
- **14 pattern findings**, including a serial console
  (`console=ttyS0`), a Telnet server applet, weak-crypto API
  references (RC4, MD5, SHA-1), and private-key headers that the
  tool downgraded to medium because no key material follows them
  in the file (header constants inside a crypto library, not
  embedded keys).

## What it did not find — and why that is honest

The Linux kernel version, Dropbear, and dnsmasq are in this
firmware but do not appear in the report: the kernel is compressed
inside its partition, and Dropbear/dnsmasq build their version
banners at runtime from separate strings, so no single banner
string exists for v1 to match. v1 reports only what it can see and
prove. Filesystem extraction (which would surface these) is a
later phase, not v1.

## Files

- `openwrt-x86-64-23.05.5-report.html` — the readable report
- `openwrt-x86-64-23.05.5-report.json` — the full JSON report
- `openwrt-x86-64-23.05.5-sbom.cyclonedx.json` — CycloneDX 1.6 SBOM
  (validated against the official CycloneDX 1.6 JSON Schema)
- `openwrt-x86-64-23.05.5-sbom.spdx.json` — SPDX 2.3 SBOM
  (validated against the official SPDX 2.3 JSON Schema)

## Reproduce it

Download the image from the URL above, verify the SHA-256, gunzip
it, and run the command above. CVE counts may grow over time as
NVD publishes new CVEs for these versions — the report records
the scan date.
