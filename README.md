# firmware-security-toolkit
Firmware analysis CLI. Identifies format and chip family, extracts strings,
maps ELF sections with resolved names, and flags known vulnerable patterns.

## Covers
Firmware Analyst (entry-level) · Reverse Engineer (entry-level) ·
Security Analyst (embedded)

## Output
See `docs/sample-report.json`, regenerated from `sample.bin` by this code:
```
file: sample.bin
format: raw
size: 5048 bytes (chip markers scanned in first 5048)
chips: ST STM32
  [hardcoded password] admin:hunter2
  [hardcoded password] password=Sup3rSecret!
  [private key] BEGIN RSA PRIVATE KEY
  [debug interface] console_enable
  [debug interface] debug_uart
  [known-bad RNG] srand(time
```

## Quickstart
```bash
python tools/make_sample.py sample.bin     # generates a demo image
python -m fwtool.main sample.bin --vulns --sections
python -m fwtool.main sample.bin --vulns --strings --json
```

## Notes
**Sections** — 64-bit ELF only. Names are resolved through the section-header
string table, so you get `.text` and `.shstrtab` rather than bare offsets.
A 32-bit ELF returns `[]`; a non-ELF returns `None`.

**Findings** are de-duplicated per string: `srand(time(NULL)); rand();` is one
`known-bad RNG` finding, not two. Patterns are anchored so ordinary text does
not trip them — a `/root:/usr/bin:/bin` path is not flagged, while
`root:s3cret` is.

**Chip markers** are searched in the first 64 KiB only. The window actually
scanned is reported in the output so a negative result is never mistaken for a
whole-file scan. `--strings` caps at 200 entries and sets
`strings_truncated: true` when it does.

A missing input file prints an error and exits 2 instead of raising.

## Tests
```bash
pip install pytest
python -m pytest tests -q
```
18 tests, including one that runs the CLI against `/bin/ls` and asserts real
section names come back, and one that asserts `docs/sample-report.json` is
reproducible from a freshly generated image.

## What works
Format and chip-family identification, strings extraction (capped at 200
entries, with a truncation flag), 64-bit ELF section mapping with names
resolved through the section-header string table, de-duplicated
vulnerability-pattern flags, a JSON report reproducible from a generated
sample image, and a clean error with exit code 2 on a missing input file.

## What doesn't
No DNP3/OPC UA. No fuzzing harness yet. No decompression of wrapped images
(gzip/xz containers are identified, not unpacked). 32-bit ELF sections are not
parsed.

## License
MIT
