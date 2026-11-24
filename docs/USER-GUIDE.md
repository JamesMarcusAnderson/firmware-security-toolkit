# fwtool user guide (v1.0.0)

## What fwtool is for

You have a firmware image — a router update file, a camera firmware
download, a dump from a device — and you want to know: what is in it,
what is wrong with it, and which known vulnerabilities affect it?
fwtool answers that in one command, with a report you can hand to
someone who is not a reverse engineer.

It is a triage tool, not a certification. It tells you what it can
see and prove, and it says plainly what it cannot see.

## Running a scan

The full scan runs every analysis and writes every output:

```bash
fwtool firmware.bin --all --html report.html \
  --sbom-cyclonedx sbom.cyclonedx.json --sbom-spdx sbom.spdx.json \
  --out report.json
```

Each analysis can also run on its own:

| Flag | What it does |
|---|---|
| `--strings` | List printable strings (first 200 shown; the count is exact) |
| `--sections` | List ELF section headers with names (32-bit and 64-bit) |
| `--vulns` | Flag vulnerability patterns in the strings |
| `--components` | Identify software components and versions |
| `--cve` | Look up CVEs for versioned components (needs network; implies `--components`) |
| `--all` | All of the above |

Outputs:

| Flag | Output |
|---|---|
| (none) | Short text summary on screen |
| `--json` | Full report as JSON on screen |
| `--out FILE` | Full report as JSON in FILE |
| `--html FILE` | Readable HTML report in FILE |
| `--sbom-cyclonedx FILE` | CycloneDX 1.6 SBOM (JSON) in FILE |
| `--sbom-spdx FILE` | SPDX 2.3 SBOM (JSON) in FILE |

`--sbom-cyclonedx` and `--sbom-spdx` imply `--components`, so an
SBOM-only run is just:

```bash
fwtool firmware.bin --sbom-cyclonedx sbom.json
```

Exit codes: 0 means the scan ran; 2 means the input file could not
be read (missing, a directory, or permission denied). A CVE lookup
failure never changes the exit code — the failure is recorded in
the report and the rest of the scan still completes.

## Reading the HTML report

The report has five parts:

1. **What was scanned** — file, format, size, architecture, chip
   markers, string count, component count.
2. **What this report can and cannot say** — the honest-limits box.
   Read it before acting on anything below it.
3. **Summary** — finding counts by severity.
4. **Pattern findings** — each with severity, the matched text, its
   offset in the file, how many times it occurs, and what to do
   about it.
5. **Components** and **CVE findings** — each CVE with its CVSS
   score, a link to its NVD page, and its match basis: the
   component, its version, the evidence string that identified it,
   and the CPE name that was queried.

## How component fingerprinting works

Two evidence sources, both readable without extracting anything:

- **ELF dynamic-section libraries.** If the image (or a binary in
  it, when scanning a single ELF) links `libssl.so.1.1`, the tool
  records OpenSSL as present. A soname version is an API version,
  not a release version, so it is recorded as evidence only — the
  component gets no version from it.
- **Version banners.** Strings like `BusyBox v1.36.1`,
  `OpenSSL 1.1.1k`, `Linux version 5.10.146`, or a versioned library
  path like `/usr/lib/libmbedtls.so.2.28.9` identify a component
  and its release version.

Only versioned components are sent to the CVE lookup. A component
with no known version still appears in the SBOM (with no version)
and in the report, so you can see what was found but not checked.

## How the CVE lookup works

For each versioned component, fwtool builds a CPE name
(Common Platform Enumeration — the standard way to name a software
product and version) and asks the public NVD API for CVEs recorded
against it. No account or key is needed. Without a key the NVD
allows 5 requests per 30 seconds, so the tool waits about 6
seconds between lookups; with a key (`NVD_API_KEY` environment
variable or `--api-key`) the limit is 50 per 30 seconds and the
tool waits 0.6 seconds. Results are cached under
`~/.cache/fwtool/nvd/` for 7 days (`--cache-dir` changes the
location), so repeat scans make no network calls.

A CVE finding means NVD records that component version as
affected. It does not mean the vulnerable code is reachable in
this firmware — that takes manual review. The match basis on each
finding is there so you can check the claim yourself.

## How the pattern findings work

The tool matches anchored patterns against the image's printable
strings. The pattern set covers hardcoded passwords and
credentials, private keys, debug interfaces, weak crypto, insecure
protocols, disabled certificate checks, bad random-number
generation, backdoor markers, and sensitive file references. Each
finding has a severity (critical / high / medium / low) and a
plain-language recommendation.

Patterns are built to avoid the usual false positives:

- `/etc/passwd` lines (`root:x:0:0:...`) are not credentials.
- `chown root:root` is a user:group pair, not a credential.
- Format strings (`password: %s`), filler values (`<redacted>`),
  and code (`password:this.password`, `password:false`) are not
  credentials.
- A serial console (`console=ttyS0`) is flagged; the ordinary
  local console (`console=tty0`) is not.
- A private-key header with no key material after it is downgraded
  to medium and labelled — it is usually a header constant inside
  a crypto library. A header followed by base64 key material stays
  critical.

Identical matches are reported once, with an occurrence count.

## The SBOM, honestly scoped

The SBOM lists the components the tool fingerprinted. It is
**component-fingerprint-based**: v1 does not extract filesystems,
so components that leave no version banner and no dynamic-library
trace are not listed. The SBOM is not a full inventory of an
extracted filesystem, and every SBOM document says so in its own
text. Use it as a starting inventory and a CRA-evidence input, not
as a complete bill of materials. Filesystem extraction is planned
as a later phase.

Both SBOM formats validate against their official JSON Schemas
(CycloneDX 1.6, SPDX 2.3).

## What v1 cannot do

- Extract filesystems (SquashFS, JFFS2, UBI, gzip/xz containers).
  These are identified, not unpacked.
- See inside compressed parts of an image. If a component's
  strings are compressed, the tool cannot see them. (The demo
  scan in `docs/demo/` shows this honestly: the kernel, Dropbear,
  and dnsmasq versions are not reported because they are not
  visible in the raw image.)
- Run or emulate the firmware, or prove a finding is reachable.
- Fingerprint a component whose version banner is built at
  runtime from separate strings (for example, some daemons print
  their name and version from different string constants).

## Troubleshooting

- **`error: no such file`** — the input path is wrong, or the file
  is a directory. Exit code 2.
- **CVE lookup errors in the report** — usually no network, or the
  NVD rate limit. Wait a minute and re-run (cached results are
  reused); for frequent scanning, set `NVD_API_KEY`.
- **No components found** — the image may be compressed throughout
  (see "What v1 cannot do"), or it may genuinely contain no
  fingerprinted component. Check the strings count: a healthy
  firmware image has thousands of strings; a fully compressed one
  has very few readable ones.
- **The macOS download will not run on an Intel Mac** — the macOS
  build is Apple Silicon only. Run from source with Python 3.11+.
