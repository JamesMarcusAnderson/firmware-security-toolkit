"""Component and version fingerprinting from firmware images.

Two evidence sources, both readable without extracting any filesystem:

1. ELF dynamic-section entries (DT_NEEDED sonames, DT_SONAME) — the
   libraries a binary links against.
2. Version-banner strings in the image's printable strings — the
   "Name X.Y.Z" banners libraries and daemons print or embed.

Every fingerprint carries its evidence (the exact string or soname and
where it came from) so a reader can check it. A fingerprint without a
concrete release version is still recorded — it goes in the SBOM with
no version — but it is never sent to the CVE lookup, because a
versionless query would return every CVE ever filed against the
product. A soname version (libssl.so.1.1) is an API version, not a
release version, so it is recorded as evidence only, never as the
component's version.
"""
import re
import struct

# (name, part, vendor, product, [version patterns])
# part: "a" = application, "o" = operating system (CPE part field).
# Each pattern must capture the version in group 1; an optional group 2
# captures a CPE "update" suffix (e.g. OpenSSH 8.4p1 -> version 8.4,
# update p1; ntp 4.2.8p15 -> version 4.2.8, update p15).
COMPONENTS = [
    ("OpenSSL", "a", "openssl", "openssl",
     [r"OpenSSL (\d+\.\d+\.\d+[a-z]?)"]),
    ("BusyBox", "a", "busybox", "busybox",
     [r"BusyBox v(\d+\.\d+\.\d+)"]),
    ("Linux kernel", "o", "linux", "linux_kernel",
     [r"Linux version (\d+\.\d+\.\d+)"]),
    ("zlib", "a", "zlib", "zlib",
     [r"zlib (\d+\.\d+\.\d+)",
      r"libz\.so\.(\d+\.\d+\.\d+)"]),
    ("curl", "a", "haxx", "curl",
     [r"(?:lib)?curl[/ ](\d+\.\d+\.\d+)"]),
    ("Dropbear", "a", "dropbear", "dropbear",
     [r"Dropbear sshd v?(\d{4}\.\d+)"]),
    ("dnsmasq", "a", "dnsmasq", "dnsmasq",
     [r"dnsmasq[- ]v?(\d+\.\d+(?:\.\d+)?)"]),
    ("U-Boot", "a", "denx", "u-boot",
     [r"U-Boot (\d{4}\.\d+)"]),
    ("OpenSSH", "a", "openbsd", "openssh",
     [r"OpenSSH_(\d+\.\d+)p(\d+)"]),
    ("lighttpd", "a", "lighttpd", "lighttpd",
     [r"lighttpd/(\d+\.\d+\.\d+)"]),
    ("mbedTLS", "a", "arm", "mbed_tls",
     [r"mbed ?TLS (\d+\.\d+\.\d+)",
      r"libmbed(?:tls|crypto)\.so\.(\d+\.\d+\.\d+)"]),
    ("wolfSSL", "a", "wolfssl", "wolfssl",
     [r"wolfSSL (\d+\.\d+\.\d+)"]),
    ("glibc", "a", "gnu", "glibc",
     [r"GNU C Library.*release version (\d+\.\d+(?:\.\d+)?)",
      r"GLIBC_(\d+\.\d+)"]),
    ("uClibc", "a", "uclibc", "uclibc",
     [r"uClibc (\d+\.\d+\.\d+)"]),
    ("SQLite", "a", "sqlite", "sqlite",
     [r"SQLite (\d+\.\d+\.\d+)", r"sqlite3[-_](\d+\.\d+\.\d+)"]),
    ("expat", "a", "libexpat", "libexpat",
     [r"expat[/ _-](\d+\.\d+\.\d+)",
      r"libexpat\.so\.(\d+\.\d+\.\d+)"]),
    ("libxml2", "a", "xmlsoft", "libxml2",
     [r"libxml2[/ ](\d+\.\d+\.\d+)",
      r"libxml2\.so\.(\d+\.\d+\.\d+)"]),
    ("PCRE", "a", "pcre", "pcre",
     [r"PCRE version (\d+\.\d+(?:\.\d+)?)"]),
    ("PCRE2", "a", "pcre", "pcre2",
     [r"PCRE2[ /-](\d+\.\d+(?:\.\d+)?)"]),
    ("FreeRTOS", "o", "amazon", "freertos",
     [r"FreeRTOS [Vv]?(\d+\.\d+\.\d+)"]),
    ("wpa_supplicant", "a", "w1.fi", "wpa_supplicant",
     [r"wpa_supplicant v?(\d+\.\d+(?:\.\d+)?)"]),
    ("hostapd", "a", "w1.fi", "hostapd",
     [r"hostapd v?(\d+\.\d+(?:\.\d+)?)"]),
    ("Net-SNMP", "a", "net-snmp", "net-snmp",
     [r"NET-SNMP version: (\d+\.\d+\.\d+)"]),
    ("Samba", "a", "samba", "samba",
     [r"Samba version (\d+\.\d+\.\d+)"]),
    ("vsftpd", "a", "vsftpd", "vsftpd",
     [r"vsftpd (\d+\.\d+\.\d+)"]),
    ("ProFTPD", "a", "proftpd", "proftpd",
     [r"ProFTPD (\d+\.\d+\.\d+[a-z]?)"]),
    ("Apache HTTP Server", "a", "apache", "http_server",
     [r"Apache/(\d+\.\d+\.\d+)"]),
    ("nginx", "a", "nginx", "nginx",
     [r"nginx/(\d+\.\d+\.\d+)"]),
    ("PHP", "a", "php", "php",
     [r"PHP (\d+\.\d+\.\d+)"]),
    ("Python", "a", "python", "python",
     [r"Python (\d+\.\d+\.\d+)"]),
    ("Lua", "a", "lua", "lua",
     [r"Lua (\d+\.\d+\.\d+)"]),
    ("iptables", "a", "netfilter", "iptables",
     [r"iptables v(\d+\.\d+\.\d+)"]),
    ("bzip2", "a", "bzip", "bzip2",
     [r"bzip2.*Version (\d+\.\d+\.\d+)"]),
    ("xz", "a", "tukaani", "xz",
     [r"XZ Utils\) (\d+\.\d+\.\d+)"]),
    ("GoAhead", "a", "embedthis", "goahead",
     [r"GoAhead[/ ](\d+\.\d+\.\d+)"]),
    ("Boa", "a", "boa", "boa_webserver",
     [r"Boa/(\d+\.\d+\.\d+)"]),
    ("mini_httpd", "a", "acme", "mini_httpd",
     [r"mini_httpd/(\d+\.\d+)"]),
    ("NTP", "a", "ntp", "ntp",
     [r"ntpd (\d+\.\d+\.\d+)p(\d+)"]),
    ("Mosquitto", "a", "eclipse", "mosquitto",
     [r"mosquitto version (\d+\.\d+\.\d+)"]),
    ("OpenVPN", "a", "openvpn", "openvpn",
     [r"OpenVPN (\d+\.\d+\.\d+)"]),
    ("strongSwan", "a", "strongswan", "strongswan",
     [r"strongSwan (\d+\.\d+\.\d+)"]),
    ("libevent", "a", "libevent", "libevent",
     [r"libevent[- ](\d+\.\d+\.\d+)"]),
    ("libpcap", "a", "tcpdump", "libpcap",
     [r"libpcap version (\d+\.\d+\.\d+)",
      r"libpcap\.so\.(\d+\.\d+\.\d+)"]),
    ("tcpdump", "a", "tcpdump", "tcpdump",
     [r"tcpdump version (\d+\.\d+\.\d+)"]),
]

# DT_NEEDED soname -> component name. The soname proves the library is
# linked; it does not prove a release version.
SONAME_MAP = {
    "libssl.so": "OpenSSL",
    "libcrypto.so": "OpenSSL",
    "libcurl.so": "curl",
    "libz.so": "zlib",
    "libpcre.so": "PCRE",
    "libpcre2-8.so": "PCRE2",
    "libsqlite3.so": "SQLite",
    "libexpat.so": "expat",
    "libxml2.so": "libxml2",
    "libmbedtls.so": "mbedTLS",
    "libmbedcrypto.so": "mbedTLS",
    "libwolfssl.so": "wolfSSL",
    "libc.so": "glibc",
    "libevent.so": "libevent",
    "libpcap.so": "libpcap",
    "libmosquitto.so": "Mosquitto",
    "liblua.so": "Lua",
    "libpython": "Python",
}

_BY_NAME = {name: (part, vendor, product) for name, part, vendor, product, _ in COMPONENTS}
_PATTERNS = [(name, re.compile(p)) for name, _, _, _, pats in COMPONENTS for p in pats]


def _cpe_escape(value):
    """Escape a CPE 2.3 formatted-string field (minimal, per the spec)."""
    return value.replace("\\", "\\\\").replace(":", "\\:").replace(" ", "_")


def cpe_name(component):
    """Build the CPE 2.3 name for a versioned fingerprint, or None.

    component is a fingerprint dict with keys name, version, and
    optionally update.
    """
    name = component["name"]
    version = component.get("version")
    if name not in _BY_NAME or not version:
        return None
    part, vendor, product = _BY_NAME[name]
    update = component.get("update") or "*"
    # 13 fields: cpe, 2.3, part, vendor, product, version, update,
    # edition, language, sw_edition, target_sw, target_hw, other.
    fields = ["cpe", "2.3", part, _cpe_escape(vendor), _cpe_escape(product),
              _cpe_escape(version), _cpe_escape(update),
              "*", "*", "*", "*", "*", "*"]
    return ":".join(fields)


def _parse_elf_dynamic(data):
    """Return DT_NEEDED / DT_SONAME strings from an ELF file's bytes.

    Reads PT_DYNAMIC via the program headers; falls back to the
    .dynamic section if there are no program headers. Returns [] for
    non-ELF data or files with no dynamic section.
    """
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return []
    if data[4] not in (1, 2) or data[5] not in (1, 2):
        return []
    is64 = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    try:
        if is64:
            e_phoff, = struct.unpack_from(order + "Q", data, 0x20)
            e_shoff, = struct.unpack_from(order + "Q", data, 0x28)
            e_phentsize, e_phnum = struct.unpack_from(order + "HH", data, 0x36)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(order + "HHH", data, 0x3A)
        else:
            e_phoff, = struct.unpack_from(order + "I", data, 0x1C)
            e_shoff, = struct.unpack_from(order + "I", data, 0x20)
            e_phentsize, e_phnum = struct.unpack_from(order + "HH", data, 0x2A)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(order + "HHH", data, 0x2E)
    except struct.error:
        return []

    def vaddr_to_offset(vaddr):
        """Map a virtual address to a file offset via PT_LOAD segments."""
        phdr_size = 56 if is64 else 32
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + phdr_size > len(data):
                break
            if is64:
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
                    order + "IIQQQQ", data, off)
            else:
                p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
                    order + "IIIII", data, off)
            if p_type != 1:                      # PT_LOAD
                continue
            if p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        return None

    dyn_off = None
    dyn_size = None
    phdr_size = 56 if is64 else 32
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + phdr_size > len(data):
            break
        p_type, = struct.unpack_from(order + "I", data, off)
        if p_type != 2:                          # PT_DYNAMIC
            continue
        if is64:
            _, _, p_offset, _, _, p_filesz = struct.unpack_from(order + "IIQQQQ", data, off)
        else:
            _, p_offset, _, _, p_filesz = struct.unpack_from(order + "IIIII", data, off)
        dyn_off, dyn_size = p_offset, p_filesz
        break

    if dyn_off is None:
        # Fallback: find the .dynamic section by name.
        shdr_size = 64 if is64 else 40
        if e_shnum and e_shnum < 0xFF00 and e_shstrndx < e_shnum:
            str_off = e_shoff + e_shstrndx * e_shentsize
            try:
                if is64:
                    s_off, s_size = struct.unpack_from(order + "QQ", data, str_off + 0x18)
                else:
                    s_off, s_size = struct.unpack_from(order + "II", data, str_off + 0x10)
                table = data[s_off:s_off + s_size]
            except struct.error:
                table = b""
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                if off + shdr_size > len(data):
                    break
                name_off, sh_type = struct.unpack_from(order + "II", data, off)
                end = table.find(b"\0", name_off)
                name = table[name_off:end if end >= 0 else None].decode("ascii", "replace")
                if name == ".dynamic":
                    if is64:
                        dyn_off, dyn_size = struct.unpack_from(order + "QQ", data, off + 0x18)
                    else:
                        dyn_off, dyn_size = struct.unpack_from(order + "II", data, off + 0x10)
                    break
    if dyn_off is None or dyn_off + 8 > len(data):
        return []

    # Walk the dynamic entries: DT_NEEDED=1, DT_SONAME=14, DT_STRTAB=5,
    # DT_STRSZ=10, DT_NULL=0. Tag values are 8 bytes (64-bit) / 4 (32-bit).
    entry_size = 16 if is64 else 8
    needed, soname, strtab_v, strsz = [], None, None, None
    pos = dyn_off
    limit = dyn_off + (dyn_size or 0) if dyn_size else len(data)
    while pos + entry_size <= min(limit, len(data)):
        if is64:
            tag, val = struct.unpack_from(order + "qQ", data, pos)
        else:
            tag, val = struct.unpack_from(order + "iI", data, pos)
        pos += entry_size
        if tag == 0:
            break
        if tag == 1:
            needed.append(val)
        elif tag == 14:
            soname = val
        elif tag == 5:
            strtab_v = val
        elif tag == 10:
            strsz = val
    if strtab_v is None:
        return []
    strtab_off = vaddr_to_offset(strtab_v)
    if strtab_off is None:
        # .dynamic-section fallback: the string table usually follows the
        # dynamic section in the file; without program headers we cannot
        # resolve virtual addresses, so give up rather than guess.
        return []

    def dyn_str(index):
        if strsz is not None and index >= strsz:
            return None
        start = strtab_off + index
        end = data.find(b"\0", start, strtab_off + (strsz or len(data) - strtab_off))
        if end < 0:
            return None
        return data[start:end].decode("ascii", "replace")

    out = []
    for index in needed:
        s = dyn_str(index)
        if s:
            out.append(s)
    if soname is not None:
        s = dyn_str(soname)
        if s:
            out.append(s)
    return out


def _version_key(version):
    """Sortable key for dotted versions: '2.35' > '2.17' > '2.2.5'."""
    parts = []
    for piece in re.split(r"[.-]", version):
        if piece.isdigit():
            parts.append((1, int(piece), ""))
        else:
            digits = re.match(r"(\d+)(.*)", piece)
            if digits:
                parts.append((1, int(digits.group(1)), digits.group(2)))
            else:
                parts.append((0, 0, piece))
    return parts


def _soname_base(soname):
    """Strip the version suffix: libssl.so.1.1 -> libssl.so."""
    base = soname.split(".so", 1)[0] + ".so"
    return base


def fingerprint(path, found_strings):
    """Fingerprint components in a firmware image.

    path: the image file (read for ELF dynamic data).
    found_strings: the output of strings.extract(path).

    Returns a list of fingerprint dicts, sorted by name:
    {name, version, update, evidence, evidence_source, offset,
     sightings, cpe}
    """
    found = {}

    def record(name, version, update, evidence, source, offset):
        key = name
        entry = found.get(key)
        if entry is None:
            found[key] = {
                "name": name,
                "version": version,
                "update": update,
                "evidence": evidence,
                "evidence_source": source,
                "offset": offset,
                "sightings": 1,
            }
            return
        entry["sightings"] += 1
        # A banner version beats a soname (versionless) record.
        if entry["version"] is None and version is not None:
            entry.update({"version": version, "update": update,
                          "evidence": evidence, "evidence_source": source,
                          "offset": offset})

    # 1. ELF dynamic section: linked libraries (presence, no version).
    try:
        with open(path, "rb") as f:
            data = f.read()
        for soname in _parse_elf_dynamic(data):
            base = _soname_base(soname)
            name = SONAME_MAP.get(base)
            if name is None:
                # libpython3.10.so.1.0 style names: match by prefix.
                for prefix, mapped in SONAME_MAP.items():
                    if base.startswith(prefix):
                        name = mapped
                        break
            if name:
                record(name, None, None, soname, "elf-dynamic", None)
    except OSError:
        pass

    # 2. Version banners in the printable strings.
    glibc_symbol_max = None           # highest GLIBC_x.y symbol version seen
    for s in found_strings:
        text = s["string"]
        for name, pattern in _PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            if pattern.pattern.startswith("GLIBC_"):
                # Symbol versions sort lowest-first in a binary; only the
                # highest one says anything about the glibc it needs.
                ver = m.group(1)
                if glibc_symbol_max is None or _version_key(ver) > _version_key(glibc_symbol_max):
                    glibc_symbol_max = ver
                break
            version = m.group(1)
            update = None
            if len(m.groups()) > 1 and m.group(2):
                update = "p" + m.group(2)
            record(name, version, update, text, "version-string", s["offset"])
            break                                    # one component per string

    if glibc_symbol_max is not None:
        entry = found.get("glibc")
        if entry is None or entry["version"] is None:
            # No release banner found: the highest symbol version is the
            # best evidence available, and it is labelled as such.
            record("glibc", glibc_symbol_max, None,
                   "GLIBC_%s (highest symbol version found; minimum glibc "
                   "the binary was built against, not a release version)"
                   % glibc_symbol_max, "symbol-version", None)

    out = []
    for name in sorted(found):
        entry = found[name]
        entry["cpe"] = cpe_name(entry)
        out.append(entry)
    return out
