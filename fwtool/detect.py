MAGIC = [
    (b"\x7fELF",               "ELF"),
    (b"\x55\xAA",              "BIOS/UEFI"),
    (b"UBI#",                  "UBIFS"),
    (b"\x27\x05\x19\x56",      "uImage"),
    (b"ANDROID!",              "Android boot"),
    (b"\x1f\x8b\x08",          "gzip"),
    (b"\xFD7zXZ",              "xz"),
    (b"BZh",                   "bzip2"),
    (b"\x89PNG",               "PNG"),
    (b"\xFF\xD8\xFF",          "JPEG"),
]

CHIP_MARKERS = [
    (b"ESP32",   "Espressif ESP32"),
    (b"ESP8266", "Espressif ESP8266"),
    (b"RP2040",  "Raspberry Pi RP2040"),
    (b"STM32",   "ST STM32"),
    (b"BCM",     "Broadcom BCM"),
    (b"Qualcomm", "Qualcomm"),
    (b"MTK",     "MediaTek"),
]

# How far into the image chip markers are searched. Reported in the output so a
# negative result is never mistaken for a whole-file scan.
MARKER_SCAN_BYTES = 64 * 1024


def identify(path, head):
    """Identify container format from magic bytes and chip family from markers.

    Raises FileNotFoundError if path does not exist.
    """
    fmt = "raw"
    for magic, name in MAGIC:
        if head.startswith(magic):
            fmt = name
            break

    with open(path, "rb") as f:
        window = f.read(MARKER_SCAN_BYTES)
        f.seek(0, 2)
        file_size = f.tell()

    chips = [name for marker, name in CHIP_MARKERS if marker in window]
    return {
        "format": fmt,
        "chip_markers": chips,
        "size": file_size,
        "marker_scan_bytes": min(MARKER_SCAN_BYTES, file_size),
    }
