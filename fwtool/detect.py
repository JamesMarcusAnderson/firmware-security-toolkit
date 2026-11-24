import struct

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
    (b"hsqs",                  "SquashFS"),
    (b"\x85\x19",              "JFFS2"),
    (b"\x45\x3d\xcd\x28",      "CramFS"),
    (b"HDR0",                  "TRX"),
    (b"\xd0\x0d\xfe\xed",      "FIT image / device tree"),
    (b"MZ",                    "PE executable"),
    (b"PK\x03\x04",            "ZIP"),
    (b"7z\xbc\xaf\x27\x1c",    "7-Zip"),
    (b"\x28\xb5\x2f\xfd",      "Zstandard"),
    (b"\x5d\x00\x00",          "LZMA"),
    (b"\xfe\xed\xfa\xce",      "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf",      "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe",      "Mach-O 32-bit (reverse)"),
    (b"\xcf\xfa\xed\xfe",      "Mach-O 64-bit (reverse)"),
    (b"\xca\xfe\xba\xbe",      "Mach-O universal"),
    (b"QFI\xfb",               "QCOW"),
]

CHIP_MARKERS = [
    (b"ESP32",   "Espressif ESP32"),
    (b"ESP8266", "Espressif ESP8266"),
    (b"RP2040",  "Raspberry Pi RP2040"),
    (b"RP2350",  "Raspberry Pi RP2350"),
    (b"STM32",   "ST STM32"),
    (b"STM8",    "ST STM8"),
    (b"BCM",     "Broadcom BCM"),
    (b"Qualcomm", "Qualcomm"),
    (b"MTK",     "MediaTek"),
    (b"nRF52",   "Nordic nRF52"),
    (b"nRF53",   "Nordic nRF53"),
    (b"nRF91",   "Nordic nRF91"),
    (b"Nordic",  "Nordic Semiconductor"),
    (b"CC253",   "TI CC253x"),
    (b"CC265",   "TI CC265x"),
    (b"MSP430",  "TI MSP430"),
    (b"PIC32",   "Microchip PIC32"),
    (b"ATSAM",   "Microchip SAM"),
    (b"ATmega",  "Microchip ATmega"),
    (b"ATtiny",  "Microchip ATtiny"),
    (b"Microchip", "Microchip"),
    (b"LPC55",   "NXP LPC55"),
    (b"Kinetis", "NXP Kinetis"),
    (b"i.MX",    "NXP i.MX"),
    (b"NXP",     "NXP"),
    (b"Allwinner", "Allwinner"),
    (b"Rockchip", "Rockchip"),
    (b"Amlogic", "Amlogic"),
    (b"Realtek", "Realtek"),
    (b"Atheros", "Qualcomm Atheros"),
    (b"Marvell", "Marvell"),
    (b"Infineon", "Infineon"),
    (b"Renesas", "Renesas"),
    (b"Silicon Labs", "Silicon Labs"),
    (b"Cypress", "Cypress/Infineon"),
    (b"Beken",   "Beken"),
    (b"Bouffalo", "Bouffalo Lab"),
    (b"BL602",   "Bouffalo BL602"),
    (b"Telink",  "Telink"),
    (b"GD32",    "GigaDevice GD32"),
    (b"CH32",    "WCH CH32"),
    (b"HiSilicon", "HiSilicon"),
    (b"Unisoc",  "Unisoc"),
    (b"Spreadtrum", "Spreadtrum/Unisoc"),
    (b"SAMD",    "Microchip SAM D"),
    (b"Cortex-M", "ARM Cortex-M"),
    (b"Cortex-A", "ARM Cortex-A"),
    (b"RISC-V",  "RISC-V"),
    (b"MIPS32",  "MIPS32"),
]

# ELF e_machine values (from the ELF specification).
ELF_MACHINES = {
    3: "x86 (32-bit)",
    62: "x86-64",
    40: "ARM",
    183: "AArch64",
    8: "MIPS",
    243: "RISC-V",
    20: "PowerPC",
    21: "PowerPC64",
    50: "IA-64",
    75: "VAX",
    2: "SPARC",
    43: "SPARC V9",
    165: "ARC",
    140: "Tensilica Xtensa",
    164: "Qualcomm Hexagon",
    0: "none",
}

# How far into the image chip markers are searched. Reported in the output so a
# negative result is never mistaken for a whole-file scan.
MARKER_SCAN_BYTES = 64 * 1024


def elf_architecture(head):
    """Return the CPU architecture of an ELF file, or None.

    head is the first bytes of the file. Returns None for non-ELF data
    or a header too short to read.
    """
    if head[:4] != b"\x7fELF" or len(head) < 20:
        return None
    if head[5] not in (1, 2):                    # EI_DATA: LE or BE
        return None
    order = "<" if head[5] == 1 else ">"
    machine, = struct.unpack_from(order + "H", head, 18)
    if machine in ELF_MACHINES:
        return ELF_MACHINES[machine]
    return "e_machine %d" % machine


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
    info = {
        "format": fmt,
        "chip_markers": chips,
        "size": file_size,
        "marker_scan_bytes": min(MARKER_SCAN_BYTES, file_size),
    }
    arch = elf_architecture(head)
    if arch:
        info["architecture"] = arch
    return info
