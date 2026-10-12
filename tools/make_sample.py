#!/usr/bin/env python3
"""Build a reproducible sample firmware image for demos and tests.

Usage:
    python tools/make_sample.py docs/sample.bin

The image is a plausible STM32 blob: a few marker strings, a hard-coded
credential, a private key header and a debug flag, padded with noise.
"""
import os
import sys

STRINGS = [
    b"STM32F407VG bootloader v1.3.2",
    b"admin:hunter2",
    b"password=Sup3rSecret!",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB",
    b"-----END RSA PRIVATE KEY-----",
    b"console_enable=1",
    b"debug_uart=/dev/ttyS0",
    b"srand(time(NULL)); return rand();",
    b"firmware update region @ 0x08010000",
    b"normal looking string with nothing to see",
]


def build():
    out = bytearray(b"\x00" * 256)              # vector table placeholder
    out[0:4] = b"\x2e\xa1\x0f\x20"              # plausible initial SP
    for s in STRINGS:
        out += b"\x00" * 32
        out += s + b"\x00"
    out += os.urandom(4096)                     # noise
    return bytes(out)


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <output.bin>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "wb") as f:
        f.write(build())
    print(f"wrote {sys.argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
