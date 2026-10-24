import struct

SHN_UNDEF_LIMIT = 0xff00


def _shstrtab(data, sh_off, sh_entsize, sh_num, sh_strndx, is64=True):
    """Return the section-header string table, or b'' if unavailable."""
    if sh_strndx >= sh_num:
        return b""
    off = sh_off + sh_strndx * sh_entsize
    if is64:
        str_offset, str_size = struct.unpack_from("<QQ", data, off + 0x18)
    else:
        str_offset, str_size = struct.unpack_from("<II", data, off + 0x10)
    if str_offset + str_size > len(data):
        return b""
    return data[str_offset:str_offset + str_size]


def _name_at(table, name_offset):
    end = table.find(b"\0", name_offset)
    if end < 0:
        return table[name_offset:].decode("ascii", "replace")
    return table[name_offset:end].decode("ascii", "replace")


def elf_sections(path):
    """List ELF section headers with resolved names.

    Returns None if the file is not an ELF, otherwise one dict per
    section. Supports both 64-bit and 32-bit ELF files.
    """
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        return None
    if data[4] not in (1, 2):           # ELFCLASS32 or ELFCLASS64 only
        return []

    is64 = data[4] == 2
    if is64:
        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        shdr_size = 0x40
    else:
        e_shoff, = struct.unpack_from("<I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x2E)
        shdr_size = 0x28
    if e_shnum == 0 or e_shentsize == 0:
        return []
    if e_shnum >= SHN_UNDEF_LIMIT:      # extended section numbering: unsupported
        return []

    table = _shstrtab(data, e_shoff, e_shentsize, e_shnum, e_shstrndx, is64)
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + shdr_size > len(data):
            break
        if is64:
            name_off, sh_type, sh_flags = struct.unpack_from("<IIQ", data, off)
            sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, off + 0x10)
        else:
            name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                struct.unpack_from("<IIIIII", data, off)
        out.append({
            "index": i,
            "name": _name_at(table, name_off) if table else None,
            "type": sh_type,
            "flags": sh_flags,
            "addr": sh_addr,
            "size": sh_size,
            "file_offset": sh_offset,
        })
    return out
