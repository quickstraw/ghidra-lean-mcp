"""Generate a minimal ARM64 (little-endian) ELF ET_EXEC with two symbols.

`start` returns 0 (movz w0,#0; ret); `add2` adds two args (add w0,w0,w1; ret).
Full section headers (.text, .shstrtab, .symtab, .strtab) so Ghidra's ELF
loader imports it AND analysis discovers functions. No toolchain needed.
"""

from __future__ import annotations

import struct
from pathlib import Path

TEXT = b"\x00\x00\x80\x52\xc0\x03\x5f\xd6"  # start: movz w0,#0 ; ret
TEXT += b"\x00\x00\x00\x00\x20\x01\x00\x00\xc0\x03\x5f\xd6"  # add2: add w0,w0,w1 ; ret

SHSTRTAB = b"\x00.text\x00.shstrtab\x00.symtab\x00.strtab\x00"
STRTAB = b"\x00start\x00add2\x00"


def build_elf(text: bytes = TEXT) -> bytes:
    text_off = 64 + 56
    text = _pad8(text)
    shstr_off = text_off + len(text)
    shstrtab = _pad8(SHSTRTAB)
    sym_count = 2  # STB_GLOBAL symbols, Ndx=1 (.text)
    symsize = 24
    sym_off = shstr_off + len(shstrtab)
    symtab = sym_off
    strtab_off = sym_off + sym_count * symsize
    strtab = _pad8(STRTAB)
    shoff = strtab_off + len(strtab)
    num_sh = 5
    total = shoff + num_sh * 64
    _ = total

    eh = bytearray(64)
    eh[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    struct.pack_into("<H", eh, 16, 2)  # ET_EXEC
    struct.pack_into("<H", eh, 18, 0xB7)  # AArch64
    struct.pack_into("<I", eh, 20, 1)  # v1
    struct.pack_into("<Q", eh, 32, 0x1000)  # entry
    struct.pack_into("<Q", eh, 40, 0x40)  # phoff
    struct.pack_into("<Q", eh, 48, shoff)  # shoff
    struct.pack_into("<H", eh, 52, 64)  # e_ehsize
    struct.pack_into("<H", eh, 54, 56)  # e_phentsize
    struct.pack_into("<H", eh, 56, 1)  # e_phnum
    struct.pack_into("<H", eh, 58, 64)  # e_shentsize
    struct.pack_into("<H", eh, 60, num_sh)  # e_shnum
    struct.pack_into("<H", eh, 62, 2)  # e_shstrndx

    ph = bytearray(56)
    struct.pack_into("<I", ph, 0, 1)  # PT_LOAD
    struct.pack_into("<Q", ph, 8, text_off)  # offset
    struct.pack_into("<Q", ph, 16, 0x1000)  # vaddr
    struct.pack_into("<Q", ph, 24, 0x1000)  # paddr
    struct.pack_into("<Q", ph, 32, len(text))  # filesz
    struct.pack_into("<Q", ph, 40, len(text))  # memsz
    struct.pack_into("<Q", ph, 48, 8)  # align: p_offset ≡ p_vaddr (mod align)
    struct.pack_into("<I", ph, 4, 0x6)  # PF_R + PF_W

    def sh(
        name: int,
        typ: int,
        flags: int,
        addr: int,
        off: int,
        size: int,
        link: int = 0,
        align: int = 1,
    ):
        b = bytearray(64)
        struct.pack_into("<I", b, 0, name)
        struct.pack_into("<I", b, 4, typ)
        struct.pack_into("<Q", b, 8, flags)
        struct.pack_into("<Q", b, 16, addr)
        struct.pack_into("<Q", b, 24, off)
        struct.pack_into("<Q", b, 32, size)
        struct.pack_into("<I", b, 40, link)
        struct.pack_into("<Q", b, 56, align)
        return bytes(b)

    def sym(name: int, info: int, shndx: int, value: int, size: int):
        b = bytearray(24)
        struct.pack_into("<I", b, 0, name)
        struct.pack_into("<B", b, 4, info)
        struct.pack_into("<H", b, 6, shndx)
        struct.pack_into("<Q", b, 8, value)
        struct.pack_into("<Q", b, 16, size)
        return bytes(b)

    syms = b""
    syms += sym(1, 0x12, 1, 0x1000, 8)  # start: GLOBAL FUNC, .text
    syms += sym(7, 0x12, 1, 0x1004, 8)  # add2: GLOBAL FUNC, .text

    shs = b""
    shs += sh(0, 0, 0, 0, 0, 0)  # NULL
    shs += sh(1, 1, 0x6, 0x1000, text_off, len(text), align=8)  # .text
    shs += sh(7, 3, 0, 0, shstr_off, len(shstrtab))  # .shstrtab
    shs += sh(16, 2, 0, 0, symtab, len(syms), link=4, align=8)  # .symtab
    shs += sh(25, 3, 0, 0, strtab_off, len(strtab))  # .strtab

    return bytes(eh) + bytes(ph) + text + shstrtab + syms + strtab + shs


def _pad8(data: bytes) -> bytes:
    if len(data) % 8:
        data += b"\x00" * (8 - len(data) % 8)
    return data


def write_fixture(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_elf())
    return path
