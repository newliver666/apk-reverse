#!/usr/bin/env python3
"""PLT stub -> imported symbol mapping, and byte-level .so diffing.

Built for hardened/rebuilt native libraries where the usual paths lie:
  * section headers are often forged, so tools that walk sections (readelf -x,
    objdump -d on named sections, pyelftools' section API) return confidently
    wrong or empty results;
  * a linear disassembler can stop silently on a buffer that does not start at
    an instruction boundary, so "no matches" from it is not evidence.

Therefore this tool walks PT_LOAD / PT_DYNAMIC by hand and decodes the two
stub shapes with its own decoders (no capstone dependency, no silent stops).

Why you need the stub -> symbol map: when a hardening library terminates the
process, it does so through a PLT stub. To suppress it safely you must know
*which* symbol a given stub resolves to -- inferring from position or from a
comment is how you end up freezing `snprintf` or `pthread_exit` and reporting
it as "the patch did not work".

Usage
-----
  # full stub table
  python elf_plt.py libfoo.so

  # what do these stubs call?
  python elf_plt.py libfoo.so --query 0x9920 0x9950

  # find the stub for one symbol (and every caller of it)
  python elf_plt.py libfoo.so --symbol kill --callers

  # what changed between the original and a rebuilt library?
  python elf_plt.py original.so --diff rebuilt.so

  # same, but also name the symbol each changed stub belongs to
  python elf_plt.py original.so --diff rebuilt.so --name-regions
"""

import argparse
import hashlib
import struct
import sys

PT_LOAD = 1
PT_DYNAMIC = 2

DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_STRSZ = 10
DT_SYMENT = 11
DT_PLTREL = 20
DT_JMPREL = 23

EM_X86_64 = 62
EM_AARCH64 = 183

ARCH_NAME = {EM_X86_64: "x86_64", EM_AARCH64: "aarch64"}


# --------------------------------------------------------------------------
# ELF parsing (program headers only -- never trust the section table here)
# --------------------------------------------------------------------------

class Elf:
    def __init__(self, data, path=""):
        self.data = data
        self.path = path
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] != 2:
            raise ValueError("only 64-bit ELF is supported")
        self.machine = struct.unpack_from("<H", data, 18)[0]
        self.phoff = struct.unpack_from("<Q", data, 32)[0]
        self.phentsize = struct.unpack_from("<H", data, 54)[0]
        self.phnum = struct.unpack_from("<H", data, 56)[0]
        self.loads = []          # (vaddr, offset, filesz, memsz, flags)
        self.dynamic = None      # (offset, size)
        self.gnu_eh_frame = None
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            p_type, p_flags = struct.unpack_from("<II", data, off)
            p_offset, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack_from(
                "<QQQQQQ", data, off + 8)
            if p_type == PT_LOAD:
                self.loads.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
            elif p_type == PT_DYNAMIC:
                self.dynamic = (p_offset, p_filesz)
            elif p_type == 0x6474e550:
                self.gnu_eh_frame = (p_vaddr, p_filesz)

    @property
    def arch(self):
        return ARCH_NAME.get(self.machine, "machine=%d" % self.machine)

    def exec_segment(self):
        for seg in self.loads:
            if seg[4] & 1:
                return seg
        raise ValueError("no executable PT_LOAD segment")

    def vaddr_to_off(self, vaddr):
        for va, fo, _fs, ms, _fl in self.loads:
            if va <= vaddr < va + ms:
                return fo + (vaddr - va)
        return None

    def dynamic_tags(self):
        if self.dynamic is None:
            raise ValueError("no PT_DYNAMIC segment")
        tags = {}
        off, size = self.dynamic
        for j in range(size // 16):
            t, v = struct.unpack_from("<qQ", self.data, off + j * 16)
            if t == 0:
                break
            tags[t] = v
        return tags


def reloc_map(elf):
    """{GOT vaddr: imported symbol name} from DT_JMPREL (+ DT_RELA when present)."""
    tags = elf.dynamic_tags()
    if DT_STRTAB not in tags or DT_SYMTAB not in tags:
        return {}
    strtab_o = elf.vaddr_to_off(tags[DT_STRTAB])
    symtab_o = elf.vaddr_to_off(tags[DT_SYMTAB])
    strsz = tags.get(DT_STRSZ, 0)
    if strtab_o is None or symtab_o is None:
        return {}

    def symname(idx):
        so = symtab_o + idx * 24
        if so + 4 > len(elf.data):
            return "?"
        (st_name,) = struct.unpack_from("<I", elf.data, so)
        if st_name >= strsz:
            return "?"
        start = strtab_o + st_name
        end = elf.data.find(b"\x00", start)
        if end < 0:
            return "?"
        return elf.data[start:end].decode("utf-8", "replace")

    out = {}
    for tag_off, tag_sz in ((DT_JMPREL, DT_PLTRELSZ), (DT_RELA, DT_RELASZ)):
        if tag_off not in tags:
            continue
        base = elf.vaddr_to_off(tags[tag_off])
        if base is None:
            continue
        n = tags.get(tag_sz, 0) // 24
        for k in range(n):
            if base + k * 24 + 16 > len(elf.data):
                break
            r_offset, r_info = struct.unpack_from("<QQ", elf.data, base + k * 24)
            out[r_offset] = symname(r_info >> 32)
    return out


# --------------------------------------------------------------------------
# Stub decoders -- written out rather than delegated, so nothing stops early
# --------------------------------------------------------------------------

def find_stubs(elf, relocs):
    """{stub_vaddr: (symbol, got_vaddr)} for the library's stub table."""
    base, foff, fsz, _ms, _fl = elf.exec_segment()
    if elf.machine == EM_X86_64:
        return _stubs_x86(elf.data, base, foff, fsz, relocs)
    if elf.machine == EM_AARCH64:
        return _stubs_arm64(elf.data, base, foff, fsz, relocs)
    return {}


def _stubs_x86(data, base, foff, fsz, relocs):
    """x86_64 PLT stub: `ff 25 <disp32>` == jmp qword ptr [rip+disp32]."""
    out = {}
    i = 0
    while i < fsz - 6:
        if data[foff + i] == 0xFF and data[foff + i + 1] == 0x25:
            disp = struct.unpack_from("<i", data, foff + i + 2)[0]
            va = base + i
            target = va + 6 + disp
            if target in relocs:
                out[va] = (relocs[target], target)
        i += 1
    return out


def _stubs_arm64(data, base, foff, fsz, relocs):
    """aarch64 PLT stub: adrp x16 / ldr x17,[x16,#off] / add x16,x16,#off / br x17.

    Note the stub is FOUR instructions (16 bytes), not four bytes. Assuming the
    shorter form leads to "borrowing" the next slot, which belongs to a
    different symbol.
    """
    out = {}
    off = 0
    while off < fsz - 16:
        w0, w1, w2, w3 = struct.unpack_from("<IIII", data, foff + off)
        dec = _decode_adrp(w0, base + off)
        if dec is not None:
            page, rd0 = dec
            ldr = _decode_ldr_unsigned(w1)
            add = _decode_add_imm(w2)
            br = _decode_br(w3)
            if (ldr is not None and add is not None and br is not None
                    and rd0 == 16 and ldr[0] == 16 and ldr[1] == 17
                    and add[0] == 16 and add[1] == 16
                    and ldr[2] == add[2] and br == 17):
                got = page + add[2]
                if got in relocs:
                    out[base + off] = (relocs[got], got)
        off += 4
    return out


def _sign_extend(value, bits):
    if value & (1 << (bits - 1)):
        value -= (1 << bits)
    return value


def _decode_adrp(word, pc):
    """adrp Rd, #imm  ->  (target_page, Rd).  None if not an adrp."""
    if (word >> 31) & 1 != 1:
        return None
    if ((word >> 24) & 0x1F) != 0x10:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    imm = _sign_extend(imm, 21)
    return (pc & ~0xFFF) + (imm << 12), (word & 0x1F)


def _decode_ldr_unsigned(word):
    """ldr Rt, [Rn, #imm] (64-bit unsigned offset) -> (Rn, Rt, byte_offset)."""
    if (word >> 30) != 0b11:          # size == 64-bit
        return None
    if ((word >> 27) & 0x7) != 0b111:
        return None
    if ((word >> 24) & 0x3) != 0b01:
        return None
    imm12 = (word >> 10) & 0xFFF
    rn = (word >> 5) & 0x1F
    rt = word & 0x1F
    return rn, rt, imm12 * 8


def _decode_add_imm(word):
    """add Rd, Rn, #imm -> (Rn, Rd, imm).

    Encoding: sf op S 100010 sh imm12 Rn Rd
      bits[31]=sf  bits[30]=op  bits[29]=S  bits[28:23]=100010 (6 bits, not 9)
    """
    if (word >> 31) & 1 != 1:            # sf must be 1 (64-bit form)
        return None
    if ((word >> 23) & 0x3F) != 0b100010:
        return None
    if (word >> 22) & 1:                 # shifted form -- not what stubs use
        return None
    imm12 = (word >> 10) & 0xFFF
    rn = (word >> 5) & 0x1F
    rd = word & 0x1F
    return rn, rd, imm12


def _decode_br(word):
    """br Rn -> Rn, or None."""
    if (word & 0xFFFFFC1F) == 0xD61F0000:
        return (word >> 5) & 0x1F
    return None


def find_branch_callers(elf, target_vaddr, limit=500):
    """Addresses of BL/B instructions that branch to target_vaddr."""
    base, foff, fsz, _ms, _fl = elf.exec_segment()
    hits = []
    if elf.machine == EM_AARCH64:
        off = 0
        while off < fsz - 4:
            (w,) = struct.unpack_from("<I", data_slice(elf.data, foff + off, 4))
            if (w & 0xFC000000) in (0x94000000, 0x14000000):   # BL / B
                imm = _sign_extend(w & 0x03FFFFFF, 26) << 2
                if base + off + imm == target_vaddr:
                    hits.append(base + off)
                    if len(hits) >= limit:
                        break
            off += 4
    elif elf.machine == EM_X86_64:
        i = 0
        while i < fsz - 5:
            if elf.data[foff + i] == 0xE8:
                disp = struct.unpack_from("<i", elf.data, foff + i + 1)[0]
                if base + i + 5 + disp == target_vaddr:
                    hits.append(base + i)
                    if len(hits) >= limit:
                        break
            i += 1
    return hits


def data_slice(data, off, n):
    return data[off:off + n]


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def load(path):
    with open(path, "rb") as fh:
        return Elf(fh.read(), path)


def cmd_list(elf, args):
    relocs = reloc_map(elf)
    stubs = find_stubs(elf, relocs)
    base, foff, fsz, _ms, _fl = elf.exec_segment()
    print("== %s" % elf.path)
    print("   arch=%s  exec seg: vaddr=0x%x file=0x%x size=0x%x" % (elf.arch, base, foff, fsz))
    print("   imported relocations=%d   stubs resolved=%d" % (len(relocs), len(stubs)))
    if not stubs:
        print("   NOTE: zero stubs resolved. Either the library has no PLT, or the")
        print("         hardening removed/forged the relocation tables. Do not read")
        print("         this as 'the library imports nothing'.")
    for va in sorted(stubs):
        sym, got = stubs[va]
        print("   0x%08x -> %-34s (GOT 0x%x)" % (va, sym, got))
    return stubs


def cmd_query(elf, args):
    relocs = reloc_map(elf)
    stubs = find_stubs(elf, relocs)
    for a in args.query:
        va = int(a, 0)
        hit = stubs.get(va)
        if hit:
            print("0x%x -> %s (GOT 0x%x)" % (va, hit[0], hit[1]))
        else:
            print("0x%x -> not a resolved stub" % va)


def cmd_symbol(elf, args):
    relocs = reloc_map(elf)
    stubs = find_stubs(elf, relocs)
    wanted = args.symbol
    found = [(va, sym, got) for va, (sym, got) in stubs.items() if sym == wanted]
    if not found:
        near = sorted({s for _v, (s, _g) in stubs.items()
                       if wanted in s or s in wanted})[:10]
        print("no stub resolves to %r" % wanted)
        if near:
            print("  similar: %s" % ", ".join(near))
        return
    for va, sym, got in sorted(found):
        print("stub 0x%x -> %s (GOT 0x%x)" % (va, sym, got))
        if args.callers:
            callers = find_branch_callers(elf, va)
            print("  callers of the stub: %d" % len(callers))
            for c in callers:
                print("    0x%x" % c)
            print("  NOTE: a stub-level patch covers all of these. A call-site-level")
            print("        patch must cover every one of them, plus any caller reached")
            print("        through a cached function pointer (not listed here).")


def cmd_diff(elf_a, args):
    path_b = args.diff
    elf_b = load(path_b)
    a, b = elf_a.data, elf_b.data
    print("== diff")
    print("   A %s  %d bytes  sha256=%s" % (elf_a.path, len(a), hashlib.sha256(a).hexdigest()[:16]))
    print("   B %s  %d bytes  sha256=%s" % (path_b, len(b), hashlib.sha256(b).hexdigest()[:16]))
    if len(a) != len(b):
        print("   SIZE DIFFERS: %d vs %d -- a length change is itself a finding"
              % (len(a), len(b)))
    n = min(len(a), len(b))
    runs = []
    i = 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            runs.append((i, j - i))
            i = j
        else:
            i += 1
    total = sum(r[1] for r in runs)
    print("   differing bytes=%d in %d run(s)" % (total, len(runs)))

    regions = {}
    if args.name_regions:
        relocs_a = reloc_map(elf_a)
        stubs_a = find_stubs(elf_a, relocs_a)

        def describe(off):
            for va, (sym, _got) in stubs_a.items():
                size = 16 if elf_a.machine == EM_AARCH64 else 16
                if va <= off < va + size:
                    return "PLT stub for %s" % sym
            return ""

        regions = {"describe": describe}

    for off, ln in runs:
        note = ""
        if regions:
            note = regions["describe"](off)
            if note:
                note = "   <- " + note
        print("   off=0x%06x len=%-4d A: %s" % (off, ln, a[off:off + ln].hex(" ")))
        print("   %s        B: %s%s" % (" " * 14, b[off:off + ln].hex(" "), note))
    if args.name_regions and not runs:
        print("   (identical)")


def main():
    ap = argparse.ArgumentParser(
        description="PLT stub -> symbol mapping and .so diffing for hardened libraries.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("so", help="path to the ELF (.so)")
    ap.add_argument("--query", nargs="+", metavar="ADDR",
                    help="resolve specific stub addresses (hex ok)")
    ap.add_argument("--symbol", metavar="NAME",
                    help="find the stub that resolves to this symbol")
    ap.add_argument("--callers", action="store_true",
                    help="with --symbol: also list branch call sites")
    ap.add_argument("--diff", metavar="OTHER_SO",
                    help="byte-compare against another library")
    ap.add_argument("--name-regions", action="store_true",
                    help="with --diff: name the symbol each changed stub belongs to")
    args = ap.parse_args()

    try:
        elf = load(args.so)
    except Exception as e:
        sys.exit("error: %s" % e)

    if args.diff:
        cmd_diff(elf, args)
    elif args.query:
        cmd_query(elf, args)
    elif args.symbol:
        cmd_symbol(elf, args)
    else:
        cmd_list(elf, args)


if __name__ == "__main__":
    main()
