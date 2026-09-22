#!/usr/bin/env python3
"""java2c_probe.py - collect the evidence that decides HOW a target was hardened.

The question this answers is narrow on purpose. Faced with "the Java methods have
no bodies", four different mechanisms produce that observation and they need four
different routes:

  Java2C            Java bytecode translated to C, compiled into a .so. No dex
                    bytecode exists at runtime, ever. Route: read the .so.
  Extraction shell  Real dex bytecode, encrypted at rest, decrypted at runtime.
                    Route: dump memory, then validate the dump.
  VMP               Real dex bytecode replaced by private opcodes fed to an
                    interpreter. Route: measure, then usually stop.
  JNI sinking       A few hot methods deliberately moved to native by hand.
                    Route: reverse the .so; the dex is still readable.

The expensive mistake is reading the first shape as the second: the analyst goes
looking for a decrypted DEX that is never produced, because nothing was ever
encrypted. This script prints the discriminating evidence and labels each item
strong / medium / weak so the reading is not mistaken for a verdict.

Usage (paths are always explicit; nothing is discovered implicitly):

  python java2c_probe.py --apk sample.apk
  python java2c_probe.py --apk sample.apk --json
  python java2c_probe.py --dex classes.dex --so lib/arm64-v8a/libnc.so
  python java2c_probe.py --dir extracted/          # every *.dex and *.so below

Exit codes: 0 = evidence collected, 1 = no usable input, 2 = argument error.
"""

import argparse
import json
import os
import re
import struct
import sys
import zipfile

# ---------------------------------------------------------------------------
# dex parsing (self-contained; deliberately does not import the repo's dexutil)
# ---------------------------------------------------------------------------

ACC_NATIVE = 0x0100
ACC_ABSTRACT = 0x0400

# Instruction length in 16-bit code units, for the subset that a stub or a
# decompiled-from-C body produces. Unknown opcodes return 1 so a counting error
# can never inflate the trivial-body ratio; see the note on that metric below.
_INSN_UNITS = {
    0x00: 1, 0x01: 1, 0x02: 1, 0x03: 1, 0x04: 1, 0x05: 1, 0x06: 1, 0x07: 1,
    0x08: 1, 0x09: 1, 0x0a: 1, 0x0b: 1, 0x0c: 1, 0x0d: 1, 0x0e: 1, 0x0f: 1,
    0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3,
    0x18: 5, 0x19: 2, 0x1a: 2, 0x1b: 3, 0x1c: 2, 0x1d: 1, 0x1e: 1, 0x1f: 1,
    0x20: 1, 0x21: 1, 0x22: 1, 0x23: 1, 0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
    0x28: 1, 0x29: 1, 0x2a: 1, 0x2b: 1, 0x2c: 1, 0x2d: 1, 0x2e: 1, 0x2f: 1,
    0x30: 1, 0x31: 1, 0x32: 1, 0x33: 1, 0x34: 1, 0x35: 1, 0x36: 1, 0x37: 1,
    0x38: 1, 0x39: 1, 0x3a: 1, 0x3b: 1, 0x3c: 1, 0x3d: 1, 0x3e: 1, 0x3f: 1,
    0x40: 1, 0x41: 1, 0x42: 1, 0x43: 1, 0x44: 2, 0x45: 2, 0x46: 2, 0x47: 2,
    0x48: 2, 0x49: 2, 0x4a: 2, 0x4b: 2, 0x4c: 2, 0x4d: 2, 0x4e: 2, 0x4f: 2,
    0x50: 2, 0x51: 2, 0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2,
    0x58: 2, 0x59: 2, 0x5a: 2, 0x5b: 2, 0x5c: 2, 0x5d: 2, 0x5e: 2, 0x5f: 2,
    0x60: 2, 0x61: 2, 0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2, 0x66: 2, 0x67: 2,
    0x68: 2, 0x69: 2, 0x6a: 2, 0x6b: 2, 0x6c: 2, 0x6d: 2, 0x6e: 3, 0x6f: 3,
    0x70: 3, 0x71: 3, 0x72: 3, 0x73: 1, 0x74: 1, 0x75: 1, 0x76: 1, 0x77: 1,
    0x78: 2, 0x79: 2, 0x7a: 2, 0x7b: 2, 0x7c: 2, 0x7d: 2, 0x7e: 2, 0x7f: 2,
    0x80: 2, 0x81: 2, 0x82: 2, 0x83: 2, 0x84: 2, 0x85: 2, 0x86: 2, 0x87: 2,
    0x88: 2, 0x89: 2, 0x8a: 2, 0x8b: 2, 0x8c: 2, 0x8d: 2, 0x8e: 2, 0x8f: 2,
    0x90: 2, 0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2, 0x95: 2, 0x96: 2, 0x97: 2,
    0x98: 2, 0x99: 2, 0x9a: 2, 0x9b: 2, 0x9c: 2, 0x9d: 2, 0x9e: 2, 0x9f: 2,
    0xa0: 2, 0xa1: 2, 0xa2: 2, 0xa3: 2, 0xa4: 2, 0xa5: 2, 0xa6: 2, 0xa7: 2,
    0xa8: 2, 0xa9: 2, 0xaa: 2, 0xab: 2, 0xac: 2, 0xad: 2, 0xae: 2, 0xaf: 2,
    0xb0: 1, 0xb1: 1, 0xb2: 2, 0xb3: 2, 0xb4: 2, 0xb5: 2, 0xb6: 2, 0xb7: 2,
    0xb8: 2, 0xb9: 2, 0xba: 2, 0xbb: 2, 0xbc: 2, 0xbd: 2, 0xbe: 2, 0xbf: 2,
    0xc0: 2, 0xc1: 2, 0xc2: 2, 0xc3: 2, 0xc4: 2, 0xc5: 2, 0xc6: 2, 0xc7: 2,
    0xc8: 2, 0xc9: 2, 0xca: 2, 0xcb: 2, 0xcc: 2, 0xcd: 2, 0xce: 2, 0xcf: 2,
    0xd0: 2, 0xd1: 2, 0xd2: 2, 0xd3: 2, 0xd4: 2, 0xd5: 2, 0xd6: 2, 0xd7: 2,
    0xd8: 2, 0xd9: 2, 0xda: 2, 0xdb: 2, 0xdc: 2, 0xdd: 2, 0xde: 2, 0xdf: 2,
    0xe0: 2, 0xe1: 2, 0xe2: 2, 0xe3: 0, 0xe4: 0, 0xe5: 0, 0xe6: 0, 0xe7: 0,
    0xe8: 0, 0xe9: 0, 0xea: 0, 0xeb: 0, 0xec: 0, 0xed: 0, 0xee: 0, 0xef: 0,
    0xf0: 0, 0xf1: 0, 0xf2: 0, 0xf3: 0, 0xf4: 0, 0xf5: 0, 0xf6: 0, 0xf7: 0,
    0xf8: 0, 0xf9: 0, 0xfa: 0, 0xfb: 0, 0xfc: 0, 0xfd: 0, 0xfe: 0, 0xff: 0,
}

_RETURN_OPS = (0x0e, 0x0f, 0x10, 0x11)


def _uleb128(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("uleb128 truncated")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 too long")


class Dex(object):
    """Minimal structural reader: header, class_defs, class_data, code_item."""

    def __init__(self, data, name):
        self.data = data
        self.name = name
        self.header_ok = False
        self.header_note = ""
        self.methods = []          # dicts: class, name, flags, code_off, units
        self.class_names = []
        self.native_methods = 0
        self.abstract_methods = 0
        self.body_methods = 0
        self.no_code_methods = 0   # neither native nor abstract, yet code_off == 0
        self.trivial_bodies = 0
        self.native_with_code = 0
        self.fully_native_classes = 0
        self.native_dominated_classes = 0
        self.parse_error = None
        self._parse()

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _parse(self):
        d = self.data
        if len(d) < 112 or d[:4] != b"dex\n":
            self.parse_error = "not a dex image (bad magic or too short)"
            return
        try:
            file_size = self._u32(0x20)
            string_ids_size = self._u32(0x38)
            string_ids_off = self._u32(0x3C)
            type_ids_size = self._u32(0x40)
            type_ids_off = self._u32(0x44)
            method_ids_size = self._u32(0x58)
            method_ids_off = self._u32(0x5C)
            class_defs_size = self._u32(0x60)
            class_defs_off = self._u32(0x64)
        except Exception as exc:                      # pragma: no cover
            self.parse_error = "header read failed: %s" % exc
            return

        # Header claims vs. reality. A truncated or padded capture is the normal
        # way this probe is handed bad input, so say which one happened.
        if file_size != len(d):
            self.header_note = "header file_size=%d actual=%d" % (file_size, len(d))
        else:
            self.header_ok = True

        if not (0 < string_ids_size < 1 << 22 and string_ids_off + string_ids_size * 4 <= len(d)):
            self.parse_error = "string_ids table out of bounds"
            return

        string_offsets = [self._u32(string_ids_off + 4 * i) for i in range(string_ids_size)]

        def string_at(idx):
            if idx < 0 or idx >= len(string_offsets):
                return "<bad-string-idx-%d>" % idx
            off = string_offsets[idx]
            _, pos = _uleb128(d, off)          # utf16 length, ignored
            end = d.find(b"\x00", pos)
            if end < 0:
                return "<unterminated>"
            return d[pos:end].decode("utf-8", "replace")

        try:
            type_desc = [string_at(self._u32(type_ids_off + 4 * i))
                         for i in range(type_ids_size)]
        except Exception as exc:
            self.parse_error = "type_ids read failed: %s" % exc
            return

        try:
            if method_ids_off + method_ids_size * 8 > len(d):
                raise ValueError("method_ids out of bounds")
            method_info = []
            for i in range(method_ids_size):
                base = method_ids_off + 8 * i
                class_idx = self._u16(base)
                name_idx = self._u32(base + 4)
                desc = type_desc[class_idx] if class_idx < len(type_desc) else "?"
                method_info.append((desc, string_at(name_idx)))
        except Exception as exc:
            self.parse_error = "method_ids read failed: %s" % exc
            return

        if class_defs_off + class_defs_size * 32 > len(d):
            self.parse_error = "class_defs table out of bounds"
            return

        per_class_native = {}
        per_class_total = {}

        for ci in range(class_defs_size):
            base = class_defs_off + 32 * ci
            class_idx = self._u32(base)
            class_data_off = self._u32(base + 24)
            cname = type_desc[class_idx] if class_idx < len(type_desc) else "?%d" % class_idx
            self.class_names.append(cname)

            if class_data_off == 0:
                continue
            try:
                pos = class_data_off
                static_fields, pos = _uleb128(d, pos)
                instance_fields, pos = _uleb128(d, pos)
                direct_methods, pos = _uleb128(d, pos)
                virtual_methods, pos = _uleb128(d, pos)

                for _ in range(static_fields + instance_fields):
                    _, pos = _uleb128(d, pos)      # field_idx_diff
                    _, pos = _uleb128(d, pos)      # access_flags

                # direct_methods and virtual_methods are two independent encoded
                # lists: each one's first method_idx_diff is relative to 0. Walking
                # them as a single run silently mis-attributes every virtual
                # method, so they are decoded as two passes.
                for list_size in (direct_methods, virtual_methods):
                    method_idx = 0
                    for _ in range(list_size):
                        diff, pos = _uleb128(d, pos)
                        flags, pos = _uleb128(d, pos)
                        code_off, pos = _uleb128(d, pos)
                        method_idx += diff

                        if method_idx < len(method_info):
                            mcls, mname = method_info[method_idx]
                        else:
                            mcls, mname = "?", "?%d" % method_idx

                        units = None
                        if code_off:
                            units = self._u16(code_off + 12)   # insns_size

                        self.methods.append({
                            "class": mcls, "name": mname, "flags": flags,
                            "code_off": code_off, "units": units,
                        })
                        # Constructors are excluded from the per-class shape: a
                        # Java2C pass leaves <init>/<clinit> in Java in practice,
                        # and counting them would make "all methods native" an
                        # essentially unreachable test.
                        named = mname not in ("<init>", "<clinit>")
                        if named:
                            per_class_total[cname] = per_class_total.get(cname, 0) + 1

                        if flags & ACC_NATIVE:
                            self.native_methods += 1
                            if named:
                                per_class_native[cname] = per_class_native.get(cname, 0) + 1
                            if code_off:
                                self.native_with_code += 1
                        elif flags & ACC_ABSTRACT:
                            self.abstract_methods += 1
                        elif code_off == 0:
                            self.no_code_methods += 1
                        else:
                            self.body_methods += 1
                            if self._is_trivial(code_off, units):
                                self.trivial_bodies += 1
            except Exception:
                # One unreadable class_data must not void the whole measurement.
                continue

        for cname, total in per_class_total.items():
            if total < 3:
                continue
            native_here = per_class_native.get(cname, 0)
            if native_here == total:
                self.fully_native_classes += 1
            if native_here >= 0.7 * total:
                self.native_dominated_classes += 1

    def _is_trivial(self, code_off, units):
        """A body that only returns a constant: the classic stub shape.

        Approximation, and labelled as such: it walks the instruction stream with
        the length table above and accepts only nop/move/const/return. Anything
        that touches a field, calls out, or branches is not a stub.
        """
        if not units:
            return False
        insns_off = code_off + 16
        if insns_off + units * 2 > len(self.data):
            return False
        try:
            pos = 0
            seen = 0
            while pos < units and seen < 8:
                word = struct.unpack_from("<H", self.data, insns_off + pos * 2)[0]
                op = word & 0xFF
                if op in _RETURN_OPS:
                    return True if seen <= 2 else False
                if op == 0x00 or 0x01 <= op <= 0x09 or 0x12 <= op <= 0x19:
                    step = _INSN_UNITS.get(op, 1)
                    if step == 0:
                        return False
                    pos += step
                    seen += 1
                    continue
                return False
            return False
        except Exception:
            return False

    # -- derived metrics ---------------------------------------------------
    @property
    def total_methods(self):
        return len(self.methods)

    @property
    def native_ratio(self):
        return (float(self.native_methods) / self.total_methods) if self.total_methods else 0.0

    @property
    def trivial_ratio(self):
        return (float(self.trivial_bodies) / self.body_methods) if self.body_methods else 0.0

    def summary(self):
        return {
            "name": self.name,
            "size": len(self.data),
            "header_size_matches": self.header_ok,
            "header_note": self.header_note,
            "classes": len(self.class_names),
            "total_methods": self.total_methods,
            "native_methods": self.native_methods,
            "native_ratio": round(self.native_ratio, 4),
            "abstract_methods": self.abstract_methods,
            "body_methods": self.body_methods,
            "no_code_methods": self.no_code_methods,
            "native_with_code": self.native_with_code,
            "trivial_bodies": self.trivial_bodies,
            "trivial_ratio": round(self.trivial_ratio, 4),
            "fully_native_classes": self.fully_native_classes,
            "native_dominated_classes": self.native_dominated_classes,
            "bytes_per_class": int(len(self.data) / len(self.class_names)) if self.class_names else 0,
            "parse_error": self.parse_error,
        }


# ---------------------------------------------------------------------------
# ELF parsing (self-contained; no lief / pyelftools dependency)
# ---------------------------------------------------------------------------

# Each entry: (regex, label, strength, meaning). Strength is what stops a weak
# hit from being read as a verdict - see the printed weak-criteria block.
_STRINGSIGS = [
    (rb"Dex2C", "Dex2C", "strong", "dcc toolchain marker in code/rodata"),
    (rb"dynamic_register_compile_methods", "dcc-register-fn", "strong",
     "dcc's generated RegisterNatives entry point"),
    (rb"dcc", "dcc", "weak", "3 letters: matches unrelated words (e.g. 'addcc')"),
    (rb"JNI_OnLoad", "JNI_OnLoad", "weak", "present in almost every JNI library"),
    (rb"RegisterNatives", "RegisterNatives", "weak",
     "dynamic registration; ordinary JNI libraries use it too"),
    (rb"libc\+\+_shared\.so", "libc++_shared", "weak", "NDK C++ runtime, not a hardening marker"),
    (rb"c\+\+_static", "c++_static", "weak", "dcc's default APP_STL; also a common NDK setting"),
    (rb"FindClass", "FindClass", "weak", "any JNI callback path"),
    (rb"GetMethodID", "GetMethodID", "weak", "any JNI callback path"),
    (rb"GetStaticMethodID", "GetStaticMethodID", "weak", "any JNI callback path"),
    (rb"CallObjectMethod", "CallObjectMethod", "weak", "any JNI callback path"),
    (rb"CallStaticObjectMethod", "CallStaticObjectMethod", "weak", "any JNI callback path"),
    (rb"NewLocalRef", "NewLocalRef", "weak", "generated code that manages refs by hand"),
    (rb"ScopedLocalRef", "ScopedLocalRef", "medium", "dcc runtime header name"),
    (rb"well_known_classes", "well_known_classes", "medium", "dcc runtime header name"),
]

_JNI_CALLS = ("FindClass", "GetMethodID", "GetStaticMethodID", "CallObjectMethod",
              "CallStaticObjectMethod", "CallIntMethod", "CallVoidMethod",
              "CallStaticIntMethod", "NewObject", "GetFieldID")


class Elf(object):
    """Enough of ELF to answer: what is exported, what is imported, what is inside."""

    def __init__(self, data, name):
        self.data = data
        self.name = name
        self.arch = "unknown"
        self.is_elf = False
        self.dynsym = []          # (name, shndx)
        self.sig_hits = {}        # label -> (count, strength, meaning)
        self.java_symbols = []
        self.has_jni_onload = False
        self.imports_register_natives = False
        self.jni_call_refs = []
        self.elf_note = ""
        self._parse()

    def _parse(self):
        d = self.data
        if len(d) < 64 or d[:4] != b"\x7fELF":
            self.elf_note = "not an ELF image"
            return
        self.is_elf = True
        ei_class = d[4]
        ei_data = d[5]
        if ei_class not in (1, 2):
            self.elf_note = "bad EI_CLASS=%d" % ei_class
            return
        endian = "<" if ei_data == 1 else ">"
        is64 = ei_class == 2
        try:
            e_type = struct.unpack_from(endian + "H", d, 16)[0]
            e_machine = struct.unpack_from(endian + "H", d, 18)[0]
            if is64:
                e_shoff = struct.unpack_from(endian + "Q", d, 0x28)[0]
                e_shentsize = struct.unpack_from(endian + "H", d, 0x3A)[0]
                e_shnum = struct.unpack_from(endian + "H", d, 0x3C)[0]
                e_shstrndx = struct.unpack_from(endian + "H", d, 0x3E)[0]
            else:
                e_shoff = struct.unpack_from(endian + "I", d, 0x20)[0]
                e_shentsize = struct.unpack_from(endian + "H", d, 0x2E)[0]
                e_shnum = struct.unpack_from(endian + "H", d, 0x30)[0]
                e_shstrndx = struct.unpack_from(endian + "H", d, 0x32)[0]
        except struct.error as exc:
            self.elf_note = "header read failed: %s" % exc
            return

        self.arch = {
            3: "x86", 8: "mips", 20: "ppc", 40: "arm", 62: "x86_64",
            183: "aarch64", 243: "riscv",
        }.get(e_machine, "machine-%d" % e_machine)
        if e_type not in (2, 3):
            self.elf_note = "e_type=%d (not EXEC/DYN)" % e_type

        # Strings first: it is the check that works even when the section table
        # has been stripped, which is the common case for a hardened library.
        self._scan_strings()

        if e_shoff and e_shnum and e_shoff + e_shnum * e_shentsize <= len(d):
            self._read_sections(endian, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)
        else:
            self.elf_note = (self.elf_note + "; " if self.elf_note else "") + \
                "no usable section table (stripped?) - symbol checks skipped"

    def _scan_strings(self):
        d = self.data
        for pattern, label, strength, meaning in _STRINGSIGS:
            count = len(re.findall(pattern, d))
            if count:
                self.sig_hits[label] = (count, strength, meaning)
        for call in _JNI_CALLS:
            if re.search(re.escape(call).encode(), d):
                self.jni_call_refs.append(call)

    def _read_sections(self, endian, is64, shoff, shentsize, shnum, shstrndx):
        d = self.data
        sections = []
        for i in range(shnum):
            base = shoff + i * shentsize
            try:
                if is64:
                    name_off = struct.unpack_from(endian + "I", d, base)[0]
                    sh_type = struct.unpack_from(endian + "I", d, base + 4)[0]
                    sh_offset = struct.unpack_from(endian + "Q", d, base + 0x18)[0]
                    sh_size = struct.unpack_from(endian + "Q", d, base + 0x20)[0]
                    sh_link = struct.unpack_from(endian + "I", d, base + 0x28)[0]
                    sh_entsize = struct.unpack_from(endian + "Q", d, base + 0x38)[0]
                else:
                    name_off = struct.unpack_from(endian + "I", d, base)[0]
                    sh_type = struct.unpack_from(endian + "I", d, base + 4)[0]
                    sh_offset = struct.unpack_from(endian + "I", d, base + 0x10)[0]
                    sh_size = struct.unpack_from(endian + "I", d, base + 0x14)[0]
                    sh_link = struct.unpack_from(endian + "I", d, base + 0x18)[0]
                    sh_entsize = struct.unpack_from(endian + "I", d, base + 0x24)[0]
            except struct.error:
                return
            sections.append((name_off, sh_type, sh_offset, sh_size, sh_link, sh_entsize))

        if shstrndx >= len(sections):
            return
        _, _, str_off, str_size, _, _ = sections[shstrndx]
        if str_off + str_size > len(d):
            return
        shstr = d[str_off:str_off + str_size]

        def sec_name(off):
            end = shstr.find(b"\x00", off)
            return shstr[off:end if end >= 0 else len(shstr)].decode("utf-8", "replace")

        for name_off, sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
            # SHT_DYNSYM == 11, SHT_SYMTAB == 2
            if sh_type not in (2, 11):
                continue
            if sh_link >= len(sections):
                continue
            _, _, dstr_off, dstr_size, _, _ = sections[sh_link]
            if dstr_off + dstr_size > len(d) or sh_offset + sh_size > len(d):
                continue
            dstr = d[dstr_off:dstr_off + dstr_size]
            entsize = sh_entsize or (24 if is64 else 16)
            if entsize == 0:
                continue
            for off in range(sh_offset, sh_offset + sh_size, entsize):
                try:
                    if is64:
                        st_name = struct.unpack_from(endian + "I", d, off)[0]
                        st_shndx = struct.unpack_from(endian + "H", d, off + 6)[0]
                    else:
                        st_name = struct.unpack_from(endian + "I", d, off)[0]
                        st_shndx = struct.unpack_from(endian + "H", d, off + 14)[0]
                except struct.error:
                    break
                if st_name >= len(dstr):
                    continue
                end = dstr.find(b"\x00", st_name)
                sname = dstr[st_name:end if end >= 0 else len(dstr)].decode("utf-8", "replace")
                if not sname:
                    continue
                self.dynsym.append((sname, st_shndx))
                if sname.startswith("Java_"):
                    self.java_symbols.append(sname)
                if sname == "JNI_OnLoad":
                    self.has_jni_onload = True
                # Substring match, so a C implementation (bare name) and a C++
                # one (mangled form) are both caught. In practice NEITHER is
                # present: see the note on dynamic-registration in classify().
                if "RegisterNatives" in sname and st_shndx == 0:
                    self.imports_register_natives = True

    def summary(self):
        return {
            "name": self.name,
            "size": len(self.data),
            "is_elf": self.is_elf,
            "arch": self.arch,
            "elf_note": self.elf_note,
            "dynsym_entries": len(self.dynsym),
            "java_symbols": len(self.java_symbols),
            "java_symbol_sample": self.java_symbols[:5],
            "exports_JNI_OnLoad": self.has_jni_onload,
            "imports_RegisterNatives": self.imports_register_natives,
            "jni_call_refs": sorted(self.jni_call_refs),
            "signature_hits": {k: {"count": v[0], "strength": v[1], "meaning": v[2]}
                               for k, v in sorted(self.sig_hits.items())},
        }


# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------

def classify(dexes, elves, so_bytes_total):
    """Turn measurements into a type guess plus the reasoning behind it.

    Every rule below is a shape test, not a proof, and the confidence is reported
    so a low-confidence Java2C reading is not mistaken for a confirmed one.
    """
    evidence = []
    verdict = "no-hardening-signal"
    confidence = "low"

    dex_metrics = [d for d in dexes if not d.parse_error]
    total_methods = sum(d.total_methods for d in dex_metrics)
    total_native = sum(d.native_methods for d in dex_metrics)
    native_ratio = (float(total_native) / total_methods) if total_methods else 0.0
    fully_native = sum(d.fully_native_classes for d in dex_metrics)
    native_dominated = sum(d.native_dominated_classes for d in dex_metrics)
    no_code = sum(d.no_code_methods for d in dex_metrics)
    trivial_bodies = sum(d.trivial_bodies for d in dex_metrics)
    body_methods = sum(d.body_methods for d in dex_metrics)
    trivial_ratio = (float(trivial_bodies) / body_methods) if body_methods else 0.0

    java_syms = sum(len(e.java_symbols) for e in elves)
    register_natives_ref = any(e.imports_register_natives for e in elves)
    has_jni_onload = any(e.has_jni_onload for e in elves)
    # The reliable static signature of dynamic registration is the ABSENCE of
    # Java_* symbols from a library that does export a JNI entry point. Looking
    # for a literal RegisterNatives symbol does not work: NDK's C++ jni.h
    # implements it as an inline member that calls through the function table,
    # so no such symbol is emitted (measured: a real library exports JNI_OnLoad
    # with zero Java_* and zero RegisterNatives symbols).
    # Judged per library, not across the set: one library registering
    # dynamically says nothing about another that exports static symbols.
    dynamic_register_shape = any(e.has_jni_onload and not e.java_symbols for e in elves)
    tool_markers = []
    for e in elves:
        for label, (count, strength, meaning) in e.sig_hits.items():
            if strength == "strong":
                tool_markers.append("%s(x%d) in %s" % (label, count, os.path.basename(e.name)))
    medium_markers = []
    for e in elves:
        for label, (count, strength, meaning) in e.sig_hits.items():
            if strength == "medium":
                medium_markers.append("%s in %s" % (label, os.path.basename(e.name)))

    # --- dex-layer shape -------------------------------------------------
    java2c_dex_shape = (native_dominated >= 2) or (native_ratio >= 0.35 and total_native >= 10)
    jni_sink_dex_shape = 0 < total_native <= 20 and native_ratio < 0.15
    stub_shape = no_code > 0 or (body_methods >= 8 and trivial_ratio >= 0.5)

    if dex_metrics:
        evidence.append({
            "claim": "dex layer: native declaration density %.2f%% (%d/%d)"
                     % (native_ratio * 100, total_native, total_methods),
            "strength": "medium" if java2c_dex_shape else "strong",
            "supports": "java2c" if java2c_dex_shape else "baseline",
            "note": "High density with whole classes turned native is the Java2C shape. "
                    "It is NOT sufficient on its own: a hand-written JNI class looks "
                    "identical in dex, so the .so layer decides.",
        })
        evidence.append({
            "claim": "dex layer: %d classes are native-dominated (>=70%% native of >=3 "
                     "named methods), %d fully native" % (native_dominated, fully_native),
            "strength": "medium",
            "supports": "java2c" if native_dominated >= 2 else "baseline",
            "note": "A hand-written JNI boundary class normally keeps its Java half, so "
                    "whole classes turned native are the Java2C shape. Constructors are "
                    "excluded: they stay in Java even after a translation pass.",
        })
        if no_code:
            evidence.append({
                "claim": "dex layer: %d non-native, non-abstract methods have no code_item"
                         % no_code,
                "strength": "strong",
                "supports": "extraction-shell/vmp",
                "note": "Structurally invalid for plain Java; expect a loader that "
                        "fills bodies at runtime, or a private-opcode converter.",
            })
        if trivial_ratio:
            evidence.append({
                "claim": "dex layer: %.0f%% of method bodies are return-a-constant stubs "
                         "(%d/%d)" % (trivial_ratio * 100, trivial_bodies, body_methods),
                "strength": "medium",
                "supports": "extraction-shell/vmp" if stub_shape else "baseline",
                "note": "Approximate metric (see --help). Empty bodies are the signature "
                        "of an extraction shell or a VMP, not of Java2C.",
            })

    # --- native-layer shape ----------------------------------------------
    if elves:
        evidence.append({
            "claim": "native layer: %d exported Java_* symbols across %d library(ies)"
                     % (java_syms, len(elves)),
            "strength": "strong" if java_syms else "medium",
            "supports": "java2c" if java_syms else "none",
            "note": "Static-linkage form. Compare the count against the dex native "
                    "method count: a rough 1:1 map is the Java2C signature.",
        })
        if dynamic_register_shape:
            dyn_libs = sorted(os.path.basename(e.name)
                              for e in elves if e.has_jni_onload and not e.java_symbols)
            evidence.append({
                "claim": "native layer: dynamic registration in %s "
                         "(JNI_OnLoad exported, zero Java_* symbols)"
                         % ", ".join(dyn_libs),
                "strength": "strong",
                "supports": "dynamic-registration",
                "note": "Binding happens at runtime, so a symbol search comes back empty "
                        "and fails SILENTLY. Do not expect a RegisterNatives symbol "
                        "either: NDK's C++ jni.h makes it an inline member that calls "
                        "through the function table, so none is emitted.",
            })
        if register_natives_ref:
            evidence.append({
                "claim": "native layer: a RegisterNatives symbol is imported",
                "strength": "weak",
                "supports": "dynamic-registration",
                "note": "Only a C-side implementation leaves this name; its absence "
                        "proves nothing.",
            })
        if has_jni_onload:
            evidence.append({
                "claim": "native layer: JNI_OnLoad exported",
                "strength": "weak",
                "supports": "jni-boundary-exists",
                "note": "Present in nearly every JNI library. Holds no information "
                        "about which hardening was applied.",
            })
        if tool_markers:
            evidence.append({
                "claim": "native layer: toolchain markers found: %s" % ", ".join(tool_markers),
                "strength": "strong",
                "supports": "java2c",
                "note": "A Dex-to-C toolchain leaves its own runtime symbols behind.",
            })
        if medium_markers:
            evidence.append({
                "claim": "native layer: runtime markers found: %s" % ", ".join(medium_markers),
                "strength": "medium",
                "supports": "java2c",
                "note": "dcc runtime header names; suggestive, and easy to rename.",
            })

    # --- verdict ----------------------------------------------------------
    if tool_markers and (java2c_dex_shape or java_syms):
        verdict, confidence = "java2c", "high"
    elif java2c_dex_shape and java_syms and total_native and \
            (float(java_syms) / total_native) >= 0.5:
        verdict, confidence = "java2c", "high"
    elif java2c_dex_shape and medium_markers:
        verdict, confidence = "java2c", "medium"
    elif java2c_dex_shape and dynamic_register_shape:
        # A Dex-to-C toolchain that hides its symbols (dcc's Application.mk ships
        # -fvisibility=hidden) leaves exactly this: a JNI entry point and a
        # registration table, with no Java_* name to search for.
        verdict, confidence = "java2c", "medium"
    elif stub_shape:
        verdict, confidence = "extraction-shell-or-vmp", "medium"
    elif java2c_dex_shape:
        verdict, confidence = "java2c-suspect-needs-so", "low"
    elif jni_sink_dex_shape:
        verdict, confidence = "jni-sinking", "medium"
    elif dex_metrics or elves:
        verdict, confidence = "no-hardening-signal", "medium"

    routes = {
        "java2c": [
            "Do NOT look for a decrypted DEX: none exists, at any point, in memory.",
            "Read the C in the .so: each translated method is one function with a "
            "JNIEnv*/jobject prefix.",
            "Rebuild the call graph through the JNI reverse calls "
            "(FindClass/GetMethodID/CallXxxMethod).",
        ],
        "java2c-suspect-needs-so": [
            "Supply the matching .so (--so) before acting: the dex shape alone "
            "cannot separate Java2C from a hand-written JNI class.",
            "If no .so carries the logic, re-read the dex shape as ordinary Java.",
        ],
        "extraction-shell-or-vmp": [
            "Dump memory and measure the dump with scripts/dex_dump_validate.py.",
            "If the dump is mostly stubs, the bodies are filled at invocation time: "
            "references/advanced-unpacking.md.",
            "If bodies decode as private opcodes, that is a VMP - recovery cost "
            "usually exceeds the task value.",
        ],
        "jni-sinking": [
            "The dex is still readable: locate the Java call site, then reverse "
            "the one or few native functions.",
            "references/native-and-so.md, then the algorithm tooling.",
        ],
        "dynamic-registration": [
            "Hook or find RegisterNatives to read the binding table at runtime.",
        ],
        "no-hardening-signal": [
            "Proceed with ordinary dex-level analysis.",
        ],
    }

    return {
        "verdict": verdict,
        "confidence": confidence,
        "metrics": {
            "dex_total_methods": total_methods,
            "dex_native_methods": total_native,
            "dex_native_ratio": round(native_ratio, 4),
            "dex_fully_native_classes": fully_native,
            "dex_native_dominated_classes": native_dominated,
            "dex_no_code_methods": no_code,
            "dex_trivial_ratio": round(trivial_ratio, 4),
            "so_java_symbols": java_syms,
            "so_dynamic_registration": dynamic_register_shape,
            "so_bytes_total": so_bytes_total,
        },
        "evidence": evidence,
        "route": routes.get(verdict, []),
        "weak_criteria_warning": [
            "JNI_OnLoad / RegisterNatives / libc++_shared.so / FindClass appear in "
            "ordinary JNI libraries: a hit is not a hardening verdict.",
            "A high native ratio is also produced by hand-written JNI code and by R8 "
            "stripping Java bodies; only the .so layer separates these.",
            "The trivial-body ratio is approximate and flags extraction shells and "
            "VMPs, never Java2C.",
        ],
    }


# ---------------------------------------------------------------------------
# input collection
# ---------------------------------------------------------------------------

def _looks_like_dex(data):
    return data[:4] == b"dex\n"


def _looks_like_elf(data):
    return data[:4] == b"\x7fELF"


def collect(args):
    dex_blobs = []
    elf_blobs = []
    sources = []

    def add_file(path):
        try:
            with open(path, "rb") as fp:
                data = fp.read()
        except OSError as exc:
            print("warning: cannot read %s (%s)" % (path, exc), file=sys.stderr)
            return
        if _looks_like_dex(data):
            dex_blobs.append((os.path.basename(path), data))
            sources.append(path)
        elif _looks_like_elf(data):
            elf_blobs.append((os.path.basename(path), data))
            sources.append(path)
        else:
            print("warning: %s is neither a dex nor an ELF image, skipped" % path,
                  file=sys.stderr)

    for path in args.dex or []:
        add_file(path)
    for path in args.so or []:
        add_file(path)

    apks = list(args.apk or [])
    for directory in (args.dir or []):
        for root, _dirs, files in os.walk(directory):
            for fn in files:
                full = os.path.join(root, fn)
                low = fn.lower()
                if low.endswith(".apk"):
                    apks.append(full)
                elif low.endswith((".dex", ".so")):
                    add_file(full)

    for apk in apks:
        if not os.path.exists(apk):
            print("warning: apk not found: %s" % apk, file=sys.stderr)
            continue
        sources.append(apk)
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    low = info.filename.lower()
                    if not (low.endswith(".dex") or low.endswith(".so")):
                        continue
                    if info.file_size > 256 * 1024 * 1024:
                        print("warning: skipping oversized entry %s (%d B)"
                              % (info.filename, info.file_size), file=sys.stderr)
                        continue
                    data = zf.read(info)
                    label = os.path.basename(info.filename)
                    if _looks_like_dex(data):
                        dex_blobs.append((label, data))
                    elif _looks_like_elf(data):
                        elf_blobs.append((label, data))
        except zipfile.BadZipFile:
            print("warning: %s is not a readable zip/apk" % apk, file=sys.stderr)

    return dex_blobs, elf_blobs, sources


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Collect the evidence that separates Java2C from an extraction "
                    "shell, a VMP and ordinary JNI sinking.",
        epilog="Weak criteria (hits that do NOT establish a verdict on their own): "
               "JNI_OnLoad, RegisterNatives, libc++_shared.so, FindClass/GetMethodID, "
               "and a bare 'dcc' substring. The trivial-body ratio is advisory: it "
               "flags extraction shells and VMPs, never Java2C.",
    )
    parser.add_argument("--apk", action="append", help="APK to inspect (repeatable)")
    parser.add_argument("--dex", action="append", help="dex image (repeatable)")
    parser.add_argument("--so", action="append", help="ELF library (repeatable)")
    parser.add_argument("--dir", action="append",
                        help="directory scanned recursively for *.apk/*.dex/*.so")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    if not any([args.apk, args.dex, args.so, args.dir]):
        parser.error("at least one of --apk/--dex/--so/--dir is required")

    dex_blobs, elf_blobs, sources = collect(args)
    if not dex_blobs and not elf_blobs:
        print("error: no usable dex or ELF input found", file=sys.stderr)
        return 1

    dexes = [Dex(data, name) for name, data in dex_blobs]
    elves = [Elf(data, name) for name, data in elf_blobs]
    result = classify(dexes, elves, sum(len(d) for _n, d in elf_blobs))

    report = {
        "inputs": sources,
        "dex": [d.summary() for d in dexes],
        "native": [e.summary() for e in elves],
        "classification": result,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
        return 0

    print("=" * 72)
    print("java2c_probe: hardening classification evidence")
    print("=" * 72)
    print("inputs: %d file(s)" % len(sources))
    for src in sources:
        print("  - %s" % src)

    print("\n[dex layer]")
    if not dexes:
        print("  (no dex supplied: the dex-layer metrics are unmeasured, so a")
        print("   Java2C reading cannot be supported or excluded from this input)")
    for d in dexes:
        s = d.summary()
        if s["parse_error"]:
            print("  %s: PARSE ERROR: %s" % (s["name"], s["parse_error"]))
            continue
        print("  %s: %d B, %d classes, %d methods, native %d (%.2f%%), "
              "native-dominated classes %d, fully native %d"
              % (s["name"], s["size"], s["classes"], s["total_methods"],
                 s["native_methods"], s["native_ratio"] * 100,
                 s["native_dominated_classes"], s["fully_native_classes"]))
        print("    no-code methods %d, trivial bodies %d/%d (%.0f%%), header %s"
              % (s["no_code_methods"], s["trivial_bodies"], s["body_methods"],
                 s["trivial_ratio"] * 100,
                 "OK" if s["header_size_matches"] else "MISMATCH: " + s["header_note"]))

    print("\n[native layer]")
    if not elves:
        print("  (no .so supplied)")
    for e in elves:
        s = e.summary()
        if not s["is_elf"]:
            print("  %s: not ELF (%s)" % (s["name"], s["elf_note"]))
            continue
        print("  %s: %d B, %s, dynsym %d entries, Java_* %d, JNI_OnLoad %s, "
              "RegisterNatives-import %s"
              % (s["name"], s["size"], s["arch"], s["dynsym_entries"],
                 s["java_symbols"], s["exports_JNI_OnLoad"],
                 s["imports_RegisterNatives"]))
        if s["elf_note"]:
            print("    note: %s" % s["elf_note"])
        if s["signature_hits"]:
            for label, info in s["signature_hits"].items():
                print("    [%s] %s x%d - %s"
                      % (info["strength"], label, info["count"], info["meaning"]))

    print("\n[classification]")
    print("  verdict    : %s" % result["verdict"])
    print("  confidence : %s" % result["confidence"])
    print("\n  evidence:")
    for item in result["evidence"]:
        print("    (%s) %s" % (item["strength"], item["claim"]))
        print("        note: %s" % item["note"])
    print("\n  route:")
    for line in result["route"]:
        print("    - %s" % line)
    print("\n  weak criteria - a hit here is NOT a verdict:")
    for line in result["weak_criteria_warning"]:
        print("    ! %s" % line)
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
