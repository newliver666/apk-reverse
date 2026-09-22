#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal, dependency-free dex reader: structure walk + exact instruction decode.

WHY THIS EXISTS
---------------
Locating the exact byte offset of one instruction is where byte-level patching
either works or wastes an afternoon. Two shortcuts do not work and are worth
naming so nobody re-derives them:

  * Reconstructing offsets from a baksmali listing. `.line` directives track
    SOURCE lines, and one source line can span several instructions, so the
    values repeat and do not map 1:1 onto code offsets.
  * Matching a guessed byte sequence. Encodings vary with register numbers and
    operand widths, and a plausible-looking opcode can belong to a different
    format than you assume (0x38 is `if-test`, 22t/4 bytes -- not `if-testz`).

So: walk class -> class_data_item -> method -> code_item, then decode forward with
a complete format table, and match on decoded semantics instead of bytes.

Three details in the walk that silently produce wrong answers:

  * `class_data_item` member indices are DELTAS against the previous entry in the
    same list. Reading a raw uleb as an absolute index yields real-looking wrong
    members.
  * dalvik encodes switch/array payloads as `00 <ident> <size>` with ident 1..3.
    A plain `00 00` is an ordinary one-unit nop; treating every 00 as a payload
    swallows the next instruction and desynchronises the rest of the method.
  * The header field order is easy to mis-remember. See OFFSETS below, and always
    sanity-check the parsed sizes against the file.

Pure standard library. Import it, or run it for a per-method dump:

    python dexutil.py <dex-or-apk> <Class/Name;> <method> <descriptor>
"""

import hashlib
import sys
import zipfile

# Verified dex header offsets. After magic(8) + checksum(4) + signature(20):
OFFSETS = {
    "file_size": 0x20, "header_size": 0x24, "endian_tag": 0x28,
    "link_size": 0x2C, "link_off": 0x30, "map_off": 0x34,
    "string_ids_size": 0x38, "string_ids_off": 0x3C,
    "type_ids_size": 0x40, "type_ids_off": 0x44,
    "proto_ids_size": 0x48, "proto_ids_off": 0x4C,
    "field_ids_size": 0x50, "field_ids_off": 0x54,
    "method_ids_size": 0x58, "method_ids_off": 0x5C,
    "class_defs_size": 0x60, "class_defs_off": 0x64,
    "data_size": 0x68, "data_off": 0x6C,
}

# NOTE — known defect, measured, deliberately not guessed at.
#
# This NAME table is misaligned with the opcode slots from roughly 0x1a onward. Measured
# against dexlib2 by joining both decoders on instruction offset: the slot this table
# calls `array-length` decodes as `instance-of`, the slot called `new-instance` decodes
# as `array-length`, the slot called `goto/16` decodes as `goto`. Exact or not, the point
# is that the names are NOT a safe key for looking up an authoritative width.
#
# The width decisions in `insn_units` are keyed on the opcode VALUE, not on these names,
# so a wrong name does not by itself corrupt a decode -- but it will mislead a reader,
# and it misled one here into "fixing" two widths that were already right.
#
# Fixed and verified in this pass (method: full-decode alignment on three real dex
# images, asserting each walk ends exactly on insns_off + insns_size*2):
#   * payload widths. The field after the `00 <ident>` is a DIFFERENT quantity per
#     payload kind: packed-switch has size(uint16)+first_key(int32), sparse-switch has
#     size(uint16)+size*(key,target), fill-array-data has element_width(uint16)+
#     size(uint32). All three were previously read as `1 + <one uint16>`, so a 30-element
#     4-byte-wide array payload counted as 5 units instead of 64.
#   * 0x22 is 22c (2 units) and 0x23/0x24 are 35c/3rc (3 units); they sat in each other's
#     groups.
#   * 0x20 was grouped as 2 units.
# Result: methods whose decode fails to land on the exact end went from 137/113/70 to
# 44/51/30 across the three images.
#
# Still open: the name misalignment above. It needs the table rebuilt from an
# independent decoder in one pass, not edited slot by slot -- two slot-wise edits made
# during this investigation were reverted after measurement showed they made alignment
# worse. Treat a name from this table as a hint, and check any width you intend to rely
# on against a second decoder.
OP_NAMES = {
    0x00: "nop", 0x01: "move", 0x02: "move/from16", 0x03: "move/16",
    0x04: "move-wide", 0x05: "move-wide/from16", 0x06: "move-wide/16", 0x07: "move-object",
    0x08: "move-object/from16", 0x09: "move-object/16", 0x0A: "move-result", 0x0B: "move-result-wide",
    0x0C: "move-result-object", 0x0D: "move-exception", 0x0E: "return-void", 0x0F: "return",
    0x10: "return-wide", 0x11: "return-object", 0x12: "const/4", 0x13: "const/16",
    0x14: "const", 0x15: "const/high16", 0x16: "const-wide/16", 0x17: "const-wide/32",
    0x18: "const-wide", 0x19: "const-wide/high16", 0x1A: "const-string", 0x1B: "const-string/jumbo",
    0x1C: "const-class", 0x1D: "monitor-enter", 0x1E: "monitor-exit", 0x1F: "check-cast",
    0x20: "instance-of", 0x21: "array-length", 0x22: "new-instance", 0x23: "new-array",
    0x24: "filled-new-array", 0x25: "filled-new-array/range", 0x26: "fill-array-data", 0x27: "throw",
    0x28: "goto", 0x29: "goto/16", 0x2A: "goto/32", 0x2B: "packed-switch",
    0x2C: "sparse-switch", 0x2D: "cmpl-float", 0x2E: "cmpg-float", 0x2F: "cmpl-double",
    0x30: "cmpg-double", 0x31: "cmp-long", 0x32: "if-eq", 0x33: "if-ne",
    0x34: "if-lt", 0x35: "if-ge", 0x36: "if-gt", 0x37: "if-le",
    0x38: "if-eqz", 0x39: "if-nez", 0x3A: "if-ltz", 0x3B: "if-gez",
    0x3C: "if-gtz", 0x3D: "if-lez", 0x44: "aget", 0x45: "aget-wide",
    0x46: "aget-object", 0x47: "aget-boolean", 0x48: "aget-byte", 0x49: "aget-char",
    0x4A: "aget-short", 0x4B: "aput", 0x4C: "aput-wide", 0x4D: "aput-object",
    0x4E: "aput-boolean", 0x4F: "aput-byte", 0x50: "aput-char", 0x51: "aput-short",
    0x52: "iget", 0x53: "iget-wide", 0x54: "iget-object", 0x55: "iget-boolean",
    0x56: "iget-byte", 0x57: "iget-char", 0x58: "iget-short", 0x59: "iput",
    0x5A: "iput-wide", 0x5B: "iput-object", 0x5C: "iput-boolean", 0x5D: "iput-byte",
    0x5E: "iput-char", 0x5F: "iput-short", 0x60: "sget", 0x61: "sget-wide",
    0x62: "sget-object", 0x63: "sget-boolean", 0x64: "sget-byte", 0x65: "sget-char",
    0x66: "sget-short", 0x67: "sput", 0x68: "sput-wide", 0x69: "sput-object",
    0x6A: "sput-boolean", 0x6B: "sput-byte", 0x6C: "sput-char", 0x6D: "sput-short",
    0x6E: "invoke-virtual", 0x6F: "invoke-super", 0x70: "invoke-direct", 0x71: "invoke-static",
    0x72: "invoke-interface", 0x74: "invoke-virtual/range", 0x75: "invoke-super/range", 0x76: "invoke-direct/range",
    0x77: "invoke-static/range", 0x78: "invoke-interface/range", 0x7B: "neg-int", 0x7C: "not-int",
    0x7D: "neg-long", 0x7E: "not-long", 0x7F: "neg-float", 0x80: "neg-double",
    0x81: "int-to-long", 0x82: "int-to-float", 0x83: "int-to-double", 0x84: "long-to-int",
    0x85: "long-to-float", 0x86: "long-to-double", 0x87: "float-to-int", 0x88: "float-to-long",
    0x89: "float-to-double", 0x8A: "double-to-int", 0x8B: "double-to-long", 0x8C: "double-to-float",
    0x8D: "int-to-byte", 0x8E: "int-to-char", 0x8F: "int-to-short", 0x90: "add-int",
    0x91: "sub-int", 0x92: "mul-int", 0x93: "div-int", 0x94: "rem-int",
    0x95: "and-int", 0x96: "or-int", 0x97: "xor-int", 0x98: "shl-int",
    0x99: "shr-int", 0x9A: "ushr-int", 0x9B: "add-long", 0x9C: "sub-long",
    0x9D: "mul-long", 0x9E: "div-long", 0x9F: "rem-long", 0xA0: "and-long",
    0xA1: "or-long", 0xA2: "xor-long", 0xA3: "shl-long", 0xA4: "shr-long",
    0xA5: "ushr-long", 0xA6: "add-float", 0xA7: "sub-float", 0xA8: "mul-float",
    0xA9: "div-float", 0xAA: "rem-float", 0xAB: "add-double", 0xAC: "sub-double",
    0xAD: "mul-double", 0xAE: "div-double", 0xAF: "rem-double", 0xB0: "add-int/2addr",
    0xB1: "sub-int/2addr", 0xB2: "mul-int/2addr", 0xB3: "div-int/2addr", 0xB4: "rem-int/2addr",
    0xB5: "and-int/2addr", 0xB6: "or-int/2addr", 0xB7: "xor-int/2addr", 0xB8: "shl-int/2addr",
    0xB9: "shr-int/2addr", 0xBA: "ushr-int/2addr", 0xBB: "add-long/2addr", 0xBC: "sub-long/2addr",
    0xBD: "mul-long/2addr", 0xBE: "div-long/2addr", 0xBF: "rem-long/2addr", 0xC0: "and-long/2addr",
    0xC1: "or-long/2addr", 0xC2: "xor-long/2addr", 0xC3: "shl-long/2addr", 0xC4: "shr-long/2addr",
    0xC5: "ushr-long/2addr", 0xC6: "add-float/2addr", 0xC7: "sub-float/2addr", 0xC8: "mul-float/2addr",
    0xC9: "div-float/2addr", 0xCA: "rem-float/2addr", 0xCB: "add-double/2addr", 0xCC: "sub-double/2addr",
    0xCD: "mul-double/2addr", 0xCE: "div-double/2addr", 0xCF: "rem-double/2addr", 0xD0: "add-int/lit16",
    0xD1: "rsub-int", 0xD2: "mul-int/lit16", 0xD3: "div-int/lit16", 0xD4: "rem-int/lit16",
    0xD5: "and-int/lit16", 0xD6: "or-int/lit16", 0xD7: "xor-int/lit16", 0xD8: "add-int/lit8",
    0xD9: "rsub-int/lit8", 0xDA: "mul-int/lit8", 0xDB: "div-int/lit8", 0xDC: "rem-int/lit8",
    0xDD: "and-int/lit8", 0xDE: "or-int/lit8", 0xDF: "xor-int/lit8", 0xE0: "shl-int/lit8",
    0xE1: "shr-int/lit8", 0xE2: "ushr-int/lit8", 0xFA: "invoke-polymorphic", 0xFB: "invoke-polymorphic/range",
    0xFC: "invoke-custom", 0xFD: "invoke-custom/range", 0xFE: "const-method-handle", 0xFF: "const-method-type",
}

# Instruction length in 16-bit code units, one entry per valid opcode.
#
# Keyed by opcode from the format specification, NOT inferred from a mnemonic
# and NOT copied from a run of neighbours. 0x16-0x2C alternates
# 2,3,5,2,2,3,2,1,1,2,2,1,2,2,3,3,3,1,1,2,3,3,3 -- an entire run where the
# plausible-looking "same family, same width" assumption is wrong at nine
# opcodes. A single wrong entry shifts every instruction after it in the same
# method, and the decode keeps producing plausible instructions, so nothing
# looks broken until an operand index walks off its table.
OP_UNITS = {
    0x00: 1, 0x01: 1, 0x02: 2, 0x03: 3,
    0x04: 1, 0x05: 2, 0x06: 3, 0x07: 1,
    0x08: 2, 0x09: 3, 0x0A: 1, 0x0B: 1,
    0x0C: 1, 0x0D: 1, 0x0E: 1, 0x0F: 1,
    0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2,
    0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3,
    0x18: 5, 0x19: 2, 0x1A: 2, 0x1B: 3,
    0x1C: 2, 0x1D: 1, 0x1E: 1, 0x1F: 2,
    0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2,
    0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
    0x28: 1, 0x29: 2, 0x2A: 3, 0x2B: 3,
    0x2C: 3, 0x2D: 2, 0x2E: 2, 0x2F: 2,
    0x30: 2, 0x31: 2, 0x32: 2, 0x33: 2,
    0x34: 2, 0x35: 2, 0x36: 2, 0x37: 2,
    0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2,
    0x3C: 2, 0x3D: 2, 0x44: 2, 0x45: 2,
    0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2,
    0x4A: 2, 0x4B: 2, 0x4C: 2, 0x4D: 2,
    0x4E: 2, 0x4F: 2, 0x50: 2, 0x51: 2,
    0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2,
    0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2,
    0x5A: 2, 0x5B: 2, 0x5C: 2, 0x5D: 2,
    0x5E: 2, 0x5F: 2, 0x60: 2, 0x61: 2,
    0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2,
    0x66: 2, 0x67: 2, 0x68: 2, 0x69: 2,
    0x6A: 2, 0x6B: 2, 0x6C: 2, 0x6D: 2,
    0x6E: 3, 0x6F: 3, 0x70: 3, 0x71: 3,
    0x72: 3, 0x74: 3, 0x75: 3, 0x76: 3,
    0x77: 3, 0x78: 3, 0x7B: 1, 0x7C: 1,
    0x7D: 1, 0x7E: 1, 0x7F: 1, 0x80: 1,
    0x81: 1, 0x82: 1, 0x83: 1, 0x84: 1,
    0x85: 1, 0x86: 1, 0x87: 1, 0x88: 1,
    0x89: 1, 0x8A: 1, 0x8B: 1, 0x8C: 1,
    0x8D: 1, 0x8E: 1, 0x8F: 1, 0x90: 2,
    0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2,
    0x95: 2, 0x96: 2, 0x97: 2, 0x98: 2,
    0x99: 2, 0x9A: 2, 0x9B: 2, 0x9C: 2,
    0x9D: 2, 0x9E: 2, 0x9F: 2, 0xA0: 2,
    0xA1: 2, 0xA2: 2, 0xA3: 2, 0xA4: 2,
    0xA5: 2, 0xA6: 2, 0xA7: 2, 0xA8: 2,
    0xA9: 2, 0xAA: 2, 0xAB: 2, 0xAC: 2,
    0xAD: 2, 0xAE: 2, 0xAF: 2, 0xB0: 1,
    0xB1: 1, 0xB2: 1, 0xB3: 1, 0xB4: 1,
    0xB5: 1, 0xB6: 1, 0xB7: 1, 0xB8: 1,
    0xB9: 1, 0xBA: 1, 0xBB: 1, 0xBC: 1,
    0xBD: 1, 0xBE: 1, 0xBF: 1, 0xC0: 1,
    0xC1: 1, 0xC2: 1, 0xC3: 1, 0xC4: 1,
    0xC5: 1, 0xC6: 1, 0xC7: 1, 0xC8: 1,
    0xC9: 1, 0xCA: 1, 0xCB: 1, 0xCC: 1,
    0xCD: 1, 0xCE: 1, 0xCF: 1, 0xD0: 2,
    0xD1: 2, 0xD2: 2, 0xD3: 2, 0xD4: 2,
    0xD5: 2, 0xD6: 2, 0xD7: 2, 0xD8: 2,
    0xD9: 2, 0xDA: 2, 0xDB: 2, 0xDC: 2,
    0xDD: 2, 0xDE: 2, 0xDF: 2, 0xE0: 2,
    0xE1: 2, 0xE2: 2, 0xFA: 4, 0xFB: 4,
    0xFC: 3, 0xFD: 3, 0xFE: 2, 0xFF: 2,
}

# Opcode groups whose operands are a pair of registers plus an int16 offset.
IF_TEST = set(range(0x32, 0x38))    # 22t: 2 register nibbles + int16
IF_TESTZ = set(range(0x38, 0x3E))   # 21t: 1 register nibble + int16
RETURN_OPS = (0x0F, 0x10, 0x11)
MOVE_RESULT_OPS = (0x0A, 0x0B, 0x0C)
INVOKE_OPS = tuple(range(0x6E, 0x73)) + tuple(range(0x74, 0x79))
# opcodes that read an instance field: (dest_reg, object_reg, field_idx)
IFIELD_OPS = tuple(range(0x52, 0x59))
# opcodes that write an instance field: (value_reg, object_reg, field_idx)
PFIELD_OPS = tuple(range(0x59, 0x60))
SFIELD_OPS = tuple(range(0x60, 0x6E))


def u16(b, o):
    return b[o] | (b[o + 1] << 8)


def u32(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)


def s16(v):
    return v - 0x10000 if v > 0x7FFF else v


def read_uleb(b, o):
    """ULEB128 -> (value, new_offset). Member indices in class_data are deltas."""
    result = 0
    shift = 0
    while True:
        x = b[o]
        o += 1
        result |= (x & 0x7F) << shift
        if (x & 0x80) == 0:
            break
        shift += 7
    return result, o


def insn_units(op, data, pos, end):
    """Instruction length in 16-bit code units.

    Widths come from OP_UNITS, the format specification's table -- not from a
    mnemonic, and not from a run of neighbours. The failure that replaces was
    quiet in the worst way: a wrong width keeps producing plausible instructions,
    just shifted, so every offset derived after that point is wrong and nothing in
    the output says so. The traps worth naming:

      * Width is not a family property. `const-wide/16` (0x16) is 2 units,
        `const-wide/32` (0x17) is 3 and `const-wide` (0x18) is 5; `const-class`
        (0x1C) is 2 while `monitor-exit` (0x1E) is 1; `instance-of` (0x20) is 2
        while `array-length` (0x21) is 1. Nine opcodes in 0x16-0x2C break the
        "same family, same width" reading.
      * `0x32`-`0x3D` (if-test 22t / if-testz 21t) are **2** units, not 1.
        Treating them as 1 invents a fake second instruction at every branch.
      * `0x1A` (const-string, 21c) and `0x1B` (const-string/jumbo, 31c) are
        different widths; only the jumbo form carries a 32-bit string index.
      * The `goto` family sits at `0x28` (10t, **1** unit), `0x29` (20t, **2**)
        and `0x2A` (30t, **3**) -- one slot later than the obvious reading, which
        puts `throw`, `goto`, `goto/16` at 0x27/0x28/0x29.

    Whenever a decode is used to derive a patch offset, assert that the walk ends
    exactly on `insns_off + insns_size*2`. See `decode_all`.
    """
    if op == 0x00:
        # Pseudo-instructions. `00 <ident>` with ident 1..3 is a switch or
        # fill-array payload; a plain `00 00` is a one-unit nop, so never treat
        # every 00 as a payload.
        #
        # Each payload has its OWN layout, and the field after the ident is not
        # the same quantity in all three:
        #
        #   0x0100 packed-switch-payload: ident, size(uint16), first_key(int32),
        #          then size * int32 targets
        #          -> 2 + 2 + size*4 bytes  =  4 + size*2 units
        #   0x0200 sparse-switch-payload: ident, size(uint16), then size pairs of
        #          (int32 key, int32 target)
        #          -> 2 + 2 + size*8 bytes  =  2 + size*4 units
        #   0x0300 fill-array-data-payload: ident, element_width(uint16),
        #          size(uint32), then the raw data padded to an even byte count
        #          -> 4 units + ceil(size * element_width / 2)
        #
        # Reading size out of the wrong slot desynchronises silently: the walk
        # keeps producing plausible instructions, only shifted. Measured on a
        # real AOT class initialiser, a fill-array payload of 30 four-byte
        # elements (64 units) was counted as 5, which is the bug this fixes.
        if pos + 8 <= end:
            ident = data[pos + 1] & 0xFF
            if ident == 0x01:
                return 4 + u16(data, pos + 2) * 2
            if ident == 0x02:
                return 2 + u16(data, pos + 2) * 4
            if ident == 0x03:
                width = u16(data, pos + 2)
                count = u32(data, pos + 4)
                return 4 + (count * width + 1) // 2
        return 1
    # Unallocated opcodes (0x3E-0x43, 0x73, 0x79-0x7A, 0xE3-0xF9) never appear in
    # a valid dex; anything unlisted is treated as one unit so a corrupt stream
    # still terminates rather than running off the end.
    return OP_UNITS.get(op, 1)


class Dex(object):
    """Structural reader for one dex image."""

    def __init__(self, data, name="classes.dex"):
        self.d = data
        self.name = name
        self.header = {k: u32(data, v) for k, v in OFFSETS.items()}

    # ---- sanity -----------------------------------------------------------
    def check(self):
        """Return a list of structural complaints; empty means it parses."""
        problems = []
        size = len(self.d)
        if self.d[:4] != b"dex\n":
            problems.append("not a dex: magic=%r" % self.d[:4])
        for key in ("string_ids_off", "type_ids_off", "proto_ids_off",
                    "field_ids_off", "method_ids_off", "class_defs_off"):
            off = self.header[key]
            if not (0 < off < size):
                problems.append("%s=0x%x out of range (file size %d)"
                                % (key, off, size))
        declared = self.header["file_size"]
        if declared and declared != size:
            problems.append("header file_size=%d but actual=%d" % (declared, size))
        return problems

    # ---- index tables -----------------------------------------------------
    def string(self, idx):
        p = u32(self.d, self.header["string_ids_off"] + idx * 4)
        _utf16_len, p = read_uleb(self.d, p)
        end = self.d.index(b"\x00", p)
        return self.d[p:end].decode("utf-8", "replace")

    def string_safe(self, idx):
        """Like string() but never raises -- a desynced decode passes junk index.

        A renderer that throws on a bad index hides the very symptom the caller is
        looking for (a decode that has drifted), so return a marker instead.
        """
        try:
            if idx >= self.header["string_ids_size"]:
                return "<string_idx %d out of range>" % idx
            return self.string(idx)
        except Exception:
            return "<string_idx %d unreadable>" % idx

    def type_(self, idx):
        return self.string(u32(self.d, self.header["type_ids_off"] + idx * 4))

    def proto(self, idx):
        o = self.header["proto_ids_off"] + idx * 12
        ret = self.type_(u32(self.d, o + 4))
        poff = u32(self.d, o + 8)
        params = []
        if poff:
            n = u32(self.d, poff)
            p = poff + 4
            for _ in range(n):
                params.append(self.type_(u16(self.d, p)))
                p += 2
        return "(" + "".join(params) + ")" + ret

    def field(self, idx):
        o = self.header["field_ids_off"] + idx * 8
        return (self.type_(u16(self.d, o)), self.string(u32(self.d, o + 4)),
                self.type_(u16(self.d, o + 2)))

    def method(self, idx):
        o = self.header["method_ids_off"] + idx * 8
        return (self.type_(u16(self.d, o)), self.string(u32(self.d, o + 4)),
                self.proto(u16(self.d, o + 2)))

    def find_class(self, fqcn):
        """Return the class_def_item offset for a 'Lpkg/Name;' FQCN, or None."""
        for i in range(self.header["class_defs_size"]):
            o = self.header["class_defs_off"] + i * 32
            if self.type_(u32(self.d, o)) == fqcn:
                return o
        return None

    def methods_of(self, fqcn):
        """Yield (section, method_idx, class, name, descriptor, code_off)."""
        cd = self.find_class(fqcn)
        if cd is None:
            raise KeyError("class not found: %s" % fqcn)
        for item in self.methods_at(cd):
            yield item

    def methods_at(self, class_def_off):
        """Same as methods_of(), from a class_def_item offset you already have.

        methods_of() calls find_class(), which is a linear scan of class_defs, so
        walking every class in a dex through it costs O(n^2). A caller that is
        already iterating class_defs should come through here instead.
        """
        p = u32(self.d, class_def_off + 24)
        if p == 0:
            return
        sf, p = read_uleb(self.d, p)
        inf, p = read_uleb(self.d, p)
        dm, p = read_uleb(self.d, p)
        vm, p = read_uleb(self.d, p)
        for _ in range(sf + inf):                     # skip field lists
            _i, p = read_uleb(self.d, p)
            _a, p = read_uleb(self.d, p)
        for section, count in (("direct", dm), ("virtual", vm)):
            running = 0
            for _ in range(count):
                diff, p = read_uleb(self.d, p)
                running += diff                        # indices are delta-encoded
                _acc, p = read_uleb(self.d, p)
                code_off, p = read_uleb(self.d, p)
                cls, name, desc = self.method(running)
                yield section, running, cls, name, desc, code_off

    def find_method(self, fqcn, name, desc):
        """Return (section, method_idx, code_off) or None."""
        for section, idx, _cls, nm, ds, code_off in self.methods_of(fqcn):
            if nm == name and ds == desc:
                return section, idx, code_off
        return None

    def find_methods_named(self, fqcn, name):
        """All overloads of a name -> list of (section, idx, desc, code_off)."""
        out = []
        for section, idx, _cls, nm, ds, code_off in self.methods_of(fqcn):
            if nm == name:
                out.append((section, idx, ds, code_off))
        return out

    def class_names(self):
        for i in range(self.header["class_defs_size"]):
            o = self.header["class_defs_off"] + i * 32
            yield self.type_(u32(self.d, o))

    # ---- code -------------------------------------------------------------
    def code_info(self, code_off):
        return {
            "registers": u16(self.d, code_off),
            "ins": u16(self.d, code_off + 2),
            "outs": u16(self.d, code_off + 4),
            "tries": u16(self.d, code_off + 6),
            "debug_info_off": u32(self.d, code_off + 8),
            "insns_size": u32(self.d, code_off + 12),
            "insns_off": code_off + 16,
        }

    def decode(self, code_off):
        """Yield dicts describing each instruction of one method body.

        Callers should assert the walk ends exactly on insns_off+insns_size*2;
        landing short or long means the format table is wrong somewhere.
        """
        info = self.code_info(code_off)
        pos = info["insns_off"]
        end = pos + info["insns_size"] * 2
        while pos < end:
            op = self.d[pos]
            units = insn_units(op, self.d, pos, end)
            if units < 1 or pos + units * 2 > end:
                return
            yield {
                "off": pos, "op": op, "units": units,
                "name": OP_NAMES.get(op, "op_%02x" % op),
                "raw": bytes(self.d[pos:pos + units * 2]),
                "registers": info["registers"],
            }
            pos += units * 2

    def decode_all(self, code_off):
        """Full listing as a list, plus a verdict on whether it ended cleanly."""
        insns = list(self.decode(code_off))
        info = self.code_info(code_off)
        expected = info["insns_off"] + info["insns_size"] * 2
        ended = insns[-1]["off"] + insns[-1]["units"] * 2 if insns else info["insns_off"]
        return insns, (ended == expected), expected

    def insn_at(self, code_off, target_off):
        for insn in self.decode(code_off):
            if insn["off"] == target_off:
                return insn
        return None

    # ---- operand helpers --------------------------------------------------
    def branch_target(self, insn):
        """Absolute target of a branch, or None if the instruction is not one."""
        op, pos, raw = insn["op"], insn["off"], insn["raw"]
        if op in IF_TEST or op in IF_TESTZ:
            return pos + s16(u16(self.d, pos + 2)) * 2
        if op == 0x28:                       # goto (10t, signed byte)
            off = raw[1]
            if off > 127:
                off -= 256
            return pos + off * 2
        if op == 0x29:                       # goto/16 (20t, signed int16)
            return pos + s16(u16(self.d, pos + 2)) * 2
        if op == 0x2A:                       # goto/32 (30t, signed int32)
            off = u32(self.d, pos + 2)
            if off > 0x7FFFFFFF:
                off -= 0x100000000
            return pos + off * 2
        return None

    def branch_regs(self, insn):
        """(regs_read, kind) for a conditional branch."""
        if insn["op"] in IF_TEST:
            return [insn["raw"][1] >> 4, insn["raw"][1] & 0xF], "if-test"
        if insn["op"] in IF_TESTZ:
            return [insn["raw"][1] & 0xF], "if-testz"
        return [], None

    def all_targets(self, code_off):
        """Set of every absolute branch target in one method."""
        targets = set()
        for insn in self.decode(code_off):
            t = self.branch_target(insn)
            if t is not None:
                targets.add(t)
        return targets

    # ---- description ------------------------------------------------------
    def describe(self, insn):
        """One-line human rendering with resolved field/method/string names."""
        op, pos, raw = insn["op"], insn["off"], insn["raw"]
        text = "0x%x: %-14s %s" % (pos, raw.hex(), insn["name"])
        if op in IF_TEST:
            text += " v%d,v%d -> 0x%x" % (raw[1] >> 4, raw[1] & 0xF,
                                          self.branch_target(insn))
        elif op in IF_TESTZ:
            text += " v%d -> 0x%x" % (raw[1] & 0xF, self.branch_target(insn))
        elif op in (0x28, 0x29, 0x2A):
            text += " -> 0x%x" % self.branch_target(insn)
        elif op in IFIELD_OPS:
            cls, nm, ty = self.field(u16(self.d, pos + 2))
            text += " v%d <- v%d.%s:%s" % (raw[1] & 0xF, raw[1] >> 4, nm, ty)
        elif op in PFIELD_OPS:
            cls, nm, ty = self.field(u16(self.d, pos + 2))
            text += " v%d -> v%d.%s:%s" % (raw[1] & 0xF, raw[1] >> 4, nm, ty)
        elif op in SFIELD_OPS:
            cls, nm, ty = self.field(u16(self.d, pos + 2))
            text += " %s.%s:%s" % (cls, nm, ty)
        elif op in INVOKE_OPS:
            cls, nm, ds = self.method(u16(self.d, pos + 2))
            text += " %s.%s%s" % (cls, nm, ds)
        elif op == 0x1A:
            # const-string (21c): uint16 string index at byte offset 2.
            text += ' "%s"' % self.string_safe(u16(self.d, pos + 2))
        elif op == 0x1B:
            # const-string/jumbo (31c): the index is a uint32, so reading it as a
            # uint16 would silently name a different string.
            text += ' "%s"' % self.string_safe(u32(self.d, pos + 2))
        elif op == 0x12:
            lit = raw[1] & 0xF
            text += " v%d, %d" % (raw[1] >> 4, lit - 16 if lit > 7 else lit)
        return text


# ---------------------------------------------------------------------------
# dex header integrity
# ---------------------------------------------------------------------------

def fix_dex_header(data):
    """Recompute a dex header's checksum and signature IN THE CORRECT ORDER.

    Order is not cosmetic:
        bytes 12..32 = sha1(data[32:])      -- signature first
        bytes  8..12 = adler32(data[12:])   -- checksum last, covers the signature

    Reversed, the adler32 is taken while the signature field is still zeroed, so
    the header never verifies. Android logs
    `Failure to verify dex file ...: Bad checksum (computed, expected)` -- the
    real value shows up as "expected" -- and falls back to interpreting the dex,
    which can surface as an unrelated ClassNotFoundException at startup.

    Accepts and returns a bytearray; also returns the before/after values so a
    caller can print them.
    """
    before_checksum = int.from_bytes(data[8:12], "little")
    before_signature = bytes(data[12:32])

    data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
    after_signature = bytes(data[12:32])

    import zlib
    after_checksum = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    data[8:12] = after_checksum.to_bytes(4, "little")

    return {
        "before_checksum": before_checksum, "after_checksum": after_checksum,
        "before_signature": before_signature, "after_signature": after_signature,
    }


def verify_dex_header(data):
    """Return (checksum_ok, signature_ok) for a bytearray/bytes dex."""
    import zlib
    stored_c = int.from_bytes(data[8:12], "little")
    calc_c = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    return stored_c == calc_c, bytes(data[12:32]) == hashlib.sha1(bytes(data[32:])).digest()


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def load_dex(source, entry=None):
    """Load a Dex from a .dex path, an .apk/.zip path, or raw bytes.

    For an archive, `entry` picks a member (default: the first classes*.dex).
    Returns (Dex, entry_name).
    """
    if isinstance(source, (bytes, bytearray)):
        return Dex(bytes(source), entry or "<bytes>"), entry or "<bytes>"
    path = str(source)
    if path.lower().endswith((".apk", ".zip", ".jar", ".xapk", ".apks", ".apkm")):
        with zipfile.ZipFile(path) as z:
            if entry:
                return Dex(z.read(entry), entry), entry
            candidates = sorted(n for n in z.namelist()
                                if n.startswith("classes") and n.endswith(".dex"))
            if not candidates:
                raise ValueError("no classes*.dex in %s" % path)
            name = candidates[0]
            return Dex(z.read(name), name), name
    with open(path, "rb") as fh:
        return Dex(fh.read(), path), path


def main(argv):
    if len(argv) != 5:
        print(__doc__)
        return 2
    target, fqcn, name, desc = argv[1:5]
    dex, entry = load_dex(target)
    print("== %s (entry %s, %d bytes)" % (target, entry, len(dex.d)))
    problems = dex.check()
    for p in problems:
        print("  [structure] %s" % p)
    if problems:
        print("  refusing to continue on a structurally broken read")
        return 1

    found = dex.find_method(fqcn, name, desc)
    if not found:
        print("method not found: %s->%s%s" % (fqcn, name, desc))
        print("methods in class:")
        for section, idx, _c, nm, ds, code_off in dex.methods_of(fqcn):
            print("  [%s] %s%s code_off=0x%x" % (section, nm, ds, code_off))
        return 1

    section, idx, code_off = found
    info = dex.code_info(code_off)
    insns, clean, expected = dex.decode_all(code_off)
    print("== %s.%s%s  [%s] method_idx=%d" % (fqcn, name, desc, section, idx))
    print("   code_off=0x%x insns_off=0x%x insns_size=%d registers=%d"
          % (code_off, info["insns_off"], info["insns_size"], info["registers"]))
    print("   decoded %d instructions; ended cleanly: %s" % (len(insns), clean))
    if not clean:
        print("   WARNING: decode did not land on 0x%x -- offsets below are suspect"
              % expected)

    regs = info["registers"]
    over = [i for i in insns if _max_reg(i) >= regs]
    if over:
        print("   WARNING: %d instruction(s) reference a register >= %d; "
              "desync likely" % (len(over), regs))

    targets = dex.all_targets(code_off)
    print("   branch targets: %s" % ", ".join(sorted("0x%x" % t for t in targets)))
    print("-- listing --")
    for insn in insns:
        mark = " <== branch target" if insn["off"] in targets else ""
        print("  " + dex.describe(insn) + mark)
    return 0


def _max_reg(insn):
    """Highest register number named by an instruction (rough but sufficient)."""
    raw, op = insn["raw"], insn["op"]
    if op in IF_TEST or op in IFIELD_OPS or op in PFIELD_OPS:
        return max(raw[1] >> 4, raw[1] & 0xF)
    if op in IF_TESTZ:
        return raw[1] & 0xF
    if op == 0x12:
        return raw[1] >> 4
    if op in (0x01, 0x04, 0x07, 0x0F, 0x10, 0x11):
        return raw[1] & 0xF          # 12x: two 4-bit registers
    if op in (0x0A, 0x0B, 0x0C, 0x0D, 0x1C, 0x1D, 0x1E, 0x1F, 0x22):
        return raw[1]                # 11x / 21c: one 8-bit register
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
