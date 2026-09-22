#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Locate an instruction by decoded semantics and report its exact byte offset.

WHY THIS EXISTS
---------------
You know what the instruction *does* ("a branch on the config boolean whose target
starts the countdown") but you need the *byte offset* to patch it. Two shortcuts
fail:

  * baksmali listings give smali line numbers, not code offsets. `.line` tracks
    source lines, breaks 1:N, and cannot be converted reliably.
  * a hard-coded offset dies the moment the sample is rebuilt, and a wrong offset
    in an equal-length patch corrupts the neighbouring instruction silently.

So this tool decodes the method and filters on semantics. It always prints the
surrounding instructions so you can see which side of a branch you are about to
change -- the polarity mistake is the most common way a patch does the exact
opposite of the goal and still starts cleanly.

Filter language (all optional; combined with AND, comma = OR within a repeated
flag):

  NAME                     substring match on the class, method or string operand
  @Member                  field or method name operand equals/contains Member
  =literal                a const/4 literal equals this integer
  #Class/member            a branch whose TARGET reads this field of this class
  >kind                    instruction kind: if-test if-testz invoke return
                           move-result const4 nop goto switch field sfield
  $name                    the ENCLOSING method name must contain this

Examples
--------
  # a boolean gate whose taken path reads Cfg.enabled
  python dex_find_insn.py app.apk --class 'Lcom/example/SplashActivity;' \\
      --method u --filter '#Lcom/example/Cfg;*enabled'

  # every invoke of a method named like goHome, with 3 lines of context
  python dex_find_insn.py app.apk --filter '@goHome' --kind invoke -C 3

  # where a specific literal is compared
  python dex_find_insn.py app.apk --class 'Lcom/example/PlayerActivity;' --filter '=1' --kind if-testz

Exit codes: 0 = at least one hit, 1 = no hits (a finding: say so, do not retry the
same filter), 2 = usage error.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dexutil import (  # noqa: E402
    IF_TEST, IF_TESTZ, INVOKE_OPS, MOVE_RESULT_OPS, load_dex,
)

_KIND_MAP = {
    "if-test": IF_TEST,
    "if-testz": IF_TESTZ,
    "invoke": INVOKE_OPS,
    "return": (0x0F, 0x10, 0x11),
    "move-result": MOVE_RESULT_OPS,
    "const4": (0x12,),
    "const16": (0x13,),
    "goto": (0x28, 0x29, 0x2A),
    "switch": (0x2B, 0x2C),
    "nop": (0x00,),
}
_FIELD_READ = tuple(range(0x52, 0x59))
_FIELD_WRITE = tuple(range(0x59, 0x60))
_SFIELD = tuple(range(0x60, 0x6E))
_KIND_MAP["field"] = _FIELD_READ
_KIND_MAP["field-write"] = _FIELD_WRITE
_KIND_MAP["sfield"] = _SFIELD


class Filter(object):
    """One compiled filter expression."""

    def __init__(self, text):
        self.raw = text
        self.kind = text[1:] if text.startswith(">") else None
        self.member = text[1:] if text.startswith("@") else None
        self.literal = int(text[1:]) if text.startswith("=") else None
        self.target_field = None
        self.target_class = None
        self.enclosing = text[1:] if text.startswith("$") else None
        self.text = None
        if text.startswith("#"):
            spec = text[1:]
            if "/" in spec and ("*" in spec):
                cls, mem = spec.split("*", 1)
                self.target_class, self.target_field = cls, mem
            elif "*" in spec:
                self.target_field = spec.split("*", 1)[1]
            else:
                self.target_class = spec
        elif not any(text.startswith(p) for p in ("@", "=", ">", "$")):
            self.text = text

    def describe(self):
        return self.raw


def _operand_text(dex, insn):
    """All names this instruction mentions (class, method, field, string)."""
    parts = []
    op = insn["op"]
    if op in INVOKE_OPS:
        cls, nm, ds = dex.method(int.from_bytes(insn["raw"][2:4], "little"))
        parts += [cls, nm, ds]
    elif op in _FIELD_READ + _FIELD_WRITE + _SFIELD:
        cls, nm, ty = dex.field(int.from_bytes(insn["raw"][2:4], "little"))
        parts += [cls, nm, ty]
    elif op in (0x19, 0x1A):
        parts.append(dex.string_safe(int.from_bytes(insn["raw"][2:4], "little")))
    return parts


def _matches(dex, insn, filters, code_off):
    """All filters must hold (AND)."""
    for f in filters:
        if f.kind:
            ops = _KIND_MAP.get(f.kind)
            if ops is None:
                raise ValueError("unknown kind: %s" % f.kind)
            if insn["op"] not in ops:
                return False
        if f.literal is not None:
            if insn["op"] != 0x12:
                return False
            val = insn["raw"][1] & 0xF
            if val > 7:
                val -= 16
            if val != f.literal:
                return False
        if f.member:
            if insn["op"] not in INVOKE_OPS:
                return False
            _cls, nm, _ds = dex.method(int.from_bytes(insn["raw"][2:4], "little"))
            if f.member not in nm:
                return False
        if f.target_class or f.target_field:
            tgt = dex.branch_target(insn)
            if tgt is None:
                return False
            t_insn = dex.insn_at(code_off, tgt)
            if t_insn is None or not (0x52 <= t_insn["op"] <= 0x58):
                return False
            cls, nm, _ty = dex.field(int.from_bytes(t_insn["raw"][2:4], "little"))
            if f.target_class and f.target_class != cls:
                return False
            if f.target_field and f.target_field not in nm:
                return False
        if f.text:
            hay = " ".join(_operand_text(dex, insn))
            if f.text.lower() not in hay.lower():
                return False
    return True


def scan(dex, filters, kind_only=None, class_pattern=None, method_pattern=None,
         limit=None):
    """Yield (fqcn, method_name, descriptor, code_off, insn, all_insns, idx)."""
    hits = 0
    cls_re = re.compile(class_pattern) if class_pattern else None
    mth_re = re.compile(method_pattern) if method_pattern else None

    for fqcn in dex.class_names():
        if cls_re and not cls_re.search(fqcn):
            continue
        try:
            methods = list(dex.methods_of(fqcn))
        except Exception:
            continue
        for section, midx, _c, name, desc, code_off in methods:
            if code_off == 0:
                continue
            if mth_re and not mth_re.search(name):
                continue
            for f in filters:
                if f.enclosing and f.enclosing not in name:
                    break
            insns = list(dex.decode(code_off))
            # a decode that does not land on the method end means offsets here
            # cannot be trusted; report the method rather than silent misses
            info = dex.code_info(code_off)
            expected = info["insns_off"] + info["insns_size"] * 2
            clean = (insns[-1]["off"] + insns[-1]["units"] * 2 == expected) if insns else False
            for i, insn in enumerate(insns):
                if kind_only and insn["op"] not in _KIND_MAP.get(kind_only, ()):
                    continue
                if filters and not _matches(dex, insn, filters, code_off):
                    continue
                yield (fqcn, name, desc, code_off, insn, insns, i, clean)
                hits += 1
                if limit and hits >= limit:
                    return


def main(argv):
    ap = argparse.ArgumentParser(
        description="Find an instruction by decoded semantics; print its exact "
                    "byte offset and surrounding context.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples")[-1][:1500])
    ap.add_argument("target", help=".dex or .apk/.zip (use --entry to pick a dex)")
    ap.add_argument("--entry", help="archive member (default: first classes*.dex)")
    ap.add_argument("--class", dest="cls", help="regex over the class descriptor")
    ap.add_argument("--method", help="regex over the method name")
    ap.add_argument("--filter", action="append", default=[],
                    help="filter expression, repeatable (AND across, OR within a flag "
                         "list). See the module docstring for the language.")
    ap.add_argument("--kind", help="restrict to one instruction kind (see docstring)")
    ap.add_argument("-C", "--context", type=int, default=2,
                    help="instructions of context to print (default 2)")
    ap.add_argument("--limit", type=int, default=40, help="max hits (default 40)")
    ap.add_argument("--show-unclean", action="store_true",
                    help="also print hits from methods whose decode did not align")
    args = ap.parse_args(argv[1:])

    dex, entry = load_dex(args.target, args.entry)
    problems = dex.check()
    if problems:
        print("structural problems in %s (%s):" % (args.target, entry))
        for p in problems:
            print("  - %s" % p)
        return 2

    filters = [Filter(a) for a in args.filter]
    print("== %s (%s) %d classes" % (args.target, entry,
                                     dex.header["class_defs_size"]))
    if filters:
        print("   filters: %s" % ", ".join(f.describe() for f in filters))

    found = 0
    for fqcn, name, desc, code_off, insn, insns, idx, clean in scan(
            dex, filters, args.kind, args.cls, args.method, args.limit):
        if not clean and not args.show_unclean:
            print("\n!! %s.%s%s  decode did not align; offsets unreliable, "
                  "skipping (use --show-unclean to see anyway)"
                  % (fqcn, name, desc))
            continue
        found += 1
        print("\n-- %s.%s%s" % (fqcn, name, desc))
        print("   code_off=0x%x  insns_off=0x%x  (decode clean: %s)"
              % (code_off, code_off + 16, clean))
        lo = max(0, idx - args.context)
        hi = min(len(insns), idx + args.context + 1)
        for j in range(lo, hi):
            marker = "  <== HIT" if j == idx else ""
            print("   %s%s" % (dex.describe(insns[j]), marker))
        print("   >>> file offset of the instruction: 0x%x" % insn["off"])
        if insn["op"] in IF_TEST or insn["op"] in IF_TESTZ:
            tgt = dex.branch_target(insn)
            t_insn = dex.insn_at(code_off, tgt)
            print("   >>> branch TAKEN target 0x%x: %s"
                  % (tgt, dex.describe(t_insn) if t_insn else "?"))
            nxt = insn["off"] + insn["units"] * 2
            n_insn = dex.insn_at(code_off, nxt)
            print("   >>> branch FALL-THROUGH 0x%x: %s"
                  % (nxt, dex.describe(n_insn) if n_insn else "?"))
            print("   >>> decide which side you want BEFORE patching; a wrong "
                  "polarity still starts cleanly")

    print("\n== %d hit(s)" % found)
    if not found:
        print("   no match. Do not retry the same filter: either the decode is "
              "unclean (see --show-unclean) or the behaviour lives in another "
              "layer (native / another dex / another class).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
