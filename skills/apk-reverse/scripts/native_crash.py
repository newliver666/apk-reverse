#!/usr/bin/env python3
"""Extract native crash blocks from a log or tombstone and locate the fault.

Native deaths are the expensive kind: no Java stack, often no obvious cause, and
the interesting question ("which library, which offset, is this a real fault or
an arranged one?") is buried in a debug dump that is tedious to read by hand.

This reads a saved `logcat` capture or a tombstone file and reports, per crash:

  * the signal, fault address, and cause
  * the register state that matters (the faulting pointer)
  * the backtrace, split into your own libraries vs system libraries
  * a verdict hint when the fault address looks *arranged* rather than accidental

With `--lib NAME=PATH` it also resolves a frame to a local copy of the library
and prints the bytes at that offset, plus a disassembly window when a decoder is
available.

Why the verdict hint matters: a hardening layer that decides the environment is
hostile rarely calls `kill`. It more often arranges a fault -- load a small
constant, use it as a pointer -- so the death looks like an ordinary bug. The
tell is a fault address that is a small integer combined with a register holding
that same integer. This script flags that shape so you look at the right place
instead of hunting a bug that is not there.

Usage
-----
  python native_crash.py capture.txt
  python native_crash.py tombstone_07
  python native_crash.py capture.txt --lib libfoo.so=/path/to/local/libfoo.so
  python native_crash.py capture.txt --lib libfoo.so=./libfoo.so --disasm 16
"""

import argparse
import os
import re
import struct
import sys

SIGNAL_RE = re.compile(
    r"signal\s+(\d+)\s+\((\w+)\)\s*,?\s*code\s+(\d+)\s*\(([^)]+)\)\s*,?\s*fault addr\s+(0x[0-9a-fA-F]+)")
PID_RE = re.compile(r"pid:\s*(\d+),\s*tid:\s*(\d+),\s*name:\s*(\S+)\s*>>>\s*(\S+)")
PROC_RE = re.compile(r"Cmdline:\s*(\S+)")
UPTIME_RE = re.compile(r"Process uptime:\s*(\d+)")
FRAME_RE = re.compile(r"#(\d+)\s+pc\s+([0-9a-fA-F]+)\s+(\S+)")
REG_RE = re.compile(r"^\s*([xX]\d{1,2}|sp|lr|pc|pst)\s+([0-9a-fA-F]{8,16})")
SYSTEM_LIB_RE = re.compile(r"^/(apex|system|vendor|data/dalvik-cache|memfd)")


def is_system_lib(path):
    if not path.startswith("/"):
        return True
    return bool(SYSTEM_LIB_RE.match(path))


def parse(text):
    """Yield crash dicts."""
    lines = text.splitlines()
    crashes = []
    i = 0
    while i < len(lines):
        m = SIGNAL_RE.search(lines[i])
        # some ROMs print the signal line without "F DEBUG"; accept both
        if not m:
            i += 1
            continue
        block = {"signal": int(m.group(1)), "signame": m.group(2),
                 "si_code": m.group(4), "fault": m.group(5),
                 "frames": [], "regs": {}, "raw": []}
        # walk up a little to pick up pid/cmdline/uptime printed just before
        for j in range(max(0, i - 25), i):
            ln = lines[j]
            mm = PID_RE.search(ln)
            if mm and "pid" not in block:
                block["pid"], block["tid"], block["tname"], block["proc"] = mm.groups()
            mm = PROC_RE.search(ln)
            if mm and "proc" not in block:
                block["proc"] = mm.group(1)
            mm = UPTIME_RE.search(ln)
            if mm:
                block["uptime"] = mm.group(1)
            if "Cause:" in ln and "cause" not in block:
                block["cause"] = ln.split("Cause:", 1)[1].strip()
        # walk down through the dump
        j = i
        while j < len(lines) and j < i + 120:
            ln = lines[j]
            if j > i + 3 and SIGNAL_RE.search(ln) and j > i + 3:
                break
            block["raw"].append(ln.strip())
            mm = PID_RE.search(ln)
            if mm and "pid" not in block:
                block["pid"], block["tid"], block["tname"], block["proc"] = mm.groups()
            mm = PROC_RE.search(ln)
            if mm and "proc" not in block:
                block["proc"] = mm.group(1)
            mm = UPTIME_RE.search(ln)
            if mm:
                block["uptime"] = mm.group(1)
            if "Cause:" in ln and "cause" not in block:
                block["cause"] = ln.split("Cause:", 1)[1].strip()
            mm = FRAME_RE.search(ln)
            if mm:
                # Backtrace lines look like either of:
                #   #00 pc 00000000000128cc  /data/app/.../lib/arm64/libfoo.so
                #   #02 pc 00000000000cccd0  /apex/.../libc.so (__pthread_start+256)
                # The path is group(3); anything after it is a symbol in parens.
                path = mm.group(3)
                rest = ln.split(path, 1)[1].strip() if path in ln else ""
                sym = ""
                m2 = re.search(r"\(([^)]+)\)", rest)
                if m2:
                    sym = m2.group(1)
                block["frames"].append({
                    "n": mm.group(1), "pc": int(mm.group(2), 16),
                    "path": path, "symbol": sym,
                })
            # Register dumps put several registers on one line, so collect all of
            # them rather than only the leading one.
            for k, v in re.findall(r"\b([xX]\d{1,2}|sp|lr|pc|pst)\s+([0-9a-fA-F]{8,16})\b",
                                   ln.replace("F DEBUG   :", " ")):
                block["regs"][k] = int(v, 16)
            if "backtrace:" in ln:
                pass
            j += 1
        i = j if j > i else i + 1
        crashes.append(block)
    return crashes


def verdict_hint(crash):
    hints = []
    fault = int(crash["fault"], 16)
    regs = crash["regs"]
    if fault <= 0x100:
        holder = [k for k, v in regs.items() if v == fault]
        hints.append("fault address is a small integer (%s)." % crash["fault"])
        if holder:
            hints.append("register(s) %s hold exactly that value -- this is the shape of an "
                         "ARRANGED fault, not an accident." % ", ".join(sorted(holder)))
        hints.append("check whether the instruction at the faulting pc loaded that constant "
                     "a few instructions earlier and used it as a pointer.")
    if crash["signame"] == "SIGKILL":
        hints.append("SIGKILL with no tombstone: this is a deliberate termination, not a bug. "
                     "No crash dump exists because nothing faulted.")
    if crash.get("cause") and "null pointer" in crash["cause"] and fault > 0x100:
        hints.append("a genuine null-ish dereference; treat as an ordinary bug unless a small "
                     "constant is involved.")
    return hints


def load_libs(specs):
    out = {}
    for s in specs or []:
        if "=" not in s:
            sys.exit("--lib expects NAME=PATH, got %r" % s)
        name, path = s.split("=", 1)
        with open(path, "rb") as fh:
            out[name] = fh.read()
    return out


def maybe_disasm(data, offset, count):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_X86, CS_MODE_64
    except Exception:
        return None
    # guess arch from ELF e_machine
    if data[:4] != b"\x7fELF":
        return None
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine == 183:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        start = offset & ~3
    elif machine == 62:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        start = max(0, offset - 16)
    else:
        return None
    out = []
    for ins in md.disasm(data[start:start + count * 8], start):
        mark = " <<<" if ins.address <= offset < ins.address + ins.size else ""
        out.append("      0x%06x  %-10s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
        if len(out) >= count:
            break
    if not out:
        # capstone stopped immediately -- say so rather than implying emptiness
        return ["      (decoder produced nothing from this offset; a silent stop is not "
                "evidence there is no code here)"]
    return out


def main():
    ap = argparse.ArgumentParser(description="Locate native crashes from a log or tombstone.")
    ap.add_argument("logfile", help="logcat capture or tombstone file")
    ap.add_argument("--lib", action="append", metavar="NAME=PATH",
                    help="resolve frames for this library name to a local file")
    ap.add_argument("--disasm", type=int, default=0, metavar="N",
                    help="disassemble N instructions around the faulting pc")
    ap.add_argument("--frames", type=int, default=12, help="how many frames to print")
    args = ap.parse_args()

    if not os.path.exists(args.logfile):
        sys.exit("no such file: %s" % args.logfile)
    with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    crashes = parse(text)
    if not crashes:
        print("no native crash block found in %s" % args.logfile)
        print("")
        print("This is a real negative only if the capture covers the death. Check:")
        print("  - was the crash buffer cleared *after* the build under test was installed?")
        print("  - does the capture include the tombstone? (a SIGKILL leaves none)")
        print("  - did the process die at all, or did it merely restart?")
        return

    libs = load_libs(args.lib)

    for idx, c in enumerate(crashes, 1):
        print("=" * 72)
        print("CRASH %d" % idx)
        print("  process   : %s" % c.get("proc", "?"))
        print("  pid/tid   : %s / %s" % (c.get("pid", "?"), c.get("tid", "?")))
        if c.get("uptime"):
            print("  uptime    : %ss  <-- time from launch to death; your test window must "
                  "exceed this" % c["uptime"])
        print("  signal    : %s (%d), si_code=%s" % (c["signame"], c["signal"], c["si_code"]))
        print("  fault addr: %s" % c["fault"])
        if c.get("cause"):
            print("  cause     : %s" % c["cause"])

        hints = verdict_hint(c)
        if hints:
            print("  HINTS")
            for h in hints:
                print("    - %s" % h)

        app_frames = [f for f in c["frames"] if not is_system_lib(f["path"])]
        if app_frames:
            print("  backtrace (your libraries):")
            for f in app_frames[:args.frames]:
                print("    #%s pc 0x%x  %s%s"
                      % (f["n"], f["pc"], os.path.basename(f["path"]),
                         ("  (%s)" % f["symbol"]) if f["symbol"] else ""))
        else:
            print("  backtrace: no frame inside an app library")
            print("    -> the fault is in the runtime or a system library; an app-side")
            print("       patch is unlikely to be the cause. Look at what called in.")

        if c["frames"]:
            print("  full backtrace:")
            for f in c["frames"][:args.frames]:
                tag = "system" if is_system_lib(f["path"]) else "APP"
                print("    #%s [%s] pc 0x%x  %s%s"
                      % (f["n"], tag, f["pc"], (f["path"] or "?"),
                         ("  (%s)" % f["symbol"]) if f["symbol"] else ""))

        # resolve against local libraries
        for f in c["frames"]:
            base = os.path.basename(f["path"])
            for name, data in libs.items():
                if name in base or base in name:
                    print("  local %s @ 0x%x:" % (name, f["pc"]))
                    if args.disasm and f is c["frames"][0]:
                        for line in maybe_disasm(data, f["pc"], args.disasm) or []:
                            print(line)
                    else:
                        print("      raw: %s" % data[f["pc"]:f["pc"] + 16].hex(" "))
        print("")

    print("=" * 72)
    print("RECORD THIS: signal, fault addr, and the time-to-death above. They are the")
    print("baseline an attempted fix must be measured against -- without them a later")
    print("run cannot distinguish 'fixed' from 'the timing changed'.")


if __name__ == "__main__":
    main()
