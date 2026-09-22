#!/usr/bin/env python3
"""Report which native libraries are ACTUALLY mapped into a live process.

`getprop ro.product.cpu.abi` tells you what the device claims to be. It does not
tell you what is executing. Those differ more often than people expect:

  * an x86_64 emulator running an app whose only native libraries are arm64,
    because an ARM translation layer is present;
  * a hardened app whose real libraries are materialized into its data
    directory at runtime, so the paths you see are not the paths inside the APK;
  * a fat APK where the package manager picked a different ABI than you assumed,
    so you patch a `.so` that never loads.

This script reads the live mapping table and reports, per library: the path, the
base address, and the architecture of the actual ELF on disk. It classifies each
path so the interesting ones stand out (system / from-APK / runtime-materialized).

Requires root to read another process's maps.

Usage:
  python lib_map.py --pkg com.example.app
  python lib_map.py --pkg com.example.app --app-only
  python lib_map.py --pid 1234 --all
  python lib_map.py --pkg com.example.app --json
  python lib_map.py --pkg com.example.app --grep ssl

Reading it:
  * A library whose path sits under the app's data dir (not under the APK's
    lib/<abi> dir) was written at runtime. That is a packer/dropper fingerprint
    and it will not be present in a repacked APK -- patch or replace with care.
  * If app libraries are 64-bit ARM but the device primary ABI is x86_64,
    a translator is in play. Timing and some native checks will differ.
  * If the library you patched does not appear here at all, your patch cannot
    matter. That is a plan problem, not a patch problem.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

E_MACHINE = {
    0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "aarch64",
    0x08: "mips", 0xF3: "riscv", 0x16: "s390", 0x15: "ppc",
}
TRANSLATOR_MARKERS = ("houdini", "libndk", "native_bridge", "libntv", "armtrans",
                      "libhoudini", "ndk_translation", "libarm", "exagear", "box64")


def run(cmd: list[str], timeout: int = 60) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return "ERROR: %s" % e


def classify(path: str, pkg: str | None) -> str:
    if path.startswith(("/system/", "/apex/", "/vendor/", "/product/", "/odm/", "/system_ext/")):
        return "system"
    if re.search(r"/data/app/", path):
        return "apk-lib"
    if pkg and (("/data/data/%s" % pkg) in path or ("/data/user/0/%s" % pkg) in path):
        return "materialized"
    if "/data/" in path:
        return "data-other"
    return "other"


def read_elf_arch(sh_fn, path: str) -> str:
    """Read the ELF header on the device and name the machine. '?' means the read failed."""
    hdr = sh_fn("dd if='%s' bs=20 count=1 2>/dev/null | od -An -tx1 2>/dev/null" % path)
    hexs = re.sub(r"[^0-9a-fA-F]", "", hdr)
    if len(hexs) < 40:
        return "?"
    b = bytes.fromhex(hexs[:40])
    if b[:4] != b"\x7fELF":
        return "not-elf"
    cls = {1: 32, 2: 64}.get(b[4], 0)
    little = b[5] == 1
    mach = int.from_bytes(b[18:20], "little" if little else "big")
    if mach in E_MACHINE:
        return E_MACHINE[mach]          # the machine name already implies the width
    return "0x%02x/%db" % (mach, cls or 0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    tgt = ap.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--pkg", help="target package name")
    tgt.add_argument("--pid", type=int, help="target pid")
    ap.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    ap.add_argument("--serial", default=None)
    ap.add_argument("--all", action="store_true", help="include system libraries")
    ap.add_argument("--app-only", action="store_true", help="only APK libs and runtime-materialized libs")
    ap.add_argument("--grep", default=None, help="only paths matching this regex")
    ap.add_argument("--no-arch", action="store_true", help="skip reading ELF headers (faster)")
    ap.add_argument("--max-libs", type=int, default=120, help="cap how many libraries get an arch probe")
    ap.add_argument("--json", action="store_true", dest="as_json")
    a = ap.parse_args()

    def sh(cmd: str, timeout: int = 60) -> str:
        base = [a.adb] + (["-s", a.serial] if a.serial else []) + ["shell", cmd]
        return run(base, timeout)

    def su(cmd: str, timeout: int = 90) -> str:
        base = [a.adb] + (["-s", a.serial] if a.serial else []) + ["shell", 'su -c "%s"' % cmd]
        return run(base, timeout)

    pid = a.pid
    if a.pkg and not pid:
        out = sh("pidof %s" % a.pkg).strip()
        if not out:
            print("no running process for %s -- launch it and let it settle first" % a.pkg, file=sys.stderr)
            return 2
        pid = int(out.split()[0])

    maps = su("cat /proc/%d/maps" % pid)
    if not maps.strip() or "No such file" in maps:
        print("cannot read /proc/%d/maps (root required, or the process is gone)" % pid, file=sys.stderr)
        return 2

    entries: dict[str, dict] = {}
    for line in maps.splitlines():
        m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\S+\s*(.*)$", line)
        if not m:
            continue
        start, end, perms, off, path = m.groups()
        path = path.strip()
        if not path or path.startswith("["):
            continue
        if not path.endswith(".so") and ".so." not in path:
            continue
        e = entries.setdefault(path, {"path": path, "perms": set(), "base": start, "count": 0})
        e["perms"].add(perms)
        e["count"] += 1
        if perms.startswith("r-x") or perms.startswith("r--"):
            e["base"] = min(e["base"], start)

    dev_abi = sh("getprop ro.product.cpu.abi").strip()
    abilist = sh("getprop ro.product.cpu.abilist").strip()
    pkg = a.pkg
    if not pkg:
        cmdline = su("cat /proc/%d/cmdline" % pid).split("\x00")[0].strip()
        pkg = cmdline or None

    rows = []
    probed = 0
    for path, e in sorted(entries.items()):
        kind = classify(path, pkg)
        if a.app_only and kind not in ("apk-lib", "materialized"):
            continue
        # --grep is an explicit narrow request, so honour it across all kinds
        if not a.all and not a.app_only and not a.grep and kind == "system":
            continue
        if a.grep and not re.search(a.grep, path):
            continue
        rows.append({"path": path, "base": e["base"], "kind": kind,
                     "perms": "/".join(sorted(e["perms"])), "maps": e["count"], "arch": "?"})

    if not a.no_arch:
        for r in rows[:a.max_libs]:
            r["arch"] = read_elf_arch(su, r["path"])
            probed += 1

    # translation markers
    markers = sorted({p for p in entries if any(t in p.lower() for t in TRANSLATOR_MARKERS)})
    app_archs = sorted({r["arch"] for r in rows if r["kind"] in ("apk-lib", "materialized")
                        and r["arch"] not in ("?", "not-elf")})
    host_is_x86 = "x86" in dev_abi
    translated = bool(markers) or (host_is_x86 and any(x.startswith(("arm", "aarch64")) for x in app_archs))

    if a.as_json:
        print(json.dumps({"pid": pid, "pkg": pkg, "device_abi": dev_abi, "abilist": abilist,
                          "translation_suspected": translated, "translator_markers": markers,
                          "libs": rows}, indent=2, ensure_ascii=False))
        return 0

    print("pid=%s  pkg=%s" % (pid, pkg or "?"))
    print("device primary abi=%s  abilist=[%s]" % (dev_abi, abilist))
    print("%-13s %-9s %-6s %-6s %s" % ("arch", "kind", "perms", "maps", "path"))
    print("-" * 100)
    for r in rows:
        print("%-13s %-9s %-6s %-6d %s" % (r["arch"], r["kind"], r["perms"], r["maps"], r["path"]))
    print("-" * 100)
    print("mapped libraries shown: %d" % len(rows))
    if not a.no_arch and probed < len(rows):
        print("(architecture probed for the first %d; raise --max-libs to cover the rest -- '?' means not probed)"
              % probed)

    if markers:
        print("\nTRANSLATOR MARKERS PRESENT:")
        for mk in markers:
            print("  " + mk)
        print("  -> native ARM code is being translated. Timing differs from a real ARM device,")
        print("     and native integrity checks may behave differently. Verify the final artifact")
        print("     on the ABI the user actually runs.")
    if app_archs:
        print("\napp library architectures: %s" % ", ".join(app_archs))
    if translated:
        print("translation suspected: YES")
    mat = [r["path"] for r in rows if r["kind"] == "materialized"]
    if mat:
        print("\nRUNTIME-MATERIALIZED libraries (not inside the APK):")
        for p in mat[:20]:
            print("  " + p)
        print("  -> written at runtime by the app or its shell. A repacked APK will not contain")
        print("     them in this location; account for that before assuming your patch is loaded.")
    if not rows:
        print("\nnothing matched. Widen with --all, or check that the process is the one that draws the UI.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
