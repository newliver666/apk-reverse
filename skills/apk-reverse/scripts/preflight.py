#!/usr/bin/env python3
"""Preflight: prove the environment is sane BEFORE you blame your patch.

Run this at the start of every experiment block, and again whenever something
fails in a way you did not expect. A large share of "my patch broke the app"
turns out to be device state, a dead device server, a leftover proxy setting, or
a clock skew -- all of which look exactly like a broken artifact.

It is deliberately read-only: it changes nothing except optional cleanup of a
device-wide proxy setting and port forwards it created itself.

Usage:
  python preflight.py
  python preflight.py --serial <serial> --pkg com.example.app
  python preflight.py --pkg com.example.app --expect-root
  python preflight.py --cleanup          # remove proxy + frida port forwards it finds
  python preflight.py --json             # machine-readable summary

Exit code is 0 when no BLOCKER was found, 1 otherwise. WARN never fails the run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

BLOCKER, WARN, OK, INFO = "BLOCKER", "WARN", "OK", "INFO"


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, level: str, area: str, detail: str, fix: str = "") -> None:
        self.rows.append((level, area, detail, fix))

    def worst(self) -> str:
        for lv in (BLOCKER, WARN, OK, INFO):
            if any(r[0] == lv for r in self.rows):
                return lv
        return OK


def run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT after %ss: %s" % (timeout, " ".join(cmd[:4]))
    except Exception as e:  # pragma: no cover - defensive
        return 1, "error: %s" % e


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adb", default=os.environ.get("ADB", "adb"), help="adb executable (default: $ADB or 'adb')")
    ap.add_argument("--serial", default=None, help="device serial; required when more than one is attached")
    ap.add_argument("--pkg", default=None, help="target package to check (optional)")
    ap.add_argument("--expect-root", action="store_true", help="treat missing root as a BLOCKER")
    ap.add_argument("--cleanup", action="store_true", help="remove leftover proxy setting and frida forwards")
    ap.add_argument("--json", action="store_true", dest="as_json")
    a = ap.parse_args()

    r = Report()
    ADB = a.adb

    # ---- host tools -------------------------------------------------------
    for tool, why in (
        ("java", "dexlib2 patcher, apksigner"),
        ("python", "all scripts"),
    ):
        found = shutil.which(tool)
        r.add(OK if found else WARN, "host:" + tool, found or "not on PATH",
              "" if found else "install it if you need " + why)
    for tool in ("apksigner", "zipalign", "aapt", "aapt2"):
        found = shutil.which(tool)
        r.add(OK if found else INFO, "host:" + tool, found or "not on PATH",
              "" if found else "only needed for signing/manifest work; build-tools on PATH helps")

    # ---- adb + device selection ------------------------------------------
    if shutil.which(ADB) is None and not os.path.exists(ADB):
        r.add(BLOCKER, "adb", "executable not found: %s" % ADB, "pass --adb <path> or set $ADB")
        return finish(r, a.as_json)

    rc, out = run([ADB, "devices", "-l"])
    if rc != 0:
        r.add(BLOCKER, "adb", "adb devices failed: %s" % out.strip()[:160], "start the adb server; check USB/emulator")
        return finish(r, a.as_json)

    devices = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1], line))
    online = [d for d in devices if d[1] == "device"]

    if not devices:
        r.add(BLOCKER, "device", "no device attached", "boot the emulator/connect the device, then re-run")
        return finish(r, a.as_json)
    if len(online) > 1 and not a.serial:
        r.add(BLOCKER, "device", "%d devices online but no --serial given" % len(online),
              "pass --serial explicitly, or adb will pick one at random and you will debug the wrong target")
    if not online:
        bad = ", ".join("%s(%s)" % (d[0], d[1]) for d in devices)
        r.add(BLOCKER, "device", "attached but not usable: %s" % bad,
              "unauthorized -> accept the USB debugging prompt; offline -> reconnect/reboot the emulator")
        return finish(r, a.as_json)

    serial = a.serial or online[0][0]
    r.add(OK, "device", "using %s (of %d online)" % (serial, len(online)), "")

    def sh(cmd: str, timeout: int = 60) -> str:
        return run([ADB, "-s", serial, "shell", cmd], timeout=timeout)[1]

    def su(cmd: str, timeout: int = 90) -> str:
        return run([ADB, "-s", serial, "shell", 'su -c "%s"' % cmd], timeout=timeout)[1]

    # ---- device facts -----------------------------------------------------
    abi = sh("getprop ro.product.cpu.abi").strip()
    abilist = sh("getprop ro.product.cpu.abilist").strip()
    rel = sh("getprop ro.build.version.release").strip()
    sdk = sh("getprop ro.build.version.sdk").strip()
    model = sh("getprop ro.product.model").strip()
    sec = sh("getenforce").strip()

    r.add(OK, "device:os", "Android %s (sdk %s) %s" % (rel, sdk, model), "")
    r.add(OK, "device:abi", "%s   abilist=[%s]" % (abi, abilist), "")
    r.add(OK if sec.lower() in ("permissive", "") else INFO, "device:selinux", sec or "?", "")

    # translation layer / emulator hints -- these change how native code behaves
    trans = []
    for probe in ("ro.dalvik.vm.native.bridge", "ro.enable.native.bridge.exec", "ro.boot.native_bridge"):
        v = sh("getprop " + probe).strip()
        if v and v != "0":
            trans.append("%s=%s" % (probe, v))
    r.add(WARN if trans else OK, "device:translation",
          "; ".join(trans) if trans else "no ARM translation declared",
          "native arm libraries run through a translator here: timing differs and "
          "some native checks misbehave" if trans else "")
    if re.search(r"^1$", sh("getprop ro.kernel.qemu").strip()):
        r.add(INFO, "device:type", "emulator (ro.kernel.qemu=1)",
              "final verification belongs on the real ABI the user will run")

    # ---- root -------------------------------------------------------------
    idout = su("id")
    has_root = "uid=0" in idout
    lvl = OK if has_root else (BLOCKER if a.expect_root else WARN)
    r.add(lvl, "root", "available" if has_root else "NOT available (%s)" % idout.strip()[:60],
          "" if has_root else "anything beyond static analysis needs root: data dirs, Frida, file locks")

    # ---- clock (silently breaks TLS work) --------------------------------
    dev_epoch = sh("date +%s").strip()
    if dev_epoch.isdigit():
        drift = abs(int(dev_epoch) - int(__import__("time").time()))
        r.add(OK if drift < 120 else WARN, "clock",
              "device/host drift %ds" % drift,
              "" if drift < 120 else
              "an expired/wrong certificate can be nothing but this clock; fix before TLS triage")

    # ---- leftover state that fakes a failure -----------------------------
    proxy = sh("settings get global http_proxy").strip()
    if proxy and proxy not in ("null", ":0"):
        r.add(WARN, "state:proxy", "device-wide http_proxy=%s" % proxy,
              "a leftover proxy makes every request fail; clear with: settings put global http_proxy :0")
        if a.cleanup:
            sh("settings put global http_proxy :0")
            r.add(INFO, "state:proxy", "cleared (--cleanup)", "")
    else:
        r.add(OK, "state:proxy", "not set", "")

    rc_f, fwd = run([ADB, "-s", serial, "forward", "--list"])
    if fwd.strip():
        r.add(INFO, "state:forwards", fwd.strip().replace("\n", " | ")[:200],
              "stale forwards point frida at the wrong place; 'adb forward --remove-all' resets them")
        if a.cleanup:
            run([ADB, "-s", serial, "forward", "--remove-all"])
            r.add(INFO, "state:forwards", "removed (--cleanup)", "")

    # ---- frida server reachability ---------------------------------------
    srv = su("pgrep -f frida-server || pgrep -f kwork")
    if srv.strip().isdigit() or srv.strip().split("\n")[0].strip().isdigit():
        r.add(OK, "frida:server", "device server process alive (pid %s)" % srv.strip().split("\n")[0].strip(), "")
    else:
        r.add(INFO, "frida:server", "no device server process found",
              "only needed for dynamic work; see references/dynamic-frida.md (name it out of obvious paths)")

    # ---- target package ---------------------------------------------------
    if a.pkg:
        pm = sh("pm list packages | grep -F %s" % a.pkg)
        installed = ("package:" + a.pkg) in pm or a.pkg in pm
        r.add(OK if installed else INFO, "target", "installed" if installed else "not installed", "")
        if installed:
            path = sh("pm path %s" % a.pkg).strip()
            uid = su("dumpsys package %s | grep -m1 userId=" % a.pkg).strip()
            r.add(INFO, "target:apk", path[:160] or "?", "")
            r.add(INFO, "target:uid", uid or "?", "re-check after every reinstall: uid increments")
            # the native library dir the package manager will use for this device
            nat = sh("dumpsys package %s | grep -m3 primaryCpuAbi" % a.pkg).strip()
            if nat:
                r.add(INFO, "target:abi", nat.replace("\n", " | ")[:160],
                      "this is the ABI the package manager chose for THIS device")
            maps = su("cat /proc/$(pidof %s | awk '{print $1}')/maps 2>/dev/null | head -1" % a.pkg)
            if maps.strip():
                r.add(INFO, "target:running", "process is running",
                      "prefer a clean cold start before measuring anything")
            else:
                r.add(OK, "target:running", "not running", "")

    # ---- free space -------------------------------------------------------
    # Report by device node, not by the mount-point column: a block device can be
    # mounted at more than one path (an ARM translation shim does exactly this on
    # some emulators), and `df` will then label /data with an unrelated path.
    space = ""
    for line in sh("df -h /data 2>/dev/null").splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 5:
            space = "%s: %s available of %s (%s used)" % (cols[0], cols[3], cols[1], cols[4])
            break
    if space:
        r.add(INFO, "device:space", space, "")

    return finish(r, a.as_json)


def finish(r: Report, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"worst": r.worst(),
                          "rows": [dict(level=lv, area=ar, detail=d, fix=f) for lv, ar, d, f in r.rows]},
                         indent=2, ensure_ascii=False))
        return 1 if r.worst() == BLOCKER else 0

    width = max(len(x[1]) for x in r.rows) if r.rows else 10
    for level, area, detail, fix in r.rows:
        print("%-8s %-*s  %s" % ("[" + level + "]", width, area, detail))
        if fix:
            print(" " * 9 + "%-*s  -> %s" % (width, "", fix))
    print("\nworst: %s" % r.worst())
    if r.worst() == BLOCKER:
        print("Fix every BLOCKER before running another experiment. Do not attribute a failure to your patch yet.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
