#!/usr/bin/env python3
"""Capture what is actually on screen -- and say whether the control tree is usable.

Why this exists
---------------
Driving a UI blind (tap a coordinate, wait, tap again) is the single most
expensive habit in device work. A look at the screen resolves in one step what
coordinate guessing cannot resolve in five: the layout moved, a different dialog
is up, a countdown is frozen, a button is disabled, text says why.

Two independent kinds of evidence, and they are not interchangeable:

  * the **image** -- always available, always truthful about what is rendered.
    It is the only evidence for UI drawn by a runtime or a web view, where no
    real controls exist.
  * the **control tree** (`uiautomator dump`) -- precise, diffable, gives exact
    bounds and text. Frequently EMPTY for canvas/webview/cross-platform UI.

This script grabs both, reports the size and whether the tree had content, so
you know which one is actually informative before you rely on it. It never
touches app state.

Usage
-----
  # one look
  python snap.py --out shots --tag before

  # watch a wait: 6 samples, 3 s apart (bounded: hard cap of 20 samples)
  python snap.py --out shots --tag waiting --count 6 --interval 3

  # tree only, no images
  python snap.py --out shots --tag tree --tree-only

  # when nothing is on screen, capture and it will say so rather than guess
  python snap.py --out shots --tag check --serial <serial>

Reading the output
------------------
  * `bytes=0` after both capture paths -> the device refused; see the note in the
    output rather than concluding the screen is blank.
  * `tree=EMPTY` -> do not plan around accessibility bounds. Use the image and
    reason from pixels, or drive the app through a non-UI path.
  * Identical hashes across samples -> nothing is changing. Stop waiting and go
    find out why (this is the stall detector).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import time

MAX_SAMPLES = 20  # hard cap so a typo cannot produce an unbounded loop


def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT after %ss: %s" % (timeout, " ".join(cmd[:4]))
    except FileNotFoundError:
        return 127, "", "not found: %s" % cmd[0]


class Dev:
    def __init__(self, adb: str, serial: str | None):
        self.adb = adb
        self.base = [adb] + (["-s", serial] if serial else [])
        self.serial = serial

    def sh(self, cmd: str, timeout: int = 60) -> str:
        return run(self.base + ["shell", cmd], timeout)[1]

    def su(self, cmd: str, timeout: int = 90) -> str:
        return run(self.base + ["shell", 'su -c "%s"' % cmd], timeout)[1]

    def pull(self, remote: str, local: str, timeout: int = 120) -> bool:
        rc, _, err = run(self.base + ["pull", remote, local], timeout)
        return rc == 0 and os.path.exists(local) and os.path.getsize(local) > 0


def tree_stats(dev: Dev, workdir: str) -> tuple[str, int, int]:
    """Return (status, node_count, text_count). status in {OK, EMPTY, FAILED}."""
    xml = "/data/local/tmp/_snap_ui.xml"
    dev.sh("rm -f " + xml)
    out = dev.su("uiautomator dump %s" % xml, timeout=90)
    if "dumped to" not in out and "UI hierchary" not in out and os.sep not in out:
        # some builds print nothing useful; fall through to the file check anyway
        pass
    local = os.path.join(workdir, "_snap_ui.xml")
    if not dev.pull(xml, local, timeout=120):
        return "FAILED", 0, 0
    try:
        data = open(local, encoding="utf-8", errors="replace").read()
    except Exception:
        return "FAILED", 0, 0
    nodes = len(re.findall(r"<node", data))
    texts = len([t for t in re.findall(r'text="([^"]*)"', data) if t.strip()])
    if nodes == 0:
        return "EMPTY", 0, 0
    # A tree with nodes but almost no text is usually a shell with no real widgets.
    return ("OK" if texts else "SPARSE"), nodes, texts


def capture_image(dev: Dev, workdir: str, name: str) -> tuple[int, str]:
    remote = "/data/local/tmp/%s.png" % name
    dev.su("rm -f " + remote)
    # on-device write then pull: the streaming form returns 0 bytes on some ROMs
    dev.su("screencap -p %s" % remote, timeout=90)
    local = os.path.join(workdir, name + ".png")
    if dev.pull(remote, local, timeout=120):
        n = os.path.getsize(local)
        if n > 0:
            return n, hashlib.sha256(open(local, "rb").read()).hexdigest()[:12]
    # fallback: stream to host
    rc, out, err = run(dev.base + ["exec-out", "screencap -p"], timeout=120)
    if rc == 0:
        data = out.encode("latin1", "ignore") if isinstance(out, str) else b""
        if data:
            open(local, "wb").write(data)
            return len(data), hashlib.sha256(data).hexdigest()[:12]
    return 0, ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    ap.add_argument("--serial", default=None, help="device serial; required when several are attached")
    ap.add_argument("--out", default="snapshots", help="output directory (created if missing)")
    ap.add_argument("--tag", default="snap", help="label used in filenames")
    ap.add_argument("--count", type=int, default=1, help="samples to take (capped at %d)" % MAX_SAMPLES)
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between samples")
    ap.add_argument("--tree-only", action="store_true", help="skip images; only read the control tree")
    ap.add_argument("--image-only", action="store_true", help="skip the control tree")
    a = ap.parse_args()

    if a.count > MAX_SAMPLES:
        print("count capped at %d (asked for %d)" % (MAX_SAMPLES, a.count), file=sys.stderr)
        a.count = MAX_SAMPLES

    workdir = os.path.abspath(a.out)
    os.makedirs(workdir, exist_ok=True)
    dev = Dev(a.adb, a.serial)

    # cheap reachability gate with a timeout, so we fail fast and informatively
    rc, out, err = run(dev.base + ["shell", "echo __ok__"], timeout=30)
    if "__ok__" not in out:
        print("device not answering: %s%s" % (out.strip()[:120], (" / " + err.strip()[:120]) if err else ""),
              file=sys.stderr)
        print("check `adb devices`; if the emulator process is alive but nothing is listening on the adb port,",
              file=sys.stderr)
        print("restart the instance through the vendor console (see references/environment.md).", file=sys.stderr)
        return 2

    tree_status = "skipped"
    nodes = texts = 0
    if not a.image_only:
        tree_status, nodes, texts = tree_stats(dev, workdir)
        print("control tree: %s (nodes=%d, non-empty text=%d)" % (tree_status, nodes, texts))
        if tree_status in ("EMPTY", "FAILED"):
            print("  -> the accessibility tree is not usable here. Do NOT plan around bounds from it.")
            print("     The image is the primary evidence for this UI. Cross-platform runtimes, web views")
            print("     and canvas-drawn UI frequently expose no real controls at all.")
        elif tree_status == "SPARSE":
            print("  -> tree exists but carries almost no text; treat it as unreliable and read the image.")

    prev_hash = None
    same_run = 0
    for i in range(a.count):
        tag = a.tag if a.count == 1 else "%s_%02d" % (a.tag, i)
        if a.tree_only:
            print("%-14s tree-only sample" % tag)
        else:
            size, digest = capture_image(dev, workdir, tag)
            if size == 0:
                print("%-14s bytes=0 -> device refused the capture. Not evidence that the screen is blank." % tag)
            else:
                note = ""
                if digest == prev_hash:
                    same_run += 1
                    note = "  (identical to previous -> nothing changed)"
                else:
                    same_run = 0
                prev_hash = digest
                print("%-14s bytes=%-8d sha=%s%s" % (tag, size, digest, note))
                print("%-14s %s" % ("", os.path.join(workdir, tag + ".png")))
                if same_run >= 2:
                    print("  -> %d identical samples in a row. This is a stall, not a slow operation." % (same_run + 1))
                    print("     Stop waiting: inspect the image, or check the app is still "
                          "alive and in the foreground.")
        if i < a.count - 1:
            time.sleep(max(0.0, a.interval))

    print("\nNow LOOK at the image(s) before deciding the next action.")
    print("Driving blind and waiting is how rounds get wasted; the screen usually states the reason.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
