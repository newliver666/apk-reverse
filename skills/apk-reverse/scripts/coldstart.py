#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cold-launch an app and capture a time line of screenshots plus logcat signals.

WHY THIS EXISTS
---------------
"Did the patch work?" for anything user-visible -- a splash/ad gate, a forced
update dialog, a login wall, a crash-on-start -- is answered by looking at the
screen over the first seconds of a launch, and by comparison against the
unmodified build. Doing that by hand produces two failures that look like
findings and are not:

  * **Sampling is not observation.** A dialog that appears and is then occluded
    can fall entirely between samples, and every frame you happened to take shows
    something else, which feels like corroboration. This tool captures on a fixed
    short cadence and, crucially, prints what it captured so a human or agent
    actually LOOKS at the frames.
  * **`am start -W` can block past a naive timeout.** It waits for the first
    frame; on some ROMs that never arrives while another window owns the display
    and the command simply hangs. This tool launches without `-W` and derives the
    time line from captures plus logcat instead.

It also records the two facts that decide whether an install even happened:
the installed version, and the on-disk APK hash. "Install succeeded" describes
the request, not the app on disk.

IMPORTANT -- before trusting any screenshot, confirm the foreground activity is
your target. A vendor package installer left on screen (a pending confirmation
from an earlier `adb install`, for example) will be captured instead of your app
and looks completely plausible. `--expect-activity` makes that check automatic.

Usage
-----
    python coldstart.py --serial <SERIAL> --pkg com.example \\
        --activity com.example/.MainActivity --duration 14 --interval 0.8 \\
        --out work/verify/orig --expect-activity com.example/.MainActivity

Requires: adb. `su` on the device is used when available for version/hash facts,
otherwise it degrades to plain `pm`/`dumpsys`.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time


def run(cmd, timeout=30, serial=None):
    """Run a command with a hard timeout; never let a call stall the run."""
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout,
                              text=True, errors='replace')
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, '', 'timeout after %ss' % timeout)


class Device(object):
    def __init__(self, serial, use_su=True, timeout=30):
        self.serial = serial
        self.timeout = timeout
        self.adb = shutil.which('adb') or 'adb'
        self.su = use_su and self._su_works()

    def _su_works(self):
        if self.serial:
            r = run(['adb', '-s', self.serial, 'shell', "su -c 'id'"], 15)
        else:
            r = run(['adb', 'shell', "su -c 'id'"], 15)
        return r.returncode == 0 and 'uid=0' in (r.stdout or '')

    def shell(self, cmd, timeout=None):
        """Run a device shell command, preferring root when available."""
        t = timeout or self.timeout
        if self.serial:
            base = ['adb', '-s', self.serial, 'shell']
        else:
            base = ['adb', 'shell']
        if self.su:
            return run(base + ["su -c '%s'" % cmd.replace("'", "'\\''")], t)
        return run(base + [cmd], t)

    def screencap(self, path, timeout=30):
        """Capture one PNG. Returns bytes written, or -1 on failure."""
        if self.serial:
            base = ['adb', '-s', self.serial]
        else:
            base = ['adb']
        try:
            with open(path, 'wb') as fh:
                subprocess.run(base + ['exec-out', 'screencap', '-p'],
                               stdout=fh, timeout=timeout)
            size = os.path.getsize(path)
            if size < 8:
                return -1
            with open(path, 'rb') as fh:
                if fh.read(8) != b'\x89PNG\r\n\x1a\n':
                    return -1
            return size
        except subprocess.TimeoutExpired:
            return -1


def foreground_activity(dev):
    r = dev.shell('dumpsys activity activities | grep -m1 ResumedActivity')
    m = re.search(r'([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)', r.stdout or '')
    return '%s/%s' % (m.group(1), m.group(2)) if m else None


def installed_facts(dev, pkg):
    facts = {}
    r = dev.shell("dumpsys package %s | grep -E 'versionCode|versionName|firstInstallTime|lastUpdateTime'" % pkg)
    for line in (r.stdout or '').splitlines():
        m = re.match(r'\s*(versionCode|versionName|firstInstallTime|lastUpdateTime)=(.*)', line)
        if m:
            facts[m.group(1)] = m.group(2).strip()
    r = dev.shell('ls /data/app/*/%s*/base.apk 2>/dev/null' % pkg)
    apk_path = (r.stdout or '').strip().splitlines()[:1]
    if apk_path:
        facts['apk_path'] = apk_path[0]
        r2 = dev.shell('sha256sum %s' % apk_path[0])
        m = re.search(r'([0-9a-f]{64})', r2.stdout or '')
        if m:
            facts['apk_sha256'] = m.group(1)
    r = dev.shell('dumpsys package %s | grep -m1 userId=' % pkg)
    m = re.search(r'userId=(\d+)', r.stdout or '')
    if m:
        facts['uid'] = m.group(1)
    return facts


def signal_counts(log_path, patterns):
    """Count occurrences of each pattern in a logcat dump."""
    try:
        with open(log_path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return {}
    return {name: len(re.findall(rx, text)) for name, rx in patterns.items()}


SIGNAL_PATTERNS = {
    'FATAL EXCEPTION': r'FATAL EXCEPTION',
    'VerifyError': r'VerifyError',
    'Bad checksum': r'Bad checksum',
    'IncompatibleClassChangeError': r'IncompatibleClassChangeError',
    'ClassNotFoundException': r'ClassNotFoundException',
    'uncaughtException': r'uncaughtException',
    'am_crash': r'am_crash',
    'ANR': r'ANR in ',
    'Displayed': r'Displayed .*\+([0-9]+)ms',
}


def main(argv):
    ap = argparse.ArgumentParser(
        description='Cold-launch an app and capture a screenshot time line plus '
                    'logcat signals, for before/after comparison.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Usage')[-1][:1200])
    ap.add_argument('--serial', help='adb serial (REQUIRED when several devices are '
                                     'online, so the wrong one is not picked at random)')
    ap.add_argument('--pkg', required=True, help='package name')
    ap.add_argument('--activity', help='component to start (default: monkey/launcher)')
    ap.add_argument('--out', default='coldstart', help='output directory')
    ap.add_argument('--duration', type=float, default=14.0, help='seconds to capture')
    ap.add_argument('--interval', type=float, default=0.8, help='seconds between frames')
    ap.add_argument('--expect-activity', help='warn if the foreground activity is not '
                                              'this (and not the package at all)')
    ap.add_argument('--no-su', action='store_true', help='never use device root')
    ap.add_argument('--keep-old', action='store_true',
                    help='do not clear existing screenshots in the output dir')
    args = ap.parse_args(argv[1:])

    if not shutil.which('adb'):
        print('error: adb not found on PATH')
        return 2

    if not args.serial:
        r = run(['adb', 'devices'])
        online = [ln.split()[0] for ln in (r.stdout or '').splitlines()[1:]
                  if len(ln.split()) >= 2 and ln.split()[1] == 'device']
        if len(online) > 1:
            print('error: %d devices online (%s) and no --serial given. adb would '
                  'pick one at random and you would debug the wrong target.'
                  % (len(online), ', '.join(online)))
            return 2
        if online:
            args.serial = online[0]
            print('[i] single device online; using %s' % args.serial)

    dev = Device(args.serial, use_su=not args.no_su)
    print('[i] serial=%s root=%s' % (args.serial, dev.su))

    os.makedirs(args.out, exist_ok=True)
    shots = os.path.join(args.out, 'shots')
    os.makedirs(shots, exist_ok=True)
    if not args.keep_old:
        for f in os.listdir(shots):
            if f.endswith('.png'):
                os.remove(os.path.join(shots, f))

    facts = installed_facts(dev, args.pkg)
    print('\n== installed build facts')
    for k in sorted(facts):
        print('   %-18s %s' % (k, facts[k]))
    if not facts.get('versionCode'):
        print('   WARNING: no versionCode found -- the package may not be installed')
    print('   (install success describes the request, not the app on disk; the '
          'sha256 above is the on-disk truth)')

    print('\n== clearing logcat')
    dev.shell('logcat -c', timeout=20)

    print('== force-stopping %s' % args.pkg)
    dev.shell('am force-stop %s' % args.pkg, timeout=20)

    print('== launching')
    t0 = time.time()
    if args.activity:
        r = dev.shell('am start -n %s' % args.activity, timeout=25)
    else:
        r = dev.shell('monkey -p %s -c android.intent.category.LAUNCHER 1' % args.pkg,
                      timeout=25)
    out = ((r.stdout or '') + (r.stderr or '')).strip()
    print('   %s' % (out.splitlines()[0] if out else '(no output)'))
    if 'Error' in out or 'Exception' in out:
        print('   LAUNCH ERROR -- read the line above before blaming the patch')

    # live logcat into a file while we capture
    log_path = os.path.join(args.out, 'logcat.txt')
    if args.serial:
        log_cmd = ['adb', '-s', args.serial, 'logcat', '-v', 'threadtime']
    else:
        log_cmd = ['adb', 'logcat', '-v', 'threadtime']
    log_fh = open(log_path, 'w', encoding='utf-8', errors='replace')
    log_proc = subprocess.Popen(log_cmd, stdout=log_fh, stderr=subprocess.DEVNULL)

    frames = []
    idx = 0
    try:
        while True:
            el = time.time() - t0
            if el > args.duration:
                break
            name = 'f%02d_%05.2fs.png' % (idx, el)
            path = os.path.join(shots, name)
            n = dev.screencap(path)
            frames.append((name, n, el))
            print('   %-20s %s' % (name, ('%d bytes' % n) if n > 0 else 'CAPTURE FAILED'))
            idx += 1
            time.sleep(max(0.0, args.interval))
    finally:
        time.sleep(0.5)
        log_proc.terminate()
        try:
            log_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            log_proc.kill()
        log_fh.close()

    fg = foreground_activity(dev)
    print('\n== foreground at end: %s' % fg)
    if args.expect_activity and fg and args.pkg not in fg:
        print('   *** FOREGROUND IS NOT YOUR APP (%s) ***' % fg)
        print('   Everything captured above shows something else -- most often a '
              'vendor package-installer confirmation left over from an install.')
        print('   Clear it (e.g. close the installer, press HOME) and re-run; do not '
              'read these frames as evidence about your build.')

    counts = signal_counts(log_path, SIGNAL_PATTERNS)
    print('\n== logcat signals (%s)' % log_path)
    for name in SIGNAL_PATTERNS:
        print('   %-32s %s' % (name, counts.get(name, 0)))

    m = re.findall(r'Displayed ([^:]+): \+([0-9]+)ms', open(log_path, encoding='utf-8',
                                                            errors='replace').read())
    if m:
        print('\n== launch timing (logcat Displayed)')
        for comp, ms in m:
            print('   %s  %s ms' % (comp.strip(), ms))
    else:
        print('\n   no "Displayed" line: the launch may not have reached a first '
              'frame (a hang or a blocking dialog looks exactly like this)')

    zero = sum(1 for _n, n, _e in frames if n <= 0)
    print('\n== %d frame(s) in %s, %d failed' % (len(frames), shots, zero))

    # the point of the tool: make inspection happen
    print('\n== INSPECT THE FRAMES. A capture nobody looked at is not evidence.')
    nonzero = [f for f in sorted(os.listdir(shots)) if f.endswith('.png')]
    if nonzero:
        print('   start with: %s' % os.path.join(shots, nonzero[0]))
        mid = nonzero[len(nonzero) // 2]
        print('   and:        %s' % os.path.join(shots, mid))
        print('   Byte-identical consecutive frames mean the screen is static -- that '
              'is a finding (a hang, or a dialog waiting), not a capture problem.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
