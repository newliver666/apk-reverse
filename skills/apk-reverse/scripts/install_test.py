#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Install an APK and run a launch health check, extracting the signals that matter.

Automates the verification loop from references/verification.md:
  install -> clear logcat -> launch -> sample pid twice -> scan for fatal signatures
  -> capture a screenshot.

Why the pid is sampled TWICE: a crash loop shows a live pid at any single instant.
The second sample catches it.

Usage
-----
  python install_test.py --apk out/app.apk --pkg com.example.app --activity .MainActivity
  python install_test.py --apk out/app.apk --pkg com.example.app --activity .MainActivity \
      --shots out/shot.png --uninstall-first --grant READ_PHONE_STATE --grant ACCESS_FINE_LOCATION

Useful flags
------------
  --uninstall-first   wipe app data (needed when the signing key changed, and the only
                      way to test "does this survive a fresh install")
  --keep-data         reinstall over the existing app (requires the same signing key;
                      preserves login state -- valuable when the feature under test
                      needs auth)
  --grant NAME        runtime permission to grant (repeatable). Must be granted as
                      root: the shell user gets SecurityException.
  --wait N            seconds between the two pid samples (default 18)

Exit code is 0 only when the app launched AND both pid samples agree.
"""
import argparse
import re
import subprocess
import sys
import time

FATAL = re.compile(
    r'FATAL EXCEPTION|VerifyError|IncompatibleClassChangeError|'
    r'ClassNotFoundException|NoClassDefFoundError|LinkageError|'
    r'Failure starting process|uncaughtException',
    re.I)


def adb(args, serial=None, timeout=600):
    cmd = ['adb']
    if serial:
        cmd += ['-s', serial]
    cmd += args
    r = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=timeout)
    return (r.stdout or '') + (('\n[stderr]\n' + r.stderr) if (r.stderr or '').strip() else '')


def sh(cmd, serial=None):
    return adb(['shell', cmd], serial)


def su(cmd, serial=None):
    return adb(['shell', 'su -c "%s"' % cmd.replace('"', '\\"')], serial)


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument('--apk', required=True)
    ap.add_argument('--pkg', required=True)
    ap.add_argument('--activity', required=True, help='e.g. .MainActivity or fully qualified')
    ap.add_argument('--serial')
    ap.add_argument('--uninstall-first', action='store_true')
    ap.add_argument('--keep-data', action='store_true')
    ap.add_argument('--grant', action='append', default=[])
    ap.add_argument('--wait', type=int, default=18)
    ap.add_argument('--shots')
    a = ap.parse_args()

    s = a.serial
    print('[0] devices:')
    print(adb(['devices', '-l']))

    if a.uninstall_first:
        print('[1] uninstall')
        print(su('am force-stop %s; pm uninstall %s' % (a.pkg, a.pkg), s))
    stage = '/data/local/tmp/_skill_stage.apk'
    print('[2] push')
    print(adb(['push', a.apk, stage], s))
    print('[3] install')
    print(su('pm install -r -t -d %s' % stage, s))

    for perm in a.grant:
        p = perm if perm.startswith('android.permission.') else 'android.permission.' + perm
        su('pm grant %s %s' % (a.pkg, p), s)

    print('[4] clear logcat')
    adb(['logcat', '-c'], s)
    comp = '%s/%s' % (a.pkg, a.activity if a.activity.startswith('.') or '.' in a.activity
                      else a.activity)
    print('[5] launch')
    print(sh('am start -n %s' % comp, s))

    time.sleep(6)
    p1 = sh('pidof %s' % a.pkg, s).strip()
    print('[6] pid @+6s : %s' % (p1 or '(dead)'))
    time.sleep(a.wait)
    p2 = sh('pidof %s' % a.pkg, s).strip()
    print('[7] pid @+%ds : %s' % (6 + a.wait, p2 or '(dead)'))

    print('[8] focus  : %s' % sh('dumpsys window | grep mCurrentFocus', s).strip())

    if a.shots:
        su('screencap -p /sdcard/_skill_shot.png', s)
        print(adb(['pull', '/sdcard/_skill_shot.png', a.shots], s))

    print('[9] fatal signatures:')
    log = adb(['logcat', '-d', '-v', 'brief'], s)
    hits = [ln for ln in log.splitlines() if FATAL.search(ln)]
    if hits:
        for ln in hits[-25:]:
            print('   ', ln)
    else:
        print('    none')

    ok = bool(p1) and p1 == p2 and not hits
    print()
    print('[result] %s' % ('OK  (launched, stable, no fatal signatures)'
                           if ok else 'CHECK (see above)'))
    print('[note] stability is NOT proof the patch worked. Exercise the changed '
          'feature and its neighbours -- see references/verification.md.')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
