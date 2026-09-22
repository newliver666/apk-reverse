#!/usr/bin/env python3
"""
sig_probe.py -- find the exact value Android returns for
`PackageInfo.signatures[0].toCharsString()`.

Why this exists: apps that use their own signing certificate as a *crypto key* need that
value hardcoded after a repack. Deriving it offline is unreliable -- it is platform
dependent, and on modern Android it is a single certificate from the chain, not the whole
`META-INF/*.RSA` blob. Get it from the device, or cross-check offline candidates.

Usage
-----
  # authoritative: read from a running (or launchable) package on a rooted device
  python sig_probe.py --live <package>
  python sig_probe.py --live <package> --serial <adb-serial> --host 127.0.0.1:27042

  # offline: enumerate candidate blobs inside META-INF/*.RSA
  python sig_probe.py --apk <apk>

Output is plain hex, ready to paste into a `const-string` smali patch.

Notes
-----
* --live needs `frida` (pip install frida) plus a matching frida-server on the device.
  Host and device versions must match; see references/dynamic-frida.md.
* `--serial` is honoured for adb calls. If several devices are attached, pass it -- Frida's
  USB auto-selection can silently pick the wrong one.
"""

import argparse
import sys
import time
import zipfile

SIG_EXTS = ('.RSA', '.DSA', '.EC')


# --------------------------------------------------------------------------- DER helpers
def _tlv(data, off):
    """Return (tag, header_len, content_len). Raises on truncation."""
    if off + 2 > len(data):
        raise ValueError('truncated TLV at %d' % off)
    tag = data[off]
    first = data[off + 1]
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or off + 2 + n > len(data):
            raise ValueError('bad length at %d' % off)
        length = int.from_bytes(data[off + 2:off + 2 + n], 'big')
        return tag, 2 + n, length
    return tag, 2, first


def _children(data, start, end):
    """Yield (tag, header_len, content_len, content_off) for each child in [start, end)."""
    off = start
    while off < end:
        tag, hlen, clen = _tlv(data, off)
        yield tag, hlen, clen, off + hlen
        off += hlen + clen


def pkcs7_certificates(blob):
    """Extract the DER certificate blobs from a PKCS#7 SignedData structure.

    ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    SignedData  ::= SEQUENCE { version, digestAlgorithms, contentInfo,
                               certificates [0] IMPLICIT SET OF Certificate, ... }
    """
    out = []
    tag, hlen, clen = _tlv(blob, 0)
    if tag != 0x30:
        return out
    content_off = hlen
    content_end = hlen + clen

    # ContentInfo -> [0] EXPLICIT -> SignedData SEQUENCE
    signed_data = None
    for t, h, c, coff in _children(blob, content_off, content_end):
        if t == 0xA0:                      # content [0] EXPLICIT
            for t2, h2, c2, coff2 in _children(blob, coff, coff + c):
                if t2 == 0x30:             # SignedData
                    signed_data = (coff2, coff2 + c2)
            break
    if signed_data is None:
        return out

    sd_start, sd_end = signed_data
    # children of SignedData: version, digestAlgorithms, contentInfo, certificates [0], ...
    seen_a0 = 0
    for t, h, c, coff in _children(blob, sd_start, sd_end):
        if t == 0xA0:                      # certificates [0] IMPLICIT
            seen_a0 += 1
            if seen_a0 > 1:
                break
            for t3, h3, c3, coff3 in _children(blob, coff, coff + c):
                if t3 == 0x30:             # a Certificate
                    out.append(blob[coff3 - h3:coff3 + c3])
    return out


def candidates_from_apk(path):
    """Every plausible hardcode candidate, longest-first, de-duplicated."""
    results = []
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist()
                 if n.upper().startswith('META-INF/') and n.upper().endswith(SIG_EXTS)]
        for name in names:
            blob = z.read(name)
            whole = ('whole ' + name, blob)
            results.append(whole)
            for i, cert in enumerate(pkcs7_certificates(blob)):
                results.append(('%s cert[%d]' % (name, i), cert))

    seen, uniq = set(), []
    for label, blob in results:
        if blob not in seen:
            seen.add(blob)
            uniq.append((label, blob))
    return uniq


# --------------------------------------------------------------------------- live route
LIVE_JS = r"""
// Single-shot read. No timers: frida's JS runtime has no setTimeout, and using one
// turns a "not ready yet" into a silent no-response. The Python side retries instead.
Java.perform(function () {
    var pkg = PKG_NAME;
    try {
        var app = Java.use('android.app.ActivityThread').currentApplication();
        if (app === null) {
            send({ ok: false, retry: true, error: 'Application not initialized yet' });
            return;
        }
        var ctx = app.getApplicationContext();
        var pm = ctx.getPackageManager();
        var pi = pm.getPackageInfo(pkg, 64);
        var arr = pi.signatures.value;
        var out = [];
        for (var i = 0; i < arr.length; i++) {
            var s = arr[i].toCharsString();
            var blen = -1;
            try { blen = arr[i].toByteArray().length; } catch (e) {}
            out.push({ i: i, hex: s, len: s.length, bytes: blen });
        }
        send({ ok: true, signatures: out });
    } catch (e) {
        send({ ok: false, error: String(e) });
    }
});
"""


def run_live(pkg, serial, host, timeout):
    try:
        import frida
    except ImportError:
        print('[!] frida not installed: pip install frida', file=sys.stderr)
        return 2

    try:
        dev = frida.get_device_manager().add_remote_device(host)
    except Exception as exc:                                  # noqa: BLE001
        print('[!] cannot reach frida-server at %s: %s' % (host, exc), file=sys.stderr)
        print('    is it running, and is the port forwarded?  '
              'adb %sforward tcp:%s tcp:27042'
              % (('-s %s ' % serial) if serial else '',
                 host.rsplit(':', 1)[-1]), file=sys.stderr)
        return 2

    # A running process is preferred; fall back to spawning so package data is readable.
    pid, spawned = None, False
    for p in dev.enumerate_processes():
        if p.name == pkg:
            pid = p.pid
            break
    if pid is None:
        try:
            pid = dev.spawn([pkg])
            spawned = True
        except Exception as exc:                              # noqa: BLE001
            print('[!] package not running and could not be spawned: %s' % exc, file=sys.stderr)
            print('    launch it once, then re-run', file=sys.stderr)
            return 2

    result = {}

    def on_msg(msg, _data):
        if msg.get('type') == 'error':
            result['_js_error'] = msg.get('description') or str(msg)
        else:
            result.update(msg.get('payload') or {})

    try:
        session = dev.attach(pid)
        if spawned:
            dev.resume(pid)
            time.sleep(1.0)

        # Retry at the Python level: right after a spawn the Application object may not
        # exist yet, and the script reports that as retryable rather than failing.
        deadline = time.time() + timeout
        while time.time() < deadline:
            result.clear()
            # V8 is required: on some frida builds the default runtime has no Java bridge,
            # and the failure looks like "no response" rather than a clear error.
            script = session.create_script(
                LIVE_JS.replace('PKG_NAME', repr(pkg).replace("'", '"')), runtime='v8')
            script.on('message', on_msg)
            script.load()
            t0 = time.time()
            while not result and time.time() - t0 < 1.5:
                time.sleep(0.1)
            if result.get('ok') or not result.get('retry'):
                break
            time.sleep(0.4)
    except Exception as exc:                                  # noqa: BLE001
        print('[!] injection failed: %s' % exc, file=sys.stderr)
        return 2

    if not result.get('ok'):
        detail = result.get('error') or result.get('_js_error') or 'no response'
        print('[!] probe failed: %s' % detail, file=sys.stderr)
        return 2

    for sig in result['signatures']:
        print('signature[%d]  toCharsString length = %d   toByteArray bytes = %d'
              % (sig['i'], sig['len'], sig['bytes']))
        print(sig['hex'])
        print()
    return 0


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(
        description='Find the exact signatures[0].toCharsString() value (for hardcoding '
                    'into a repacked APK).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--apk', help='APK to inspect offline (enumerates candidates)')
    g.add_argument('--live', metavar='PKG', help='package name; read the value from the device')
    ap.add_argument('--serial', help='adb serial (when several devices are attached)')
    ap.add_argument('--host', default='127.0.0.1:27042',
                    help='frida-server endpoint for --live (default %(default)s)')
    ap.add_argument('--timeout', type=float, default=20.0,
                    help='seconds to wait for the live probe (default %(default)s)')
    args = ap.parse_args()

    if args.live:
        return run_live(args.live, args.serial, args.host, args.timeout)

    cands = candidates_from_apk(args.apk)
    if not cands:
        print('[!] no META-INF/*.RSA|*.DSA|*.EC in %s (is it signed?)' % args.apk,
              file=sys.stderr)
        return 1

    print('Candidates in %s' % args.apk)
    print('(modern Android returns ONE certificate from the chain, not the whole .RSA --')
    print(' use --live to know which; otherwise build one variant per candidate)\n')
    for label, blob in cands:
        print('%-28s %6d bytes  %5d hex chars' % (label, len(blob), len(blob) * 2))
        print(blob.hex())
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
