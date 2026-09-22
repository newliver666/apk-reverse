#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inject a Frida probe script into a running Android app and stay resident.

WHY THIS EXISTS
---------------
`frida -U -f <pkg> -l script.js` has two failure modes that cost real debugging time:
  1. With a real device AND an emulator both attached, the USB auto-selection picks
     the emulator, so you attach to the wrong process and see nothing. This tool
     prefers an explicit remote device over `adb forward`, which cannot be hijacked.
  2. Probe output that only goes to a terminal is lost the moment the terminal
     scrolls, the session detaches, or the app crashes. Here every message is
     written to a log file *and* to stdout, with both the device timestamp and the
     host arrival timestamp -- that pair is itself evidence when you suspect a
     clock skew problem.

It also answers the three questions that otherwise produce a bare traceback:
  * is the `frida` python module importable, and which version?
  * is `adb` reachable, and is the target process actually running?
  * is an on-device frida-server answering on the forwarded port?

USAGE
-----
  python run_probe.py frida_probe.js 10 --pkg com.example.app
  python run_probe.py frida_probe.js 5  --pkg com.example.app --device <serial>
  python run_probe.py frida_probe.js 5  --pkg com.example.app --via usb
  python run_probe.py frida_probe.js 2  --pkg com.example.app --spawn
  python run_probe.py frida_probe.js 10 --pkg com.example.app --log my.log --port 27043

  <script.js>   the probe to inject (e.g. frida_probe.js, see its header to adapt)
  <minutes>     how long to stay attached (default 10)

NOTES
-----
  * The host `frida` package and the on-device `frida-server` must be the SAME
    version, and 16.x is the version to align on: 17.x can fail to locate the
    Android dynamic linker and removes the built-in Java bridge.
  * `--spawn` is the right choice when the problem happens at startup: attach-only
    misses init and the first network calls. Hooks are installed before resume.
  * Log file: a timestamped name is generated unless --log is given.
"""
import argparse
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

DEFAULT_PORT = 27042
DEFAULT_MINUTES = 10
DEFAULT_SERVER_PORT = 27042  # the port frida-server listens on, on the device

FRIDA_INSTALL_HINT = (
    'install the matching host package and the matching device server, e.g.\n'
    '    pip install frida==16.7.19\n'
    '    # then push frida-server-16.7.19-android-<abi> to the device and run it as root'
)


def host_ts():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


class Logger(object):
    """Write every line to stdout AND to a file, flushing both immediately."""

    def __init__(self, path):
        self.path = path
        self.fh = open(path, 'a', encoding='utf-8', errors='replace')

    def line(self, text):
        print(text, flush=True)
        self.fh.write(text + '\n')
        self.fh.flush()

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


def adb_run(adb, serial, args, timeout=30):
    cmd = [adb]
    if serial:
        cmd += ['-s', serial]
    cmd += args
    return subprocess.run(cmd, capture_output=True, text=True,
                          errors='replace', timeout=timeout)


def find_adb(explicit=None):
    if explicit:
        return explicit
    return shutil.which('adb') or shutil.which('adb.exe')


def get_pid(adb, serial, pkg):
    """Return (pid, raw_output). pid is None when the process is not running."""
    try:
        r = adb_run(adb, serial, ['shell', 'pidof', pkg])
    except subprocess.TimeoutExpired:
        return None, 'adb timed out'
    raw = ((r.stdout or '') + (r.stderr or '')).strip()
    if r.returncode != 0 or not raw:
        return None, raw
    first = raw.split()[0]
    if not first.isdigit():
        return None, raw
    return int(first), raw


def attach_remote(frida, port, logger):
    mgr = frida.get_device_manager()
    logger.line('[host %s] registering remote device 127.0.0.1:%d' % (host_ts(), port))
    return mgr.add_remote_device('127.0.0.1:%d' % port)


def attach_usb(frida, device_id, logger):
    if device_id:
        logger.line('[host %s] selecting usb device %s' % (host_ts(), device_id))
        return frida.get_device(device_id, timeout=5)
    logger.line('[host %s] selecting usb device (auto; an emulator can win this race)'
                % host_ts())
    return frida.get_usb_device(timeout=5)


def format_message(message):
    """Turn a frida message into one log line. Never raises."""
    kind = message.get('type')
    if kind == 'send':
        payload = message.get('payload')
        if isinstance(payload, dict):
            dev = payload.get('t') or '-'
            tag = payload.get('tag') or 'SEND'
            msg = payload.get('msg')
            if msg is None:
                msg = payload
            return dev, '%s %s' % (tag, msg)
        return '-', 'SEND %r' % (payload,)
    if kind == 'error':
        desc = message.get('description') or ''
        where = '%s:%s' % (message.get('fileName') or '?', message.get('lineNumber') or '?')
        stack = message.get('stack') or ''
        out = 'FRIDA-ERROR %s (%s)' % (desc, where)
        if stack:
            out += '\n    ' + stack.replace('\n', '\n    ')
        return '-', out
    return '-', '%s %r' % (kind, message)


def main():
    ap = argparse.ArgumentParser(
        description='Inject a Frida probe into a running Android app, log everything '
                    'to stdout and a file, and stay attached for N minutes.')
    ap.add_argument('script', help='path to the frida JS probe, e.g. frida_probe.js')
    ap.add_argument('minutes', nargs='?', type=float, default=DEFAULT_MINUTES,
                    help='how long to stay attached (default %d)' % DEFAULT_MINUTES)
    ap.add_argument('--pkg', default=None, help='target package name, e.g. com.example.app')
    ap.add_argument('--device', default=None,
                    help='adb serial (remote mode) or frida device id (usb mode)')
    ap.add_argument('--via', choices=['remote', 'usb'], default='remote',
                    help='remote = adb forward + explicit remote device (default, '
                         'cannot be hijacked by an emulator); usb = frida.get_usb_device()')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help='host-side forwarded port (default %d)' % DEFAULT_PORT)
    ap.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT,
                    help='port frida-server listens on, on the device (default %d)'
                         % DEFAULT_SERVER_PORT)
    ap.add_argument('--spawn', action='store_true',
                    help='spawn the app instead of attaching, so hooks are live before '
                         'the first network call')
    ap.add_argument('--log', default=None, help='log file path (default: auto-named)')
    ap.add_argument('--adb', default=None, help='path to adb (default: from PATH)')
    ap.add_argument('--script-timeout', type=float, default=30.0,
                    help='seconds to wait for the script to load')
    ap.add_argument('--keep-forward', action='store_true',
                    help='leave the adb forward in place after exit')
    args = ap.parse_args()

    if not os.path.isfile(args.script):
        print('probe script not found: %s' % args.script)
        return 2
    if args.spawn and not args.pkg:
        print('--spawn needs --pkg (there is no pid to attach to)')
        return 2

    log_name = args.log or ('probe-%s-%s.log'
                            % (args.pkg or 'target', datetime.now().strftime('%Y%m%d-%H%M%S')))
    logger = Logger(log_name)
    logger.line('# probe log %s' % os.path.abspath(log_name))
    logger.line('# script=%s minutes=%s via=%s pkg=%s'
                % (os.path.abspath(args.script), args.minutes, args.via, args.pkg))

    # 1) frida python package
    try:
        import frida
    except ImportError:
        logger.line(host_ts() + ' FATAL cannot import the frida python module.\n' +
                    FRIDA_INSTALL_HINT)
        logger.close()
        return 3
    logger.line('[host %s] frida python %s' % (host_ts(), getattr(frida, '__version__', '?')))

    # 2) adb
    adb = find_adb(args.adb)
    if not adb:
        logger.line(host_ts() + ' FATAL adb not found.\n'
                    '    put platform-tools on PATH, or pass --adb <path>')
        logger.close()
        return 3
    logger.line('[host %s] adb %s' % (host_ts(), adb))

    pid = None
    forward_added = False
    device = None
    session = None
    script = None
    counts = {}
    deadline = time.monotonic() + max(args.minutes, 0) * 60.0

    try:
        # 3) remote device over adb forward (default), or plain USB selection
        if args.via == 'remote':
            try:
                r = adb_run(adb, args.device,
                            ['forward', 'tcp:%d' % args.port, 'tcp:%d' % args.server_port])
            except subprocess.TimeoutExpired:
                logger.line(host_ts() + ' FATAL adb forward timed out; is the device responsive?')
                return 3
            if r.returncode != 0:
                msg = ((r.stdout or '') + (r.stderr or '')).strip()
                logger.line(host_ts() + ' FATAL adb forward failed.\n'
                            '    adb said: %s\n'
                            '    if it mentions more than one device, pass --device <serial>;\n'
                            '    check the device is visible with: adb devices' % msg)
                return 3
            forward_added = True
            logger.line('[host %s] forwarded tcp:%d -> device tcp:%d'
                        % (host_ts(), args.port, args.server_port))
            device = attach_remote(frida, args.port, logger)
        else:
            device = attach_usb(frida, args.device, logger)

        # 4) pid: spawn when asked, otherwise attach to the running process
        if args.spawn:
            try:
                pid = device.spawn([args.pkg])
            except Exception as exc:
                logger.line(host_ts() + ' FATAL spawn failed for %s: %s\n'
                            '    check the package is installed: adb shell pm list packages | grep %s'
                            % (args.pkg, exc, args.pkg))
                return 3
            logger.line('[device] spawned %s pid=%s' % (args.pkg, pid))
        else:
            if not args.pkg:
                logger.line(host_ts() + ' FATAL --pkg is required when attaching '
                                        '(or use --spawn with --pkg)')
                return 3
            pid, raw = get_pid(adb, args.device, args.pkg)
            if pid is None:
                logger.line(host_ts() + ' FATAL process not found: %s\n'
                            '    adb output: %s\n'
                            '    start the app first, or use --spawn to launch it under the probe;\n'
                            '    if pidof is unavailable on this ROM, try: adb shell ps -A'
                            % (args.pkg, raw or '<empty>'))
                return 3
            logger.line('[device] pid of %s = %d' % (args.pkg, pid))

        # 5) attach + load
        try:
            session = device.attach(pid)
        except Exception as exc:
            logger.line(host_ts() + ' FATAL attach failed: %s\n'
                        '    usual causes: frida-server not running on the device, a\n'
                        '    host/server version mismatch, or an anti-instrumentation check.\n'
                        '    %s' % (exc, FRIDA_INSTALL_HINT))
            return 3

        with open(args.script, encoding='utf-8') as fh:
            source = fh.read()

        def on_message(message, data):
            dev, text = format_message(message)
            tag = 'OTHER'
            if isinstance(message.get('payload'), dict):
                tag = message['payload'].get('tag') or 'SEND'
            elif message.get('type') == 'error':
                tag = 'FRIDA-ERROR'
            counts[tag] = counts.get(tag, 0) + 1
            logger.line('[host %s] [dev %s] %s' % (host_ts(), dev, text))
            if message.get('type') == 'error':
                desc = message.get('description') or ''
                if 'Java API not available' in desc or 'Java is not defined' in desc:
                    logger.line('[hint] the script loaded but this runtime has no Java bridge. '
                                'That is a version problem, not a hook problem: align the host '
                                'frida package and the on-device frida-server to the same 16.x '
                                'version, then retry. Do not debug the hooks until READY appears.')

        script = session.create_script(source)
        script.on('message', on_message)
        try:
            script.load()
        except Exception as exc:
            logger.line(host_ts() + ' FATAL script load failed: %s\n'
                        '    if this says "Java is not defined", the runtime has no Java\n'
                        '    bridge: align host frida and on-device frida-server to 16.x.'
                        % exc)
            return 3

        if args.spawn:
            device.resume(pid)
            logger.line('[device] resumed pid=%d (hooks were installed before resume)' % pid)

        logger.line('[host %s] attached; staying resident for %s minute(s). '
                    'Now drive the app UI.' % (host_ts(), args.minutes))

        while time.monotonic() < deadline:
            time.sleep(0.5)

    except KeyboardInterrupt:
        logger.line('[host %s] interrupted; detaching' % host_ts())
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if forward_added and not args.keep_forward:
            try:
                adb_run(adb, args.device, ['forward', '--remove', 'tcp:%d' % args.port])
                logger.line('[host %s] removed adb forward tcp:%d' % (host_ts(), args.port))
            except Exception:
                pass

        logger.line('')
        logger.line('== summary: %d message(s)' % sum(counts.values()))
        for tag in sorted(counts):
            logger.line('   %-16s %d' % (tag, counts[tag]))
        if not counts:
            logger.line('   no probe output at all. Ordered checklist:')
            logger.line('     1. did READY appear? if not, the script never loaded')
            logger.line('     2. is the class/overload name you configured really present?')
            logger.line('     3. ClassLoader: the hooks bind against the app classloader')
            logger.line('     4. did the UI action actually reach the business code?')
            logger.line('     5. check THROW lines: a local validation may have returned early')
        logger.line('# log written to %s' % os.path.abspath(log_name))
        logger.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
