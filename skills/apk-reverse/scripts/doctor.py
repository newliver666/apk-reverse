#!/usr/bin/env python3
"""Environment doctor: what can actually run here, and what is missing.

Why this exists
---------------
This skill ships a lot of scripts, and the most common failure mode reported by
users is not "the script is wrong" but "the script would not start and I could not
tell why" - a missing jar, a Python module that does not exist on this interpreter,
a device that is not connected. That wastes a whole round before any reverse
engineering happens.

Run this once before a work block. It answers three questions:

  1. Which capabilities are available right now (static / native / dynamic / device)?
  2. For every script, is it runnable as-is, or what exactly is missing?
  3. Are there environment facts that will silently poison experiments
     (clock skew, a leftover proxy, a dead device server, a wrong-ABI device)?

It never installs anything and never touches a target. Read the report, then go.

What changed, and why the report got worse
------------------------------------------
This script used to answer question 1 from a hand-written table of 28 scripts (the
directory held 51) and from a formula that read

    caps['repack + sign']    = bool(tools['java']['path']) and py['ok']
    caps['smali round-trip'] = bool(tools['java']['path']) and py['ok']

Neither ability follows from `java`: signing needs a signer and `zipalign`, a smali
round-trip needs eight jars. On a host with only a JDK both reported OK, and every gate
downstream inherited an optimism nobody had measured. A capability verdict that is
wrong in the permissive direction is worse than no verdict at all, because it is used
to decide whether a claim is supportable.

So now:

  * the script list is **scanned from this directory**, so it cannot go stale, and the
    printed `registered/checked = N / N` counts every `.py` and `.js` file here;
  * each script's third-party dependencies come from a **static AST pass** over its
    imports, checked against `sys.stdlib_module_names` -- no script is imported or run
    to find out what it needs;
  * a script this pass cannot classify is printed as `unknown` and counted, never
    dropped from the denominator;
  * capability verdicts come from `capabilities.py`, the single registry, which probes
    every atom of a capability's real closure (a missing input artifact included) and
    prints an executable next step with a cost estimate.

A report that says BLOCKED on a host which genuinely cannot sign is the point. Fix the
named atom, or route the work through a capability that is ok.

Usage
-----
    python doctor.py                     # capability + script summary
    python doctor.py --scripts           # per-script runnability table
    python doctor.py --capabilities      # every capability, with next actions
    python doctor.py --device <serial>   # include device checks
    python doctor.py --json              # machine-readable

Exit codes: 0 = nothing blocked, 3 = at least one capability blocked, 2 = usage error,
4 = internal error. The last line is `RESULT=<token>`.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(SKILL_DIR))

if HERE not in sys.path:
    sys.path.insert(0, HERE)
import capabilities as caps  # noqa: E402  (path is set above on purpose)

EXIT_OK = 0
EXIT_USE = 2
EXIT_ENV = 3
EXIT_INTERNAL = 4

TOKENS = {
    'ok': 'env_ok',
    'partial': 'env_partial',
    'blocked': 'env_blocked',
    'use': 'usage_error',
    'internal': 'internal_error',
}

_PROBE = caps.Probe()

# Host executables worth recognising inside a script's source. A literal outside this set
# is treated as data (an adb subcommand, a shell builtin, a path), never as a host tool:
# guessing too eagerly would report a missing tool that was never needed.
KNOWN_HOST_TOOLS = {
    'java', 'javac', 'keytool', 'jarsigner', 'zipalign', 'apksigner', 'adb', 'aapt',
    'aapt2', 'd8', 'dx', 'dexdump', 'frida', 'frida-ps', 'objection',
    'node', 'npm', 'unzip', 'zip', '7z', 'git', 'sqlite3', 'tshark', 'tcpdump',
    'mitmdump', 'rizin', 'rabin2', 'gdb', 'readelf', 'objdump', 'nm', 'strings',
    'clang', 'ndk-build', 'cmake', 'make', 'python', 'python3', 'blutter', 'jadx',
    'apktool', 'dex2jar', 'd2j-dex2jar',
}


# ---------------------------------------------------------------- probing

def extra_tool_dirs():
    """Directories to search beyond PATH (delegated to the capability registry)."""
    return caps.extra_tool_dirs()


def which(name):
    return _PROBE.which(name)


def run(cmd, timeout=15):
    """Run a command, returning (rc, stdout+stderr). Never raises, always bounded."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
        return p.returncode, p.stdout.decode('utf-8', 'replace').strip()
    except FileNotFoundError:
        return 127, 'not found'
    except subprocess.TimeoutExpired:
        return 124, 'TIMEOUT after %ss' % timeout
    except Exception as e:  # pragma: no cover
        return 1, '%s: %s' % (type(e).__name__, e)


def have_module(name):
    """Existence only. Importing a probe target can start threads and touch devices."""
    return _PROBE.module(name)


# ---------------------------------------------------------------- tools

def tool_info():
    """name -> {path, version, note}. Version probes are bounded and failure is data."""
    out = {}
    probes = [
        ('java', ['java', '-version']),
        ('javac', ['javac', '-version']),
        ('keytool', ['keytool', '-help']),
        ('jarsigner', ['jarsigner', '-help']),
        ('adb', ['adb', 'version']),
        ('apksigner', ['apksigner', '--version']),
        ('zipalign', ['zipalign']),
        ('dexdump', ['dexdump']),
        ('frida', ['frida', '--version']),
        ('frida-ps', ['frida-ps', '--version']),
        ('objection', ['objection', '--version']),
        ('apktool', ['apktool', '--version']),
        ('jadx', ['jadx', '--version']),
        ('python', [sys.executable, '--version']),
        ('unzip', ['unzip', '-v']),
        ('git', ['git', '--version']),
        ('sqlite3', ['sqlite3', '--version']),
        ('node', ['node', '--version']),
        ('tshark', ['tshark', '-v']),
        ('mitmdump', ['mitmdump', '--version']),
        ('rizin', ['rizin', '-v']),
        ('rabin2', ['rabin2', '-v']),
        ('gdb', ['gdb', '--version']),
        ('readelf', ['readelf', '--version']),
        ('adb-devices', ['adb', 'devices']),
    ]
    for name, cmd in probes:
        if cmd[0] != sys.executable and which(cmd[0]) is None:
            # A tool that ships as a runnable .jar is not on PATH but is still usable via
            # `java -jar`. Reporting it missing would make the report lie downward.
            jar_hit = _PROBE.find_jar(name)
            if jar_hit:
                out[name] = {'path': jar_hit,
                             'version': 'runnable as: java -jar %s'
                                        % os.path.basename(jar_hit),
                             'note': 'jar-only (not a PATH command)'}
            else:
                out[name] = {'path': None, 'version': None, 'note': 'not on PATH'}
            continue
        rc, txt = run(cmd)
        first = ''
        for line in txt.splitlines():
            line = line.strip()
            if line:
                first = line
                break
        out[name] = {
            'path': which(cmd[0]) or cmd[0],
            'version': first[:160],
            'note': '' if rc == 0 else 'exit %d: %s' % (rc, txt[:120]),
        }
    return out


def java_toolchain():
    """Find the jars a smali round-trip or a signer needs, wherever they live."""
    found = {}
    for d in _PROBE.jar_dirs():
        for dirpath, _dirs, files in os.walk(d):
            if dirpath.count(os.sep) - d.count(os.sep) > 3:
                continue
            for f in files:
                if f.lower().endswith('.jar'):
                    found.setdefault(f, os.path.join(dirpath, f))
    return found


# ---------------------------------------------------------------- static script analysis

def _const_strings(tree):
    """Module- and function-level `NAME = 'literal'` bindings, best effort."""
    consts = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt, val = node.targets[0], node.value
            if isinstance(tgt, ast.Name) and isinstance(val, ast.Constant) \
                    and isinstance(val.value, str):
                consts.setdefault(tgt.id, val.value)
    return consts


def _as_name(node, consts):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    return None


def _first_list_elem(call_node, consts):
    """`subprocess.run(['adb', ...])`: the first element of the first list argument."""
    for arg in getattr(call_node, 'args', []):
        if isinstance(arg, ast.List) and arg.elts:
            return _as_name(arg.elts[0], consts)
    return None


def static_python_deps(path):
    """Third-party modules and host tools a .py file needs, from its source alone.

    Returns (modules, tools, error). `error` is set when the file could not be parsed,
    which the caller must surface as `unknown` rather than as "no dependencies".
    """
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            src = fh.read()
        tree = ast.parse(src, path)
    except (OSError, SyntaxError) as exc:
        return [], [], '%s: %s' % (type(exc).__name__, exc)

    stdlib = set(sys.stdlib_module_names)
    local = {f[:-3] for f in os.listdir(HERE) if f.endswith('.py')}
    modules, tools = set(), set()
    consts = _const_strings(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                modules.add(a.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                modules.add(node.module.split('.')[0])
        elif isinstance(node, ast.Call):
            fn = node.func
            attr = fn.attr if isinstance(fn, ast.Attribute) else (
                fn.id if isinstance(fn, ast.Name) else '')
            # A dependency is a tool the script *resolves in order to use*, or the
            # program of a subprocess. A bare `shutil.which('x')` is only a probe -- the
            # script usually handles the negative branch itself -- and counting it as a
            # dependency reports doctor.py as needing frida-server, which is a device
            # binary it merely looks for.
            if attr in ('resolve_tool', 'find_executable'):
                if node.args:
                    name = _as_name(node.args[0], consts)
                    if name in KNOWN_HOST_TOOLS:
                        tools.add(name)
            elif attr in ('run', 'check_output', 'check_call', 'Popen', 'call', 'spawn',
                          'execvp', 'execv'):
                name = _first_list_elem(node, consts)
                if name in KNOWN_HOST_TOOLS:
                    tools.add(name)

    third = sorted(m for m in modules
                   if m not in stdlib and m not in local and not m.startswith('_'))
    return third, sorted(tools), None


def static_js_deps(path):
    """Modules a Frida JS script `require()`s. Frida's require is not a Python import,
    so these are recorded as declarations, not resolved against the Python environment."""
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            src = fh.read()
    except OSError as exc:
        return [], 'OSError: %s' % exc
    # strip line comments cheaply; a require() inside a string is not worth the parser
    body = '\n'.join(ln.split('//')[0] for ln in src.splitlines())
    return sorted(set(re.findall(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", body))), None


def discover_scripts():
    """Every `.py` and `.js` in this directory. The list is the directory, not a table."""
    names = []
    for f in sorted(os.listdir(HERE)):
        if f.endswith(('.py', '.js')) and os.path.isfile(os.path.join(HERE, f)):
            names.append(f)
    return names


def scan_scripts(cap_results):
    """Per-script facts: static deps, declared capability, and a verdict.

    The verdict is the conjunction of the two independent facts about the script --
    whether its own dependencies resolve, and whether the capability it serves is
    available -- so a script is never reported runnable merely because it exists.
    """
    rows = []
    for name in discover_scripts():
        path = os.path.join(HERE, name)
        kind = 'js' if name.endswith('.js') else 'py'
        cap_ids, cap_source = caps.capabilities_for_script(name, path)

        row = {
            'script': name, 'kind': kind, 'present': os.path.isfile(path),
            'capabilities': cap_ids if cap_ids else [],
            'capability_source': cap_source,
            'modules': [], 'missing_modules': [], 'tools': [], 'missing_tools': [],
            'js_requires': [], 'error': None, 'deps_source': '', 'verdict': 'ok',
        }

        if kind == 'py':
            mods, tools, err = static_python_deps(path)
            row['deps_source'] = 'ast-import-scan'
            row['error'] = err
            row['modules'] = mods
            row['tools'] = tools
            row['missing_modules'] = [m for m in mods if not have_module(m)]
            row['missing_tools'] = [t for t in tools if which(t) is None]
        else:
            reqs, err = static_js_deps(path)
            row['deps_source'] = 'js-require-scan'
            row['error'] = err
            row['js_requires'] = reqs

        cap_states = [cap_results[c]['status'] for c in row['capabilities']
                      if c in cap_results]
        missing_modules = row['missing_modules']
        missing_tools = row['missing_tools']
        cap_unknown = cap_ids is None
        # A script's verdict is the conjunction of two independent facts: whether its own
        # dependencies resolve, and whether the capability it serves is available.
        #
        # A missing *module* is fatal to the process (the import is at module level), so
        # it blocks. A missing *tool* is not always fatal: repack.py resolves apksigner /
        # keytool / zipalign only on the signing path, so on a host with no build-tools it
        # is still fully usable with --no-sign, and calling that BLOCKED would be a
        # pessimism of its own. When at least one capability the script serves is not
        # blocked, a missing tool downgrades the script to PARTIAL and names the tool.
        if cap_unknown or row['error']:
            row['verdict'] = 'unknown'
        elif cap_states and all(s == 'blocked' for s in cap_states):
            row['verdict'] = 'blocked'
        elif missing_modules:
            row['verdict'] = 'blocked'
        elif missing_tools and not cap_states:
            row['verdict'] = 'blocked'
        elif missing_tools or 'partial' in cap_states:
            row['verdict'] = 'partial'
        else:
            row['verdict'] = 'ok'

        row['runnable'] = row['verdict'] in ('ok', 'partial')
        rows.append(row)
    return rows


# ---------------------------------------------------------------- device

def device_report(serial=None):
    if which('adb') is None:
        return {'available': False, 'reason': 'adb not on PATH',
                'devices': [], 'root': False, 'device_frida_processes': []}
    cmd = ['adb'] + (['-s', serial] if serial else []) + ['devices', '-l']
    rc, txt = run(cmd, timeout=20)
    if rc != 0:
        return {'available': False, 'reason': txt[:200], 'devices': [],
                'root': False, 'device_frida_processes': []}
    devices = []
    for line in txt.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith('*'):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append({'serial': parts[0], 'state': parts[1],
                            'info': ' '.join(parts[2:])[:160]})
    out = {'available': True, 'devices': devices, 'raw': txt[:400], 'root': False,
           'device_frida_processes': []}
    if not devices:
        out['reason'] = 'no device/emulator attached'
        return out

    tgt = serial or devices[0]['serial']
    props = {}
    for key in ('ro.product.cpu.abi', 'ro.product.cpu.abilist', 'ro.build.version.release',
                'ro.build.version.sdk', 'ro.product.model'):
        rc, v = run(['adb', '-s', tgt, 'shell', 'getprop', key], timeout=15)
        props[key] = v if rc == 0 else ''
    out['target'] = tgt
    out['props'] = props

    # root?
    rc, v = run(['adb', '-s', tgt, 'shell', 'su -c id'], timeout=15)
    out['root'] = (rc == 0 and 'uid=0' in v)
    out['root_raw'] = v[:120]

    # clock skew: a classic silent experiment-poisoner
    rc, dev_epoch = run(['adb', '-s', tgt, 'shell', 'date +%s'], timeout=15)
    try:
        dev_t = int(dev_epoch.strip())
        out['clock_skew_s'] = abs(time.time() - dev_t)
    except Exception:
        out['clock_skew_s'] = None

    # leftover forwards and proxies
    rc, fwd = run(['adb', '-s', tgt, 'forward', '--list'], timeout=15)
    out['forwards'] = [ln for ln in fwd.splitlines() if ln.strip()][:10]
    rc, prox = run(['adb', '-s', tgt, 'shell', 'settings get global http_proxy'], timeout=15)
    out['http_proxy'] = prox.strip()[:120]

    # is a frida server already running on device? (a common source of "the app
    # suddenly detects instrumentation" while you believe nothing is attached)
    rc, ps = run(['adb', '-s', tgt, 'shell', 'ps -A'], timeout=20)
    hits = [ln for ln in ps.splitlines()
            if 'frida' in ln.lower() and 'grep' not in ln.lower()]
    out['device_frida_processes'] = [h.strip()[:140] for h in hits[:6]]
    return out


# ---------------------------------------------------------------- reporting

def capability_section(results, verbose=True):
    lines = caps.human_report(results, verbose=verbose)
    blocked = [c for c, r in results.items() if r['status'] == 'blocked']
    partial = [c for c, r in results.items() if r['status'] == 'partial']
    lines.append('')
    lines.append('  ok=%d  partial=%d  blocked=%d  (of %d capabilities)'
                 % (len(results) - len(blocked) - len(partial), len(partial),
                    len(blocked), len(results)))
    return lines


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error. Keep the RESULT= contract on that path too:
    a caller that branches on the last line must not have to special-case bad usage."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write('%s: error: %s\n' % (self.prog, message))
        print('RESULT=%s' % TOKENS['use'])
        raise SystemExit(EXIT_USE)


def main():
    ap = _Parser(
        description='Check what this environment can actually do. Exit 0 = nothing '
                    'blocked, 3 = a capability is blocked, 2 = usage, 4 = internal.')
    ap.add_argument('--device', default=None, metavar='SERIAL', help='probe this device')
    ap.add_argument('--scripts', action='store_true', help='per-script runnability table')
    ap.add_argument('--capabilities', action='store_true',
                    help='every capability with its missing atoms and next actions '
                         '(the default prints the same list compactly)')
    ap.add_argument('--json', action='store_true', dest='as_json', help='emit JSON')
    args = ap.parse_args()

    try:
        py = {'version': '%d.%d.%d' % sys.version_info[:3],
              'ok': sys.version_info[:2] >= (3, 9),
              'note': '' if sys.version_info[:2] >= (3, 9)
                      else 'scripts target 3.9+; older interpreters may fail on syntax'}
        dev = device_report(args.device)
        # Hand the device facts to the registry so it does not re-probe the device.
        _PROBE.set_device({
            'available': bool(dev.get('devices')),
            'devices': [d['serial'] for d in dev.get('devices', [])],
            'root': bool(dev.get('root')),
            'frida_server': bool(dev.get('device_frida_processes')),
            'reason': dev.get('reason', ''),
        })
        cap_results = caps.resolve_all(_PROBE)
        tools = tool_info()
        jars = java_toolchain()
        rows = scan_scripts(cap_results)
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write('internal error: %s: %s\n' % (type(exc).__name__, exc))
        print('RESULT=%s' % TOKENS['internal'])
        return EXIT_INTERNAL

    status, code, token = caps.verdict(cap_results)

    counts = {'ok': 0, 'partial': 0, 'blocked': 0, 'unknown': 0}
    for r in rows:
        counts[r['verdict']] = counts.get(r['verdict'], 0) + 1
    unknown = [r['script'] for r in rows if r['verdict'] == 'unknown']
    total = len(rows)
    py_files = sum(1 for r in rows if r['kind'] == 'py')
    js_files = total - py_files

    warnings = []
    for cid, r in cap_results.items():
        for m in r['partial']:
            warnings.append('%s: reduced -- %s' % (cid, m['atom']))
    if unknown:
        warnings.append('dependency verdict unknown for %d script(s): %s'
                        % (len(unknown), ', '.join(unknown)))
    for r in rows:
        for m in r['missing_modules']:
            warnings.append('%s: missing python module %s' % (r['script'], m))
        for t in r['missing_tools']:
            warnings.append('%s: missing tool %s' % (r['script'], t))

    # The next action is the first *blocked* capability's, not the first partial one's:
    # a reduced capability is a caveat, a blocked one is what stops the work.
    hints = [cap_results[c]['next_action'] for c in caps.CAPABILITIES
             if c in cap_results and cap_results[c]['status'] == 'blocked'
             and cap_results[c]['next_action']]

    if args.as_json:
        payload = {
            'status': status,
            'exit_code': code,
            'capability': None,
            'next_action': hints[0] if hints else '',
            'warnings': warnings,
            'evidence': [
                {'kind': 'capability', 'capability': cid, 'atom': e['atom'],
                 'ok': e['ok'], 'detail': e['detail'], 'source': e['source']}
                for cid, r in cap_results.items() for e in r['evidence']
            ] + [
                {'kind': 'script', 'script': r['script'],
                 'detail': 'verdict=%s deps=%s capabilities=%s'
                           % (r['verdict'], r['deps_source'],
                              ','.join(r['capabilities']) or 'unknown')}
                for r in rows
            ],
            # the pre-existing keys are kept so an existing consumer keeps working
            'python': py,
            'tools': tools,
            'jars': jars,
            'device': dev,
            'capabilities': cap_results,
            'capabilities_legacy': {c: r['status'] for c, r in cap_results.items()},
            'scripts': rows,
            'script_counts': {'registered': total, 'checked': total,
                              'py': py_files, 'js': js_files,
                              'ok': counts['ok'], 'partial': counts['partial'],
                              'blocked': counts['blocked'], 'unknown': counts['unknown']},
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print('RESULT=%s' % token)
        return code

    print('=' * 74)
    print('apk-reverse environment doctor')
    print('=' * 74)
    print('platform : %s %s / %s' % (platform.system(), platform.release(),
                                     platform.machine()))
    print('python   : %s  %s' % (py['version'], '' if py['ok'] else '<-- ' + py['note']))

    print('\n--- capabilities (%d) ---' % len(cap_results))
    for line in capability_section(cap_results, verbose=args.capabilities):
        print(line)

    print('\n--- tools ---')
    for name, info in tools.items():
        if name in ('adb-devices',):
            continue
        mark = 'OK ' if info['path'] else '-- '
        ver = info['version'] or info['note']
        print('  [%s] %-12s %s' % (mark, name, (ver or '')[:96]))

    print('\n--- java jars found near this skill ---')
    if jars:
        for k in sorted(jars):
            print('  %s' % k)
    else:
        print('  (none) - a smali round-trip needs the baksmali/smali/dexlib2 jar set.')
        print('  smtool.py reads --cp, then APK_REVERSE_SMALI_CP, then scripts/smali_cp.txt.')
        print('  doctor.py itself looks under APKREV_JARS and this skill directory.')

    print('\n--- device ---')
    if not dev.get('available'):
        print('  unavailable: %s' % dev.get('reason'))
    elif not dev.get('devices'):
        print('  no device attached (adb works)')
    else:
        print('  target   : %s' % dev.get('target'))
        for k, v in (dev.get('props') or {}).items():
            print('  %-9s: %s' % (k.replace('ro.', ''), v))
        print('  root     : %s' % ('yes' if dev.get('root') else 'no'))
        skew = dev.get('clock_skew_s')
        if skew is not None:
            flag = ' <-- FIX THIS, clock drift poisons time-based checks' if skew > 30 else ''
            print('  clock skew: %ss%s' % (skew, flag))
        if dev.get('forwards'):
            print('  leftovers : adb forward entries still present: %s' % dev['forwards'])
        if dev.get('http_proxy', '').strip() not in ('', 'null', ':0'):
            print('  leftovers : device http_proxy = %s' % dev['http_proxy'])
        if dev.get('device_frida_processes'):
            print('  WARNING   : a frida process is already running on device:')
            for p in dev['device_frida_processes']:
                print('              %s' % p)
            print('              If the target dies only while this is up, you are looking at')
            print('              a probe aimed at YOU. Stop it before concluding anything.')

    print('\n--- scripts ---')
    print('  directory: %s' % HERE)
    print('  registered/checked = %d / %d   (.py=%d, .js=%d)'
          % (total, total, py_files, js_files))
    print('  ok=%d  partial=%d  blocked=%d  unknown=%d'
          % (counts['ok'], counts['partial'], counts['blocked'], counts['unknown']))

    if args.scripts:
        for r in rows:
            mark = {'ok': 'OK     ', 'partial': 'PARTIAL', 'blocked': 'BLOCKED',
                    'unknown': 'UNKNOWN'}[r['verdict']]
            why = []
            if not r['present']:
                why.append('file missing')
            if r['error']:
                why.append('unparsed: %s' % r['error'][:60])
            if r['missing_modules']:
                why.append('missing modules: ' + ', '.join(r['missing_modules']))
            if r['missing_tools']:
                why.append('missing tools: ' + ', '.join(r['missing_tools']))
            if r['kind'] == 'js':
                why.append('frida JS (requires scanned: %s)'
                           % (', '.join(r['js_requires']) or 'none'))
            if r['capability_source'] == 'mapped' and not r['capabilities']:
                why.append('no capability mapped')
            if r['capability_source'] == 'self':
                why.append('reports on this environment rather than using it')
            caps_txt = ','.join(r['capabilities']) if r['capabilities'] else (
                'self' if r['capability_source'] == 'self' else 'unknown')
            print('  [%s] %-30s %-28s %s'
                  % (mark, r['script'], caps_txt, '; '.join(why)))
        if counts['unknown']:
            print('\n  UNKNOWN means this pass could not decide the dependency set. It is '
                  'counted above,\n  not skipped: read the file before trusting it.')
    else:
        print('  use --scripts for the per-script table')
    if counts['blocked']:
        blocked_names = [r['script'] for r in rows if r['verdict'] == 'blocked']
        print('  blocked scripts (%d): %s'
              % (len(blocked_names), ', '.join(blocked_names[:8])
                 + (' ...' if len(blocked_names) > 8 else '')))

    if hints:
        print('\n--- next action ---')
        print('  %s' % hints[0])

    print('\nRead references/long-task-discipline.md before a long block:')
    print('  bound every wait, look at the screen while you wait, and record the '
          'time-to-death before patching.')
    print('RESULT=%s' % token)
    return code


if __name__ == '__main__':
    sys.exit(main())
