#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capability registry: the one place that decides what this host can actually do.

WHY THIS EXISTS
---------------
`doctor.py` used to answer "can I repack and sign here?" from a hand-written guess:

    caps['repack + sign']    = bool(tools['java']['path']) and py['ok']
    caps['smali round-trip'] = bool(tools['java']['path']) and py['ok']

Neither of those abilities follows from `java` being on PATH. Signing needs a signer
(`apksigner`, or an `uber-apk-signer` jar) and `zipalign`; a smali round-trip needs eight
jars on a classpath. On a host with only a JDK, that formula reported OK for both, and
every gate downstream that trusted the report inherited an optimism nobody had measured.

So the capability question is answered here, once, from probed facts:

  * a capability has a **closure** -- the atoms it needs, plus the capabilities it depends
    on, expanded recursively (`depends_on`), so `repack_signed` cannot be OK while its
    own prerequisite `repack_unsigned` is blocked;
  * an atom is either probed on this host (a tool on PATH / `APKREV_TOOLS`, an importable
    module, a jar set, a device, a root shell) or it is an external **artifact** the host
    cannot install (`artifacts:dart_snapshot`) -- those are reported as missing, never
    silently assumed;
  * a missing atom carries a **next action that can be executed**, not a mood: the exact
    directory to expose, environment variable to set, or `pip`/download command to run;
  * a cost estimate is attached only where this repository has measured one, and is
    labelled `unverified` where it has not. A guess presented as a measurement is exactly
    the failure this module exists to remove.

Any tool this repository prefers over a generic alternative is listed under the atom it
belongs to, so "use X" is backed by a probe rather than a recommendation.

WHAT IT DOES NOT DO
-------------------
It never installs anything, never imports a probed module (probing uses
`importlib.util.find_spec`, so a module is never executed), and never touches a target.

CAPABILITY DECLARATION
----------------------
A script may declare its capability as the first line of its own docstring, written as

    capability: <capability_id>[, <capability_id>]

directly under the opening quotes, before the prose. `doctor.py` reads that declaration
when it is present. Scripts without one are resolved through `SCRIPT_CAPABILITIES` below,
which is an explicit, auditable mapping; a script present in neither is reported as
`unknown` and **counted**, never skipped.

Usage
-----
    python capabilities.py                    # every capability, one line each
    python capabilities.py --verbose          # + missing atoms and the next action
    python capabilities.py --list             # ids and names only
    python capabilities.py <capability_id>    # one capability, verbosely
    python capabilities.py --json             # machine-readable, all
    python capabilities.py --json static_dex  # machine-readable, one

Exit codes: 0 = every capability ok, 3 = at least one blocked, 2 = usage error,
4 = internal error. The last line is `RESULT=<token>`.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(SKILL_DIR))

# ---------------------------------------------------------------- exit codes
# 0 success / 1 negative finding / 2 usage / 3 environment short of a capability
# 4 internal error. Shared by every script in this kit; keep the numbers stable.
EXIT_OK = 0
EXIT_USE = 2
EXIT_ENV = 3
EXIT_INTERNAL = 4

TOKENS = {
    'ok': 'capabilities_ok',
    'partial': 'capabilities_partial',
    'blocked': 'capabilities_blocked',
    'use': 'usage_error',
    'internal': 'internal_error',
}

# ---------------------------------------------------------------- atoms

SMALI_JARS = [
    'smali-2.5.2.jar',
    'antlr-runtime-3.5.2.jar',
    'stringtemplate-3.2.1.jar',
    'baksmali-2.5.2.jar',
    'util-2.5.2.jar',
    'jcommander-1.64.jar',
    'guava-27.1-android.jar',
    'dexlib2-2.5.2.jar',
]

# Cost estimates. `basis` is the strength label of the *measurement*:
#   observed   -- timed in this repository, figure and source recorded
#   unverified -- nobody here has timed it; the number is a planning aid only
ATOMS = {
    'python39': {
        'name': 'Python 3.9+',
        'kind': 'python',
        'est_minutes': 0,
        'basis': 'observed',
    },
    'module:capstone': {
        'name': 'capstone (disassembly backend)',
        'kind': 'module',
        'module': 'capstone',
        'install': 'python -m pip install capstone',
        'est_minutes': 1,
        'basis': 'unverified',
    },
    'module:frida': {
        'name': 'frida (host package)',
        'kind': 'module',
        'module': 'frida',
        'install': 'python -m pip install frida',
        'est_minutes': 2,
        'basis': 'unverified',
        'note': 'the host package version must match the frida-server version on device',
    },
    'tool:java': {
        'name': 'java (JDK)',
        'kind': 'tool',
        'tool': 'java',
        'install': 'install a JDK 17+ and put its bin/ on PATH',
        'est_minutes': 15,
        'basis': 'unverified',
    },
    'tool:javac': {
        'name': 'javac (JDK compiler)',
        'kind': 'tool',
        'tool': 'javac',
        'install': 'install a JDK (not a JRE); javac ships with the JDK',
        'est_minutes': 15,
        'basis': 'unverified',
    },
    'tool:keytool': {
        'name': 'keytool (keystore creation)',
        'kind': 'tool',
        'tool': 'keytool',
        'install': 'keytool ships with the JDK; put <JDK>/bin on PATH '
                   '(a JDK whose launcher dir is on PATH only exposes java/javac)',
        'est_minutes': 2,
        'basis': 'unverified',
    },
    'tool:jarsigner': {
        'name': 'jarsigner (v1 signature check)',
        'kind': 'tool',
        'tool': 'jarsigner',
        'install': 'jarsigner ships with the JDK; put <JDK>/bin on PATH',
        'est_minutes': 2,
        'basis': 'unverified',
    },
    'tool:zipalign': {
        'name': 'zipalign (Android build-tools)',
        'kind': 'tool',
        'tool': 'zipalign',
        'install': 'install Android build-tools: sdkmanager "build-tools;34.0.0", '
                   'then expose the directory (see the APKREV_TOOLS hint)',
        'est_minutes': 10,
        'basis': 'unverified',
    },
    'tool:apksigner': {
        'name': 'apksigner (Android build-tools)',
        'kind': 'tool',
        'tool': 'apksigner',
        'install': 'install Android build-tools: sdkmanager "build-tools;34.0.0", '
                   'then expose the directory (see the APKREV_TOOLS hint)',
        'est_minutes': 10,
        'basis': 'unverified',
    },
    'tool:jadx': {
        'name': 'jadx (decompiler)',
        'kind': 'tool',
        'tool': 'jadx',
        'install': 'download the jadx release zip and either put its bin/ on PATH or '
                   'put the unpacked directory on APKREV_TOOLS',
        'est_minutes': 5,
        'basis': 'unverified',
    },
    'tool:apktool': {
        'name': 'apktool (resource round-trip)',
        'kind': 'tool',
        'tool': 'apktool',
        'install': 'download apktool.jar + the wrapper script and put them on PATH '
                   'or on APKREV_TOOLS',
        'est_minutes': 5,
        'basis': 'unverified',
    },
    'tool:adb': {
        'name': 'adb (platform-tools)',
        'kind': 'tool',
        'tool': 'adb',
        'install': 'install Android platform-tools and put the directory on PATH',
        'est_minutes': 5,
        'basis': 'unverified',
    },
    'tool:frida-cli': {
        'name': 'frida CLI',
        'kind': 'tool',
        'tool': 'frida',
        'install': 'python -m pip install frida-tools',
        'est_minutes': 3,
        'basis': 'unverified',
    },
    'tool:git': {
        'name': 'git',
        'kind': 'tool',
        'tool': 'git',
        'install': 'install git and put it on PATH',
        'est_minutes': 5,
        'basis': 'unverified',
    },
    'tool:dexdump': {
        'name': 'dexdump (independent dex reader)',
        'kind': 'tool',
        'tool': 'dexdump',
        'install': 'dexdump ships in Android build-tools; expose the build-tools '
                   'directory (see the APKREV_TOOLS hint)',
        'est_minutes': 1,
        'basis': 'unverified',
    },
    'toolchain:ndk': {
        'name': 'NDK / kernel build chain (clang for android kernels)',
        'kind': 'tool',
        'tool': 'clang',
        'install': 'install the NDK and a matching kernel source tree; a kernel-side '
                   'build needs the device kernel headers, not just clang',
        'est_minutes': 45,
        'basis': 'unverified',
    },
    'jars:smali': {
        'name': 'smali/baksmali jar set (8 jars)',
        'kind': 'jars',
        'jars': SMALI_JARS,
        'install': 'download the 8 jars listed in scripts/smali_cp.txt, then either set '
                   'APK_REVERSE_SMALI_CP=<dir> (what smtool.py reads), write the paths '
                   'into scripts/smali_cp.txt, or pass --cp per invocation',
        'est_minutes': 5,
        'basis': 'unverified',
        'note': 'smali_cp.txt ships with bare filenames only, so it does not resolve '
                'to real jars until the paths are filled in',
    },
    'artifact:signer': {
        'name': 'an APK signer (apksigner, or uber-apk-signer jar)',
        'kind': 'any',
        'alternatives': ['tool:apksigner', 'jar:uber-apk-signer'],
        'install': 'install Android build-tools for apksigner, or download '
                   'uber-apk-signer.jar and point APKREV_JARS at its directory',
        'est_minutes': 10,
        'basis': 'unverified',
    },
    'device': {
        'name': 'a connected device (adb sees one)',
        'kind': 'device',
        'install': 'attach a device or start an emulator, confirm with: adb devices',
        'est_minutes': 2,
        'basis': 'unverified',
    },
    'device_root': {
        'name': 'root shell on that device (su -c id)',
        'kind': 'device_root',
        'install': 'this is a property of the device, not of the host: use an '
                   'engineering/userdebug build, Magisk/KernelSU, or an emulator '
                   'started with -writable-system',
        'est_minutes': 20,
        'basis': 'unverified',
    },
    'device_frida_server': {
        'name': 'frida-server available on the device',
        'kind': 'device_frida',
        'install': 'push the frida-server build matching the host package version and '
                   'the device ABI, then start it as root; run_probe.py --via usb also '
                   'accepts a host-side server',
        'est_minutes': 5,
        'basis': 'unverified',
    },
    'artifact:dart_snapshot': {
        'name': 'a Dart AOT snapshot dump (pp.txt + asm/ from blutter, or aotopsy)',
        'kind': 'artifact',
        'path_glob': None,
        'install': 'this is an input artifact, not an installable tool: build blutter '
                   '(git clone worawit/blutter, one build per Dart version) and run it '
                   'against libapp.so, or run the pinned aotopsy front end',
        'est_minutes': 2,
        'basis': 'observed',
        'note': 'blutter build measured at ~78 s end to end in this repository '
                '(docs/tool-verification/TOOL-VERDICTS.md); nothing else in this '
                'capability is blocked by it',
    },
}

# Repository files a gate needs. Checked relative to REPO_ROOT.
GATE_FILES = {
    'file:check_repo.py': 'check_repo.py',
    'file:check_refs.py': 'check_refs.py',
    'file:check_commands.py': 'check_commands.py',
    'file:scan_leaks.py': 'skills/apk-reverse/scripts/scan_leaks.py',
}

# ---------------------------------------------------------------- capabilities
#
# `required` participates in the verdict: any missing atom blocks the capability.
# `optional` degrades it: the capability still runs, but a named part of it does not.
# `depends_on` is expanded recursively, so a prerequisite's blockers are inherited.

CAPABILITIES = {
    'static_dex': {
        'name': 'Static dex / zip / strings analysis',
        'required': ['python39'],
        'optional': [],
        'scripts': ['dexutil.py', 'dex_strings.py', 'dex_classdiff.py', 'dex_strpatch.py',
                    'dex_patch_bytes.py', 'dex_find_insn.py', 'dex_check_verifier.py',
                    'find_refs.py', 'apk_diff.py', 'blob_decode.py'],
        'note': 'dexutil is the shared reader; its decoder is checked against the '
                'official dexdump output rather than against itself',
    },
    'static_native': {
        'name': 'Static ELF / .so analysis and constant patching',
        'required': ['python39'],
        'optional': ['module:capstone'],
        'scripts': ['elf_plt.py', 'so_constpatch.py', 'svc_scan.py', 'native_crash.py'],
        'note': 'elf_plt and so_constpatch do not need capstone; svc_scan refuses to '
                'run without it, and native_crash needs it for the arm64 disassembly',
    },
    'static_jadx': {
        'name': 'jadx decompilation',
        'required': ['python39', 'tool:jadx'],
        'optional': [],
        'note': 'preferred over reading smali by hand when the question is Java-level: '
                'one command replaces a whole-tree search',
    },
    'static_apktool': {
        'name': 'apktool unpack / resource round-trip',
        'required': ['python39', 'tool:apktool'],
        'optional': ['tool:java'],
        'note': 'not on the dex-patching path; needed only when resources or the '
                'manifest must be rebuilt as XML',
    },
    'smali_roundtrip': {
        'name': 'Smali disassemble / assemble round-trip',
        'required': ['python39', 'tool:java', 'jars:smali'],
        'optional': ['tool:javac'],
        'scripts': ['smtool.py', 'patch_smali.py'],
        'note': 'javac is only needed to compile a fixture (vmp_diff_harness.py); '
                'the round-trip itself runs jars through java -cp',
    },
    'repack_unsigned': {
        'name': 'Repack an APK without signing (--no-sign path)',
        'required': ['python39'],
        'optional': [],
        'scripts': ['repack.py'],
        'note': 'the unsigned path needs no Java tooling at all: it is zipfile plus '
                'the STORED-entry and alignment rules',
    },
    'repack_signed': {
        'name': 'Repack, align and sign an APK',
        'required': ['python39', 'tool:java', 'tool:keytool', 'tool:zipalign',
                     'artifact:signer'],
        'optional': ['tool:jarsigner'],
        'depends_on': ['repack_unsigned'],
        'scripts': ['repack.py', 'install_test.py'],
        'note': 'this is the capability the old doctor reported from `java` alone; '
                'each of java / keytool / zipalign / signer is probed separately here',
    },
    'device_static': {
        'name': 'On-device static work (pull, list, read files)',
        'required': ['python39', 'tool:adb', 'device'],
        'optional': [],
        'scripts': ['devsh.py', 'preflight.py'],
    },
    'device_root': {
        'name': 'On-device privileged work (root shell)',
        'required': ['python39', 'device_root'],
        'optional': [],
        'depends_on': ['device_static'],
        'scripts': ['coldstart.py', 'snap.py', 'grab_crash.py', 'lib_map.py'],
        'note': 'device_root is a property of the device; a non-root device blocks this '
                'and nothing on the host can install its way out',
    },
    'frida_dynamic': {
        'name': 'Frida dynamic instrumentation',
        'required': ['python39', 'module:frida', 'tool:adb', 'device'],
        'optional': ['tool:frida-cli', 'device_frida_server', 'device_root'],
        'scripts': ['run_probe.py', 'spawn_patch_detach.py', 'stalker_report.py',
                    'anti_detect_probe.js', 'hook_patch_only.js'],
        'note': 'run_probe.py --via usb tolerates a missing device frida-server; '
                'spawn-mode hooks need permission the app may refuse',
    },
    'frida_rpc': {
        'name': 'Frida RPC bridge (rpc.exports to host)',
        'required': ['python39', 'module:frida', 'tool:adb', 'device'],
        'optional': ['device_frida_server'],
        'depends_on': ['frida_dynamic'],
        'scripts': ['frida_rpc_serve.py', 'rpc_template.js'],
    },
    'dart_aot_full': {
        'name': 'Dart AOT full analysis (pool strings, caller index, disassembly)',
        'required': ['python39', 'artifact:dart_snapshot'],
        'optional': ['module:capstone'],
        'scripts': ['dart_pool_strings.py', 'dart_pprefs.py', 'dart_disasm.py'],
        'note': 'without capstone the caller index and pool strings still work and the '
                'annotated disassembly does not',
    },
    'dex_dump_analysis': {
        'name': 'Dumped-dex analysis (dedupe, structural checks, stub ratio)',
        'required': ['python39'],
        'optional': ['module:frida'],
        'scripts': ['dex_dump_validate.py', 'dex_mem_scan.py'],
        'note': 'the validators need nothing but the standard library; frida is only '
                'how the dump gets produced in the first place',
    },
    'protocol_decode': {
        'name': 'Schema-free protobuf decoding',
        'required': ['python39'],
        'optional': [],
        'scripts': ['protobuf_decode_raw.py', 'datastore_inject.py'],
        'note': 'no third-party module: the decoder and the DataStore container are '
                'both implemented in the standard library',
    },
    'kernel_side': {
        'name': 'Kernel-side scaffold generation and build',
        'required': ['python39'],
        'optional': ['toolchain:ndk'],
        'scripts': ['kernelsu_syscall_mask.py', 'lsposed_scaffold.py'],
        'note': 'generating the KernelSU/APatch scaffold needs only python; actually '
                'building and loading it needs a kernel toolchain this host does not have',
    },
    'publish_gate': {
        'name': 'Repository publish gates',
        'required': ['python39', 'tool:git', 'file:check_repo.py', 'file:check_refs.py',
                     'file:check_commands.py'],
        'optional': ['file:scan_leaks.py'],
        'note': 'four independent gates: paths/frontmatter, reference resolution, '
                'documented-command correctness, and target-identity leaks',
    },
}


def _all_atoms():
    """Atom ids that are implicitly satisfied (file:*, jar:*) or declared in ATOMS."""
    extra = {
        'jar:uber-apk-signer': {
            'name': 'uber-apk-signer.jar',
            'kind': 'jar',
            'jar': 'uber-apk-signer',
            'install': 'download uber-apk-signer.jar and put its directory on APKREV_JARS',
            'est_minutes': 3,
            'basis': 'unverified',
        },
    }
    for atom_id, rel in GATE_FILES.items():
        extra[atom_id] = {
            'name': os.path.basename(rel) + ' (repository gate)',
            'kind': 'file',
            'relpath': rel,
            'install': 'restore %s in the repository checkout' % rel,
            'est_minutes': 1,
            'basis': 'observed',
        }
    table = dict(ATOMS)
    table.update(extra)
    return table


ALL_ATOMS = _all_atoms()


# ---------------------------------------------------------------- probing

def extra_tool_dirs():
    """Directories searched beyond PATH.

    A tool installed by full path (a versioned build-tools directory, an unpacked jadx
    release) is invisible to a PATH-only probe, and reporting it missing makes the whole
    capability table lie in the pessimistic direction. `APKREV_TOOLS` (os.pathsep
    separated) covers exactly those.
    """
    dirs = []
    env = os.environ.get('APKREV_TOOLS')
    if env:
        dirs.extend(d for d in env.split(os.pathsep) if d)
    dirs.append(os.path.join(SKILL_DIR, 'tools'))
    return [d for d in dirs if d and os.path.isdir(d)]


class Probe:
    """Host facts, probed once per process and cached.

    Modules are never imported: `importlib.util.find_spec` answers existence without
    executing module-level code, which matters for frida (it starts threads and enumerates
    devices on import) and for any script that behaves differently under `__main__`.
    """

    def __init__(self, device=None):
        self._tool_cache = {}
        self._device = device
        self._device_probed = device is not None
        self._notes = []

    def set_device(self, device):
        """Adopt an already-probed device result so the device is not probed twice."""
        self._device = device
        self._device_probed = True

    # -- tools -------------------------------------------------------
    def which(self, name):
        if name in self._tool_cache:
            return self._tool_cache[name]
        hit = shutil.which(name)
        if not hit:
            exts = [''] if os.name != 'nt' else ['.exe', '.bat', '.cmd', '.ps1', '']
            for d in extra_tool_dirs():
                for root, _dirs, files in os.walk(d):
                    if root.count(os.sep) - d.count(os.sep) > 3:
                        continue
                    for f in files:
                        stem, ext = os.path.splitext(f)
                        if stem.lower() == name.lower() and ext.lower() in exts:
                            hit = os.path.join(root, f)
                            break
                    if hit:
                        break
                if hit:
                    break
        self._tool_cache[name] = hit
        return hit

    def module(self, name):
        try:
            return importlib.util.find_spec(name) is not None
        except Exception:
            return False

    def java_bin_dirs(self):
        """Directories that plausibly hold the rest of a JDK whose java is on PATH."""
        outs = []
        java = self.which('java')
        if java:
            outs.append(os.path.dirname(java))
        home = os.environ.get('JAVA_HOME')
        if home:
            outs.append(os.path.join(home, 'bin'))
        return [d for d in outs if os.path.isdir(d)]

    def which_in(self, name, dirs):
        for d in dirs:
            for cand in (name, name + '.exe', name + '.bat', name + '.cmd'):
                p = os.path.join(d, cand)
                if os.path.isfile(p):
                    return p
        return None

    def jar_dirs(self):
        """Every directory worth searching for a jar, in priority order."""
        dirs = []
        cp = os.environ.get('APK_REVERSE_SMALI_CP')
        if cp:
            dirs.append(cp)
        j = os.environ.get('APKREV_JARS')
        if j:
            dirs.extend(d for d in j.split(os.pathsep) if d)
        dirs.extend([os.path.join(HERE, 'dexpatch'), HERE, os.path.join(HERE, 'libs'),
                     os.path.join(HERE, 'jar'), os.path.join(SKILL_DIR, 'tools')])
        dirs.extend(extra_tool_dirs())
        # a smali_cp.txt with real paths is authoritative when present
        cp_file = os.path.join(HERE, 'smali_cp.txt')
        if os.path.isfile(cp_file):
            try:
                with open(cp_file, encoding='utf-8') as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            d = os.path.dirname(line)
                            if d:
                                dirs.append(d)
            except OSError:
                pass
        out = []
        for d in dirs:
            if d and os.path.isdir(d) and d not in out:
                out.append(d)
        return out

    def find_jar(self, stem):
        """Locate `<stem>.jar` or `<stem>-<version>.jar` under the jar search paths."""
        for d in self.jar_dirs():
            for root, _dirs, files in os.walk(d):
                if root.count(os.sep) - d.count(os.sep) > 3:
                    continue
                for f in sorted(files):
                    if not f.lower().endswith('.jar'):
                        continue
                    low = f.lower()
                    if low == stem.lower() + '.jar' or low.startswith(stem.lower() + '-'):
                        return os.path.join(root, f)
        return None

    def jar_set(self, names):
        """Return (found, missing) for an explicit jar filename list."""
        found, missing = {}, []
        pool = {}
        for d in self.jar_dirs():
            for root, _dirs, files in os.walk(d):
                if root.count(os.sep) - d.count(os.sep) > 3:
                    continue
                for f in files:
                    if f.lower().endswith('.jar'):
                        pool.setdefault(f.lower(), os.path.join(root, f))
        cp = os.environ.get('APK_REVERSE_SMALI_CP')
        if cp and os.path.isfile(cp):
            pool.setdefault(os.path.basename(cp).lower(), cp)
        for n in names:
            hit = pool.get(n.lower())
            if hit:
                found[n] = hit
            else:
                missing.append(n)
        return found, missing

    # -- build tools -------------------------------------------------
    def build_tools_candidates(self):
        """Directories that hold apksigner/zipalign, including ones not yet exposed."""
        cands = []
        for key in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
            root = os.environ.get(key)
            if root:
                bt = os.path.join(root, 'build-tools')
                if os.path.isdir(bt):
                    for v in sorted(os.listdir(bt), reverse=True):
                        cands.append(os.path.join(bt, v))
        home = os.path.expanduser('~')
        for root in (os.path.join(home, 'AppData', 'Local', 'Android', 'Sdk', 'build-tools'),
                     os.path.join(home, 'Android', 'Sdk', 'build-tools'),
                     os.path.join(home, 'Library', 'Android', 'sdk', 'build-tools'),
                     '/opt/android-sdk/build-tools',
                     '/usr/lib/android-sdk/build-tools'):
            if os.path.isdir(root):
                for v in sorted(os.listdir(root), reverse=True):
                    cands.append(os.path.join(root, v))
        # a directory named like a build-tools release, wherever the operator put it
        for base in (os.path.join(os.path.dirname(REPO_ROOT), 'tools'),
                     'E:\\tools', 'C:\\tools', '/opt/tools'):
            if not os.path.isdir(base):
                continue
            for entry in sorted(os.listdir(base)):
                d = os.path.join(base, entry)
                if not os.path.isdir(d):
                    continue
                if self.which_in('zipalign', [d]) or self.which_in('apksigner', [d]):
                    cands.append(d)
                for sub in sorted(os.listdir(d)):
                    sd = os.path.join(d, sub)
                    if os.path.isdir(sd) and (self.which_in('zipalign', [sd]) or
                                              self.which_in('apksigner', [sd])):
                        cands.append(sd)
        out = []
        for c in cands:
            if c not in out and os.path.isdir(c) and (
                    self.which_in('zipalign', [c]) or self.which_in('apksigner', [c])):
                out.append(c)
        return out

    # -- device ------------------------------------------------------
    def device(self):
        if self._device_probed:
            return self._device
        self._device_probed = True
        if not self.which('adb'):
            self._device = {'available': False, 'reason': 'adb not on PATH',
                            'devices': [], 'root': False, 'frida_server': None}
            return self._device
        rc, txt = _run(['adb', 'devices'], timeout=20)
        devices = []
        for line in txt.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith('*'):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == 'device':
                devices.append(parts[0])
        out = {'available': bool(devices), 'devices': devices, 'root': False,
               'frida_server': None,
               'reason': '' if devices else (txt.strip()[:160] or 'no device attached')}
        if devices:
            serial = devices[0]
            rc, v = _run(['adb', '-s', serial, 'shell', 'su -c id'], timeout=15)
            out['root'] = rc == 0 and 'uid=0' in v
            rc, ps = _run(['adb', '-s', serial, 'shell', 'ps -A'], timeout=20)
            hits = [ln for ln in ps.splitlines()
                    if 'frida' in ln.lower() and 'grep' not in ln.lower()]
            if rc == 0:
                out['frida_server'] = bool(hits)
        self._device = out
        return out

    # -- atom satisfaction -------------------------------------------
    def check(self, atom_id):
        """Return (satisfied, detail). `detail` names what was found or what is absent."""
        spec = ALL_ATOMS.get(atom_id)
        if spec is None:
            return False, 'unknown atom %r' % atom_id
        kind = spec['kind']
        if kind == 'python':
            ok = sys.version_info[:2] >= (3, 9)
            return ok, 'python %d.%d.%d' % sys.version_info[:3]
        if kind == 'module':
            return self.module(spec['module']), 'module %s' % spec['module']
        if kind == 'tool':
            hit = self.which(spec['tool'])
            if hit:
                return True, hit
            # a JDK whose launcher shim is on PATH hides keytool/jarsigner/javac
            hit = self.which_in(spec['tool'], self.java_bin_dirs())
            if hit:
                return True, hit
            return False, 'not on PATH or APKREV_TOOLS'
        if kind == 'jars':
            found, missing = self.jar_set(spec['jars'])
            if not missing:
                return True, '%d/%d jars' % (len(found), len(spec['jars']))
            return False, '%d/%d jars (missing: %s)' % (
                len(found), len(spec['jars']), ', '.join(missing))
        if kind == 'jar':
            hit = self.find_jar(spec['jar'])
            return (True, hit) if hit else (False, '%s.jar not found' % spec['jar'])
        if kind == 'any':
            tried = []
            for alt in spec['alternatives']:
                ok, detail = self.check(alt)
                if ok:
                    return True, '%s -> %s' % (alt, detail)
                tried.append('%s (%s)' % (alt, detail))
            return False, '; '.join(tried)
        if kind == 'file':
            p = os.path.join(REPO_ROOT, spec['relpath'])
            return os.path.isfile(p), spec['relpath']
        if kind == 'device':
            dev = self.device()
            return bool(dev.get('devices')), (
                'device %s' % dev['devices'][0] if dev.get('devices')
                else dev.get('reason', 'no device'))
        if kind == 'device_root':
            dev = self.device()
            if not dev.get('devices'):
                return False, 'no device, so root cannot be established'
            return bool(dev.get('root')), ('su -c id returned uid=0' if dev.get('root')
                                           else 'su -c id did not return uid=0')
        if kind == 'device_frida':
            dev = self.device()
            if not dev.get('devices'):
                return False, 'no device'
            if dev.get('frida_server'):
                return True, 'a frida process is running on device'
            hit = self.which('frida') or self.which('frida-server')
            return False, ('no frida process seen on device' +
                           ('; a host-side %s exists but a device server still has to be '
                            'started or --via usb used' % hit if hit else ''))
        if kind == 'artifact':
            return False, ('an input artifact this host cannot install; '
                           'produce it once and pass its path')
        return False, 'unhandled atom kind %r' % kind


def _run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
        return p.returncode, p.stdout.decode('utf-8', 'replace')
    except FileNotFoundError:
        return 127, 'not found'
    except subprocess.TimeoutExpired:
        return 124, 'TIMEOUT after %ss' % timeout
    except Exception as exc:  # pragma: no cover
        return 1, '%s: %s' % (type(exc).__name__, exc)


# ---------------------------------------------------------------- closure

def closure(capability_id):
    """Expand `depends_on` into (required_atoms, optional_atoms) in stable order.

    A prerequisite's requirements are inherited as required: `repack_signed` cannot be
    usable while the repacking it is built on does not work. A prerequisite's *optional*
    atoms stay optional, so a degraded input stage degrades the dependent capability
    instead of blocking it in a way that would be a lie of its own.
    """
    req, opt, seen = [], [], set()

    def walk(cid):
        if cid in seen:
            return
        seen.add(cid)
        spec = CAPABILITIES.get(cid)
        if spec is None:
            return
        for a in spec.get('required', []):
            if a not in req:
                req.append(a)
        for a in spec.get('optional', []):
            if a not in req and a not in opt:
                opt.append(a)
        for dep in spec.get('depends_on', []):
            walk(dep)

    walk(capability_id)
    return req, opt


def dynamic_hint(atom_id, probe):
    """Narrow a next action to what is already on this host.

    A generic "install the Android build-tools" is a mood; "they are already unpacked at
    E:\\tools\\android-14, export APKREV_TOOLS" is the step that actually unblocks the run.
    Returns (install_text, est_minutes_or_None, basis) where a `None` estimate keeps the
    atom's own figure.
    """
    spec = ALL_ATOMS[atom_id]
    base = spec.get('install', '')

    if spec['kind'] == 'tool':
        cands = probe.build_tools_candidates()
        if cands and spec['tool'] in ('zipalign', 'apksigner', 'dexdump'):
            return ('build-tools are already unpacked here but are not on the search path: '
                    'set APKREV_TOOLS=%s (found: %s)'
                    % (os.pathsep.join(cands[:2]), ', '.join(cands[:2])), 0, 'observed')
        if spec['tool'] in ('keytool', 'jarsigner', 'javac'):
            jd = probe.java_bin_dirs()
            if jd and not probe.which_in(spec['tool'], jd):
                return ('the directory on PATH (%s) is a launcher shim, not a full JDK bin/: '
                        'put %%JAVA_HOME%%\\bin first, or install a JDK - a JRE ships no %s'
                        % (jd[0], spec['tool']), None, None)

    if atom_id == 'jars:smali':
        searched = probe.jar_dirs()
        if searched:
            return ('%s -- searched already: %s' % (base, ', '.join(searched[:4])),
                    None, None)

    return base, None, None


def resolve(capability_id, probe=None):
    """Resolve one capability to {capability,status,missing,partial,next_action,...}."""
    if capability_id not in CAPABILITIES:
        raise KeyError(capability_id)
    probe = probe or Probe()
    spec = CAPABILITIES[capability_id]
    req, opt = closure(capability_id)

    missing, partial, evidence, hints = [], [], [], []
    est_total, est_unknown = 0, False

    for atom_id in req:
        ok, detail = probe.check(atom_id)
        atom = ALL_ATOMS[atom_id]
        evidence.append({'atom': atom_id, 'ok': ok, 'detail': detail,
                         'source': 'required'})
        if not ok:
            hint, dyn_minutes, dyn_basis = dynamic_hint(atom_id, probe)
            minutes = dyn_minutes if dyn_minutes is not None else atom.get('est_minutes')
            basis = dyn_basis or atom.get('basis', 'unverified')
            missing.append({'atom': atom_id, 'name': atom['name'], 'detail': detail,
                            'install': hint,
                            'est_minutes': minutes,
                            'basis': basis,
                            'note': atom.get('note', '')})
            if minutes is None:
                est_unknown = True
            else:
                est_total += minutes
            if hint:
                hints.append(hint)

    for atom_id in opt:
        ok, detail = probe.check(atom_id)
        atom = ALL_ATOMS[atom_id]
        evidence.append({'atom': atom_id, 'ok': ok, 'detail': detail,
                         'source': 'optional'})
        if not ok:
            partial.append({'atom': atom_id, 'name': atom['name'], 'detail': detail,
                            'install': atom.get('install', ''),
                            'est_minutes': atom.get('est_minutes'),
                            'basis': atom.get('basis', 'unverified'),
                            'note': atom.get('note', '')})

    status = 'blocked' if missing else ('partial' if partial else 'ok')
    bases = {m['basis'] for m in missing}
    return {
        'capability': capability_id,
        'name': spec['name'],
        'status': status,
        'missing': missing,
        'partial': partial,
        'next_action': hints[0] if hints else '',
        'install_hint': hints,
        'est_minutes': None if (est_unknown and not est_total) else est_total,
        'est_basis': ('mixed' if len(bases) > 1 else (bases.pop() if bases else 'observed')),
        'scripts': spec.get('scripts', []),
        'note': spec.get('note', ''),
        'evidence': evidence,
    }


def resolve_all(probe=None):
    probe = probe or Probe()
    return {cid: resolve(cid, probe) for cid in CAPABILITIES}


def verdict(results):
    """(status, exit_code, token) for a set of resolved capabilities.

    `partial` does not fail the gate: the capability works and names its own gap. Only a
    blocked capability does, because that is the case where a gate would otherwise pass a
    claim this host cannot support.
    """
    statuses = {r['status'] for r in results.values()}
    if 'blocked' in statuses:
        return 'blocked', EXIT_ENV, TOKENS['blocked']
    if 'partial' in statuses:
        return 'partial', EXIT_OK, TOKENS['partial']
    return 'ok', EXIT_OK, TOKENS['ok']


# ---------------------------------------------------------------- script -> capability

# Scripts that declare `capability:` in their first docstring line override this map.
# Anything in neither is reported as unknown and counted.
SCRIPT_CAPABILITIES = {
    'dexutil.py': ['static_dex'],
    'dex_strings.py': ['static_dex'],
    'dex_classdiff.py': ['static_dex'],
    'dex_strpatch.py': ['static_dex'],
    'dex_patch_bytes.py': ['static_dex'],
    'dex_find_insn.py': ['static_dex'],
    'dex_check_verifier.py': ['static_dex'],
    'find_refs.py': ['static_dex'],
    'apk_diff.py': ['static_dex'],
    'blob_decode.py': ['static_dex'],
    'elf_plt.py': ['static_native'],
    'so_constpatch.py': ['static_native'],
    'svc_scan.py': ['static_native'],
    'native_crash.py': ['static_native'],
    'smtool.py': ['smali_roundtrip'],
    'patch_smali.py': ['smali_roundtrip'],
    'repack.py': ['repack_unsigned', 'repack_signed'],
    'install_test.py': ['repack_signed', 'device_static'],
    'devsh.py': ['device_static'],
    'preflight.py': ['device_static'],
    'coldstart.py': ['device_static', 'device_root'],
    'snap.py': ['device_static', 'device_root'],
    'grab_crash.py': ['device_static', 'device_root'],
    'lib_map.py': ['device_static', 'device_root'],
    'usb_net_proxy.py': ['device_static'],
    'run_probe.py': ['frida_dynamic'],
    'spawn_patch_detach.py': ['frida_dynamic'],
    'stalker_report.py': ['frida_dynamic'],
    'stalker_trace.js': ['frida_dynamic'],
    'anti_detect_probe.js': ['frida_dynamic'],
    'hook_patch_only.js': ['frida_dynamic'],
    'frida_probe.js': ['frida_dynamic'],
    'frida_rpc_serve.py': ['frida_rpc'],
    'rpc_template.js': ['frida_rpc'],
    'dart_pool_strings.py': ['dart_aot_full'],
    'dart_pprefs.py': ['dart_aot_full'],
    'dart_disasm.py': ['dart_aot_full'],
    'dex_dump_validate.py': ['dex_dump_analysis'],
    'dex_mem_scan.py': ['dex_dump_analysis'],
    'protobuf_decode_raw.py': ['protocol_decode'],
    'datastore_inject.py': ['protocol_decode'],
    'kernelsu_syscall_mask.py': ['kernel_side'],
    'lsposed_scaffold.py': ['kernel_side'],
    'java2c_probe.py': ['static_dex', 'static_native'],
    'vmp_diff_harness.py': ['smali_roundtrip'],
    'scan_leaks.py': ['publish_gate'],
    'mt_mcp_probe.py': ['device_static'],
    'tls_check.py': ['protocol_decode'],
    'probe_api.py': ['protocol_decode'],
    'sig_probe.py': ['frida_dynamic', 'static_dex'],
}

# `doctor.py` and `capabilities.py` report on the environment rather than consume it.
SELF_SCRIPTS = {'doctor.py', 'capabilities.py'}


def declared_capability(path):
    """Read a `capability:` declaration from a script's own header.

    Returns (list_of_ids_or_None, source). For a `.py` file the declaration must be the
    first line under the opening docstring quotes -- an example inside the prose further
    down is documentation, not a declaration, and reading it as one would make this very
    module claim a capability called `<capability_id>`. For a `.js` file the line is read
    from the leading `//` comments, because a Frida script is not Python and is never
    parsed as such.
    """
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            src = fh.read()
    except OSError as exc:
        return None, 'unparsed: %s' % type(exc).__name__

    if path.endswith('.js'):
        for line in src.splitlines()[:20]:
            s = line.strip().lstrip('/#*').strip()
            if s.startswith('capability:'):
                ids = [x.strip() for x in s.split(':', 1)[1].split(',') if x.strip()]
                return ids, 'declared'
        return None, 'mapped'

    try:
        tree = ast.parse(src, path)
    except SyntaxError:
        return None, 'unparsed: SyntaxError'
    doc = ast.get_docstring(tree) or ''
    for line in doc.splitlines()[1:4]:
        line = line.strip()
        if line.startswith('capability:'):
            ids = [x.strip() for x in line.split(':', 1)[1].split(',') if x.strip()]
            return ids, 'declared'
    return None, 'mapped'


def capabilities_for_script(name, path=None):
    """Capabilities a script serves: its own declaration first, then the map.

    Returns (list_of_ids_or_None, source). `None` means "not determinable", which the
    caller must report as unknown rather than treat as an empty requirement set.
    """
    if path is None:
        path = os.path.join(HERE, name)
    ids, source = declared_capability(path)
    if ids:
        return ids, source
    if source.startswith('unparsed'):
        return None, source
    if name in SELF_SCRIPTS:
        return [], 'self'
    return SCRIPT_CAPABILITIES.get(name), 'mapped'


# ---------------------------------------------------------------- CLI

def human_report(results, verbose=False):
    lines = []
    width = max(len(c) for c in results) if results else 10
    for cid in sorted(results):
        r = results[cid]
        mark = {'ok': 'OK     ', 'partial': 'PARTIAL', 'blocked': 'BLOCKED'}[r['status']]
        lines.append('  [%s] %-*s %s' % (mark, width, cid, r['name']))
        if r['status'] != 'ok' or verbose:
            for m in r['missing'] + r['partial']:
                tag = 'missing' if m in r['missing'] else 'reduced'
                lines.append('            %-7s : %s -- %s' % (tag, m['atom'], m['detail']))
                if m.get('install'):
                    est = m.get('est_minutes')
                    cost = ('~%d min, %s' % (est, m['basis'])) if est is not None \
                        else 'cost unverified'
                    lines.append('            %-7s   next: %s   [%s]'
                                 % ('', m['install'], cost))
                if m.get('note'):
                    lines.append('            %-7s   note: %s' % ('', m['note']))
            if r['note'] and (verbose or r['status'] != 'ok'):
                lines.append('            note    : %s' % r['note'])
    return lines


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error. Keep the RESULT= contract on that path too:
    a caller that branches on the last line must not have to special-case bad usage."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write('%s: error: %s\n' % (self.prog, message))
        print('RESULT=%s' % TOKENS['use'])
        raise SystemExit(EXIT_USE)


def main(argv=None):
    ap = _Parser(
        prog='capabilities.py',
        description='Resolve what this host can actually do, from probed atoms. '
                    'Never installs anything; never imports the modules it probes.')
    ap.add_argument('capability', nargs='?', default=None,
                    help='resolve one capability id (see --list)')
    ap.add_argument('--list', action='store_true', help='ids and names only')
    ap.add_argument('--verbose', '-v', action='store_true',
                    help='print every atom, including the ones that are present')
    ap.add_argument('--json', action='store_true', dest='as_json',
                    help='machine-readable output')
    ap.add_argument('--device-result', default=None, metavar='JSON_PATH',
                    help='reuse a device probe result recorded by doctor.py --json')
    args = ap.parse_args(argv)

    if args.capability and args.capability not in CAPABILITIES:
        known = ', '.join(sorted(CAPABILITIES))
        sys.stderr.write('error: unknown capability %r\nknown: %s\n'
                         % (args.capability, known))
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE

    if args.list:
        for cid in sorted(CAPABILITIES):
            print('%-22s %s' % (cid, CAPABILITIES[cid]['name']))
        print('RESULT=%s' % TOKENS['ok'])
        return EXIT_OK

    device = None
    if args.device_result:
        try:
            with open(args.device_result, encoding='utf-8') as fh:
                blob = json.load(fh)
            dev = blob.get('device', blob)
            device = {
                'available': bool(dev.get('devices') or dev.get('available')),
                'devices': [d.get('serial') if isinstance(d, dict) else d
                            for d in (dev.get('devices') or [])],
                'root': bool(dev.get('root')),
                'frida_server': bool(dev.get('device_frida_processes')),
                'reason': dev.get('reason', ''),
            }
        except (OSError, ValueError, AttributeError) as exc:
            sys.stderr.write('error: could not read --device-result: %s\n' % exc)
            print('RESULT=%s' % TOKENS['use'])
            return EXIT_USE

    try:
        probe = Probe(device=device)
        if args.capability:
            results = {args.capability: resolve(args.capability, probe)}
        else:
            results = resolve_all(probe)
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write('internal error: %s: %s\n' % (type(exc).__name__, exc))
        print('RESULT=%s' % TOKENS['internal'])
        return EXIT_INTERNAL

    status, code, token = verdict(results)

    if args.as_json:
        evidence = []
        hints = []
        for r in results.values():
            for e in r['evidence']:
                evidence.append({
                    'capability': r['capability'], 'atom': e['atom'],
                    'ok': e['ok'], 'detail': e['detail'], 'source': e['source'],
                })
            hints.extend(r['install_hint'])
        payload = {
            'status': status,
            'exit_code': code,
            'capability': args.capability,
            'capabilities': results,
            'evidence': evidence,
            'warnings': [
                m['atom'] for r in results.values() for m in r['partial']
            ],
            'next_action': hints[0] if hints else '',
            'install_hint': hints,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print('RESULT=%s' % token)
        return code

    print('=' * 74)
    print('apk-reverse capability registry')
    print('=' * 74)
    print('python   : %d.%d.%d' % sys.version_info[:3])
    for line in human_report(results, verbose=args.verbose):
        print(line)

    blocked = [c for c, r in results.items() if r['status'] == 'blocked']
    partial = [c for c, r in results.items() if r['status'] == 'partial']
    print('\n  ok=%d  partial=%d  blocked=%d  (of %d capabilities)'
          % (len(results) - len(blocked) - len(partial), len(partial), len(blocked),
             len(results)))
    if blocked:
        print('\n  A blocked capability is a fact about this host, not a verdict on the task.')
        print('  Fix the named atom, or route the task through a capability that is ok.')
    print('RESULT=%s' % token)
    return code


if __name__ == '__main__':
    sys.exit(main())
