#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Repack an APK with replaced dex files, drop ONLY the signature entries, and re-sign.

Pipeline: replace dex files -> drop signature artifacts -> zip, keeping
AndroidManifest.xml and resources.arsc STORED -> zipalign + sign -> verify.

Everything machine-specific is a parameter or resolved from PATH. No JDK path is
baked in, no keystore password is baked in, no target app is assumed.

Keystore handling:
  --ks <path> is where the keystore lives. If it does not exist, one is generated
  with keytool and its password is stored next to it as <ks>.pass.txt, so the next
  run reuses it. Passwords are never hardcoded in this script. That file is a local
  artifact -- do not commit it.

Usage examples:
  # roundtrip: reuse the original dexes unchanged, proves the pipeline itself works
  python repack.py --apk work/orig.apk --dexdir work/x_orig --out work/out/roundtrip.apk

  # real patch: swap a single dex (name=path), other dexes kept from the apk
  python repack.py --apk work/orig.apk --dex classes8.dex=work/patch/classes8.dex \
      --out work/out/patched.apk

  # no signing, no java tooling required at all
  python repack.py --apk work/orig.apk --dexdir work/x_orig --out work/unsigned.apk --no-sign

Notes:
  * All java tooling is invoked through python subprocess, never through a host
    shell (PowerShell drops arguments in ways that look like tool failures).
  * uber-apk-signer silently skips already-signed apks (reports 0 processed), which
    is why signature entries are always dropped before signing.
  * uber-apk-signer is used for SIGNING to keep the verified path unchanged;
    apksigner is used for VERIFYING when present, with an explicit sdk range.
"""
import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys
import zipfile

STORE_ONLY = ('AndroidManifest.xml', 'resources.arsc')


def log(msg):
    print(msg, flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors='replace', **kw)


# ---------------------------------------------------------------------------
# Tool resolution: PATH first, explicit flag second, never a baked-in path.
# ---------------------------------------------------------------------------
def sibling_tool(exe, name):
    """Look for `name` next to `exe`, for JDKs whose bin dir is not on PATH."""
    if not exe:
        return None
    folder = os.path.dirname(exe)
    for cand in (name, name + '.exe', name + '.bat'):
        path = os.path.join(folder, cand)
        if os.path.exists(path):
            return path
    return None


def resolve_tool(name, explicit=None, hint_exe=None):
    if explicit:
        return explicit
    found = shutil.which(name)
    if found:
        return found
    return sibling_tool(hint_exe, name)


def resolve_tools(args):
    """Locate java/keytool/jarsigner/zipalign/apksigner. Missing ones stay None."""
    java = resolve_tool('java', args.java)
    tools = {
        'java': java,
        'keytool': resolve_tool('keytool', args.keytool, java),
        'jarsigner': resolve_tool('jarsigner', args.jarsigner, java),
        'zipalign': resolve_tool('zipalign', args.zipalign),
        'apksigner': resolve_tool('apksigner', args.apksigner),
    }
    return tools


def require(tools, key, why):
    if tools.get(key):
        return tools[key]
    raise SystemExit(
        "error: '%s' was not found on PATH, and it is needed to %s.\n"
        "  install a JDK (17+ recommended) / Android build-tools and put them on PATH,\n"
        "  or pass the path explicitly (--%s <path>).\n"
        "  Path lookup is deliberate: a machine-specific absolute path must never be\n"
        "  baked into this script." % (key, why, key))


# ---------------------------------------------------------------------------
# Keystore
# ---------------------------------------------------------------------------
def read_pwd_file(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as fh:
            txt = fh.read().strip()
        return txt or None
    except OSError:
        return None


def ensure_keystore(ks_path, alias, password, keytool):
    """Return the keystore password, generating the keystore on first use."""
    pwd_file = ks_path + '.pass.txt'

    if os.path.exists(ks_path):
        pwd = password or read_pwd_file(pwd_file)
        if not pwd:
            raise SystemExit(
                'error: keystore %s exists but its password is unknown.\n'
                '  pass --ks-pass <pw>, or write the password into %s' % (ks_path, pwd_file))
        log('[ks] reuse %s (alias=%s)' % (ks_path, alias))
        return pwd

    pwd = password or read_pwd_file(pwd_file)
    generated = pwd is None
    if generated:
        # keytool rejects passwords shorter than 6 characters.
        pwd = secrets.token_urlsafe(12)

    folder = os.path.dirname(ks_path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    cmd = [keytool, '-genkeypair', '-keystore', ks_path, '-alias', alias,
           '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
           '-storepass', pwd, '-keypass', pwd,
           '-dname', 'CN=apkreverse, OU=dev, O=dev, L=NA, ST=NA, C=NA']
    r = run(cmd)
    if r.returncode != 0:
        log('[ks] keytool failed rc=%d\n%s\n%s' % (r.returncode, r.stdout, r.stderr))
        raise SystemExit(1)

    try:
        with open(pwd_file, 'w', encoding='utf-8') as fh:
            fh.write(pwd + '\n')
        os.chmod(pwd_file, 0o600)
    except OSError as exc:
        log('[ks] could not persist the password: %s' % exc)

    log('[ks] generated %s (alias=%s)' % (ks_path, alias))
    if generated:
        log('[ks] password stored in %s -- local artifact, do not commit it' % pwd_file)
    return pwd


# ---------------------------------------------------------------------------
# Split APK / App Bundle sets
#
# A store build is often NOT one file. An App Bundle turns into
#     base.apk + split_config.arm64_v8a.apk + split_config.xxhdpi.apk + ...
# and every member carries the same package name and its own signature. Two
# consequences, and they are the reason this section exists:
#
#   * Signing only the base leaves the set disagreeing about its certificate.
#     `pm install-multiple` then refuses the whole set, with a signature error
#     that points at the base rather than at the member you did not sign.
#   * "Just merge them into one APK" is free only for splits that carry CODE or
#     NATIVE LIBRARIES. A split that carries RESOURCES cannot be folded in
#     without merging `resources.arsc` -- rewriting the table, its global string
#     pool and its type/entry offsets -- which is a resource-compiler job, not a
#     byte-level one. A wrongly merged arsc produces an APK that installs and
#     then renders the wrong thing, or fails on the first resource lookup.
#
# So the job here is to say which of the two routes is legal for a given set and
# then do that one, instead of always emitting the same artifact.
# ---------------------------------------------------------------------------
ABI_SPLIT_NAMES = ('armeabi', 'armeabi_v7a', 'arm64_v8a', 'x86', 'x86_64',
                   'riscv64', 'mips', 'mips64')
DENSITY_SPLIT_NAMES = ('ldpi', 'mdpi', 'tvdpi', 'hdpi', 'xhdpi', 'xxhdpi',
                       'xxxhdpi', 'anydpi', 'nodpi')
# A split is required to carry an `resources.arsc`, so an almost-empty table is
# normal and must not be mistaken for real resources. Measured on a real set:
# the density splits that hold nothing but a placeholder table are 40 bytes,
# while the ones that actually own drawables are 9-15 KB.
EMPTY_ARSC_BYTES = 1024


def find_apks(root):
    """Every .apk at or under `root`.

    Recursive on purpose: `adb pull <dir> <dest>` creates `<dest>/<dir>/`, so a
    pulled set arrives one level deeper than the caller expects (measured).
    """
    if os.path.isfile(root):
        return [os.path.abspath(root)]
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for name in sorted(filenames):
            if name.lower().endswith('.apk'):
                found.append(os.path.abspath(os.path.join(dirpath, name)))
    return sorted(found)


def axml_string_pool(blob):
    """Decode the string pool of a binary AndroidManifest.xml. No dependencies.

    Only the pool is decoded, not the element tree: every name this script needs
    (`package`, `split`, `configForSplit`, `isSplitRequired`) is a pool entry, and
    a hand-rolled element walk is where such parsers usually go wrong. The pool
    is also what makes equal-length hex patching of a manifest possible later.
    """
    import struct
    if len(blob) < 36 or struct.unpack_from('<H', blob, 0)[0] != 0x0003:
        return None                      # not binary XML
    if struct.unpack_from('<H', blob, 8)[0] != 0x0001:
        return None                      # no string pool where one must be
    hdr_size = struct.unpack_from('<H', blob, 10)[0]
    count, _styles, flags, strings_start, _styles_start = struct.unpack_from(
        '<IIIII', blob, 16)
    if not 0 < count <= 1000000:
        return None
    offsets = struct.unpack_from('<%dI' % count, blob, 8 + hdr_size)
    utf8 = bool(flags & (1 << 8))
    base = 8 + strings_start
    out = []
    for off in offsets:
        p = base + off
        if p >= len(blob):
            return None
        try:
            if utf8:
                n = blob[p]
                p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | blob[p]
                    p += 1
                m = blob[p]
                p += 1
                if m & 0x80:
                    m = ((m & 0x7F) << 8) | blob[p]
                    p += 1
                out.append(blob[p:p + m].decode('utf-8', 'replace'))
            else:
                n = struct.unpack_from('<H', blob, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', blob, p)[0]
                    p += 2
                out.append(blob[p:p + n * 2].decode('utf-16-le', 'replace'))
        except (IndexError, struct.error):
            return None
    return out


def axml_root_attrs(blob):
    """Attributes of the root <manifest> element, as {name: value}.

    Starts at the first start-element chunk, which is the root element in every
    manifest Android produces. Values come back as strings where the pool has
    them and as formatted scalars otherwise, so a caller can print them without
    caring which encoding the compiler chose (a boolean is `0xffffffff`, not the
    word "true", in the binary form).
    """
    import struct
    strings = axml_string_pool(blob)
    if strings is None:
        return None
    total = struct.unpack_from('<I', blob, 4)[0] or len(blob)
    end = min(len(blob), total)
    off = 8
    while off + 8 <= end:
        ctype, _hsize, csize = struct.unpack_from('<HHI', blob, off)
        if csize < 8 or off + csize > end:
            break
        if ctype == 0x0102:                       # RES_XML_START_ELEMENT
            attr_start, attr_size, attr_count = struct.unpack_from(
                '<HHH', blob, off + 24)
            attrs = {}
            first = off + 16 + attr_start
            for i in range(attr_count):
                p = first + i * attr_size
                if p + 20 > off + csize:
                    break
                name_i, raw_i = struct.unpack_from('<II', blob, p + 4)
                _size, _res0, dtype = struct.unpack_from('<HBB', blob, p + 12)
                data = struct.unpack_from('<I', blob, p + 16)[0]
                name = strings[name_i] if name_i < len(strings) else '?'
                if dtype == 0x03:
                    val = strings[data] if data < len(strings) else ''
                elif raw_i != 0xFFFFFFFF and raw_i < len(strings):
                    val = strings[raw_i]
                elif dtype == 0x10:
                    val = str(data - (1 << 32) if data >= (1 << 31) else data)
                elif dtype == 0x11:
                    val = '0x%x' % data
                elif dtype == 0x12:
                    val = 'true' if data else 'false'
                elif dtype == 0x01:
                    val = '@ref/0x%08x' % data
                else:
                    val = 'type=0x%02x/0x%x' % (dtype, data)
                attrs[name] = val
            return attrs
        off += csize
    return None


def inspect_apk(path):
    """Structural facts about one member of a split set, from the zip alone.

    Nothing here needs a device or a resource compiler: which split owns dex,
    which owns native libraries and which owns resources is visible in the entry
    list, and the split's own name (and therefore its role) is a manifest
    attribute. Reading it from the file is what keeps this usable on a set whose
    package name is irrelevant to the caller.
    """
    info = {'path': os.path.abspath(path), 'name': os.path.basename(path),
            'size': os.path.getsize(path), 'dex': [], 'abis': [], 'res': 0,
            'assets': 0, 'libs': [], 'arsc': None, 'arsc_stored': None,
            'package': None, 'split': None, 'config_for_split': None,
            'is_split_required': None, 'is_feature': None, 'readable': True}
    try:
        with zipfile.ZipFile(path, 'r') as z:
            names = []
            for item in z.infolist():
                name = item.filename
                names.append(name)
                if item.is_dir():
                    continue
                if re.match(r'^classes\d*\.dex$', name):
                    info['dex'].append(name)
                elif name == 'resources.arsc':
                    info['arsc'] = item.file_size
                    info['arsc_stored'] = (item.compress_type == 0)
                elif name.startswith('lib/') and name.count('/') >= 2:
                    abi = name.split('/')[1]
                    if abi not in info['abis']:
                        info['abis'].append(abi)
                    info['libs'].append(name)
                elif name.startswith('res/'):
                    info['res'] += 1
                elif name.startswith('assets/'):
                    info['assets'] += 1
            if 'AndroidManifest.xml' in names:
                attrs = axml_root_attrs(z.read('AndroidManifest.xml')) or {}
                info['package'] = attrs.get('package')
                info['split'] = attrs.get('split')
                info['config_for_split'] = attrs.get('configForSplit')
                info['is_split_required'] = attrs.get('isSplitRequired')
                info['is_feature'] = attrs.get('isFeatureSplit')
    except (zipfile.BadZipFile, OSError) as exc:
        info['readable'] = False
        info['error'] = str(exc)
    return info


def split_role(info):
    """What a member of a set contributes: base / abi / code / resources.

    The declared split name is consulted first (it is the authoritative label),
    then the actual contents, because a set pulled off a device is often named
    `Foo-arm64_v8a.apk` while its manifest still says `config.arm64_v8a`.
    """
    if not info.get('readable'):
        return 'unreadable'
    if not info.get('split'):
        return 'base'
    name = info['split']
    tail = name.split('.', 1)[1] if '.' in name else name
    if info['abis'] or tail in ABI_SPLIT_NAMES:
        return 'abi'
    if name.startswith('config.'):
        if tail in DENSITY_SPLIT_NAMES:
            return 'density'
        return 'config'
    if info['dex']:
        return 'code'
    return 'split'


def split_has_real_resources(info):
    """True when folding this split into the base would require merging arsc."""
    if info.get('res'):
        return True
    return (info.get('arsc') or 0) > EMPTY_ARSC_BYTES


def pick_base(items):
    """The base is the member with no `split` attribute; ties break toward dex."""
    cands = [i for i in items if not i.get('split')]
    if not cands:
        return None, []
    cands.sort(key=lambda i: (not i['dex'], -i['size']))
    return cands[0], cands[1:]


def split_report(items):
    """Human-readable inventory of a set: the input to the route decision."""
    rows = []
    for i in items:
        role = split_role(i)
        extra = []
        if i['dex']:
            extra.append('dex=%s' % ','.join(i['dex']))
        if i['abis']:
            extra.append('libs=%s' % ','.join(i['abis']))
        if i['res']:
            extra.append('res=%d entries' % i['res'])
        if i['arsc'] is not None:
            extra.append('arsc=%d%s' % (i['arsc'], '' if i['arsc_stored'] else ' COMPRESSED'))
        if i['assets']:
            extra.append('assets=%d' % i['assets'])
        rows.append('%-10s %-40s %10d B  split=%-18s %s'
                    % (role, i['name'], i['size'], i.get('split') or '-',
                       ' '.join(extra)))
    return rows


def plan_split_set(items):
    """Decide merge vs resign for this set, and say why in one sentence each.

    Returns (base, others, blockers, notes). `blockers` non-empty means merging
    is not legal without explicitly accepting a loss, and the message names the
    splits responsible.
    """
    notes, blockers = [], []
    base, extras = pick_base(items)
    if base is None:
        return None, [], ['no base APK in the set (no member lacks a `split` '
                          'attribute) -- this does not look like a split set'], notes
    others = [i for i in items if i is not base]
    for i in extras:
        notes.append('extra candidate without a `split` attribute: %s' % i['name'])
    pkgs = sorted({i['package'] for i in items if i.get('package')})
    if len(pkgs) > 1:
        notes.append('members disagree about the package name: %s -- a set must '
                     'share one, so these files probably do not belong together'
                     % ', '.join(pkgs))
    if base.get('is_split_required') == 'true':
        notes.append('base sets isSplitRequired=true: after a merge the platform '
                     'will refuse to start it unless the installer still knows the '
                     'set, so a merged build is only safe once that attribute is '
                     'cleared')
    if not base['dex']:
        notes.append('base carries no classes*.dex (unusual: %s)'
                     % (', '.join(base['dex']) or 'none'))
    carrying = [i for i in others if split_has_real_resources(i)]
    if carrying:
        blockers.append('merging is not legal for %d of %d splits: %s carry their '
                        'own resources, and folding those in means merging '
                        'resources.arsc (a resource-compiler job). Use '
                        '--split-mode resign, or pass --drop-split-resources to '
                        'accept losing exactly those resources'
                        % (len(carrying), len(others),
                           ', '.join(i.get('split') or i['name'] for i in carrying)))
    elif others:
        notes.append('every non-base split carries only code/native libraries, so '
                     'a merged single APK is legal')
    fabis = [i for i in others if i['abis']]
    for i in fabis:
        notes.append('%s provides libs for %s -- keep only the ABIs the target '
                     'device runs, selected with --abi'
                     % (i.get('split') or i['name'], ','.join(i['abis'])))
    return base, others, blockers, notes


def collect_split_inputs(args):
    """Every APK the caller pointed at as part of one set (empty = not a set)."""
    if not (args.split_dir or args.split):
        return []
    paths = []
    if args.split_dir:
        paths += find_apks(os.path.abspath(args.split_dir))
    for p in (args.split or []):
        ap = os.path.abspath(p)
        paths += find_apks(ap) if os.path.isdir(ap) else [ap]
    if args.apk:
        ap = os.path.abspath(args.apk)
        if ap not in paths:
            paths.append(ap)
    # A set is a set: dedupe by real path so `--split-dir X --split X/base.apk`
    # does not try to merge an APK into itself.
    seen, out = set(), []
    for p in paths:
        key = os.path.normcase(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def abi_of_split(info):
    """The ABI a split provides, from its lib directories or its split name."""
    if info['abis']:
        return info['abis'][0]
    name = (info.get('split') or '').split('.', 1)[-1]
    return name.replace('_', '-') if name in ABI_SPLIT_NAMES else None


def merge_split_set(base, others, out_apk, allow_drop_resources=False, keep_abi=None):
    """Fold a set into one standalone APK: base plus every foldable member.

    Folded: `classes*.dex` (renumbered so the second dex becomes classes2.dex),
    `lib/**` and `assets/**`. Not folded: `res/**` and `resources.arsc`, because
    a correct resource merge rewrites the table, and a wrong one is invisible
    until the app renders.

    Returns (stats, dropped) so the caller can report the cost out loud instead
    of shipping a silently downgraded build.
    """
    plan = []
    taken = set()
    stats = {'dex': 0, 'libs': 0, 'assets': 0, 'conflicts': 0}
    dropped = []

    with zipfile.ZipFile(base['path'], 'r') as z:
        for item in z.infolist():
            name = item.filename
            if item.is_dir() or is_signature_entry(name):
                continue
            taken.add(name)
            plan.append((name, item, z.read(name),
                         name in STORE_ONLY or os.path.basename(name) in STORE_ONLY))
    base_dex = len([n for n in taken if re.match(r'^classes\d*\.dex$', n)])
    next_dex = base_dex + 1          # a base with no dex still wants classes.dex first

    for info in others:
        if info['abis'] and keep_abi and keep_abi not in abi_of_split(info):
            dropped.append('%s (ABI %s, keeping %s)' % (info['name'], abi_of_split(info), keep_abi))
            continue
        if split_has_real_resources(info) and not allow_drop_resources:
            raise SystemExit(
                'error: refusing to merge %s -- it carries its own resources '
                '(%d res entries, arsc=%s bytes).\n'
                '  Folding it in would require merging resources.arsc, which this '
                'script does not do.\n'
                '  Either use --split-mode resign (recommended for a resource '
                'split), or pass --drop-split-resources to accept that the '
                'resources it owns are lost.'
                % (info['name'], info['res'], info['arsc']))
        with zipfile.ZipFile(info['path'], 'r') as z:
            for item in z.infolist():
                name = item.filename
                if item.is_dir() or is_signature_entry(name):
                    continue
                if name == 'AndroidManifest.xml':
                    continue                      # the base manifest already exists
                if name == 'resources.arsc' or name.startswith('res/'):
                    dropped.append('%s: %s' % (info['name'], name))
                    continue
                if re.match(r'^classes\d*\.dex$', name):
                    new = 'classes%d.dex' % next_dex if next_dex > 1 else 'classes.dex'
                    while new in taken:
                        next_dex += 1
                        new = 'classes%d.dex' % next_dex
                    data = z.read(name)
                    zi = zipfile.ZipInfo(new, date_time=(2024, 1, 1, 0, 0, 0))
                    plan.append((new, zi, data, False))
                    taken.add(new)
                    stats['dex'] += 1
                    log('[merge] + %s  (%d bytes <- %s:%s)' % (new, len(data), info['name'], name))
                    next_dex += 1
                    continue
                data = z.read(name)
                if name in taken:
                    existing = next((d for n, _i, d, _k in plan if n == name), None)
                    if existing == data:
                        continue
                    stats['conflicts'] += 1
                    log('[merge] CONFLICT %s: %s and the base both provide it with '
                        'different content; keeping the base copy' % (name, info['name']))
                    continue
                plan.append((name, item, data, name in STORE_ONLY))
                taken.add(name)
                if name.startswith('lib/'):
                    stats['libs'] += 1
                elif name.startswith('assets/'):
                    stats['assets'] += 1
                log('[merge] + %s  (%d bytes <- %s)' % (name, len(data), info['name']))

    _write_aligned_zip(out_apk, plan)
    return stats, dropped


def resign_split_set(items, outdir, sign_one):
    """Sign every member of a set with the same keystore, keeping the structure.

    Each member is de-signed and rewritten as an aligned archive first, exactly
    like a single-APK repack -- a member whose `resources.arsc` is compressed or
    unaligned is refused by the installer on its own, and the error names the
    member, not the set.
    """
    os.makedirs(outdir, exist_ok=True)
    scratch = os.path.join(outdir, '.unsigned')
    if os.path.isdir(scratch):
        shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(scratch, exist_ok=True)
    outs = []
    for info in items:
        unsigned = os.path.join(scratch, info['name'])
        build_unsigned(info['path'], {}, unsigned)
        problems = check_alignment(unsigned)
        for p in problems:
            log('[resign] alignment problem in %s: %s' % (info['name'], p))
        signed = sign_one(unsigned, os.path.join(outdir, info['name']))
        outs.append((info, signed))
        log('[resign] %s -> %s (%d bytes)' % (info['name'], signed, os.path.getsize(signed)))
    shutil.rmtree(scratch, ignore_errors=True)
    return outs


def cert_fingerprints(apk, tools):
    """SHA-256 of each signer certificate, as reported by apksigner."""
    apksigner = tools.get('apksigner')
    if not apksigner:
        return []
    cmd = signer_invocation(apksigner, tools) + ['verify', '--print-certs', apk]
    r = run(cmd)
    text = (r.stdout or '') + (r.stderr or '')
    return sorted({m.lower() for m in re.findall(r'SHA-256 digest:\s*([0-9a-fA-F:]+)', text)})


# ---------------------------------------------------------------------------
# Packing
# ---------------------------------------------------------------------------
def collect_replacement_dex(dexdir=None, dex_pairs=None):
    repl = {}
    if dexdir:
        for name in sorted(os.listdir(dexdir)):
            if re.match(r'^classes\d*\.dex$', name):
                repl[name] = os.path.join(dexdir, name)
    for pair in (dex_pairs or []):
        if '=' not in pair:
            raise SystemExit('--dex expects name=path, got %r' % pair)
        name, path = pair.split('=', 1)
        repl[name] = path
    return repl


def is_signature_entry(name):
    """True ONLY for JAR/APK signature artifacts directly under META-INF/.

    META-INF/services/**, META-INF/androidx/**, META-INF/native-image/** and every
    other subdirectory are RUNTIME RESOURCES and must survive repacking. Anything
    that is not directly under META-INF/ is kept by construction.
    """
    if not name.upper().startswith('META-INF/'):
        return False
    rest = name[len('META-INF/'):]
    if '/' in rest:
        return False
    up = rest.upper()
    if up == 'MANIFEST.MF':
        return True
    return up.endswith(('.SF', '.RSA', '.DSA', '.EC'))


def build_unsigned(apk, repl, out_apk, drop_signatures=True):
    """Write a new apk with dex replaced and only signature entries dropped.

    IMPORTANT (root cause of a startup crash, do not regress):
    Stripping the WHOLE META-INF/ breaks ServiceLoader-based runtime wiring. Android
    reads these registries at runtime, and they live in the APK:
        META-INF/services/kotlinx.coroutines.internal.MainDispatcherFactory
        META-INF/services/io.ktor.client.HttpClientEngineContainer
        META-INF/services/<lib>.core.*                     (third-party SDK registries)
        META-INF/services/<obfuscated-class-name>          (R8-renamed providers)
    Deleting them makes the app die at startup with something like:
        IllegalStateException: Module with the Main dispatcher is missing ...
    and the message never points at META-INF, so the cause is very hard to find.
    Therefore: drop signature artifacts only, keep every META-INF subdirectory.

    ALIGNMENT. Writing the entries with a plain zipfile writer produces an archive
    Android R+ refuses to install:

        Failure [-124: Failed parse during installPackageLI: Targeting R+ (version
        30 and above) requires the resources.arsc of installed APKs to be stored
        uncompressed and aligned on a 4-byte boundary]

    Two independent requirements hide in that message: `resources.arsc` must be
    STORED (not deflated), and its data must start at a 4-byte boundary. The same
    applies to uncompressed `lib/*.so`. Python's zipfile cannot express an entry
    offset, so this writer emits the local headers itself and pads the local extra
    field to hit the boundary.
    """
    seen = set()
    replaced_names = set(repl)

    # Collect (name, source, data, keep_stored) in output order.
    plan = []
    with zipfile.ZipFile(apk, 'r') as zin:
        for item in zin.infolist():
            name = item.filename
            base = os.path.basename(name)
            if item.is_dir():
                continue
            if drop_signatures and is_signature_entry(name):
                log('[zip] - %s (signature artifact)' % name)
                continue
            if name in replaced_names:
                continue
            plan.append((name, item, zin.read(name),
                         name in STORE_ONLY or base in STORE_ONLY))
    for name, path in sorted(repl.items()):
        with open(path, 'rb') as fh:
            data = fh.read()
        info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
        plan.append((name, info, data, False))
        log('[zip] + %s  (%d bytes <- %s)' % (name, len(data), path))

    _write_aligned_zip(out_apk, plan)
    seen.update(name for name, _i, _d, _k in plan)
    return seen


ALIGN = 4
# Entries Android requires to be STORED, and (for some) 4-byte aligned.
ALIGNED_STORED = ('resources.arsc',)
# ABI-split libraries live at `lib/<abi>/*.so`, so the pattern must allow one more path segment:
# `^lib/[^/]+\.so$` matches nothing in a real APK and silently disabled STORED/alignment handling
# for every native library -- measured on a 435-entry real package (zip-safety pass, 2026-09).
ALIGNED_PATTERNS = (re.compile(r'^lib/(?:[^/]+/)*[^/]+\.so$'),)
FILLER_NAME = 'META-INF/ALIGN.RSV'


def _needs_alignment(name):
    if name in ALIGNED_STORED:
        return True
    return any(p.match(name) for p in ALIGNED_PATTERNS)


def _dos_word(dt):
    """(time, date) MS-DOS words for a zip local header."""
    y, mo, d, h, mi, s = dt
    if y < 1980:
        y, mo, d, h, mi, s = 1980, 1, 1, 0, 0, 0
    return (h << 11) | (mi << 5) | (s // 2), ((y - 1980) << 9) | (mo << 5) | d


def _local_header(nlen, method, crc, csize, usize, dt, flags=0, extralen=0):
    t, dd = _dos_word(dt)
    import struct
    return struct.pack('<IHHHHHIIIHH', 0x04034B50, 20, flags, method,
                       t, dd, crc, csize, usize, nlen, extralen)


def _deflate_raw(data):
    """Raw deflate (no zlib wrapper), which is what a zip method-8 entry holds.

    zlib.compress() prepends a 2-byte zlib header. Some readers tolerate it, some
    do not, and the failure reads as a corrupt entry rather than a bad compressor
    call, so use wbits=-15 and get it right the first time.
    """
    import zlib
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _write_aligned_zip(out_path, plan):
    """Write a zip whose STORED entries can be relied on for offset alignment.

    Padding rule, and why it is not just `(-offset) % 4`: a zip extra area is a
    sequence of (id, size, payload) records, so its minimum useful length is 4
    bytes. A required pad of 1-3 bytes therefore CANNOT be expressed in the extra
    field. When that happens this writer inserts a stored filler entry of exactly
    the needed size instead -- the filler has a computable size, so the following
    entry still lands on the boundary.
    """
    import struct
    import zlib

    order = []
    meta = {}
    offset = 0
    scratch = out_path + '.tmp'

    with open(scratch, 'wb') as out:
        for name, info, data, keep_stored in plan:
            name_b = name.encode('utf-8')
            if keep_stored:
                method, payload = 0, data
            else:
                method, payload = 8, _deflate_raw(data)
            crc = zlib.crc32(data) & 0xFFFFFFFF

            # reach the boundary before the local header of an aligned entry
            if _needs_alignment(name):
                need = (ALIGN - ((offset + 30 + len(name_b)) % ALIGN)) % ALIGN
                if need in (1, 2, 3):
                    off2, fill_meta = _emit_filler(out, offset, need)
                    order.append(FILLER_NAME)
                    meta[FILLER_NAME] = fill_meta
                    offset = off2

            extra, extralen = b'', 0
            if _needs_alignment(name):
                head = 30 + len(name_b)
                if (offset + head) % ALIGN != 0:
                    # expressible pad: one (id,size,payload) record >= 4 bytes
                    pad = (ALIGN - ((offset + head) % ALIGN)) % ALIGN
                    if pad < 4:
                        pad += ALIGN
                    extra = b'\xfe\xca' + struct.pack('<H', pad - 4) + b'\x00' * (pad - 4)
                    extralen = len(extra)

            flags = getattr(info, 'flag_bits', 0)
            local_header_offset = offset          # the CD points at the HEADER
            out.write(_local_header(len(name_b), method, crc, len(payload),
                                    len(data), info.date_time, flags, extralen))
            out.write(name_b)
            out.write(extra)
            data_off = offset + 30 + len(name_b) + extralen
            if out.tell() != data_off:
                raise RuntimeError('offset bookkeeping drift for %s' % name)
            if _needs_alignment(name) and data_off % ALIGN != 0:
                raise RuntimeError('%s not aligned: data at 0x%x' % (name, data_off))
            out.write(payload)
            offset = out.tell()

            order.append(name)
            meta[name] = {'name_b': name_b, 'method': method, 'crc': crc,
                          'csize': len(payload), 'usize': len(data),
                          'local_offset': local_header_offset,
                          'date_time': info.date_time, 'flag_bits': flags,
                          'external_attr': getattr(info, 'external_attr', 0)}

        cd_start = out.tell()
        for name in order:
            m = meta[name]
            t, dd = _dos_word(m['date_time'])
            # central directory: sig, ver_made, ver_need, flags, method, time,
            # date, crc, csize, usize, namelen, extralen, commentlen, disk,
            # int_attr, ext_attr, local_header_offset
            out.write(struct.pack(
                '<IHHHHHHIIIHHHHHII', 0x02014B50, 20, 20, m.get('flag_bits', 0),
                m['method'], t, dd, m['crc'], m['csize'], m['usize'],
                len(m['name_b']), 0, 0, 0, 0,
                (m['external_attr'] >> 16) & 0xFFFF, m['local_offset']))
            out.write(m['name_b'])
        cd_size = out.tell() - cd_start
        out.write(struct.pack('<IHHHHIIH', 0x06054B50, 0, 0, len(order), len(order),
                              cd_size, cd_start, 0))

    shutil.move(scratch, out_path)
    return order


def _emit_filler(out, offset, size):
    """Insert a stored, zero-filled entry of exactly `size` payload bytes."""
    import zlib
    name_b = FILLER_NAME.encode('utf-8')
    payload = b'\x00' * size
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    out.write(_local_header(len(name_b), 0, crc, size, size, (1980, 1, 1, 0, 0, 0)))
    out.write(name_b)
    out.write(payload)
    return out.tell(), {'name_b': name_b, 'method': 0, 'crc': crc,
                        'csize': size, 'usize': size,
                        'local_offset': offset,
                        'date_time': (1980, 1, 1, 0, 0, 0), 'external_attr': 0}


def check_alignment(apk):
    """Report storage + 4-byte alignment of the entries Android insists on.

    Returns a list of complaint strings; empty means the install gate is satisfied.
    """
    import struct
    bad = []
    with zipfile.ZipFile(apk, 'r') as z, open(apk, 'rb') as fh:
        for i in z.infolist():
            if not (i.filename in ALIGNED_STORED or _needs_alignment(i.filename)):
                continue
            fh.seek(i.header_offset)
            lh = fh.read(30)
            nlen, elen = struct.unpack('<HH', lh[26:30])
            data_off = i.header_offset + 30 + nlen + elen
            if i.compress_type != 0:
                bad.append('%s is compressed (method=%d); Android R+ requires '
                           'STORED' % (i.filename, i.compress_type))
            if i.filename != FILLER_NAME and data_off % ALIGN != 0:
                bad.append('%s data offset 0x%x is not %d-byte aligned'
                           % (i.filename, data_off, ALIGN))
    return bad


def zip_report(apk):
    """Entry summary, including the storage/alignment facts Android gates on.

    Only entries that MUST be aligned are judged on alignment. `AndroidManifest.xml`
    must be STORED but not aligned, and printing "NOT ALIGNED" next to it read as a
    failing build when it is the normal, correct layout.
    """
    import struct
    rows = []
    with zipfile.ZipFile(apk, 'r') as z, open(apk, 'rb') as fh:
        for i in z.infolist():
            base = os.path.basename(i.filename)
            must_align = _needs_alignment(i.filename)
            needs = (i.filename in STORE_ONLY or base in STORE_ONLY or must_align)
            if needs:
                fh.seek(i.header_offset)
                lh = fh.read(30)
                nlen, elen = struct.unpack('<HH', lh[26:30])
                data_off = i.header_offset + 30 + nlen + elen
                verdict = ('aligned' if data_off % ALIGN == 0
                           else 'NOT ALIGNED') if must_align else '-'
                stored = 'STORED' if i.compress_type == 0 else \
                    'COMPRESSED(method=%d)' % i.compress_type
                rows.append('%-40s %-22s offset=0x%-8x %s'
                            % (i.filename, stored, data_off, verdict))
            if re.match(r'^classes\d*\.dex$', i.filename):
                rows.append('%s %d bytes method=%d crc=%08x' % (
                    i.filename, i.file_size, i.compress_type, i.CRC))
    return rows


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------
def signer_invocation(path, tools):
    """Command prefix that runs apksigner, whatever shape it was shipped as.

    A build-tools directory offers `apksigner.bat` (Windows), `apksigner` (a
    shell wrapper) or the bare `lib/apksigner.jar`. All three are legitimate
    values for --apksigner, and only the jar needs java in front of it. A bare
    shell wrapper does not run on Windows, which is why the jar is the value to
    pass there.
    """
    if path.lower().endswith('.jar'):
        java = require(tools, 'java', 'run apksigner.jar')
        return [java, '-jar', path]
    return [path]


def sign_with_apksigner(unsigned_apk, out_apk, ks, alias, password, tools):
    """zipalign + apksigner (v1+v2+v3) -- the route that needs no uber-apk-signer.

    Order is load-bearing: align first, sign second. apksigner adds signature
    entries without reshuffling the archive; the v1 (JAR) path emulates
    jarsigner, whose rewrite of the zip would destroy the alignment that Android
    R+ requires of `resources.arsc`.
    """
    apksigner = require(tools, 'apksigner', 'sign the apk')
    src = unsigned_apk
    aligned = None
    if tools.get('zipalign'):
        aligned = unsigned_apk + '.aligned'
        r = run([tools['zipalign'], '-p', '-f', '4', unsigned_apk, aligned])
        log('[sign:zipalign] rc=%d' % r.returncode)
        if r.returncode != 0 or not os.path.exists(aligned):
            log(((r.stdout or '') + (r.stderr or '')).strip())
            raise SystemExit('error: zipalign failed; refusing to sign an '
                             'unaligned build')
        src = aligned
    else:
        log('[sign:zipalign] skipped: zipalign not available; the archive written '
            'by this script is already 4-byte aligned (see the alignment gate)')
    try:
        cmd = signer_invocation(apksigner, tools) + [
            'sign', '--ks', ks, '--ks-key-alias', alias,
            '--ks-pass', 'pass:' + password, '--key-pass', 'pass:' + password,
            '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
            '--v3-signing-enabled', 'true', '--out', out_apk, src]
        r = run(cmd)
        log('[sign:apksigner] rc=%d' % r.returncode)
        log(((r.stdout or '') + (r.stderr or '')).strip())
        if r.returncode != 0 or not os.path.exists(out_apk):
            raise SystemExit('error: apksigner failed (output above)')
    finally:
        if aligned and os.path.exists(aligned):
            os.remove(aligned)
    return out_apk


def choose_signer(args, tools):
    """Pick the signing route: the jar when it exists, else apksigner directly.

    The jar stays first so an existing workflow does not change behaviour. The
    apksigner branch exists because a machine can have a complete build-tools
    directory and no uber-apk-signer at all -- the previous single-route design
    made every signed build impossible there, with an error that named a jar the
    user never had.
    """
    jar = args.signer_jar or os.environ.get('APK_SIGNER_JAR', 'uber-apk-signer.jar')
    kind = getattr(args, 'signer', 'auto')
    if kind in ('auto', 'jar') and os.path.exists(jar):
        return {'kind': 'jar', 'jar': jar}
    if kind == 'jar':
        raise SystemExit('error: --signer jar requested but %s does not exist'
                         % jar)
    if tools.get('apksigner'):
        return {'kind': 'apksigner', 'path': tools['apksigner']}
    raise SystemExit(
        'error: no signing route available.\n'
        '  * uber-apk-signer.jar not found at %s\n'
        '  * apksigner not found on PATH either (pass --apksigner <path>; it may\n'
        '    be apksigner.bat, an apksigner wrapper, or lib/apksigner.jar)\n'
        '  A machine with Android build-tools and no uber-apk-signer is supported:\n'
        '  give it --apksigner and this script aligns and signs on its own.' % jar)


def sign_apk(unsigned_apk, workdir, ks, alias, password, tools, signer_jar):
    java = require(tools, 'java', 'run the signer jar')
    if not os.path.exists(signer_jar):
        raise SystemExit(
            'error: signer jar not found: %s\n'
            '  pass --signer-jar <path>, or set APK_SIGNER_JAR.\n'
            '  Any zipalign+apksigner based signer works here.' % signer_jar)

    outdir = os.path.join(workdir, 'signed')
    if os.path.isdir(outdir):
        shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir, exist_ok=True)

    cmd = [java, '-jar', signer_jar,
           '--apks', unsigned_apk,
           '--ks', ks, '--ksAlias', alias,
           '--ksPass', password, '--ksKeyPass', password,
           '-o', outdir, '--verbose']
    r = run(cmd)
    log('[sign] rc=%d' % r.returncode)
    log(r.stdout.strip())
    if r.stderr.strip():
        log('[sign][stderr] ' + r.stderr.strip())

    cand = os.path.join(outdir, os.path.basename(unsigned_apk))
    if not os.path.exists(cand):
        outs = [os.path.join(outdir, f) for f in os.listdir(outdir)] \
            if os.path.isdir(outdir) else []
        if not outs:
            raise SystemExit('signing produced no output')
        cand = outs[0]
    return cand


def verify_apk(apk, tools, signer_jar=None, expect_signed=True):
    log('== verify: %s' % apk)
    ok = True
    sig_checks = 0  # real signature-verification tools that actually ran

    # 1) apksigner -- the authoritative check, but ONLY with an explicit sdk range.
    #
    # READ THIS BEFORE CONCLUDING THE SIGNATURE IS BROKEN:
    # `apksigner verify` with no range checks the signature schemes implied by the
    # APK's own minSdkVersion. With minSdk >= 24 it prints v1/v2 as false while the
    # files in META-INF are perfectly fine, which looks exactly like a failed signing
    # step. Always pass --min-sdk-version / --max-sdk-version so the v1/v2/v3 results
    # are meaningful.
    if tools.get('apksigner'):
        sig_checks += 1
        r = run(signer_invocation(tools['apksigner'], tools) + [
            'verify', '--print-certs', '--verbose',
            '--min-sdk-version', '21', '--max-sdk-version', '34', apk])
        log('[verify:apksigner] rc=%d\n%s' % (r.returncode, ((r.stdout or '') +
            (r.stderr or '')).strip()[:3000]))
        if r.returncode != 0:
            ok = False
    else:
        log('[verify:apksigner] skipped: apksigner not on PATH.\n'
            '  Do NOT judge the signature from a bare `apksigner verify`: with\n'
            '  minSdk >= 24 its default range reports v1/v2 as false even when the\n'
            '  signature is valid. The correct invocation is:\n'
            '    apksigner verify --print-certs --verbose --min-sdk-version 21 '
            '--max-sdk-version 34 <apk>')

    # 2) signer jar's own verify (also re-checks alignment)
    if signer_jar and os.path.exists(signer_jar) and tools.get('java'):
        sig_checks += 1
        r = run([tools['java'], '-jar', signer_jar, '-a', apk, '-y'])
        log('[verify:signer] rc=%d\n%s' % (r.returncode, (r.stdout or '').strip()))
        if r.returncode != 0 and 'DOES NOT VERIFY' in (r.stdout or ''):
            ok = False

    # 3) jarsigner (v1 / JAR signature)
    if tools.get('jarsigner'):
        sig_checks += 1
        r = run([tools['jarsigner'], '-verify', '-certs', apk])
        txt = ((r.stdout or '') + (r.stderr or '')).strip()
        log('[verify:jarsigner] rc=%d\n%s' % (r.returncode, txt[:2000]))
        if 'jar verified' not in txt and 'verified' not in txt.lower():
            log('[verify:jarsigner] note: not reported as verified (see output above)')

    # 4) keytool cert dump
    if tools.get('keytool'):
        r = run([tools['keytool'], '-printcert', '-jarfile', apk])
        log('[verify:keytool] rc=%d\n%s' % (r.returncode, (r.stdout or '').strip()[:1500]))

    # 5) zipalign check
    if tools.get('zipalign'):
        r = run([tools['zipalign'], '-c', '-v', '4', apk])
        log('[verify:zipalign] rc=%d' % r.returncode)
        if r.returncode != 0:
            log((r.stdout or '').strip()[:1500])
    else:
        log('[verify:zipalign] skipped: zipalign not on PATH')

    # 6) v2/v3 APK Signing Block presence, read straight from the file
    with open(apk, 'rb') as fh:
        blob = fh.read()
    log('[verify:v2block] %s' % ('present' if b'APK Sig Block 42' in blob else 'MISSING'))

    # A build nobody could verify is not a passing build. Saying OK here would
    # violate the first rule of this skill ("an APK is not done until it is
    # verified"): report UNVERIFIED and fail instead.
    if expect_signed and sig_checks == 0:
        log('[result] UNVERIFIED: no signature verification tool was available '
            '(apksigner / jarsigner / signer jar). This is NOT an OK result.')
        return False
    return ok


def fingerprint(apk, tools):
    """Signer fingerprints. keytool when there is one, apksigner otherwise.

    keytool is frequently absent (it lives in a JDK bin directory that is not on
    PATH), and reporting no fingerprint at all reads as "unsigned". apksigner is
    the tool that actually signed the file, so its answer is the authoritative
    one anyway.
    """
    if tools.get('keytool'):
        r = run([tools['keytool'], '-printcert', '-jarfile', apk])
        found = re.findall(r'(SHA1|SHA256):\s*([0-9A-F:]+)', r.stdout or '')
        if found:
            return found
    return [('SHA-256', f) for f in cert_fingerprints(apk, tools)]


def resolve_keystore(args, tools):
    """Return (keystore path, password), creating the keystore on first use."""
    if not args.ks:
        raise SystemExit(
            "error: --ks is required when signing (there is no default keystore).\n"
            "  e.g. --ks work/out/release.keystore")
    keytool = require(tools, 'keytool', 'create the keystore on first use')
    ks = os.path.abspath(args.ks)
    return ks, ensure_keystore(ks, args.ks_alias, args.ks_pass, keytool)


def sign_one_artifact(unsigned_apk, out_path, args, tools, signer, ks, password, workdir):
    """Sign one unsigned APK through whichever route choose_signer() picked."""
    if signer['kind'] == 'jar':
        signed = sign_apk(unsigned_apk, workdir, ks, args.ks_alias, password,
                          tools, signer['jar'])
        if os.path.abspath(signed) != os.path.abspath(out_path):
            shutil.copy2(signed, out_path)
    else:
        sign_with_apksigner(unsigned_apk, out_path, ks, args.ks_alias, password, tools)
    return out_path


def scratch_dir(args, fallback):
    workdir = os.path.abspath(args.workdir) if args.workdir else fallback
    if not workdir:
        workdir = os.getcwd()
    os.makedirs(workdir, exist_ok=True)
    return workdir


def run_split_mode(args, tools):
    """Handle --split-dir / --split: inventory the set, pick a legal route, act.

    Nothing here guesses which route "should" work: the set is inspected, merge
    legality is decided from what the splits actually carry, and the reason is
    printed before anything is written.
    """
    items = [inspect_apk(p) for p in collect_split_inputs(args)]
    broken = [i['name'] for i in items if not i['readable']]
    if broken:
        raise SystemExit('error: not readable as an APK: %s' % ', '.join(broken))

    log('== split set: %d apk(s), %d bytes total'
        % (len(items), sum(i['size'] for i in items)))
    for row in split_report(items):
        log('  ' + row)

    base, others, blockers, notes = plan_split_set(items)
    if base is None or not others:
        for b in blockers:
            log('[plan] BLOCKED: %s' % b)
        if base is not None:
            log('[plan] %s is the only member -- a single APK: run without '
                '--split/--split-dir' % base['name'])
        return 2
    log('[plan] base = %s (package=%s)' % (base['name'], base.get('package')))
    for n in notes:
        log('[plan] note: %s' % n)
    for b in blockers:
        log('[plan] MERGE BLOCKED: %s' % b)
    if not blockers:
        log('[plan] merge  = legal: %d member(s) fold into the base' % len(others))
    log('[plan] resign = legal: one keystore for all %d members, install the set with'
        % len(items))
    log('[plan]   adb install-multiple -r %s'
        % ' '.join(i['name'] for i in items))

    mode = args.split_mode
    if mode == 'auto':
        if blockers:
            mode = 'resign'
        elif (args.out or '').lower().endswith('.apk'):
            mode = 'merge'
        else:
            mode = 'resign'
        log('[plan] --split-mode auto resolved to: %s' % mode)

    if mode == 'analyze':
        log('[result] analyze only: nothing was written. Pass --split-mode '
            'merge|resign|auto to act on this set.')
        return 0

    if mode == 'merge':
        return _split_merge(args, tools, base, others)

    outdir = args.split_out_dir or (os.path.abspath(args.out) if args.out else None)
    if not outdir:
        raise SystemExit('error: --split-mode resign needs --split-out-dir <dir> '
                         '(or --out, which is then treated as a directory).')
    outdir = os.path.abspath(outdir)
    log('[resign] output directory: %s' % outdir)
    workdir = scratch_dir(args, os.path.join(outdir, '.work'))
    signer = None
    ks = password = None
    if not args.no_sign:
        signer = choose_signer(args, tools)
        ks, password = resolve_keystore(args, tools)
        log('[resign] signer route: %s' % signer['kind'])

    if args.no_sign:
        def sign_member(unsigned, out_path):
            shutil.copy2(unsigned, out_path)
            return out_path
    else:
        def sign_member(unsigned, out_path):
            return sign_one_artifact(unsigned, out_path, args, tools, signer,
                                     ks, password, workdir)

    outs = resign_split_set(items, outdir, sign_member)

    fps = set()
    ok_all = True
    signer_jar = signer['jar'] if signer and signer['kind'] == 'jar' else None
    for info, path in outs:
        if not verify_apk(path, tools, signer_jar, expect_signed=not args.no_sign):
            ok_all = False
        for f in cert_fingerprints(path, tools):
            fps.add(f)
            log('[cert] %s  %s' % (info['name'], f))

    if not args.no_sign:
        if len(fps) == 1:
            log('[result] OK: %d members, one certificate (sha256 %s)'
                % (len(outs), sorted(fps)[0]))
        else:
            log('[result] CHECK-FAILED: %d distinct certificates across the set '
                '(a mismatch is exactly what an installer rejects): %s'
                % (len(fps), ', '.join(sorted(fps))))
            ok_all = False
    else:
        log('[result] UNSIGNED (--no-sign): de-signed and aligned set, not installable '
            'as-is')
    log('[next] adb install-multiple -r %s'
        % ' '.join(os.path.join(outdir, i['name']) for i in items))
    return 0 if ok_all else 2


def _split_merge(args, tools, base, others):
    """The merge half of run_split_mode (kept separate to stay readable)."""
    if not args.out:
        raise SystemExit('error: --split-mode merge needs --out <merged.apk>')
    out = os.path.abspath(args.out)
    folder = os.path.dirname(out)
    if folder:
        os.makedirs(folder, exist_ok=True)
    unsigned = out + '.unsigned'
    if os.path.exists(unsigned):
        os.remove(unsigned)

    stats, dropped = merge_split_set(base, others, unsigned,
                                     allow_drop_resources=args.drop_split_resources,
                                     keep_abi=args.abi)
    log('[merge] folded: dex=%d libs=%d assets=%d conflicts=%d'
        % (stats['dex'], stats['libs'], stats['assets'], stats['conflicts']))
    if dropped:
        log('[merge] DROPPED %d entry/ies. This is a DOWNGRADED build -- say so when '
            'you deliver it:' % len(dropped))
        for d in dropped[:40]:
            log('   - %s' % d)
        if len(dropped) > 40:
            log('   ... and %d more' % (len(dropped) - 40))

    for row in zip_report(unsigned):
        log('[zip]   ' + row)
    problems = check_alignment(unsigned)
    if problems:
        log('== ALIGNMENT/STORAGE GATE FAILED -- do not ship this build:')
        for p in problems:
            log('   - %s' % p)
    else:
        log('== alignment gate: resources.arsc STORED and 4-byte aligned (OK)')

    if args.no_sign:
        shutil.move(unsigned, out)
        log('[out] %s (%d bytes)' % (out, os.path.getsize(out)))
        log('[result] UNSIGNED (--no-sign): inspection only, not installable as-is')
        return 0

    workdir = scratch_dir(args, folder or os.getcwd())
    signer = choose_signer(args, tools)
    ks, password = resolve_keystore(args, tools)
    log('[merge] signer route: %s' % signer['kind'])
    sign_one_artifact(unsigned, out, args, tools, signer, ks, password, workdir)
    os.remove(unsigned)
    log('[out] %s (%d bytes)' % (out, os.path.getsize(out)))

    ok = verify_apk(out, tools,
                    signer['jar'] if signer['kind'] == 'jar' else None)
    for algo, val in fingerprint(out, tools):
        log('[cert] %s %s' % (algo, val))
    log('[result] %s' % ('OK' if ok else 'CHECK-FAILED'))
    log('[next] adb install -r %s   (one file, no set to keep together)' % out)
    return 0 if ok else 2


def main():
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Repack an APK with replaced dex files, drop only the signature '
                    'entries, re-sign and verify.\n'
                    'Also handles SPLIT APK / App Bundle sets (base.apk plus\n'
                    'split_config.*.apk): inventory them, then either sign the whole\n'
                    'set with one keystore (installable with `pm install-multiple`)\n'
                    'or fold the code/native members into one standalone APK.',
        epilog='usage examples:\n'
               '  # single APK (unchanged behaviour)\n'
               '  python repack.py --apk original.apk --dexdir dex/ --out out.apk '
               '--ks ks.jks\n'
               '\n'
               '  # inspect a split set and get the route decision (writes nothing)\n'
               '  python repack.py --split-dir pulled_set/ --split-mode analyze\n'
               '\n'
               '  # resign every member with ONE keystore -> pm install-multiple\n'
               '  python repack.py --split-dir pulled_set/ --split-mode resign \\\n'
               '      --split-out-dir signed_set/ --ks ks.jks \\\n'
               '      --apksigner /path/to/lib/apksigner.jar\n'
               '\n'
               '  # fold code/native splits into one standalone APK\n'
               '  python repack.py --split-dir pulled_set/ --split-mode merge \\\n'
               '      --out merged.apk --ks ks.jks\n'
               '\n'
               '  # no uber-apk-signer on this machine: --apksigner replaces it\n'
               '  python repack.py --apk app.apk --out out.apk --ks ks.jks \\\n'
               '      --apksigner /path/to/lib/apksigner.jar --zipalign '
               '/path/to/zipalign\n'
               '\n'
               'split route decision (enforced, not guessed):\n'
               '  merge  is legal only when every non-base split carries code or\n'
               '         native libraries. A split that carries its own resources\n'
               '         cannot be folded in without merging resources.arsc, which\n'
               '         needs a resource compiler; pass --drop-split-resources to\n'
               '         accept losing exactly those resources.\n'
               '  resign always works: one keystore, v1+v2+v3 on every member.\n')
    ap.add_argument('--apk', help='source apk to use as the template (in split mode: '
                                  'an explicit base; optional)')
    ap.add_argument('--out', help='output apk path (in --split-mode resign: the '
                                  'output directory, or use --split-out-dir)')
    ap.add_argument('--dexdir', help='directory of classes*.dex to swap in')
    ap.add_argument('--dex', action='append', default=[],
                    help='name=path, repeatable, e.g. classes8.dex=work/patch/classes8.dex')
    ap.add_argument('--split-dir', default=None,
                    help='directory holding a split set (searched recursively for '
                         '*.apk); every member must share one package name')
    ap.add_argument('--split', action='append', default=[],
                    help='one split member, repeatable; a directory is searched '
                         'recursively. Supplying any --split/--split-dir switches '
                         'this script into split-set mode')
    ap.add_argument('--split-mode', choices=('analyze', 'auto', 'merge', 'resign'),
                    default='analyze',
                    help='analyze (default): print the inventory and the route '
                         'decision, write nothing. auto: merge when that is legal '
                         'and --out ends in .apk, else resign. merge: fold into one '
                         'standalone APK (--out). resign: sign every member with one '
                         'keystore (--split-out-dir)')
    ap.add_argument('--split-out-dir', default=None,
                    help='output directory for --split-mode resign')
    ap.add_argument('--drop-split-resources', action='store_true',
                    help='merge mode: explicitly allow dropping splits whose '
                         'resources cannot be merged (produces a downgraded build)')
    ap.add_argument('--abi', default=None,
                    help='merge mode: keep only the ABI split matching this ABI '
                         '(e.g. arm64-v8a). Compare with the device via '
                         '`getprop ro.product.cpu.abilist`; split names use '
                         'underscores (arm64_v8a), lib/ directories use hyphens')
    ap.add_argument('--workdir', default=None,
                    help='scratch directory (default: next to --out)')
    ap.add_argument('--ks', default=None, help='keystore path (created on first use)')
    ap.add_argument('--ks-alias', default='apkreverse', help='keystore alias')
    ap.add_argument('--ks-pass', default=None,
                    help='keystore password; default: <ks>.pass.txt, else generated')
    ap.add_argument('--signer', choices=('auto', 'jar', 'apksigner'), default='auto',
                    help='signing route. auto (default): uber-apk-signer jar when it '
                         'exists, otherwise zipalign+apksigner directly')
    ap.add_argument('--signer-jar', default=None,
                    help='jar used for zipalign+sign (default: $APK_SIGNER_JAR or '
                         'uber-apk-signer.jar)')
    ap.add_argument('--no-sign', action='store_true', help='stop after writing the apk')
    ap.add_argument('--java', default=None, help='path to java (default: from PATH)')
    ap.add_argument('--keytool', default=None, help='path to keytool (default: from PATH)')
    ap.add_argument('--jarsigner', default=None, help='path to jarsigner (default: from PATH)')
    ap.add_argument('--zipalign', default=None, help='path to zipalign (default: from PATH)')
    ap.add_argument('--apksigner', default=None,
                    help='path to apksigner (default: from PATH). Accepts '
                         'apksigner.bat, an apksigner wrapper, or lib/apksigner.jar')
    args = ap.parse_args()

    tools = resolve_tools(args)

    split_mode = bool(args.split_dir or args.split)
    if not split_mode:
        if not args.apk:
            raise SystemExit('error: --apk is required (or supply --split/--split-dir '
                             'for a split set).')
        if not args.out:
            raise SystemExit('error: --out is required.')

    if split_mode:
        return run_split_mode(args, tools)

    apk = os.path.abspath(args.apk)
    out = os.path.abspath(args.out)
    if not os.path.exists(apk):
        raise SystemExit('missing apk: %s' % apk)

    # Default the scratch dir next to --out; never to a machine-specific path.
    workdir = scratch_dir(args, os.path.dirname(out))

    repl = collect_replacement_dex(args.dexdir, args.dex)
    log('[in ] %s (%d bytes)' % (apk, os.path.getsize(apk)))
    log('[tools] java=%s keytool=%s apksigner=%s zipalign=%s'
        % (tools['java'], tools['keytool'], tools['apksigner'], tools['zipalign']))
    log('[repl] %s' % (', '.join('%s<-%s' % (k, v) for k, v in sorted(repl.items())) or '<none>'))

    unsigned = os.path.join(workdir, 'unsigned.apk')
    if os.path.exists(unsigned):
        os.remove(unsigned)
    build_unsigned(apk, repl, unsigned)
    log('[zip] unsigned written: %d bytes' % os.path.getsize(unsigned))
    for row in zip_report(unsigned):
        log('[zip]   ' + row)

    signer = None
    if args.no_sign:
        shutil.copy2(unsigned, out)
    else:
        signer = choose_signer(args, tools)
        log('[sign] route: %s' % signer['kind'])
        ks, password = resolve_keystore(args, tools)
        sign_one_artifact(unsigned, out, args, tools, signer, ks, password, workdir)

    log('[out] %s (%d bytes)' % (out, os.path.getsize(out)))
    log('== zip layout of final apk')
    for row in zip_report(out):
        log('   ' + row)
    alignment_problems = check_alignment(out)
    if alignment_problems:
        log('== ALIGNMENT/STORAGE GATE FAILED -- do not ship this build:')
        for p in alignment_problems:
            log('   - %s' % p)
        log('   Android R+ (targetSdk 30+) refuses to install an APK whose '
            'resources.arsc is compressed or not 4-byte aligned.')
    else:
        log('== alignment gate: resources.arsc STORED and 4-byte aligned (OK)')

    ok = verify_apk(out, tools,
                    signer['jar'] if signer and signer['kind'] == 'jar' else None,
                    expect_signed=not args.no_sign)
    if not args.no_sign:
        for algo, val in fingerprint(out, tools):
            log('[cert] %s %s' % (algo, val))
        log('[result] %s' % ('OK' if ok else 'CHECK-FAILED'))
    else:
        log('[result] UNSIGNED (--no-sign): good for inspection, not installable as-is')
    log('[reminder] repacking is not done until the app launches and the changed '
        'behavior is exercised on a device: see scripts/install_test.py')
    return 0 if ok else 2


if __name__ == '__main__':
    sys.exit(main())
