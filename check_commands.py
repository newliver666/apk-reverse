#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate every `python <script>.py ...` command this repository's docs tell a reader
to run, against the script's own argument table.

WHY THIS EXISTS
---------------
`check_repo.py` proves that a reference path *resolves* and that every script answers
`--help`. Neither check can see the failure that costs a round: a documented command
whose flags no longer exist. The repository has already shipped one.

  `references/signature-derived-keys.md` documented
      python scripts/sig_probe.py --live --pkg <pkg>
  for a long time. `sig_probe.py` takes `--live PKG` and has never had a `--pkg`, so the
  command failed with "unrecognized arguments" at the one moment a reader was following
  the page instead of the tool. A doc-vs-code drift like this is invisible to every
  structural gate: the file exists, the line number is right, the script runs.

HOW IT DECIDES
--------------
The argument table is read from the script's source with `ast`:
`ArgumentParser()` / `add_argument()` calls are parsed statically, so no script is
executed to learn its interface. A script whose interface cannot be read statically (a
hand-rolled `sys.argv` parser, a generated parser) falls back to parsing its own `--help`
output, and one that offers neither is reported as `unverifiable` -- counted, not
silently skipped, because "no finding" from an unread interface is not evidence.

Two allowance rules keep the report honest rather than noisy:

  * argparse accepts a **unique prefix** of a long option (`--min-sdk` for
    `--min-sdk-version`), so a prefix that resolves to exactly one known flag passes.
  * argparse's own `-h/--help` is always accepted.

Workbench references (`tools/...`, which `.gitignore` excludes) are reported as
`workbench` and skipped: `docs/tool-verification/README.md` states that such a path is an
operation record, not something a reader can open, so a missing file there is not drift.

Usage
-----
    python check_commands.py                     # validate the documented surface
    python check_commands.py --fix-report        # one machine-readable line per finding
    python check_commands.py --json              # machine-readable, full detail
    python check_commands.py --path docs/        # restrict to one subtree
    python check_commands.py --include-workbench # also resolve tools/... references
    python check_commands.py --quiet             # only findings

Exit codes: 0 = every documented command matches its script, 1 = at least one
inconsistency, 2 = usage error, 4 = internal error. The last line is `RESULT=<token>`.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(ROOT, 'skills', 'apk-reverse')
SCRIPT_DIR = os.path.join(SKILL_DIR, 'scripts')

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_USE = 2
EXIT_INTERNAL = 4

TOKENS = {
    'ok': 'commands_ok',
    'drift': 'commands_drift',
    'use': 'usage_error',
    'internal': 'internal_error',
}

NO_VALUE_ACTIONS = {'store_true', 'store_false', 'store_const', 'count', 'help',
                    'version', 'append_const'}
VARIABLE_NARGS = {'*', '+', '?', 'REMAINDER', 'argparse.REMAINDER'}

CMD_TOKEN_RE = re.compile(r'^(python3?|py)(\.exe)?$', re.I)
FLAG_RE = re.compile(r'^(--[A-Za-z][A-Za-z0-9_-]*)(=.*)?$')
SHORT_RE = re.compile(r'^(-[A-Za-z0-9])(=.*)?$')
USAGE_FLAG_RE = re.compile(r'(\[?-{1,2}[A-Za-z][A-Za-z0-9_-]*)\]?')

# Documented commands whose script lives in ANOTHER repository's checkout, reached by a
# path relative to that checkout rather than to this one. A silent allow-list is how a
# real drift gets buried, so every entry carries its reason and the report prints the
# whole table: an exclusion a reader can audit is not a hole.
EXTERNAL_SCRIPTS = {
    'scripts/init_env_win.py':
        "blutter's own environment script, run from inside the blutter checkout -- the "
        "record's preceding line is `git clone --depth 1 worawit/blutter` "
        "(docs/tool-verification/TOOL-VERDICTS.md)",
    # Both spellings of the same upstream entry point are declared, because the two records write
    # it differently and each spelling has to stand on its own: `./dcc.py` (invoked from inside its
    # checkout) and the bare `dcc.py` after a `cd` into it. Both are here for the same reason --
    # the `cd`-then-bare-name form only skips while the gitignored `tools/` tree happens to exist,
    # so recognition by filename alone reported drift on a clean checkout.
    './dcc.py':
        "the entry point of the dcc checkout, invoked as `./dcc.py` from inside it after "
        "`cd tools/_work/bench/repos/dcc` -- the `./` is what says so, and this repository "
        "ships no dcc.py (docs/tool-verification/EXTENSION-reconstruction.md)",
    'dcc.py':
        "the dcc tool's own entry point, run from inside its checkout -- the record's "
        "preceding line is `cd tools/_work/bench/repos/dcc`, and this repository ships "
        "no dcc.py (docs/tool-verification/EXTENSION-java2c.md). Declared rather than "
        "inferred because the `cd`-then-bare-name form only skips as workbench-after-cd "
        "while the gitignored tools/ tree happens to exist locally; a clean checkout has "
        "no such file to recognise, and without this entry the gate reported drift there.",
}

# Commands an evidence record *quotes* rather than offers. The key is (document,
# normalised command text), not a line number, so it survives edits above it. Each entry
# needs a reason, and the report prints them: an exclusion a reader can audit is not a
# hole, whereas a silent one would be indistinguishable from a missed drift.
QUOTED_COMMANDS = {
    ('docs/tool-verification/FINDINGS.md',
     'python scripts/sig_probe.py --live --pkg <pkg>'):
        "FINDINGS.md quotes this command as the historical defect it records. It is "
        "evidence about the drift, not an instruction a reader runs; the page's own text "
        "says the script has no --pkg.",
    ('docs/tool-verification/EXTENSION-reconstruction.md',
     'python scripts/sig_probe.py --live --pkg <pkg>'):
        "the same command appears in this pass's evidence file as the `--fix-report` "
        "output that proves the checker catches it -- a reproduction of a defect, printed "
        "with the fix beside it.",
}


# ---------------------------------------------------------------- script argument tables

def _str_const(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) \
        else None


def _kwarg(call, name):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _nargs_value(call):
    """nargs as its plain Python value ('+', '*', '?', an int) or None."""
    node = _kwarg(call, 'nargs')
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    name = getattr(node, 'attr', None) or getattr(node, 'id', None)
    return name


def _takes_value(call):
    """Does this add_argument() consume the following token?

    `nargs='?'` and `nargs='*'` consume zero or more *following* tokens, so for the
    purpose of deciding whether the next token is a value they are treated as consuming
    one; the caller additionally refuses to count positional arguments whenever an
    option with a variable nargs exists, because that count is not decidable statically.
    """
    action = _str_const(_kwarg(call, 'action')) if _kwarg(call, 'action') else None
    if action in NO_VALUE_ACTIONS:
        return False
    nargs = _nargs_value(call)
    if isinstance(nargs, int) and nargs == 0:
        return False
    return True


def _positional_bounds(positional):
    """(min, max) tokens this positional accepts. `max` is None for unbounded."""
    nargs = positional.get('nargs')
    if isinstance(nargs, int):
        return nargs, nargs
    if nargs in ('+', 'REMAINDER', 'argparse.REMAINDER'):
        return 1, None
    if nargs == '*':
        return 0, None
    if nargs == '?':
        return 0, 1
    return 1, 1


def ast_arg_table(path):
    """Parse the argparse interface out of a script without running it.

    Returns (spec, error). `spec` is None when the file defines no `add_argument` call at
    all, which means the interface has to be read some other way.
    """
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            tree = ast.parse(fh.read(), path)
    except (OSError, SyntaxError) as exc:
        return None, '%s: %s' % (type(exc).__name__, exc)

    subparser_vars = set()
    flags = {}        # flag -> {'takes_value','nargs','group'}
    positionals = []  # {'name','nargs','group'}
    dynamic = []      # add_argument calls whose names are not literals

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        tgt, val = node.targets[0], node.value
        if isinstance(tgt, ast.Name) and isinstance(val, ast.Call) \
                and getattr(val.func, 'attr', '') == 'add_subparsers':
            subparser_vars.add(tgt.id)

    # `sub = main.add_subparsers(); p = sub.add_parser('cmd')` -- the sub-parser object
    # is a separate interface, so its flags are attributed to `cmd` rather than to the
    # top-level parser. Merging them into one set would hide a real drift behind a
    # sibling subcommand's flag.
    #
    # One variable can be reused across several sub-parsers (`p = sub.add_parser('a')`
    # then `p = sub.add_parser('b')`), so the mapping keeps every name the variable was
    # bound to; the parameters are then attributed to the group as a whole.
    sub_parser_names = {}
    subcommands = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt, val = node.targets[0], node.value
            if isinstance(tgt, ast.Name) and isinstance(val, ast.Call) \
                    and getattr(val.func, 'attr', '') == 'add_parser' and val.args:
                name = _str_const(val.args[0])
                if name:
                    sub_parser_names.setdefault(tgt.id, set()).add(name)
                    subcommands.add(name)
        if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'add_parser' \
                and node.args:
            name = _str_const(node.args[0])
            if name:
                subcommands.add(name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node.func, 'attr', '') != 'add_argument':
            continue
        group = 'top'
        owner = node.func.value
        if isinstance(owner, ast.Name) and owner.id in sub_parser_names:
            names_bound = sub_parser_names[owner.id]
            group = 'sub:' + sorted(names_bound)[0] if len(names_bound) == 1 else 'sub:*'
        elif isinstance(owner, ast.Name) and owner.id in subparser_vars:
            group = 'sub:?'
        elif isinstance(owner, ast.Call) and \
                getattr(owner.func, 'attr', '') == 'add_parser' and owner.args:
            # chained: sub.add_parser('x').add_argument(...)
            name = _str_const(owner.args[0])
            if name:
                group = 'sub:' + name

        names = [_str_const(a) for a in node.args]
        if any(isinstance(a, ast.Starred) for a in node.args) or not names:
            dynamic.append({'group': group, 'line': node.lineno})
            continue
        takes = _takes_value(node)
        nargs = _nargs_value(node)
        long_flags = [n for n in names if n and n.startswith('--')]
        short_flags = [n for n in names if n and n.startswith('-') and not n.startswith('--')]
        if not long_flags and not short_flags:
            positionals.append({'name': names[0], 'nargs': nargs, 'group': group,
                                'line': node.lineno})
            continue
        for f in long_flags + short_flags:
            flags[f] = {'takes_value': takes, 'nargs': nargs, 'group': group,
                        'line': node.lineno}

    if not flags and not positionals:
        return None, None
    return {'flags': flags, 'positionals': positionals, 'dynamic': dynamic,
            'subcommands': subcommands, 'source': 'ast', 'extra': []}, None


def help_arg_table(path):
    """Fallback: read the interface from the script's own `--help` output.

    Used when the interface is not declared through argparse at all (a hand-rolled
    `sys.argv` parser such as `smtool.py`). `--help` is then whatever the script does
    with an unrecognised first argument, which for these scripts is to print its usage
    block and exit -- so the flags are read from the whole output, with a word boundary
    in front so that a jar name like `antlr-runtime-3.5.2.jar` cannot be mistaken for
    the option `-runtime`.

    The probe runs in a throwaway directory. A probe must not leave anything behind, and
    a script that treats its first argument as an output directory would otherwise
    create one named after the flag. This is not hypothetical: the workbench carried a
    stray `--help/` directory holding planted leak fixtures, produced by exactly that
    mistake.
    """
    scratch = tempfile.mkdtemp(prefix='check-commands-help-')
    try:
        p = subprocess.run([sys.executable, '-B', path, '--help'],
                           capture_output=True, text=True, timeout=30, cwd=scratch)
    except (OSError, subprocess.TimeoutExpired):
        shutil.rmtree(scratch, ignore_errors=True)
        return None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    text = (p.stdout or '') + '\n' + (p.stderr or '')
    if not text.strip():
        return None

    flags = {}
    for raw in text.splitlines():
        stripped = raw.strip()
        for m in USAGE_FLAG_RE.finditer(stripped):
            start = m.start(1)
            if start and re.match(r'[A-Za-z0-9_.]', stripped[start - 1]):
                continue
            tok = m.group(1).strip('[]')
            if tok in ('-', '--'):
                continue
            after = stripped[m.end():].lstrip('[] ,')
            head = after.split()[0] if after.split() else ''
            takes = bool(head) and not head.startswith(('-', '['))
            flags.setdefault(tok, {'takes_value': takes, 'nargs': None,
                                   'group': 'top', 'line': 0})
    if not flags:
        return None
    return {'flags': flags, 'positionals': [], 'dynamic': [], 'subcommands': set(),
            'source': 'help', 'extra': []}


def docstring_flags(path):
    """Flags a script advertises in its own docstring's example commands.

    These are not authoritative (the argparse table is), but a flag that appears only
    here is a real drift worth reporting: the script's own documentation promises an
    interface it does not implement.
    """
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            src = fh.read()
    except OSError:
        return set()
    m = re.match(r'\s*(?:#!.*\n)?(?:#.*\n)*\s*[rubfRUBF]*("""|\'\'\')(.*?)\1', src, re.S)
    if not m:
        return set()
    out = set()
    for line in m.group(2).splitlines():
        s = line.strip()
        if s.startswith(('python ', 'python3 ', 'py ')) or s.startswith('$ python'):
            for tok in split_cmd(s):
                if tok.startswith('--') and FLAG_RE.match(tok):
                    out.add(tok.split('=')[0])
    return out


def script_spec(path):
    """The interface of one script: (spec_or_None, source_label)."""
    spec, err = ast_arg_table(path)
    if spec is not None:
        spec['extra'] = sorted(docstring_flags(path))
        return spec, ('ast', err)
    fallback = help_arg_table(path)
    if fallback is not None:
        fallback['extra'] = sorted(docstring_flags(path))
        return fallback, ('help', err)
    return None, ('none', err)


# ---------------------------------------------------------------- command extraction

def split_cmd(line):
    """Whitespace split honouring quotes. Backslashes stay literal: on Windows a
    documented path is `scripts\\x.py`, and posix shlex would eat the separator.
    Square brackets are separators, so the optional-argument notation a reference uses
    (`svc_scan.py libfoo.so [--context 3]`) yields flags rather than punctuation."""
    out, cur, quote = [], '', None
    for ch in line:
        if quote:
            if ch == quote:
                quote = None
            else:
                cur += ch
        elif ch in '"\'':
            quote = ch
        elif ch.isspace() or ch in '[]':
            if cur:
                out.append(cur)
                cur = ''
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def strip_comment(line):
    out, quote = '', None
    for i, ch in enumerate(line):
        if quote:
            out += ch
            if ch == quote:
                quote = None
        elif ch in '"\'':
            quote = ch
            out += ch
        elif ch == '#' and (i == 0 or line[i - 1].isspace()):
            break
        else:
            out += ch
    return out


def join_continuations(lines):
    """Join `\\`/`^`/backtick-continued lines so a wrapped command is read as one."""
    out, buf = [], ''
    for raw in lines:
        line = raw.rstrip()
        stripped = line.rstrip('\\^`').rstrip()
        if line.endswith('\\') or line.endswith('^') or \
                (line.endswith('`') and not line.endswith('``')):
            buf += stripped + ' '
            continue
        out.append(buf + line)
        buf = ''
    if buf:
        out.append(buf)
    return out


def split_shell(line):
    """Split one documented line into independently checkable commands.

    A documentation line is frequently compound (`python check_repo.py && python
    check_refs.py`) or a pipeline, and a redirection belongs to the shell rather than to
    the script. Reading the whole line as one argv put `&&`, `python` and the redirect
    target into the positional count, which produced findings about the document's
    punctuation instead of its commands.
    """
    parts, cur, quote, i = [], '', None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            cur += ch
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in '"\'':
            quote = ch
            cur += ch
            i += 1
            continue
        if ch in '<>':
            # `<PKG>` and `<original.dex>` are the placeholders this repository's docs
            # use for a value; `> out.txt` is a shell redirection. Reading the first as a
            # redirect truncates the command at `--pkg`, and a truncated command checks
            # clean -- which is exactly how a real drift survives a checker.
            doubled = i + 1 < len(line) and line[i + 1] == ch
            close = line.find('>', i)
            is_placeholder = (not doubled and ch == '<' and close != -1
                              and ' ' not in line[i:close + 1]
                              and '\t' not in line[i:close + 1])
            if is_placeholder:
                cur += line[i:close + 1]
                i = close + 1
                continue
            parts.append(cur)
            cur = ''
            while i < len(line) and line[i] not in ';&|':
                i += 1
            continue
        if ch == '&' and i + 1 < len(line) and line[i + 1] == '&':
            parts.append(cur)
            cur = ''
            i += 2
            continue
        if ch == '|':
            parts.append(cur)
            cur = ''
            i += 2 if (i + 1 < len(line) and line[i + 1] == '|') else 1
            continue
        if ch == ';':
            parts.append(cur)
            cur = ''
            i += 1
            continue
        cur += ch
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


FENCE_RE = re.compile(r'^\s*(`{3,}|~{3,})')
INLINE_RE = re.compile(r'`([^`\n]+)`')


def documented_commands(text):
    """Yield (line_number, command_text) for fenced code lines and inline `python ...`."""
    lines = text.splitlines()
    in_fence = False
    block = []
    block_start = 0

    for idx, raw in enumerate(lines, 1):
        if FENCE_RE.match(raw):
            if in_fence:
                # Whether an earlier line in the same block changed directory. A block that opens
                # with `cd tools/_work/bench/repos/dcc` tells the reader where to stand, so a bare
                # `python dcc.py` after it is correct -- and must not be reported as unqualified.
                chdir = any(re.match(r'\s*(\$\s*)?cd\s+\S', ln) for ln in block)
                for off, cmd in enumerate(join_continuations(block)):
                    for sub in split_shell(cmd):
                        yield (block_start + off, sub, chdir)
                block, in_fence = [], False
            else:
                in_fence, block, block_start = True, [], idx + 1
            continue
        if in_fence:
            block.append(strip_comment(raw))
            continue
        for m in INLINE_RE.finditer(raw):
            body = m.group(1).strip()
            if body.startswith(('python ', 'python3 ', 'py ')):
                for sub in split_shell(body):
                    yield (idx, sub, True)     # an inline mention has no block context to honour


def find_script_token(tokens):
    """(index, token) of the script path inside a python invocation, or None."""
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in ('-m', '--module'):
            return None, 'module invocation'
        if tok == '-c':
            return None, 'inline code'
        if tok.startswith('-'):
            i += 1
            continue
        if '...' in tok:
            # `python .../vmp_diff_harness.py ...`: the record elides the path on purpose
            return None, 'elided'
        if tok.lower().endswith('.py'):
            return i, None
        return None, 'no .py token'
    return None, 'no script argument'


_WORKBENCH_INDEX: dict[str, set[str]] = {}


def _workbench_names():
    """Basenames of every `.py` under `tools/` (gitignored, so not openable by a reader)."""
    if not _WORKBENCH_INDEX:
        base = os.path.join(ROOT, 'tools')
        names = set()
        if os.path.isdir(base):
            for dirpath, dirnames, files in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in ('.git', '__pycache__')]
                for f in files:
                    if f.endswith('.py'):
                        names.add(f)
        _WORKBENCH_INDEX['names'] = names
    return _WORKBENCH_INDEX['names']


def resolve_script(token, doc_path, include_workbench, chdir=False):
    """Where a documented script path points, or why it cannot be followed.

    The order matters, and getting it wrong made this gate blind to a real class of drift: an
    earlier revision resolved a relative path against the **document's own directory first**. A
    bare `python analyze_pair.py` written inside `docs/tool-verification/` therefore resolved to
    `tools/_work/bench/.../analyze_pair.py` -- a real file, hidden behind a gitignored directory --
    and was scored `ok`. A reader who copies that command from the repository root gets
    "No such file", which is the failure this gate exists to prevent.

    So the roots are tried in the order a reader would: repository root, then the skill's script
    directory, and only then the document's own directory (which is what `../x.py` in a nested
    README legitimately means). A hit under `tools/` is a workbench artifact either way.
    """
    norm = token.replace('\\', '/')
    if '...' in norm:
        # `python .../vmp_diff_harness.py compare ...`: the record elides the path on
        # purpose, so there is nothing to resolve and nothing to report.
        return None, 'elided'
    cands = []
    if os.path.isabs(token):
        cands.append(token)
    else:
        cands.append(os.path.join(ROOT, norm))
        if not norm.startswith('skills/'):
            cands.append(os.path.join(SKILL_DIR, norm))
        if not norm.startswith(('skills/', 'scripts/')):
            cands.append(os.path.join(SCRIPT_DIR, norm))
        cands.append(os.path.join(os.path.dirname(doc_path), norm))
    for c in cands:
        if os.path.isfile(c):
            real = os.path.realpath(c)
            tools_root = os.path.realpath(os.path.join(ROOT, 'tools')) + os.sep
            if real.startswith(tools_root) and not include_workbench:
                # reached by `../../tools/_work/...`, or by a bare name that only exists there:
                # still a workbench artifact, and `.gitignore` excludes tools/, so a reader who
                # copies the command cannot open it
                return None, 'workbench'
            return real, 'ok'
    if norm.startswith('tools/') or '/tools/' in norm:
        return None, 'workbench'
    if norm in EXTERNAL_SCRIPTS:
        # Declared upstream tools. Checked *before* the workbench-name test so the verdict does not
        # depend on the gitignored tree being present: `dcc.py` after a `cd` into its checkout is
        # external on every machine, and the version that relied on a filename match under `tools/`
        # reported drift on CI, where `tools/` does not exist.
        return None, 'external'
    if '/' not in norm and not include_workbench and norm in _workbench_names():
        if chdir:
            # The enclosing block already told the reader where to stand, so the bare name is
            # correct. Reported as a skip rather than drift, and distinguishable in the summary.
            return None, 'workbench-after-cd'
        return None, 'unqualified-workbench'
    if chdir and '/' not in norm:
        # A block that changed directory and then runs a bare name that does not resolve anywhere:
        # the name belongs to whatever was cloned into that directory, which this check cannot
        # verify. Skipped with that reason instead of being called drift -- an unverifiable line is
        # not the same claim as a broken one.
        return None, 'after-cd-unresolved'
    return None, 'missing-script'


def classify_path_scope(doc_rel):
    return doc_rel.replace(os.sep, '/')


def _allowed_positionals(spec):
    """Largest positional count the interface can accept, or None when it is unbounded
    or not decidable (a variable-nargs option can swallow any number of following tokens)."""
    for f in spec['flags'].values():
        nargs = f.get('nargs')
        if isinstance(nargs, str) and nargs in VARIABLE_NARGS:
            return None
    top, sub, unbounded = 0, 0, False
    for p in spec['positionals']:
        _lo, hi = _positional_bounds(p)
        if hi is None:
            unbounded = True
            continue
        if p['group'].startswith('sub:'):
            sub = max(sub, hi)
        else:
            top += hi
    return None if unbounded else top + sub


# ---------------------------------------------------------------- validation

def qualified_basenames(text):
    """Basenames that this document itself writes with a path, e.g. `tools/_work/.../dcc.py`.

    This is the document's own proof that a bare name further down refers to an artifact that lives
    somewhere else. It is what makes the workbench classification independent of whether the
    gitignored `tools/` tree happens to exist on the machine running the check -- which is exactly
    the difference between a developer's box and CI, and the reason this gate went red only on CI.
    """
    names = set()
    for m in re.finditer(r'[A-Za-z0-9_\-./\\]*[/\\]([A-Za-z0-9_\-]+\.py)\b', text):
        names.add(m.group(1))
    return names


def command_findings(doc_path, text, spec_cache, include_workbench):
    findings = []
    doc_rel = os.path.relpath(doc_path, ROOT)
    qualified = qualified_basenames(text)
    for line_no, cmd, chdir in documented_commands(text):
        cmd = cmd.strip()
        if not cmd:
            continue
        if cmd.startswith(('$ ', '> ', '# ')):
            cmd = cmd[2:].strip()
        tokens = split_cmd(cmd)
        if not tokens:
            continue
        stem = os.path.basename(tokens[0]).lower()
        if not CMD_TOKEN_RE.match(stem):
            continue

        if (doc_rel.replace('\\', '/'), cmd) in QUOTED_COMMANDS:
            findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                             'kind': 'quoted',
                             'detail': QUOTED_COMMANDS[(doc_rel.replace('\\', '/'), cmd)]})
            continue

        idx, skipped = find_script_token(tokens)
        if idx is None:
            findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                             'kind': 'elided' if skipped == 'elided' else 'skipped',
                             'detail': skipped or 'unparsed'})
            continue

        token = tokens[idx]
        path, why = resolve_script(token, doc_path, include_workbench, chdir)
        if path is None:
            if why == 'unqualified-workbench':
                # A bare `python analyze_pair.py` where that name only exists under `tools/`.
                # The document's own text decides which of two things it is:
                if token in qualified:
                    # ... the document writes the same name *with* a path elsewhere, so it has
                    # already told the reader where the artifact lives. A shorthand, not a broken
                    # command -- and this verdict must not depend on the gitignored tree being
                    # present, which is how the first version of this fix passed locally and
                    # failed on CI. Checked before the drift branch on purpose.
                    findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                                     'kind': 'skipped', 'script': token,
                                     'detail': 'the same document gives this script a path '
                                               'elsewhere (%s)' % token})
                    continue
                # ... it does not, so a reader who copies this from the repository root gets
                # "No such file". Reported as **drift, not a skip**: the fix is one path qualifier,
                # and this class was invisible until the resolver stopped preferring the document's
                # own directory -- the file existed *somewhere*, so the command scored `ok`.
                kind = 'drift'
                findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                                 'kind': 'unqualified-workbench', 'script': token,
                                 'suggest': ['a path that resolves from the repository root, e.g. '
                                             '`tools/.../%s`' % token],
                                 'detail': 'bare script name that only exists under tools/ '
                                           '(gitignored): a reader cannot run it'})
                continue
            if why == 'workbench':
                kind = 'workbench'
            elif why == 'external':
                kind = 'external'
            elif why == 'missing-script' and '/' not in token.replace('\\', '/') \
                    and token in qualified:
                # A bare name the document elsewhere writes *with* a path. That is the document
                # telling the reader where the artifact lives, so this line is a shorthand rather
                # than a broken command -- and saying so must not depend on the gitignored tree
                # being present, which is precisely how CI and a developer's machine differed.
                kind = 'skipped'
                why = ('bare name for a path the same document gives elsewhere '
                       '(%s)' % token)
            else:
                kind = why
            findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                             'kind': kind, 'script': token, 'detail': why})
            continue

        if path not in spec_cache:
            spec_cache[path] = script_spec(path)
        spec, (source, err) = spec_cache[path]
        base = os.path.basename(path)
        args = tokens[idx + 1:]
        has_flag = any(a.startswith('-') and a != '-' for a in args)

        if spec is None:
            if not has_flag:
                # no argument table and no flag on the command line: there is nothing
                # that could be a stale flag, so this is a clean invocation rather than
                # an unknown one (`python check_refs.py`)
                findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                                 'kind': 'clean', 'script': base,
                                 'detail': 'no readable argument table, and no flag to '
                                           'check', 'spec_source': source})
            else:
                findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                                 'kind': 'unverifiable', 'script': base,
                                 'flags_seen': [a for a in args if a.startswith('-')],
                                 'detail': 'flags present but no argument table is '
                                           'readable statically or from --help%s'
                                           % (': ' + err if err else '')})
            continue

        known = spec['flags']
        known_long = [f for f in known if f.startswith('--')]
        unknown, positions, warnings = [], [], []
        before = len(findings)
        expect_value = False
        after_ddash = False

        for tok in args:
            if after_ddash:
                positions.append(tok)
                continue
            if tok == '--':
                after_ddash = True
                continue
            if expect_value:
                # argparse refuses to consume an option-looking token as a value: it
                # reports "expected one argument" instead. So `--live --pkg <pkg>` does
                # NOT make `--pkg` the value of `--live` -- `--pkg` is a flag in its own
                # right, and an unknown one. Treating it as a value is how this checker
                # would have missed the very drift it was written for.
                if FLAG_RE.match(tok) or SHORT_RE.match(tok):
                    expect_value = False
                else:
                    expect_value = False
                    continue
            if tok.startswith('-') and not tok.startswith('--') and len(tok) > 2 and \
                    not tok.startswith('-='):
                # clustered short flags, e.g. -vv or -an
                for ch in tok[1:]:
                    f = '-' + ch
                    if f not in known and f not in ('-h',):
                        unknown.append((f, 'clustered short flag'))
                    elif known.get(f, {}).get('takes_value'):
                        expect_value = True
                        break
                continue
            m = FLAG_RE.match(tok) or SHORT_RE.match(tok)
            if m:
                flag = m.group(1)
                inline = bool(m.group(2))
                if flag in known:
                    expect_value = known[flag]['takes_value'] and not inline
                    continue
                if flag in ('-h', '--help'):
                    continue
                if flag.startswith('--'):
                    prefix_hits = [f for f in known_long if f.startswith(flag)]
                    if len(prefix_hits) == 1:
                        expect_value = known[prefix_hits[0]]['takes_value'] and not inline
                        continue
                    if len(prefix_hits) > 1:
                        unknown.append((flag, 'ambiguous prefix of ' +
                                        ', '.join(sorted(prefix_hits))))
                        continue
                unknown.append((flag, 'not in %s' % base))
                continue
            positions.append(tok)

        for flag, why_unknown in unknown:
            close = difflib.get_close_matches(flag, known_long, n=3, cutoff=0.4)
            findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                             'kind': 'unknown-flag', 'script': base, 'flag': flag,
                             'detail': why_unknown, 'suggest': close,
                             'known_flags': sorted(known)})

        # A positional count is inferred from a static reading of the parser, and an
        # argument written as a placeholder or an elision can throw it off. It is
        # reported as a low-confidence warning, never as drift: the flag table is the
        # part of the interface this checker can actually prove.
        allowed = _allowed_positionals(spec) if spec['source'] == 'ast' else None
        if allowed is not None:
            effective = positions
            subcommands = spec.get('subcommands') or set()
            if subcommands:
                # a subcommand word is consumed by the sub-parser dispatcher, not by a
                # positional of the parser the count was computed from
                if effective and effective[0] in subcommands:
                    effective = effective[1:]
                else:
                    effective = None
            if effective is not None and len(effective) > allowed:
                findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                                 'kind': 'warning', 'script': base,
                                 'detail': 'saw %d positional token(s); the script '
                                           'declares at most %d (%s)'
                                           % (len(effective), allowed,
                                              ', '.join(effective)),
                                 'suggest': []})

        # a flag the script's own docstring advertises but argparse does not implement
        for flag in spec.get('extra', []):
            if flag not in known and any(a == flag or a.startswith(flag) for a in args):
                if any(f['kind'] == 'unknown-flag' and f.get('flag') == flag
                       for f in findings if f['line'] == line_no):
                    continue
                findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                                 'kind': 'unknown-flag', 'script': base, 'flag': flag,
                                 'detail': 'shown in the script\'s own docstring but not '
                                           'declared in argparse',
                                 'suggest': difflib.get_close_matches(flag, known_long, 3),
                                 'known_flags': sorted(known)})

        if len(findings) == before:
            findings.append({'doc': doc_rel, 'line': line_no, 'command': cmd,
                             'kind': 'clean', 'script': base,
                             'detail': 'every flag resolves against %s' % base,
                             'spec_source': spec['source'],
                             'known_flags': sorted(known)})
    return findings


def collect_docs(extra_path):
    docs = []
    readme = os.path.join(ROOT, 'README.md')
    if os.path.isfile(readme):
        docs.append(readme)
    roots = [os.path.join(ROOT, 'skills'), os.path.join(ROOT, 'docs')]
    if extra_path:
        target = extra_path if os.path.isabs(extra_path) else os.path.join(ROOT, extra_path)
        if os.path.isdir(target):
            roots = [target]
        elif os.path.isfile(target):
            docs.append(target)
            roots = []
        else:
            return None
    for base in roots:
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, files in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in ('.git', 'node_modules', '__pycache__',
                                              'fixtures'))
            for f in sorted(files):
                if f.endswith('.md'):
                    docs.append(os.path.join(dirpath, f))
    seen, out = set(), []
    for d in docs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


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
        prog='check_commands.py',
        description='Validate documented `python <script>.py ...` commands against the '
                    'scripts\' own argparse tables. Flags are read with ast, so no script '
                    'is executed to learn its interface.')
    ap.add_argument('--fix-report', action='store_true',
                    help='one machine-readable line per finding, with the document line '
                         'and the unknown flag; use this to drive an edit')
    ap.add_argument('--json', action='store_true', dest='as_json',
                    help='machine-readable output')
    ap.add_argument('--path', default=None, metavar='PATH',
                    help='restrict the scan to one file or subtree (default: README.md + '
                         'skills/**/*.md + docs/**/*.md)')
    ap.add_argument('--include-workbench', action='store_true',
                    help='also treat tools/... references as requiring a real file')
    ap.add_argument('--quiet', action='store_true', help='print findings only')
    args = ap.parse_args(argv)

    docs = collect_docs(args.path)
    if docs is None:
        sys.stderr.write('error: --path does not exist: %s\n' % args.path)
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE

    spec_cache = {}
    try:
        all_findings = []
        for d in docs:
            try:
                with open(d, encoding='utf-8', errors='replace') as fh:
                    text = fh.read()
            except OSError as exc:
                sys.stderr.write('warning: unreadable %s: %s\n' % (d, exc))
                continue
            all_findings.extend(command_findings(d, text, spec_cache, args.include_workbench))
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write('internal error: %s: %s\n' % (type(exc).__name__, exc))
        print('RESULT=%s' % TOKENS['internal'])
        return EXIT_INTERNAL

    # `unqualified-workbench` counts as drift: the command names a script that only exists under a
    # gitignored directory and gives no path, so a reader who copies it fails. It is a one-token fix,
    # which is exactly why it should be reported rather than skipped.
    drift = [f for f in all_findings
             if f['kind'] in ('unknown-flag', 'missing-script', 'unqualified-workbench')]
    warnings = [f for f in all_findings if f['kind'] == 'warning']
    unverifiable = [f for f in all_findings if f['kind'] == 'unverifiable']
    workbench = [f for f in all_findings if f['kind'] == 'workbench']
    externals = [f for f in all_findings if f['kind'] == 'external']
    quoted = [f for f in all_findings if f['kind'] == 'quoted']
    skipped = [f for f in all_findings if f['kind'] in ('skipped', 'elided')]
    clean = [f for f in all_findings if f['kind'] == 'clean']
    checked = clean + drift + warnings

    status = 'drift' if drift else 'ok'
    code = EXIT_FINDING if drift else EXIT_OK
    token = TOKENS['drift'] if drift else TOKENS['ok']

    if args.as_json:
        payload = {
            'status': status,
            'exit_code': code,
            'capability': 'publish_gate',
            'evidence': [
                {'doc': f['doc'], 'line': f['line'], 'command': f['command'],
                 'kind': f['kind'], 'script': f.get('script', ''),
                 'flag': f.get('flag', ''), 'detail': f['detail'],
                 'known_flags': f.get('known_flags', [])}
                for f in all_findings
            ],
            'warnings': ['%s:%d %s' % (f['doc'], f['line'], f['detail'])
                         for f in warnings + unverifiable],
            'next_action': ('fix the reported command in %s:%d'
                            % (drift[0]['doc'], drift[0]['line'])) if drift else '',
            'summary': {
                'docs_scanned': len(docs),
                'commands_checked': len(checked),
                'clean': len(clean),
                'drift': len(drift),
                'warnings': len(warnings),
                'unverifiable': len(unverifiable),
                'workbench_skipped': len(workbench),
                'skipped': len(skipped),
                'scripts_with_readable_table': sum(1 for _s, (sp, _e) in spec_cache.items()
                                                   if sp is not None),
                'scripts_without_table': sum(1 for _s, (sp, _e) in spec_cache.items()
                                             if sp is None),
            },
            'findings': all_findings,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        # No `RESULT=` line here on purpose: appending one would make the stream invalid JSON for a
        # caller doing `| jq .` or `json.loads(stdout)`, which is the entire point of `--json`. The
        # status is a field in the document, and the exit code carries the same meaning.
        return code

    if args.fix_report:
        for f in drift:
            sug = ', '.join(f.get('suggest') or []) or '-'
            print('%s:%d\t%s\tunknown flag %s\tclosest known: %s\tcmd: %s'
                  % (f['doc'], f['line'], f.get('script', '?'),
                     f.get('flag', f['kind']), sug, f['command']))
        if not drift:
            print('# no drift: every documented flag resolves against its script')
        print('RESULT=%s' % token)
        return code

    if not args.quiet:
        print('=' * 74)
        print('documented command check')
        print('=' * 74)
        print('repository : %s' % ROOT)
        print('docs        : %d markdown file(s)' % len(docs))
        print('scripts     : %d argument table(s) read, %d without a readable table'
              % (len(spec_cache),
                 sum(1 for _s, (sp, _e) in spec_cache.items() if sp is None)))
        print('commands    : %d checked (%d clean, %d drift, %d warning)'
              % (len(checked), len(clean), len(drift), len(warnings)))
        print('skipped     : %d workbench, %d external, %d quoted, %d unverifiable, '
              '%d not a script invocation'
              % (len(workbench), len(externals), len(quoted), len(unverifiable),
                 len(skipped)))

    if drift:
        print('\n--- drift (a documented command that cannot run) ---')
        for f in sorted(drift, key=lambda x: (x['doc'], x['line'])):
            print('  %s:%d' % (f['doc'], f['line']))
            print('    cmd   : %s' % f['command'])
            if f['kind'] == 'unknown-flag':
                sug = ', '.join(f.get('suggest') or []) or 'none close'
                print('    flag  : %s (%s)' % (f['flag'], f['detail']))
                print('    known : %s' % (', '.join(f.get('known_flags', [])) or '-'))
                print('    try   : %s' % sug)
            else:
                print('    script: %s -- %s' % (f.get('script', '?'), f['detail']))

    if warnings and not args.quiet:
        print('\n--- warnings (low-confidence; not counted as drift) ---')
        for f in sorted(warnings, key=lambda x: (x['doc'], x['line'])):
            print('  %s:%d  %s  %s' % (f['doc'], f['line'], f.get('script', '?'),
                                       f['detail']))

    if externals and not args.quiet:
        print('\n--- external (a script in another repository\'s checkout) ---')
        for f in sorted(externals, key=lambda x: (x['doc'], x['line'])):
            print('  %s:%d  %s' % (f['doc'], f['line'], f['script']))
        for name, reason in sorted(EXTERNAL_SCRIPTS.items()):
            print('  %-28s %s' % (name, reason))

    if quoted and not args.quiet:
        print('\n--- quoted (evidence, not an instruction to run) ---')
        for f in sorted(quoted, key=lambda x: (x['doc'], x['line'])):
            print('  %s:%d  %s' % (f['doc'], f['line'], f['command']))
        for (_doc, _cmd), reason in sorted(QUOTED_COMMANDS.items()):
            print('  %s' % reason)

    if unverifiable and not args.quiet:
        print('\n--- unverifiable (flags present, no readable argument table) ---')
        print('  These are not pass and not fail: this checker cannot see the interface,')
        print('  so "no finding here" carries no information. Named so it is not mistaken')
        print('  for coverage.')
        seen = set()
        for f in unverifiable:
            key = (f.get('script', ''), tuple(f.get('flags_seen', [])))
            if key in seen:
                continue
            seen.add(key)
            print('  %-28s %s   %s' % (f.get('script', '?'),
                                       ' '.join(f.get('flags_seen', [])),
                                       f['detail']))
            print('  %-28s at %s:%d' % ('', f['doc'], f['line']))

    if not args.quiet:
        no_table = [p for p, (sp, _e) in sorted(spec_cache.items()) if sp is None]
        if no_table:
            print('\n--- no readable argument table (the boundary of this check) ---')
            for p in no_table:
                print('  %s' % os.path.relpath(p, ROOT))
            print('  A script with no flags has nothing that can drift, so its documented')
            print('  invocations pass without being checkable. Listed so the edge of this')
            print('  check is visible instead of implied.')

    if not args.quiet:
        print('\n  %d command(s) checked against %d script interface(s): %d drift, '
              '%d warning(s)' % (len(checked), len(spec_cache), len(drift), len(warnings)))
        if drift:
            print('  A drifting command is worse than a missing one: the reader follows it')
            print('  and blames their own environment when it fails.')
        elif not checked:
            print('  No command could be checked. That is a gap in this checker, not a')
            print('  clean bill for the documentation.')
        print('RESULT=%s' % token)
    return code


if __name__ == '__main__':
    sys.exit(main())
