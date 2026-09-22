#!/usr/bin/env python3
"""Pre-commit checks for this repository.

Assumed layout -- the one the `skills` CLI resolves:

    README.md                             repository-level docs (root)
    skills/<skill-name>/SKILL.md          the skill itself
    skills/<skill-name>/references/*.md   loaded on demand
    skills/<skill-name>/scripts/*         run, not read

Every skill under `skills/` is discovered automatically (up to three levels;
a SKILL.md at a shallower level shadows anything nested below it, which is the
CLI's own rule), so adding a second skill requires no change to this script.

Per skill:
  1. frontmatter exists, `name` matches the directory name, `description` <= 1024
  2. every scripts/*.py parses and answers --help without a traceback
  3. every `references/X.md` / `scripts/X.py` reference resolves inside that skill
  4. every reference file is reachable from that skill's SKILL.md or the README
  5. every script is mentioned somewhere in the docs

On the root README:
  6. every path it names is an explicit `skills/<name>/...` path that exists
"""
import ast
import os
import re
import subprocess
import sys

try:
    import yaml
except ImportError:   # the skills CLI is the real authority; this is a local gate
    yaml = None  # type: ignore[assignment]

ROOT = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(ROOT, 'skills')
README = os.path.join(ROOT, 'README.md')

REF_RE = re.compile(r'`?(references/[A-Za-z0-9_\-]+\.md)')
SCRIPT_RE = re.compile(r'`?(scripts/[A-Za-z0-9_\-]+\.(?:py|js))')
NAMED_PATH_RE = re.compile(
    r'skills/(?P<skill>[a-z0-9\-]+)/(?P<sub>references|scripts)/'
    r'(?P<file>[A-Za-z0-9_\-]+\.(?:md|py|js))')
BARE_PATH_RE = re.compile(r'(?<![\w/])(?P<sub>references|scripts)/'
                          r'(?P<file>[A-Za-z0-9_\-]+\.(?:md|py|js))')

fail: list[str] = []


def read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def discover_skills():
    """Return [(name, skill_dir)] for every skills/<...>/SKILL.md."""
    found = []
    if not os.path.isdir(SKILLS_DIR):
        return found
    for dirpath, dirnames, filenames in os.walk(SKILLS_DIR):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))
        rel = os.path.relpath(dirpath, SKILLS_DIR)
        depth = 0 if rel == '.' else rel.count(os.sep) + 1
        if depth > 3:
            dirnames[:] = []
            continue
        if 'SKILL.md' in filenames:
            found.append((rel.replace(os.sep, '/'), dirpath))
            dirnames[:] = []          # shallower SKILL.md shadows what is below
    return sorted(found)


NAME_RE = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')


def check_frontmatter(name, skill_dir):
    """Validate the frontmatter the way the CLI will, not merely its presence.

    This has to be a real parse. Frontmatter that satisfies a regex can still be
    rejected by a YAML parser -- an unquoted `description` containing ": " does
    it, because the colon starts a nested mapping -- and the `skills` CLI then
    reports "No skills found" and installs nothing at all.
    """
    path = os.path.join(skill_dir, 'SKILL.md')
    text = read(path)
    m = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n', text, re.S)
    if not m:
        fail.append('%s: no YAML frontmatter block' % path)
        return
    raw = m.group(1)

    if yaml is None:
        print('  WARN PyYAML is not installed, so the frontmatter was not parsed')
        line = re.search(r'^description:(.*)$', raw, re.M)
        if line:
            value = line.group(1)
            if value[:1] not in ('"', "'", '>', '|') and ': ' in value:
                fail.append('%s: unquoted description contains ": ", which a YAML '
                            'parser rejects; quote the value' % path)
        return

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        detail = str(exc).splitlines()[0]
        fail.append('%s: frontmatter is not valid YAML (%s); the skills CLI '
                    'skips a skill whose frontmatter will not parse'
                    % (path, detail))
        return
    if not isinstance(data, dict):
        fail.append('%s: frontmatter is not a YAML mapping' % path)
        return

    got = data.get('name')
    if not got:
        fail.append('%s: frontmatter has no `name`' % path)
    elif str(got) != name:
        fail.append('%s: frontmatter name %r does not match directory %r'
                    % (path, got, name))
    elif not NAME_RE.match(str(got)) or len(str(got)) > 64:
        fail.append('%s: name %r violates the spec (lowercase alphanumerics and '
                    'single hyphens, max 64 chars)' % (path, got))

    desc = data.get('description')
    if not desc:
        fail.append('%s: frontmatter has no `description`' % path)
    else:
        desc = str(desc)
        if len(desc) > 1024:
            fail.append('%s: description is %d chars (spec max 1024)'
                        % (path, len(desc)))
        elif len(desc) < 40:
            fail.append('%s: description is only %d chars, too short to tell an '
                        'agent when this skill applies' % (path, len(desc)))


def check_scripts(skill_dir):
    scripts = os.path.join(skill_dir, 'scripts')
    if not os.path.isdir(scripts):
        return
    for name in sorted(os.listdir(scripts)):
        if not name.endswith('.py'):
            continue
        path = os.path.join(scripts, name)
        try:
            ast.parse(read(path))
        except SyntaxError as exc:
            fail.append('%s: syntax error %s' % (path, exc))
            print('  FAIL %s' % name)
            continue
        run = subprocess.run([sys.executable, '-B', path, '--help'],
                             capture_output=True, timeout=60, cwd=ROOT,
                             # Decode explicitly. `text=True` alone uses the *locale* encoding, which
                             # on a Chinese Windows console is GBK: a script printing an em dash in a
                             # usage line then fails to decode, and this gate reports it as a crash.
                             # That is a defect in the gate, not in the script -- measured on this
                             # repository, where `dex_strpatch.py --help` was reported as crashed.
                             encoding='utf-8', errors='replace')
        # A script may exit non-zero on --help under the "print usage, exit 2"
        # convention. That is acceptable; a traceback is not.
        crashed = 'Traceback (most recent call last)' in (run.stderr or '')
        helped = bool((run.stdout or '').strip()) or bool(run.stderr)
        ok = (not crashed) and helped
        verdict = 'ok' if run.returncode == 0 and not crashed else \
                  ('usage-ok rc=%d' % run.returncode if ok else
                   'CRASH rc=%d' % run.returncode)
        print('  %-32s %s' % (name, verdict))
        if not ok:
            fail.append('%s --help crashed: %s' % (path, (run.stderr or '')[:300]))


def check_references(name, skill_dir, root_docs):
    """Resolve in-skill references, and confirm every file is reachable."""
    ref_dir = os.path.join(skill_dir, 'references')
    script_dir = os.path.join(skill_dir, 'scripts')
    refs = set(os.listdir(ref_dir)) if os.path.isdir(ref_dir) else set()
    scripts = set(os.listdir(script_dir)) if os.path.isdir(script_dir) else set()

    # Documents whose relative paths are rooted at the skill directory.
    own = [os.path.join(skill_dir, 'SKILL.md')]
    own += [os.path.join(ref_dir, f) for f in sorted(refs) if f.endswith('.md')]

    missing = []
    for doc in own:
        if not os.path.exists(doc):
            continue
        text = read(doc)
        for m in REF_RE.finditer(text):
            if m.group(1).split('/')[1] not in refs:
                missing.append('%s -> %s' % (os.path.relpath(doc, ROOT), m.group(1)))
        for m in SCRIPT_RE.finditer(text):
            if m.group(1).split('/')[1] not in scripts:
                missing.append('%s -> %s' % (os.path.relpath(doc, ROOT), m.group(1)))
    if missing:
        for x in sorted(set(missing)):
            print('  MISSING %s' % x)
        fail.extend(missing)

    # Reachability: nothing may be orphaned from the skill entry point.
    bodies = read(os.path.join(skill_dir, 'SKILL.md')) + root_docs
    for f in sorted(refs):
        if f.endswith('.md') and f not in bodies:
            fail.append('%s: references/%s is not mentioned anywhere' % (name, f))
            print('  UNLISTED references/%s' % f)

    all_docs = bodies
    for f in sorted(refs):
        if f.endswith('.md'):
            all_docs += read(os.path.join(ref_dir, f))
    for s in sorted(scripts):
        if s.endswith(('.py', '.js')) and s not in all_docs:
            fail.append('%s: scripts/%s is undocumented' % (name, s))
            print('  UNDOCUMENTED scripts/%s' % s)


def check_readme():
    """README paths must be explicit and must exist."""
    text = read(README)
    if not os.path.isdir(SKILLS_DIR):
        fail.append('no skills/ directory at the repository root')
        return
    skills = {d for d, _ in discover_skills()}
    named = set()
    for m in NAMED_PATH_RE.finditer(text):
        named.add(m.group(0))
        skill, sub, fname = m.group('skill'), m.group('sub'), m.group('file')
        if skill not in skills:
            fail.append('README.md: names unknown skill %r' % skill)
            print('  UNKNOWN SKILL skills/%s' % skill)
        elif not os.path.exists(os.path.join(SKILLS_DIR, skill, sub, fname)):
            fail.append('README.md: %s does not exist' % m.group(0))
            print('  MISSING %s' % m.group(0))
    # Bare relative paths are ambiguous once there is more than one skill, so the
    # README must not use them at all.
    stripped = NAMED_PATH_RE.sub('', text)
    for m in BARE_PATH_RE.finditer(stripped):
        fail.append('README.md: bare path %r should be skills/<name>/%s'
                    % (m.group(0), m.group(0)))
        print('  BARE PATH %s' % m.group(0))


def check_leaks():
    """No target identity on the committed surface.

    Path resolution, anchors and layout are all *structural* checks: they pass on a file that names
    a live app and a real phone. This one reads content, and it is deliberately not reimplemented
    here -- `scripts/scan_leaks.py` owns the rules and their exemption list, so there is one place
    to argue with. The tracked-file list is passed in so a git-ignored work area (which may
    legitimately hold real identifiers) can never produce a finding.

    A scanner error is reported as a note rather than a failure: an unreadable rule table is a
    broken tool, not a leak, and conflating the two teaches people to ignore this line.
    """
    scanner = os.path.join(SKILLS_DIR, 'apk-reverse', 'scripts', 'scan_leaks.py')
    if not os.path.isfile(scanner):
        print('  SKIP no scan_leaks.py (the leak gate is not installed)')
        return
    import subprocess
    import tempfile
    proc = subprocess.run(['git', 'ls-files'], cwd=ROOT, capture_output=True,
                          encoding='utf-8', errors='replace')
    if proc.returncode != 0 or not proc.stdout.strip():
        print('  SKIP git ls-files unavailable (not a checkout?)')
        return
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8') as fh:
        fh.write(proc.stdout)
        listing = fh.name
    try:
        run = subprocess.run([sys.executable, scanner, '--root', ROOT,
                              '--files-from', listing, '--max', '10'],
                             capture_output=True, encoding='utf-8', errors='replace')
    finally:
        os.unlink(listing)
    token = (run.stdout or '').strip().splitlines()
    token = token[-1] if token else ''
    if run.returncode == 2 or 'RESULT=error' in token:
        print('  NOTE scan_leaks.py could not complete: %s' % (run.stderr or '').strip()[:160])
        return
    if run.returncode == 0:
        print('  no strong target identity on the tracked surface (%s)' % (token or 'RESULT=clean'))
        return
    # Non-zero: report the findings, which carry their own context. The scanner prints each hit as
    # "<file>:<line>:<col>  [<category>/<strength>]  <rule>", followed by its indented match/context
    # lines. The list below keeps only the strong hits -- a weak hit is the scanner's business, not
    # this gate's -- but a weak hit sitting between two strong ones may contribute its context pair,
    # because attributing an indented line to the hit above it is heuristic. The exit code is the
    # verdict; this block is for the reader.
    print('  LEAK scan_leaks.py reported strong findings on the tracked surface:')
    keep_detail = False
    for line in (run.stdout or '').splitlines():
        stripped = line.strip()
        if re.search(r'\[(package|device|token|appkey|path)/(strong|certain)\]', stripped):
            print('    %s' % stripped)
            keep_detail = True
        elif stripped.startswith('[') and stripped.count(']') >= 2:
            keep_detail = False
        elif keep_detail and (stripped.startswith('match:') or stripped.startswith('context:')):
            print('      %s' % stripped)
    fail.append('leak scan: strong target identity on the tracked surface '
                '(run: python skills/apk-reverse/scripts/scan_leaks.py)')


def main():
    skills = discover_skills()
    print('== skills discovered ==')
    if not skills:
        print('  none (expected at least skills/<name>/SKILL.md)')
    for name, _ in skills:
        print('  skills/%s' % name)

    print('\n== frontmatter ==')
    for name, skill_dir in skills:
        check_frontmatter(name, skill_dir)
    print('  %d checked' % len(skills))

    root_docs = read(README)
    for name, skill_dir in skills:
        print('\n== %s: python syntax + --help ==' % name)
        check_scripts(skill_dir)
        print('\n== %s: reference and script paths resolve ==' % name)
        before = len(fail)
        check_references(name, skill_dir, root_docs)
        if len(fail) == before:
            print('  all referenced reference/script paths exist')

    print('\n== README paths are explicit and exist ==')
    check_readme()

    print('\n== tracked surface carries no target identity ==')
    check_leaks()

    print('\n== result: %d problem(s) ==' % len(fail))
    for f in fail:
        print('  - %s' % f)
    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
