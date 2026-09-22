#!/usr/bin/env python3
"""Keep `skills/apk-reverse/references/routing.md` coherent with `SKILL.md` and with the tree.

Why this exists: `SKILL.md` loads in full whenever this skill activates, so it carries only what has
to be one hop there -- the symptom index (recognising a failure must not become a two-hop lookup) and
the four gates with their pass criteria. The *inventory* lookups -- every reference file with when to
load it, every script with what it does -- live in `references/routing.md` and load on demand.

That split creates one risk: two tables that used to be one. This script removes it by **comparing**
the tables instead of generating one from the other:

  * the **symptom index** has a single home, `SKILL.md`; `routing.md` keeps a mirror so a reader gets
    all three tables in one load, and `--check` fails when the mirror and the live table differ;
  * the **reference and script indexes** have a single home, `routing.md`;
  * every file under `references/` must be named in the routing reference table, and every script in
    `scripts/` must be named in the routing script table -- an inventory that has drifted from the
    directory is worse than no inventory, because it reads as complete.

Usage:
    python check_routing.py            # report coherence; exit 1 on any problem
    python check_routing.py --json
"""
import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(ROOT, 'skills', 'apk-reverse')
SKILL = os.path.join(SKILL_DIR, 'SKILL.md')
REFS = os.path.join(SKILL_DIR, 'references')
SCRIPTS = os.path.join(SKILL_DIR, 'scripts')
ROUTE = os.path.join(REFS, 'routing.md')


# A markdown table separator row: pipes, dashes, colons and spaces, and at least one dash. Tested on
# the row's *cells*, not the whole line -- every data row also starts and ends with `|`, so any
# whole-line pattern loose enough to accept a separator also accepts every data row, and the reverse
# mistake drops every data row and reports an intact inventory as broken.
def is_separator(row):
    cells = [c for c in row.strip().strip('|').split('|')]
    return bool(cells) and all(c.strip() and set(c.strip()) <= set('-:') for c in cells)


# Headings are matched by prefix: they contain an em dash, and comparing against an ASCII hyphen
# silently reports "table not found" instead of failing.
PREFIXES = {
    'symptom': 'Symptom index',
    'reference': 'Reference index',
    'script': 'Script index',
}


def read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def tables(text):
    """{heading: [data rows]} -- data rows exclude the header row.

    The separator row is identified by its characters (`-`, `|`, `:`, spaces only). Do **not** use
    `set(row) > set('|-: ')` to decide this: set comparison is not a character test, and every row
    whose content happens to be a superset of those characters gets dropped -- which once classified
    43 of 53 symptom rows as "not a table row" and made the checker report the inventory as broken
    while it was intact. This file's own failure mode, found by a row count that did not add up.
    """
    out = {}
    cur = None
    for ln in text.split('\n'):
        if ln.startswith('## '):
            cur = ln[3:].strip()
            out.setdefault(cur, [])
        elif cur is not None and ln.startswith('|'):
            out[cur].append(ln)
    result = {}
    for key, rows in out.items():
        data = [r for r in rows if not is_separator(r)]
        result[key] = data[1:] if data else []      # drop the header row
    return result


def pick(sections, prefix):
    for key, rows in sections.items():
        if key.startswith(prefix):
            return rows
    return None


def cell0(row):
    return row.strip().strip('|').split('|')[0].strip().strip('`* ').lower()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    problems = []
    if not os.path.isfile(ROUTE):
        print('FAIL references/routing.md is missing -- the inventory has no home')
        print('RESULT=missing')
        return 1

    sk = tables(read(SKILL))
    rt = tables(read(ROUTE))

    live_sym = pick(sk, PREFIXES['symptom']) or []
    mirror_sym = pick(rt, PREFIXES['symptom']) or []
    ref_rows = pick(rt, PREFIXES['reference'])
    scr_rows = pick(rt, PREFIXES['script'])

    for name, rows in (('symptom (routing.md)', mirror_sym), ('reference', ref_rows),
                       ('script', scr_rows)):
        if rows is None:
            problems.append('routing.md has no %s table' % name)

    live_set = {cell0(r) for r in live_sym}
    mirror_set = {cell0(r) for r in mirror_sym}
    if live_set - mirror_set:
        problems.append('routing.md symptom mirror is missing %d row(s) present in SKILL.md: %s'
                        % (len(live_set - mirror_set), '; '.join(sorted(live_set - mirror_set))[:180]))
    if mirror_set - live_set:
        problems.append('routing.md symptom mirror has %d row(s) SKILL.md does not: %s'
                        % (len(mirror_set - live_set), '; '.join(sorted(mirror_set - live_set))[:180]))

    ref_text = ' '.join(r for r in (ref_rows or []))
    ref_files = sorted(os.path.basename(p) for p in glob.glob(os.path.join(REFS, '*.md')))
    unlisted = [f for f in ref_files if f not in ref_text]
    if unlisted:
        problems.append('routing.md reference table does not name %d reference file(s): %s'
                        % (len(unlisted), ', '.join(unlisted)))

    scr_text = ' '.join(r for r in (scr_rows or []))
    scr_files = sorted(f for f in os.listdir(SCRIPTS) if f.endswith(('.py', '.js')))
    unlisted_s = [f for f in scr_files if f not in scr_text]
    if unlisted_s:
        problems.append('routing.md script table does not name %d script(s): %s'
                        % (len(unlisted_s), ', '.join(unlisted_s)))

    report = {
        'skill_symptom_rows': len(live_sym),
        'routing_symptom_rows': len(mirror_sym),
        'routing_reference_rows': len(ref_rows or []),
        'routing_script_rows': len(scr_rows or []),
        'reference_files_in_tree': len(ref_files),
        'scripts_in_tree': len(scr_files),
        'problems': problems,
        'result': 'ok' if not problems else 'incoherent',
    }

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        print('RESULT=%s' % report['result'])
        return 1 if problems else 0

    print('routing coherence')
    print('  symptom index  : SKILL.md %d rows / routing mirror %d rows'
          % (len(live_sym), len(mirror_sym)))
    print('  reference table: %d rows, covering %d reference files' % (len(ref_rows or []), len(ref_files)))
    print('  script table   : %d rows, covering %d scripts' % (len(scr_rows or []), len(scr_files)))
    for p in problems:
        print('  FAIL %s' % p)
    print()
    if problems:
        print('== routing: %d problem(s) ==' % len(problems))
        print('RESULT=incoherent')
        return 1
    print('== routing: coherent ==')
    print('RESULT=ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
