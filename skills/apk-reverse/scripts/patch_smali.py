#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Method-level smali patcher.

Design notes (each one earned the hard way):
- Only the instruction body is replaced: from the line after the `.method` declaration up to
  (but not including) `.end method`. The `.method` / `.end method` / `.annotation` sections are
  left untouched, so modifiers and annotations survive.
- The patch manifest must state a self-consistent `.registers` value: the assembler rejects
  out-of-range registers, so `registers` must be >= the number of parameter registers and
  >= the highest register index used by any instruction + 1. Parameter registers:
  static method = number of parameters; instance method = number of parameters + 1 (this).
- The manifest is a JSON list; each entry:
  {
    "file":   "com/example/Helper.smali",              # path relative to the smali tree root
    "method": ".method public final show(Landroid/app/Activity;)V",  # exact .method line
    "registers": 3,
    "body": ["invoke-interface {p3}, ...;", "return-void"],
    "note": "why this patch exists"                     # optional, report only
  }

A literal-match tool: whitespace, operand punctuation and instruction names must match the
source exactly, and the anchor must be unique. See references/patch-audit.md section 3.

Usage:
  python patch_smali.py <smali_tree> <patch.json> [--dry-run]
"""
import json
import os
import sys


def split_methods(text):
    """Split smali text into [(method_decl, start_idx, end_idx)] using line indices."""
    lines = text.split('\n')
    out = []
    start = None
    decl = None
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('.method ') and start is None:
            start, decl = i, s
        elif s == '.end method' and start is not None:
            out.append((decl, start, i))
            start, decl = None, None
    return lines, out


def patch_one(path, decl_wanted, registers, body):
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    lines, methods = split_methods(text)
    hits = [m for m in methods if m[0] == decl_wanted.strip()]
    if not hits:
        return False, 'method not found: %s' % decl_wanted
    if len(hits) > 1:
        return False, 'ambiguous (%d matches): %s' % (len(hits), decl_wanted)
    _, start, end = hits[0]
    # Keep the .method line; rewrite the interior: .registers + body
    new_inner = ['    .registers %d' % registers, '']
    for b in body:
        new_inner.append('    ' + b)
    new_lines = lines[:start + 1] + new_inner + [''] + lines[end:]
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(new_lines))
    return True, 'ok'


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    tree = sys.argv[1]
    spec = sys.argv[2]
    dry = '--dry-run' in sys.argv
    with open(spec, 'r', encoding='utf-8') as f:
        patches = json.load(f)
    ok = fail = 0
    for p in patches:
        full = os.path.join(tree, p['file'].replace('/', os.sep))
        if not os.path.isfile(full):
            print('[MISS-FILE] %s' % p['file'])
            fail += 1
            continue
        if dry:
            with open(full, 'r', encoding='utf-8') as f:
                _, methods = split_methods(f.read())
            found = any(m[0] == p['method'].strip() for m in methods)
            print('[%s] %s :: %s' % ('DRY-OK' if found else 'DRY-MISS', p['file'], p['method']))
            ok += 1 if found else 0
            fail += 0 if found else 1
            continue
        okk, msg = patch_one(full, p['method'], p['registers'], p['body'])
        print('[%s] %s :: %s  (%s)' % ('OK' if okk else 'FAIL', p['file'],
                                       p['method'].split('(')[0].replace('.method ', ''), msg))
        ok += 1 if okk else 0
        fail += 0 if okk else 1
    print('\npatched=%d failed=%d%s' % (ok, fail, ' [dry-run]' if dry else ''))
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
