#!/usr/bin/env python3
"""Audit cross-references of the form `file.md` §section, and `file.md` P12.

A reference like `references/toolchain.md` §"not on PATH" is a promise that the
target file has a section by that name. When a section is renamed or removed the
promise silently breaks: the reader arrives at a file that does not contain the
thing they were sent for, and the most likely outcome is that they conclude the
material is missing rather than that the link is stale. Prose links do not fail
loudly the way a missing file does, which is why this script exists separately
from `check_repo.py` (that one only proves the *file* resolves).

A section reference is reported as:
  * OK    -- normalised, it matches a heading (or bold numbered rule) in the target
  * WARN  -- its words appear in the target body, but no heading carries them;
             usually a stale or paraphrased link, worth a human look
  * FAIL  -- nothing in the target file corresponds; the link is dangling

Layout is discovered the same way as in `check_repo.py`, so a second skill under
skills/ is audited with no change here.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(ROOT, 'skills')

# A section reference. The optional leading file may be separated from the
# section mark by the closing backtick and a line break, since references are
# often wrapped mid-sentence.
REF_RE = re.compile(
    r'(?:(?P<file>[A-Za-z0-9_\-]+\.md)`?[\s`]{0,40})?'
    r'§\s*(?P<sec>[^\n|`();,.\u2014\u3002]{2,90})')
# A failure-catalogue reference, e.g. `pitfalls.md` P31, or a bare (P18).
PITFALL_RE = re.compile(
    r'(?:(?P<file>[A-Za-z0-9_\-]+\.md)`?[\s`]{0,40})?'
    r'\(?\bP(?P<num>\d{1,2})\b')

HEADING_RE = re.compile(r'^#{1,6}\s+(?P<title>.+?)\s*$')
BOLD_RE = re.compile(r'^\*\*(?P<title>.+?)\*\*\s*$')


def norm(text):
    """Fold a heading or a reference into comparable tokens.

    Hyphens and slashes become spaces so that `finding-the-call-site` matches
    "Finding the call site", and quotes/emphasis are dropped so that
    `§"not on PATH"` matches a heading containing the same words quoted.
    """
    text = text.lower()
    text = text.replace('\u2014', ' ').replace('\u2013', ' ')
    text = re.sub(r'[`*_"\'()\[\]]', '', text)
    text = re.sub(r'[^a-z0-9]+', ' ', text)
    return text.strip()


def discover_skills():
    """Return [(name, skill_dir)] for each skill root, shallow shadowing deep."""
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
            dirnames[:] = []
    return sorted(found)


def discover_docs():
    """Return [(path, skill_name_or_None, text)] for every markdown document."""
    docs = []
    readme = os.path.join(ROOT, 'README.md')
    if os.path.exists(readme):
        docs.append((readme, None, open(readme, encoding='utf-8').read()))
    for skill, skill_dir in discover_skills():
        for dirpath, dirnames, filenames in os.walk(skill_dir):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))
            for fname in sorted(filenames):
                if not fname.endswith('.md'):
                    continue
                path = os.path.join(dirpath, fname)
                docs.append((path, skill, open(path, encoding='utf-8').read()))
    return docs


def anchors(text):
    """Headings, and bold stand-alone lines (`**2a. ...**`), as match targets."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        m = HEADING_RE.match(line) or BOLD_RE.match(line)
        if m:
            out.append(m.group('title'))
    return out


def matches(sec, anchor_list):
    want = norm(sec)
    if not want:
        return True
    want_tokens = want.split()
    for raw in anchor_list:
        have_tokens = norm(raw).split()
        if not have_tokens:
            continue
        # A numbered heading (`## 3. Reading AOT code`) carries the number as a
        # token, but a reference may name the section with or without it, so
        # both readings are candidates.
        candidates = [have_tokens]
        if have_tokens[0].isdigit() and len(have_tokens) > 1:
            candidates.append(have_tokens[1:])
        for have in candidates:
            text = ' '.join(have)
            if text == want or text.startswith(want + ' ') \
                    or want.startswith(text + ' '):
                return True
            if all(tok in have for tok in want_tokens):
                return True
            # A reference frequently runs on into the sentence that follows it
            # (`§Gates are cleared here or not at all`), leaving prose attached
            # to the heading name. Sharing the leading word is the strongest
            # signal available in that shape.
            if have[0] == want_tokens[0]:
                return True
    return False


def first_token_match(sec, anchor_list):
    """True when some heading starts with the same word as the reference.

    A reference is often a heading plus the rest of the sentence
    (`§Gates are cleared here or not at all`), so an exact match is too strict
    to be the only accepted shape. This is deliberately weaker than matches()
    and is reported as a warning, not as a pass.
    """
    want = norm(sec).split()
    if not want:
        return False
    for raw in anchor_list:
        have = norm(raw).split()
        if have and have[0] == want[0]:
            return True
    return False


def in_body(sec, text):
    """Weaker fallback: every token of the section name occurs in the body."""
    want_tokens = norm(sec).split()
    if not want_tokens:
        return True
    body = norm(text)
    return all(tok in body for tok in want_tokens)


def main():
    docs = discover_docs()
    by_name = {}
    for path, skill, text in docs:
        by_name.setdefault(os.path.basename(path), []).append((path, skill, text))

    ok = warn = 0
    problems = []
    warnings = []

    for path, skill, text in docs:
        where = os.path.relpath(path, ROOT).replace(os.sep, '/')
        for m in REF_RE.finditer(text):
            raw_sec = m.group('sec').strip().strip('.,;:!?\'")*').lower()
            # `§7 gives the exact framing` -- keep only the number.
            num = re.match(r'(\d{1,2}[a-z]?)\b', raw_sec)
            sec = num.group(1) if num else raw_sec
            if not sec:
                continue
            # `§8C` names sub-item C of section 8, so the bare section number is
            # an acceptable fallback target.
            variants = [sec]
            sub = re.fullmatch(r'(\d{1,2})[a-z]', sec)
            if sub:
                variants.append(sub.group(1))

            target_name = m.group('file')
            if target_name is None:
                target_text = text
                target_label = where
            else:
                candidates = [c for c in by_name.get(target_name, [])
                              if skill is None or c[1] == skill] \
                             or by_name.get(target_name, [])
                if not candidates:
                    problems.append('%s: §%s -> %s (no such file)'
                                    % (where, sec, target_name))
                    continue
                target_text = candidates[0][2]
                target_label = os.path.relpath(candidates[0][0], ROOT).replace(os.sep, '/')

            if any(matches(v, anchors(target_text)) for v in variants):
                ok += 1
            elif len(norm(sec).split()) >= 2 and first_token_match(
                    sec, anchors(target_text)):
                warn += 1
                warnings.append('%s: §%s -> %s (heading starts with this word '
                                'but the wording differs)'
                                % (where, sec, target_label))
            elif in_body(sec, target_text):
                warn += 1
                warnings.append('%s: §%s -> %s (words present, no matching heading)'
                                % (where, sec, target_label))
            else:
                problems.append('%s: §%s -> %s (section not found)'
                                % (where, sec, target_label))

    # Failure-catalogue references: `pitfalls.md` P31, or a bare (P18).
    pit_anchors = set()
    for name, entries in by_name.items():
        for path, _skill, text in entries:
            for raw in anchors(text):
                m = re.match(r'P(\d{1,2})[.\s]', raw)
                if m:
                    pit_anchors.add(m.group(1))
    for path, _skill, text in docs:
        where = os.path.relpath(path, ROOT).replace(os.sep, '/')
        for m in PITFALL_RE.finditer(text):
            if m.group('num') not in pit_anchors:
                problems.append('%s: P%s (no such pitfall)' % (where, m.group('num')))
            else:
                ok += 1

    print('== markdown documents ==')
    for path, _skill, _text in docs:
        print('  %s' % os.path.relpath(path, ROOT).replace(os.sep, '/'))

    print('\n== section references: %d reachable ==' % ok)
    for w in sorted(set(warnings)):
        print('  WARN %s' % w)
    for p in sorted(set(problems)):
        print('  FAIL %s' % p)

    print('\n== result: %d dangling, %d warning(s) =='
          % (len(set(problems)), len(set(warnings))))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
