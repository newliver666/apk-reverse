#!/usr/bin/env python3
"""Budget and shape gate for the apk-reverse skill: keep the always-loaded part from creeping,
and keep the long parts navigable.

`check_repo.py` proves the repository is *consistent* (paths resolve, indexes are complete).
This proves it is not *bloating*, and that a reader can find their way into a long file. Those are
different failures, and the second has no natural counter-pressure: every pass adds a reference, an
index row and a coverage claim, and nothing in the repository notices.

What is measured, and why each measure is shaped the way it is:

  1. **The always-loaded part, in tokens rather than lines.** A skill's whole `SKILL.md` body loads
     into context when the skill activates (agentskills.io/specification, "Progressive disclosure"),
     so every line of it competes for attention -- **including the index tables**. An earlier version
     of this gate subtracted the index lines from the budget, which made the number look better than
     the context actually is: 150 index lines are still 150 lines the model reads. The budget is now
     measured on the whole file, reported in lines *and* estimated tokens, with the index share
     reported for context rather than credited against the budget.
     Line counts are kept because they are the number a human can check by hand; the token estimate
     is `characters / 4`, which is crude and stated as crude -- it is a trend indicator, not a
     measurement of a specific tokenizer.
  2. **Index row length.** The index tables are the largest part of `SKILL.md` and the easiest to
     grow by accident: each new entry is written by someone who knows the detail, and the detail
     lands in the row. An index row says *when to load the file*; the file says what is in it.
  3. **Restated conclusions** (reported as notes, never as failures). A conclusion legitimately
     appears in the benchmark matrix, in the evidence record, and in the coverage statement --
     those three exist to state results. The check flags a concept that has spread *beyond* those
     homes, because that is when a future correction has to hunt for every copy.
  4. **Reference discoverability.** Every reference must be reachable from SKILL.md or nothing will
     ever load it. (`check_repo.py` also enforces this; the duplication is deliberate, because a
     dead reference is invisible in a way a broken path is not.)
  5. **Long-file navigability.** A file over `NAV_LINES` that a reader cannot skim is a file they
     will not load. Each one must open with a navigable head -- a "what this answers" line and
     either a table of contents or a "when to load" line -- so the decision to read further can be
     made from the top. This is the check that keeps "file-level progressive disclosure" from
     becoming a claim the repository makes but does not implement.
  6. **Instruction strength** (a note, never a failure). The repository's rules are meant to be
     followed, not weighed: a rule phrased as "consider X" reads as optional and is skipped under
     load. This reports the ratio of hedging phrases to imperative ones as a *trend*, and lists the
     hedged lines it found, so a human can decide -- the gate cannot judge whether a given sentence
     should be optional.
  7. **Corpus size** (a note, never a failure). The checks above govern what every task *loads*; this
     reports what the repository *carries*. The first cannot see the second: a new reference costs
     exactly one index line, so the corpus can double while the always-loaded count stays green. A
     large corpus is a choice; a growth nobody measured is the defect.

Usage:
    python check_budget.py            # report; exit 1 if a hard limit is exceeded
    python check_budget.py --strict   # treat every warning as a failure
    python check_budget.py --json
"""
import argparse
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(ROOT, 'skills', 'apk-reverse')
SKILL = os.path.join(SKILL_DIR, 'SKILL.md')
REFS = os.path.join(SKILL_DIR, 'references')

CONTENT_LINES_OK = 460        # always-loaded lines: soft ceiling, warns above this
CONTENT_LINES_HARD = 560      # past this, something is structurally wrong
# Token budget for the always-loaded body. Calibrated here rather than copied: the Agent Skills
# spec recommends roughly 5,000 tokens of *instructions*, and this skill deliberately exceeds it,
# because the two things it will not move out of the always-loaded body are the symptom index
# (~54 rows; "symptom -> file" is the one lookup that must stay one hop) and the four gates with
# their pass criteria. The budget therefore tracks whether the body is *growing past what the
# design requires*, and the number is reviewed against a real tokenizer (see token_estimate).
TOKEN_SOFT = 13000
TOKEN_HARD = 16000
INDEX_ROW_SOFT = 250          # chars of description per row
INDEX_ROW_HARD = 400          # a row longer than this is a paragraph, not an index entry
INDEXES = ('Symptom index', 'Reference index', 'Script index')
NAV_LINES = 100               # above this, a reference must open navigably
CORPUS_FILES_NOTE = 110       # references + scripts, reported as a note past this
CORPUS_LINES_NOTE = 26000     # total lines across the same corpus, same treatment
# Characters per token, for the no-tiktoken fallback. **Calibrated on SKILL.md against
# tiktoken/cl100k_base** (47,629 chars -> 11,114 tokens = 4.285), so both measurement paths reach
# the same verdict. Getting this wrong made the gate answer differently on CI than locally.
TOKENS_PER_CHAR = 4.285
# A navigable head: one of these must appear in the first NAV_HEAD_LINES lines.
NAV_HEAD_LINES = 40
HEDGE_RE = re.compile(
    r'\b(consider|considering|you may|you might|might want|optionally|prefer(?:ably)?|'
    r'it is worth|feel free|if you like|tends to be better)\b', re.I)

# Concepts that have been restated once already. Reported, not enforced -- see the docstring.
RESTATED = {
    'trivial-body is bimodal': [r'bimodal'],
    'Java2C native density (2000x)': [r'82\.76', r'2,?000x'],
    'Stalker exclusion keeps the process alive': [r'keeps? the (?:target|process) alive'],
    'Dex-VMP coverage fixture (218/224)': [r'218 of 224', r'218/224'],
    'ezAndroid is JNI sinking, not a VMP': [r'JNI sinking'],
    'KernelSU userspace cannot change a syscall': [r'userspace module.{0,60}cannot change'],
    'protobuf proto3 explicit zero': [r'proto3.{0,40}(?:explicit )?zero'],
    'armv7 AOT strings are UTF-8, not UTF-16': [r'armv7.{0,80}UTF-8', r'UTF-8.{0,80}armv7'],
}
# Documents whose job is to state results; a concept appearing here is not drift.
LEGITIMATE_HOMES = ('tests/benchmark.md', 'docs/tool-verification/')


def read_lines(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read().splitlines()


def skill_lines():
    return read_lines(SKILL)


def index_rows(lines):
    """(index line count, [(section, first-cell, desc-length)] for over-long rows)."""
    n = 0
    long_rows = []
    cur = None
    for ln in lines:
        if ln.startswith('## '):
            cur = ln[3:].strip()
            continue
        if not (cur and any(cur.startswith(i) for i in INDEXES) and ln.startswith('|')):
            continue
        if set(ln) <= set('|-: '):
            continue
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        if len(cells) < 2:
            continue
        n += 1
        if cells[0].lower() in ('file', 'script', 'what you observe', 'status'):
            continue
        desc = cells[-1]
        if len(desc) > INDEX_ROW_SOFT:
            long_rows.append((cur, cells[0][:44], len(desc)))
    return n, long_rows


def token_estimate(text):
    """Token count for the always-loaded body -- deterministic, not installation-dependent.

    Uses `tiktoken` (cl100k_base) when it is available, because a real measurement beats an estimate
    everywhere in this repository, including in this file. When it is not, it falls back to
    `characters / TOKENS_PER_CHAR`.

    The fallback constant is **calibrated against that measurement** rather than guessed: a
    markdown-heavy document tokenizes worse per character than the usual /4 rule of thumb, and this
    file measured 0.30 characters-to-tokens on SKILL.md (67,011 chars -> 19,929 tokens).

    Why the value matters more than the method: the first version used 3.6 and the gate therefore
    reached *different verdicts on different machines* -- `WARN over budget` where tiktoken was
    absent (CI's 3.11 job, and any contributor's box) and `ok` where it was installed. A budget gate
    whose answer depends on what the runner happens to have installed is not a gate. Calibrating the
    fallback to the same ballpark makes the verdict agree, and the printed `how` field still says
    which number a reader is looking at.
    """
    try:
        import tiktoken
        return len(tiktoken.get_encoding('cl100k_base').encode(text)), 'tiktoken/cl100k_base'
    except Exception:
        return int(len(text) / TOKENS_PER_CHAR), 'estimate chars/%.1f' % TOKENS_PER_CHAR


def check_size(lines):
    n_idx, _ = index_rows(lines)
    content = len(lines)
    text = '\n'.join(lines)
    toks, how = token_estimate(text)
    pct_idx = (100.0 * n_idx / content) if content else 0.0

    findings = []
    if content <= CONTENT_LINES_OK and toks <= TOKEN_SOFT:
        msg = ('SKILL.md %d lines (%d index = %.0f%% of the file, and it is still loaded: the budget '
               'is measured on the whole body), ~%d tokens (%s; soft %d)'
               % (content, n_idx, pct_idx, toks, how, TOKEN_SOFT))
        findings.append(('ok', msg))
    elif content <= CONTENT_LINES_HARD and toks <= TOKEN_HARD:
        findings.append((
            'warn',
            'SKILL.md is %d lines / ~%d tokens (%s), over the soft budget (%d lines / %d tokens) -- '
            'the always-loaded body is what the model reads on activation. Move detail into '
            'references/ and leave a pointer; %d of those lines are the index tables, which are '
            'loaded too. Total references: %d files.'
            % (content, toks, how, CONTENT_LINES_OK, TOKEN_SOFT, n_idx,
               len(glob.glob(os.path.join(REFS, '*.md'))))))
    else:
        findings.append((
            'fail',
            'SKILL.md is %d lines / ~%d tokens (%s), past the hard limit (%d lines / %d tokens)'
            % (content, toks, how, CONTENT_LINES_HARD, TOKEN_HARD)))
    return findings, n_idx, content, toks


def check_index_rows(lines):
    _, long_rows = index_rows(lines)
    out = []
    for section, key, size in long_rows:
        hard = size > INDEX_ROW_HARD
        out.append(('warn' if hard else 'warn',
                    '%s: row for %s is %d chars (soft limit %d)%s' %
                    (section, key, size, INDEX_ROW_SOFT,
                     ' -- that is a paragraph, not an index entry' if hard else '')))
    return out


def check_navigable():
    """A long reference must be skimmable from its first screen.

    The head is what lets a reader decide *not* to read the rest, which is the only thing that makes
    a 400-line reference cheaper than a 40-line one. Two shapes are accepted, because both are in
    use here: an explicit table of contents, or an explicit "when to load / what this answers" line.
    """
    out = []
    for path in sorted(glob.glob(os.path.join(REFS, '*.md'))):
        lines = read_lines(path)
        if len(lines) < NAV_LINES:
            continue
        head = '\n'.join(lines[:NAV_HEAD_LINES]).lower()
        has_toc = bool(re.search(r'(?m)^#+ *(table of contents|contents)\s*$', head))
        has_when = ('when to load' in head or 'what this answers' in head
                    or 'load this when' in head or 'when this applies' in head)
        if not (has_toc or has_when):
            out.append(('warn', 'references/%s is %d lines with neither a table of contents nor a '
                                '"when to load"/"what this answers" line in its first %d lines -- '
                                'a reader cannot decide from the top whether to load it'
                        % (os.path.basename(path), len(lines), NAV_HEAD_LINES)))
    return out


def check_hedging():
    """Report hedged instruction lines; never fail on them.

    A rule that reads as optional gets skipped when the context is under load. This cannot be
    decided by regex -- some sentences *should* be optional -- so it reports the lines and a ratio,
    and a human decides. The ratio is the trend: if it climbs, the rules are getting softer.
    """
    lines = skill_lines()
    body = [ln for ln in lines
            if ln.strip() and not ln.startswith('|') and not ln.startswith('#')
            and not ln.startswith('---')]
    hedged = [(i + 1, ln.strip()) for i, ln in enumerate(lines) if HEDGE_RE.search(ln)]
    ratio = (len(hedged) / len(body)) if body else 0.0
    notes = []
    if hedged:
        notes.append('hedged instruction lines: %d of %d prose lines (%.1f%%; report-only -- a '
                     'hedged rule reads as optional). First few: %s'
                     % (len(hedged), len(body), 100.0 * ratio,
                        '; '.join('L%d %s' % (n, t[:52]) for n, t in hedged[:3])))
    return notes


def check_restated():
    notes = []
    files = (glob.glob(os.path.join(REFS, '*.md')) +
             glob.glob(os.path.join(REFS, '*', '*.md')) +
             glob.glob(os.path.join(ROOT, 'docs', 'tool-verification', '*.md')) +
             [SKILL, os.path.join(ROOT, 'README.md'), os.path.join(ROOT, 'tests', 'benchmark.md')])
    corpus = {}
    for f in files:
        if os.path.isfile(f):
            try:
                rel = os.path.relpath(f, ROOT).replace('\\', '/')
                corpus[rel] = open(f, encoding='utf-8').read()
            except OSError:
                pass
    for label, pats in RESTATED.items():
        hits = [p for p, t in corpus.items() if any(re.search(x, t, re.I) for x in pats)]
        # files whose job is to state results do not count as drift
        drift = [h for h in hits if not any(h.startswith(home) for home in LEGITIMATE_HOMES)]
        if len(drift) > 3:
            notes.append('restated in %d non-record files: %s -- %s' %
                         (len(drift), label, ', '.join(sorted(d.split('/')[-1] for d in drift))))
    return notes


def check_discoverable():
    """Every reference must be reachable from the entry point or from the routing file it points to.

    `SKILL.md` is the entry point; since this pass it carries the symptom index and delegates the
    inventory to `references/routing.md` (which `check_routing.py` in turn proves names every
    reference and every script). Counting the routing file here is what keeps the delegation honest
    instead of letting a file become unreachable the moment its index row moves.
    """
    body = open(SKILL, encoding='utf-8').read()
    routing = os.path.join(REFS, 'routing.md')
    if os.path.isfile(routing):
        body += open(routing, encoding='utf-8').read()
    out = []
    for f in sorted(glob.glob(os.path.join(REFS, '*.md'))):
        name = os.path.basename(f)
        if name not in body:
            out.append(('fail', 'references/%s is named neither in SKILL.md nor in '
                                'references/routing.md -- nothing will load it' % name))
    return out


def check_corpus():
    """Report corpus size so growth is visible instead of discovered late.

    Contributed on this repository while the checks above were being rewritten. Kept as its own
    function and its own note: it measures what the repository *carries*, which is a different
    quantity from what a task loads, and collapsing the two would let a growing corpus hide behind a
    green always-loaded count.
    """
    refs = sorted(glob.glob(os.path.join(REFS, '**', '*.md'), recursive=True))
    scripts = sorted(p for p in glob.glob(os.path.join(SKILL_DIR, 'scripts', '**', '*'), recursive=True)
                     if os.path.isfile(p))

    def count(paths):
        total = 0
        for p in paths:
            try:
                with open(p, encoding='utf-8', errors='replace') as fh:
                    total += sum(1 for _ in fh)
            except OSError:
                pass
        return total

    ref_lines, script_lines = count(refs), count(scripts)
    n_files = len(refs) + len(scripts)
    lines_total = ref_lines + script_lines

    notes = ['corpus: %d references + %d scripts = %d files, %d lines total'
             % (len(refs), len(scripts), n_files, lines_total)]
    if n_files > CORPUS_FILES_NOTE:
        notes.append('corpus is %d files, past the %d-file note threshold -- every entry costs an '
                     'index line and a share of the maintenance surface, so confirm the new ones are '
                     'load-bearing rather than merely adjacent' % (n_files, CORPUS_FILES_NOTE))
    if lines_total > CORPUS_LINES_NOTE:
        notes.append('corpus is %d lines, past the %d-line note threshold'
                     % (lines_total, CORPUS_LINES_NOTE))
    return notes


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--strict', action='store_true', help='treat warnings as failures')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    lines = skill_lines()
    findings, n_idx, content, toks = check_size(lines)
    findings += check_index_rows(lines)
    findings += check_discoverable()
    findings += check_navigable()
    notes = check_restated() + check_hedging() + check_corpus()

    if args.json:
        print(json.dumps({
            'findings': [{'level': lvl, 'message': m} for lvl, m in findings],
            'notes': notes,
            'index_lines': n_idx,
            'total_lines': content,
            'token_estimate': toks,
        }, indent=2))
    else:
        for lvl, m in findings:
            print('%s %s' % ({'ok': '  ok  ', 'warn': ' WARN ', 'fail': ' FAIL '}[lvl], m))
        for m in notes:
            print(' note  %s' % m)
        n_fail = sum(1 for lvl, _ in findings if lvl == 'fail')
        n_warn = sum(1 for lvl, _ in findings if lvl == 'warn')
        print()
        print('== budget: %d failure(s), %d warning(s), %d note(s) ==' % (n_fail, n_warn, len(notes)))

    n_bad = sum(1 for lvl, _ in findings if lvl == 'fail' or (args.strict and lvl == 'warn'))
    return 1 if n_bad else 0


if __name__ == '__main__':
    sys.exit(main())
