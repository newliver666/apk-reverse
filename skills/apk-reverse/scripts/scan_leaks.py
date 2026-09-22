#!/usr/bin/env python3
"""Leak scan for a skills repository: find target identity that should not be shipped.

Why this exists: a skill repository is published, and the material feeding it is real work
notes -- device transcripts, packet captures, package listings. Target identity leaks into
those notes one line at a time (a bundle id in a `pm path` line, a device serial echoed
before a `dumpsys`, a token pasted while debugging a download), and it is invisible to
every other gate: `check_repo.py` verifies structure, `check_refs.py` verifies anchors,
neither looks at *content*. Human grep finds it only after someone thinks to look.

Two principles, both borrowed from published anonymization practice, shape the design:

  1. **A "do not anonymize" list.** Tool names, library names, function names, protocol
     field names, CVE ids, hardening-product names, public crackme/benchmark names and
     URLs, and placeholders like `<PKG>`/`<DEVICE>` are *reusable* and must never be
     reported. A scanner that flags them trains its readers to ignore it.
  2. **Context retention.** A finding is reported with the surrounding characters of its
     line, not a bare line number, so the fixer does not have to reopen the file to know
     what to delete.

Exit codes are fixed so this can gate a pipeline:

    0   clean                     nothing found outside the exemptions
    0   leaks_found_strong_only   findings exist, but every one of them is `weak`
    1   leaks_found               at least one strong/certain finding, or any finding
                                  at all under --fail-on any
    2   error                     usage or read error

and the last line of stdout is always one of

    RESULT=clean | leaks_found_strong_only | leaks_found | error

`--fail-on strong` (the default) decides which findings take the exit code off zero. It is the
maintenance-habit setting, and it exists because a repository's own documentation legitimately
contains RFC 5737 addresses, which the endpoint rules report on purpose; `--fail-on any` is the
strict pass to run before publishing. Neither setting changes what is printed.

Everything is a heuristic. A finding means "a human should look at this line", never
"this is definitely a secret". Strength labels (`certain` / `strong` / `weak`) say how
much of the matching was context rather than shape -- see references for the table.

Usage
-----
    python scan_leaks.py                                  # scan the repo it lives in
    python scan_leaks.py --root .                        # explicit root
    python scan_leaks.py --root . --format json          # machine-readable
    python scan_leaks.py --root . --only pat,appkey      # one or more categories
    python scan_leaks.py --root . --quiet                # token line only
    python scan_leaks.py --root . --fail-on any          # strict: weak hits fail too
    python scan_leaks.py --root . --list-rules

Only text files are read. Directories named in --exclude, VCS metadata, caches and
`tools/` (a git-ignored work area by convention) are skipped; a root supplied explicitly
is still scanned even if it sits under an excluded name.

Pure standard library, python3, no third-party imports. POSIX and Windows.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# --------------------------------------------------------------------------------------
# Exemption data -- the "do not anonymize" list, expressed as code so it can be audited.
# --------------------------------------------------------------------------------------

# Reverse-domain prefixes that are never a target's own identity: platforms, frameworks,
# SDK vendors, JDK/ART packages, documentation examples and this task's own fixtures.
# Matching is on the value itself and on its first two segments, lowercased.
BENIGN_PACKAGE_PREFIXES = (
    # platforms / runtimes / language packages
    "android", "androidx", "java", "javax", "jdk", "kotlin", "kotlinx", "dalvik", "org.w3c",
    "org.xml", "org.json", "org.apache", "org.jetbrains", "org.lsposed", "org.reactivestreams",
    "com.android", "com.google", "com.sun", "com.oracle", "com.squareup", "com.github",
    "io.reactivex", "io.github", "dalvik.system",
    # ad / analytics SDKs and their activities (these are inventory, not identity)
    "com.bytedance", "com.qq.e", "com.tencent", "com.kwad", "com.kuaishou", "com.baidu",
    "com.umeng", "com.sigmob", "com.bdx", "com.anythink", "com.mbridge", "com.chinatowercom",
    "cn.connor", "bytedance",
    # hardening products, by their own naming (a product name, not a target)
    "com.stub", "com.secneo", "com.qihoo", "com.nqshield", "com.tencent.StubShell",
    "com.wrapper", "com.eg.android.AlipayGphone",
    # documentation examples / fixtures used by this repository itself
    "com.example", "org.example", "net.example", "io.example", "probe.synthetic",
    # probe modules built by this repository's own verification passes
    "com.t1", "com.revprobe", "com.lsphook",
)

# Whole-value exemptions for the `bundle` rule: placeholders and documented stand-ins.
PLACEHOLDER_TOKENS = (
    "<pkg>", "<device>", "<serial>", "<app>", "<sample>", "<target>", "<host>", "<token>",
    "<label>", "<hash>", "<work>", "<out>", "<path>", "<user>", "<name>", "<id>", "<n>",
    "<pid>", "<activity>", "<module>", "<key>", "<value>", "<abi>", "<file>", "<dir>",
    "${", "{{", "%s", "%(", "$env:", "$(", "xn--",
)

# IPs that are loopback, unspecified, emulator-host or link-local. Note that the RFC 5737
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are deliberately NOT
# exempt: they are the *correct* way to write a synthetic address in a document, so a hit
# there is a signal rather than noise, and suppressing them would hide a real one.
#
# That decision costs the gate its pass condition -- this repository's own documents and its
# own usage example keep producing `endpoint/weak` hits -- so the two are separated instead:
# they stay reported, and `--fail-on strong` (the default) does not fail on them. See the
# reference file for the reasoning: a gate that cannot go green is a gate people learn to
# ignore, and `--fail-on any` is there for the publish-time strict pass.
BENIGN_IP_PREFIXES = (
    "127.", "0.0.0.0", "255.255.255.255", "169.254.", "224.", "239.", "10.0.2.", "10.0.3.",
)

# Deterministic-value words that make a package token a component name rather than a bundle
# id. A camelCase segment or one of these words at the end of a reverse-domain string is a
# *thing*, not an app -- `com.android.pathclassloader`-shaped text in a log line, or a
# library identifier quoted in a reference file.
CODE_IDENTIFIER_HINTS = (
    "pathclassloader", "dexclassloader", "bootclassloader", "inmemorydexclassloader",
    "loadedapk", "activitythread", "instrumentation", "application", "activity",
    "service", "provider", "receiver", "helper", "manager", "factory", "impl", "utils",
    "constants", "buildconfig", "r8", "internal", "runtime", "validator", "inspector",
    "converter", "adapter", "listener", "callback", "module", "trampoline", "gen",
    # string/collection methods: `args.package.split(...)` is code, not a bundle id
    "split", "substring", "indexof", "lastindexof", "tostring", "tolowercase",
    "touppercase", "equals", "hashcode", "getname", "getvalue", "length", "format",
)

# Public crackme / benchmark families whose *reverse-engineered* package names appear in
# write-ups. These are public targets, and naming them is expected reuse rather than a leak.
PUBLIC_TARGET_PREFIXES = (
    "sg.vantagepoint", "owasp.mstg", "jakhar.aseem", "com.revo", "com.example.uncrackable",
)


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(tok in low for tok in PLACEHOLDER_TOKENS)


def _slug_segments(value: str) -> list:
    return [seg for seg in re.split(r"[.\-_/]", value.lower()) if seg]


def _has_camel_mid_segment(value: str) -> bool:
    # `com.foo.BarBaz` in prose: a segment carrying an interior capital is a class name.
    for seg in re.split(r"[.\\/]", value):
        if len(seg) > 3 and re.search(r"[a-z][A-Z]", seg):
            return True
    return False


def _looks_like_code_identifier(value: str) -> bool:
    segs = _slug_segments(value)
    if not segs:
        return False
    if segs[-1] in CODE_IDENTIFIER_HINTS:
        return True
    if _has_camel_mid_segment(value):
        return True
    # `com.example.target.Helper.method` style: three or more segments whose tail is short
    # and lowercase with no digits is still prose, so only flag when a known hint appears.
    return False


def _benign_package(value: str) -> str:
    """Return an exemption reason for a reverse-domain token, or '' if it is reportable."""
    low = value.lower().strip("`'\"()[],;:")
    if not low:
        return "empty"
    if _is_placeholder(low):
        return "placeholder"
    if re.search(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$", low) is None:
        return "not a reverse-domain token"
    if low.startswith(("ca.", "de.", "jp.", "uk.", "fr.", "ru.", "cn.", "top.", "xyz.")) \
            and low.count(".") >= 3:
        return "not a reverse-domain token"
    for prefix in BENIGN_PACKAGE_PREFIXES:
        if low == prefix.lower() or low.startswith(prefix.lower() + "."):
            return "benign prefix: " + prefix
    for prefix in PUBLIC_TARGET_PREFIXES:
        if low == prefix.lower() or low.startswith(prefix.lower() + "."):
            return "public crackme/benchmark package: " + prefix
    two = ".".join(low.split(".")[:2])
    for prefix in BENIGN_PACKAGE_PREFIXES:
        if two == prefix.lower():
            return "benign prefix (2-segment): " + prefix
    if _looks_like_code_identifier(low):
        return "code identifier, not a bundle id"
    if low.count(".") < 2:
        return "single-label pair, too generic to be a bundle id"
    return ""


def _benign_ip(value: str) -> str:
    ip = value.split(":")[0]
    for prefix in BENIGN_IP_PREFIXES:
        if ip == prefix.rstrip(".") or ip.startswith(prefix):
            return "loopback/unspecified/emulator address"
    return ""


def _benign_path(value: str) -> str:
    low = value.lower()
    if _is_placeholder(low):
        return "placeholder user"
    user = re.split(r"[\\/]", low.rstrip("\\/"))[-1]
    if user in ("users", "home", "local", "tmp", "data", "appdata", "temp", "private"):
        return "no user segment"
    return ""


# A four-part dotted run of digits is an IPv4 address only when nothing nearby says
# "version". `JDK 17.0.4.1`, `build-tools 34.0.0` and `frida 16.7.19` are the shapes that
# actually occur in this repository's evidence files, and all of them are legitimate.
VERSION_CONTEXT_RE = re.compile(
    r'(?:jdk|jre|java|python|frida|node|npm|gradle|build-tools|ndk|apktool|version|ver|v)\W*$',
    re.IGNORECASE)

# An SDK's own version directory: `/5.6.10.1/`, `/1.2.3.4/`. Package-manager cache paths look
# exactly like an IPv4 literal and are inside an APK's private storage, not an endpoint.
VERSION_PATH_RE = re.compile(r'[/\\]$')

# Code member access: `args.package.split(...)`, `self.cfg.value`. A reverse-domain **shape**
# with a program's own variable in front of it is a property lookup, never a bundle id.
CODE_MEMBER_ACCESS_RE = re.compile(r'(?:\b(?:args|argv|self|this|opts|options|cfg|config)\.)')


def _benign_ip_literal(m, line: str) -> str:
    """Return an exemption reason for a bare IPv4-shaped literal, or ''."""
    reason = _benign_ip(m.group(1))
    if reason:
        return reason
    head = line[max(0, m.start() - 30):m.start()]
    if VERSION_CONTEXT_RE.search(head):
        return "version string, not an address"
    if VERSION_PATH_RE.search(head) and line[m.end():m.end() + 1] in ("/", "\\"):
        return "version directory in a package cache path, not an address"
    return ""


def _package_exempt(m, line: str, group: int = 1) -> str:
    """Line-aware bundle-id exemption: code member access first, then the benign list.

    The window starts at the capture itself, not at the whole match: an unbounded prefix in
    some rules means the match can begin well before the value, and a window that stops at
    `m.start()` would then never see the `args.` that makes it a property lookup.
    """
    vstart = m.start(group)
    if CODE_MEMBER_ACCESS_RE.search(line[max(0, vstart - 24):vstart + 12]):
        return "code member access, not a bundle id"
    return _benign_package(m.group(group))


# --------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------
# Each rule: id, category, description, strength, pattern, exemption function (optional).
# `strength` describes how much of the decision came from context rather than shape:
#   certain -- shape alone is conclusive (a provider-specific token format)
#   strong  -- shape plus a nearby context word agrees
#   weak    -- pattern only; expect false positives, read the context

RULE_SPECS = [
    (
        "bundle_pkg_attr", "package", "a `package=` bundle id in a manifest or transcript",
        "strong", r'\bpackage\s*=\s*"([A-Za-z_][A-Za-z0-9_.]*)"', lambda m: _benign_package(m.group(1)),
    ),
    (
        "bundle_pkg_decl", "package", "a bundle id in a `<manifest>` line",
        "strong", r'<manifest[^>\n]*?\spackage="([^"]+)"', lambda m: _benign_package(m.group(1)),
    ),
    (
        "bundle_pm_path", "package", "a bundle id in a `pm`/`am`/`monkey` invocation",
        "strong", r'\b(?:pm|am|monkey|cmd package)\s+[^\n]{0,40}?\b([a-z][a-z0-9_]*\.[a-z0-9_]+(?:\.[a-z0-9_]+)+)',
        lambda m: _benign_package(m.group(1)),
    ),
    (
        "bundle_process_line", "package", "a bundle id in a `ps`/`pidof`/`top` capture",
        "strong",
        r'\b(?:pidof|ps -A|ps -e|top)\b[^\n]*?(?<![\w.])([a-z][a-z0-9_]*\.[a-z0-9_]+(?:\.[a-z0-9_]+)+)(?!\s*\()',
        lambda m: _benign_package(m.group(1)),
    ),
    (
        "bundle_component", "package", "a bundle id in a `component=`/`-n` activity reference",
        "strong", r'(?:component\s*=|/\.|-\s*n\s+)(?<![\w.])([a-z][a-z0-9_]*\.[a-z0-9_]+(?:\.[a-z0-9_]+)+)(?=/)',
        lambda m: _benign_package(m.group(1)),
    ),
    (
        "device_serial", "device", "an `adb devices`-shaped device serial",
        "strong", r'(?<![\w.-])(?=[A-Z0-9]{16}(?![\w.-]))(?=[A-Z0-9]{0,15}\d)([A-Z0-9]{16})(?![\w.-])',
        # A bare run of 16 hex digits is usually a stack address, a hash fragment or a
        # protocol field -- the three cases this repository actually produces -- so an
        # all-digits token is suppressed. A real platform serial carries at least one letter.
        lambda m: "all-digit token, not a device serial" if m.group(1).isdigit() else "",
    ),
    (
        "device_serial_context", "device", "a serial next to a device/install/`su` context word",
        "strong",
        r'(?:serial|device|adb|install|flash|\bsu\b)[^\n]{0,40}?\b([A-Z0-9]{16})\b',
        None,
    ),
    (
        "device_serial_tabular", "device", "a bare 16-char token in a device-listing table",
        "strong",
        r'\b([A-Z0-9]{16})\t+(?:device|unauthorized|offline|no permissions)\b',
        None,
    ),
    (
        "token_github_pat", "token", "a GitHub fine-grained personal access token",
        "certain", r'github_pat_[A-Za-z0-9_]{20,}', None,
    ),
    (
        "token_github_classic", "token", "a GitHub classic token",
        "certain", r'\bgh[pousr]_[A-Za-z0-9]{20,}', None,
    ),
    (
        "token_env_assignment", "token", "an inline API-key/token/secret assignment",
        "strong",
        r'\b(?:API_?KEY|APIKEY|ACCESS_?TOKEN|AUTH_?TOKEN|SECRET_?KEY|SECRET|PASSWORD|PASSWD|'
        r'BEARER_?TOKEN)\s*[=:]\s*["\']?([A-Za-z0-9_\-./+]{12,})',
        None,
    ),
    (
        "token_authorization_header", "token", "a literal Authorization header value",
        "strong", r'(?:Authorization|X-Auth-Token)["\']?\s*:\s*["\']?(?:Bearer\s+|Basic\s+)?([A-Za-z0-9_\-./+=]{16,})',
        None,
    ),
    (
        "appkey_assignment", "appkey", "an SDK appkey/appsecret assignment with a literal value",
        "strong",
        r'\b(?:APPKEY|APP_KEY|appSecretKey|AppSecret|APP_SECRET|SECRET_KEY|UMENG_APPKEY|'
        r'com\.tencent\.map\.api\.KEY)\b\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,})',
        None,
    ),
    (
        "plain_addr", "endpoint", "a non-loopback literal IP:port",
        "weak", r'(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})(?![\w.])', None,
    ),
    (
        "plain_addr_ipliteral", "endpoint", "a non-loopback bare IPv4 literal",
        "weak",
        # Four dot-separated 1-3 digit groups, not bounded by further dots (which is what a
        # version string looks like: `17.0.4.1`, `5.6.10.1`) and not bounded by word
        # characters (which is what a file name looks like).
        r'(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])', None,
    ),
    (
        "user_path_posix", "path", "an absolute POSIX user-home path",
        "strong", r'(?:/home/|/Users/)([A-Za-z][A-Za-z0-9._-]{1,31})/', lambda m: _benign_path(m.group(0)),
    ),
    (
        "user_path_windows", "path", "an absolute Windows user-profile path",
        "strong", r'[A-Za-z]:\\Users\\([^\\/\s`"\']+)', lambda m: _benign_path(m.group(0)),
    ),
]

# A user path whose user segment *is* a placeholder (`C:\Users\<user>\...`) must not report;
# handled by the exemption functions above plus this post-filter.
PLACEHOLDER_PATH_RE = re.compile(r'(?:/home/|/Users/|[A-Za-z]:\\Users\\)[<{[$%]')


def build_rules():
    rules = []
    for rid, cat, desc, strength, pattern, exempt in RULE_SPECS:
        rules.append({
            "id": rid,
            "category": cat,
            "description": desc,
            "strength": strength,
            "regex": re.compile(pattern),
            "exempt": exempt,
        })
    return rules


# --------------------------------------------------------------------------------------
# Walking
# --------------------------------------------------------------------------------------

TEXT_EXTENSIONS = (".md", ".py", ".js", ".json", ".txt", ".yml", ".yaml", ".sh", ".ps1",
                   ".toml", ".cfg", ".ini", ".xml", ".java", ".smali", ".html", ".csv")

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache",
    ".pytest_cache", ".idea", ".vscode", ".tox", "site-packages", "dist", "build",
}

DEFAULT_EXCLUDES = ("tools", "存在问题和例子", "新的建议和思路", ".venv", "node_modules")

DEFAULT_ROOT_FILES = ("README.md",)
DEFAULT_ROOT_DIRS = ("skills", "docs")
ROOT_GLOBS = ("check_*.py", "build_scripts.py")


def _norm(path: str) -> str:
    return os.path.normpath(os.path.abspath(path)).replace("\\", "/").lower()


def iter_files(root: str, excludes, skip_self: bool, from_list=None):
    """Yield candidate text files.

    Layout-sensitive on purpose: given a repository root (one holding `skills/` or the
    maintenance scripts) it scans exactly the shipped surface -- README, skills/, docs/ and the
    root check scripts -- so that a git-ignored work area is not reported as if it were
    publishable. Given any other directory (a fixture, a subtree) it scans that directory
    recursively, because a caller who names a path means it.

    `from_list` overrides both behaviours: it is an explicit list of paths (relative to `root`, or
    absolute) and nothing else is read. The maintenance gate passes the tracked-file list here.
    """
    root_abs = os.path.abspath(root)
    # An explicit list is an explicit instruction: the *default* directory exemptions (a local
    # `tools/` work area, a sample folder) are about what a tree walk would otherwise pick up, and
    # must not silently drop a path the caller named. Only `--exclude` narrows an explicit list.
    if from_list is not None:
        excluded = [_norm(os.path.join(root_abs, e)) for e in (excludes or [])
                    if e not in DEFAULT_EXCLUDES]
    else:
        excluded = [_norm(os.path.join(root_abs, e)) for e in excludes]
    self_path = _norm(__file__) if skip_self else None

    def is_excluded(path: str) -> bool:
        norm = _norm(path)
        if self_path and norm == self_path:
            return True
        for ex in excluded:
            if norm == ex or norm.startswith(ex + "/"):
                return True
        return False

    candidates = []
    if from_list is not None:
        for entry in from_list:
            full = entry if os.path.isabs(entry) else os.path.join(root_abs, entry)
            if os.path.isfile(full):
                candidates.append(full)
    elif os.path.isfile(root_abs):
        candidates.append(root_abs)
    else:
        looks_like_repo = (os.path.isdir(os.path.join(root_abs, "skills"))
                           or os.path.isfile(os.path.join(root_abs, "check_repo.py")))
        if looks_like_repo:
            for name in DEFAULT_ROOT_FILES:
                p = os.path.join(root_abs, name)
                if os.path.isfile(p):
                    candidates.append(p)
            for name in DEFAULT_ROOT_DIRS:
                p = os.path.join(root_abs, name)
                if os.path.isdir(p):
                    candidates.append(p)
            for entry in sorted(os.listdir(root_abs)):
                full = os.path.join(root_abs, entry)
                if os.path.isfile(full):
                    for glob_pat in ROOT_GLOBS:
                        if re.fullmatch(glob_pat.replace("*", ".*"), entry):
                            candidates.append(full)
                            break
        else:
            candidates.append(root_abs)

    seen = set()
    for cand in candidates:
        if is_excluded(cand):
            continue
        if os.path.isfile(cand):
            key = _norm(cand)
            if key not in seen:
                seen.add(key)
                yield cand
            continue
        for dirpath, dirnames, filenames in os.walk(cand):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in SKIP_DIRS and not is_excluded(os.path.join(dirpath, d)))
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                if not fn.lower().endswith(TEXT_EXTENSIONS):
                    continue
                if is_excluded(full):
                    continue
                key = _norm(full)
                if key in seen:
                    continue
                seen.add(key)
                yield full


def read_text(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            return fh.read(), None
    except UnicodeDecodeError:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(), "decoded with replacement characters"
        except OSError as exc:
            return None, "read failed: %s" % exc
    except OSError as exc:
        return None, "read failed: %s" % exc


def context_of(line: str, start: int, end: int, before: int = 48, after: int = 48) -> str:
    left = max(0, start - before)
    right = min(len(line), end + after)
    head = "..." if left > 0 else ""
    tail = "..." if right < len(line) else ""
    return head + line[left:right].strip() + tail


def scan_text(path: str, rel: str, text: str, rules, only):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            # a minified line has no useful context; still scan it, clipped
            pass
        for rule in rules:
            if only and rule["category"] not in only:
                continue
            for m in rule["regex"].finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if not value:
                    continue
                if rule["id"] in ("plain_addr", "plain_addr_ipliteral"):
                    reason = _benign_ip(value)
                    if not reason and rule["id"] == "plain_addr_ipliteral":
                        reason = _benign_ip_literal(m, line)
                elif rule["id"] in ("user_path_windows", "user_path_posix"):
                    reason = _benign_path(value)
                    if not reason and PLACEHOLDER_PATH_RE.search(m.group(0)) is None:
                        # `<user>` style is already covered by _benign_path; re-check the
                        # *whole* match for a placeholder segment before reporting.
                        if _is_placeholder(m.group(0)):
                            reason = "placeholder path segment"
                elif rule["category"] == "package":
                    reason = _package_exempt(m, line, rule.get("group", 1))
                else:
                    reason = ""
                    if rule["exempt"] is not None:
                        reason = rule["exempt"](m)
                if reason:
                    findings.append({
                        "file": rel, "line": lineno, "column": m.start() + 1,
                        "rule": rule["id"], "category": rule["category"],
                        "strength": rule["strength"], "match": value,
                        "context": context_of(line, m.start(), m.end()),
                        "exempted": True, "exempt_reason": reason,
                    })
                    continue
                findings.append({
                    "file": rel, "line": lineno, "column": m.start() + 1,
                    "rule": rule["id"], "category": rule["category"],
                    "strength": rule["strength"], "match": value,
                    "context": context_of(line, m.start(), m.end()),
                    "exempted": False, "exempt_reason": "",
                })
    return findings


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------

def rel_of(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, os.path.abspath(root)).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="scan_leaks.py",
        description="Scan a skills repository for target identity that should not be published "
                    "(bundle ids, device serials, tokens, SDK keys, literal endpoints, user paths). "
                    "Exit 0 clean / 1 leaks_found / 2 error; prints RESULT=<token> last. "
                    "`--fail-on strong` (default) keeps the gate green when the only hits are "
                    "documentation-range addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Categories: package, device, token, appkey, endpoint, path\n"
               "Exemptions (tool names, library names, CVE ids, hardening products, public\n"
               "crackme names, <PKG>-style placeholders, loopback/emulator addresses) are built\n"
               "in and audited with --show-exempt.\n")
    default_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
    parser.add_argument("--root", default=default_root,
                        help="repository root to scan (default: the repo this script lives in)")
    parser.add_argument("--only", default="",
                        help="comma-separated categories to restrict to, e.g. pat,appkey")
    parser.add_argument("--exclude", action="append", default=[],
                        help="extra directory name to skip (repeatable)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--show-exempt", action="store_true",
                        help="also print findings that were suppressed by an exemption")
    parser.add_argument("--list-rules", action="store_true", help="print the rule table and exit")
    parser.add_argument("--max", type=int, default=0,
                        help="stop after N findings (0 = no limit)")
    parser.add_argument("--quiet", action="store_true", help="print only the RESULT token")
    parser.add_argument("--fail-on", choices=("strong", "any"), default="strong",
                        help="which findings make the exit code non-zero: `strong` (default) "
                             "fails only on strong/certain findings, `any` also fails on `weak` "
                             "ones such as an address from the RFC 5737 documentation range")
    parser.add_argument("--no-color", action="store_true", help="accepted for compatibility")
    parser.add_argument("--files-from", default="",
                        help="scan exactly the paths listed in this file (one per line, relative "
                             "to --root or absolute) instead of walking the tree -- the "
                             "maintenance gate passes the tracked-file list here, so a git-ignored "
                             "work area cannot produce findings")
    args = parser.parse_args(argv)

    rules = build_rules()

    if args.list_rules:
        print("== rules ==")
        for r in rules:
            print("  %-26s %-9s %-8s %s" % (r["id"], r["category"], r["strength"], r["description"]))
        print("RESULT=clean")
        return 0

    only = {c.strip() for c in args.only.split(",") if c.strip()}
    known = {r["category"] for r in rules}
    unknown = only - known
    if unknown:
        print("error: unknown category (or categories): %s" % ", ".join(sorted(unknown)),
              file=sys.stderr)
        print("RESULT=error")
        return 2

    root = os.path.abspath(args.root)
    if not os.path.isdir(root) and not os.path.isfile(root):
        print("error: root does not exist: %s" % root, file=sys.stderr)
        print("RESULT=error")
        return 2

    excludes = list(DEFAULT_EXCLUDES) + list(args.exclude)
    kept, exempted, errors = [], [], []
    files_scanned = 0

    from_list = None
    if args.files_from:
        # A list of exactly what a caller wants scanned (paths relative to --root, or absolute).
        # This is how the maintenance gate restricts the scan to the *committed* surface: a
        # git-ignored work area may legitimately hold real identifiers, and scanning it would turn
        # a leak gate into a false-positive generator.
        try:
            with open(args.files_from, "r", encoding="utf-8") as fh:
                from_list = [ln.strip().strip('"') for ln in fh
                             if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            print("error: cannot read --files-from %s: %s" % (args.files_from, exc),
                  file=sys.stderr)
            print("RESULT=error")
            return 2

    for path in iter_files(root, excludes, skip_self=True, from_list=from_list):
        text, err = read_text(path)
        if text is None:
            errors.append("%s: %s" % (rel_of(path, root), err))
            continue
        files_scanned += 1
        rel = rel_of(path, root)
        for f in scan_text(path, rel, text, rules, only):
            if f["exempted"]:
                exempted.append(f)
            else:
                kept.append(f)
            if args.max and len(kept) >= args.max:
                break
        if args.max and len(kept) >= args.max:
            break

    kept.sort(key=lambda f: (f["file"], f["line"], f["column"], f["rule"]))
    exempted.sort(key=lambda f: (f["file"], f["line"], f["column"], f["rule"]))

    # Collapse a rule firing more than once on the same value in the same line (labels such
    # as "device serial:" match a context rule and the shape rule at two offsets). Cross-rule
    # agreement on one line is kept: two independent rules naming the same value is stronger
    # evidence, not repetition.
    deduped, seen_keys = [], set()
    for f in kept:
        key = (f["file"], f["line"], f["rule"], f["match"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(f)
    kept = deduped

    result = "leaks_found" if kept else "clean"
    if kept and args.fail_on == "strong":
        # Weak findings are shapes a document may legitimately contain (an address from the
        # RFC 5737 documentation range in a usage example). They are still printed; they just
        # do not fail the gate. Strong/certain findings always do.
        result = "leaks_found_strong_only" if all(
            f["strength"] == "weak" for f in kept) else "leaks_found"

    if args.format == "json":
        print(json.dumps({
            "root": root,
            "files_scanned": files_scanned,
            "findings": kept,
            "exempted": exempted if args.show_exempt else [],
            "errors": errors,
            "result": result,
            "fail_on": args.fail_on,
        }, indent=2, ensure_ascii=False))
        print("RESULT=%s" % result)
        return (2 if errors else 0) if result in ("clean", "leaks_found_strong_only") else 1

    if not args.quiet:
        print("== leak scan: %d file(s) scanned under %s ==" % (files_scanned, root))
        if kept:
            counts = {}
            for f in kept:
                counts[f["category"]] = counts.get(f["category"], 0) + 1
            print("   findings by category: " + ", ".join(
                "%s=%d" % (k, counts[k]) for k in sorted(counts)))
        if errors:
            for e in errors:
                print("  READ-ERROR %s" % e)

        for f in kept:
            print("")
            print("  %s:%d:%d  [%s/%s]  %s"
                  % (f["file"], f["line"], f["column"], f["category"], f["strength"], f["rule"]))
            print("    match:   %s" % f["match"])
            print("    context: %s" % f["context"])

        if args.show_exempt and exempted:
            print("")
            print("== suppressed by exemption: %d ==" % len(exempted))
            for f in exempted:
                print("  %s:%d  [%s] %s -> %s"
                      % (f["file"], f["line"], f["rule"], f["match"], f["exempt_reason"]))

        print("")
        if kept:
            print("== result: %d finding(s) -- each one is a line to look at, not a verdict =="
                  % len(kept))
            if result == "leaks_found_strong_only":
                print("   all are `weak` (the documented address ranges); the gate is green under"
                      " the default --fail-on strong, and `--fail-on any` is the strict pass")
        else:
            print("== result: clean (nothing outside the exemption list) ==")
        if errors:
            print("== read errors: %d ==" % len(errors))

    print("RESULT=%s" % result)
    if errors and not kept:
        return 2
    if result in ("clean", "leaks_found_strong_only"):
        return 0
    return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass
    sys.exit(main())
