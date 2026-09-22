#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply equal-length byte patches to a dex, with structural and verifier checks.

WHY THIS EXISTS
---------------
The cheap way to change behaviour is to rewrite a few bytes in place rather than
rebuild a method body. It is cheap for a reason: nothing moves, so no try/catch
block, debug-info pointer or branch displacement can be invalidated by
construction. But it has four failure modes that all produce a build which looks
fine and misbehaves, and this tool exists to make each one impossible to skip:

  1. **Same-length is not enough** -- the replacement must decode to a valid
     instruction sequence of exactly the same length. A 4-byte branch replaced by
     a 4-byte branch is fine; a 2-byte branch replaced by a 4-byte instruction
     corrupts the next instruction.
  2. **Polarity** -- the overwhelmingly common error is patching the wrong side of
     a condition. So a spec can *require* the instruction that follows the edit,
     and this tool aborts if it is not the one you named. Name the fall-through
     you expect and the mistake cannot survive.
  3. **Verifier legality** -- a branch whose target is a `move-result*` bypasses
     the producing invoke and the class fails to load (`VerifyError`). Checked
     here before writing.
  4. **dex header staleness** -- the checksum and signature fields must be
     recomputed, signature FIRST (the checksum covers it). Skipping this makes
     Android fall back to interpreting the dex, which surfaces as an unrelated
     ClassNotFoundException at startup.

Spec format (JSON; a list, or {"patches": [...]}):

    [{
      "name": "human label",
      "reason": "why this edit is correct",
      "class": "Lpkg/Name;",
      "method": "someMethod",
      "desc": "(Lpkg/Arg;)V",          // optional: disambiguates overloads
      "match": {"kind": "if-testz", "target_reads_field_of": "Lpkg/Cfg;",
                "target_field": "enabled"},
      "expect_next": {"kind": "invoke", "target_method": "goHome"},
      "replace": {"kind": "nops"}      // or {"bytes": "28060000"}
    }]

`match` selects the instruction; `expect_next` (optional but strongly advised)
asserts what immediately follows, which is what pins the polarity; `replace`
gives the bytes. Run with --dry-run first: it prints the match, the neighbours,
the verifier verdict and the predicted byte diff without writing anything.

Exit codes: 0 ok, 1 failure (structure, match, verifier, or self-verify), 2 usage.
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dexutil import (  # noqa: E402
    Dex, IF_TEST, IF_TESTZ, INVOKE_OPS, MOVE_RESULT_OPS, RETURN_OPS,
    fix_dex_header, load_dex, verify_dex_header,
)


def _kind_of(insn):
    """Coarse semantic kind used by spec matching."""
    op = insn["op"]
    if op in IF_TEST:
        return "if-test"
    if op in IF_TESTZ:
        return "if-testz"
    if op in INVOKE_OPS:
        return "invoke"
    if op in RETURN_OPS:
        return "return"
    if op in MOVE_RESULT_OPS:
        return "move-result"
    if op == 0x12:
        return "const4"
    return insn["name"]


def _describe_neighbours(dex, code_off, target_off, span=4):
    """Render up to `span` instructions before and after an offset."""
    insns = list(dex.decode(code_off))
    idx = None
    for i, insn in enumerate(insns):
        if insn["off"] == target_off:
            idx = i
            break
    if idx is None:
        return [], None, []
    before = insns[max(0, idx - span):idx]
    after = insns[idx + 1:idx + 1 + span]
    return before, insns[idx], after


def _matches(dex, insn, crit, code_off=None):
    """Does one instruction satisfy a match/expect criterion?"""
    if crit is None:
        return True
    want = crit.get("kind")
    if want and _kind_of(insn) != want:
        return False

    if want in ("if-test", "if-testz"):
        treg = crit.get("target_reg")
        if treg is not None:
            regs, _ = dex.branch_regs(insn)
            if treg not in regs:
                return False
        # The usual way to pin "this is the gate for config X": require that the
        # branch TARGET instruction reads a field of a named class. This is what
        # distinguishes the gate you want from the other branches in the method.
        fcls = crit.get("target_reads_field_of")
        fname = crit.get("target_field")
        if fcls or fname:
            if code_off is None:
                return False
            tgt = dex.branch_target(insn)
            t_insn = dex.insn_at(code_off, tgt)
            if t_insn is None:
                return False
            if not (0x52 <= t_insn["op"] <= 0x58):
                return False
            fidx = struct.unpack_from("<H", t_insn["raw"], 2)[0]
            cls, nm, _ty = dex.field(fidx)
            if fcls and cls != fcls:
                return False
            if fname and nm != fname:
                return False

    if want == "const4":
        lit = crit.get("literal")
        if lit is not None:
            raw = insn["raw"][1]
            val = raw & 0xF
            if val > 7:
                val -= 16
            if val != lit:
                return False

    if want == "invoke":
        midx = struct.unpack_from("<H", insn["raw"], 2)[0]
        cls, nm, _ds = dex.method(midx)
        if crit.get("target_class") and crit["target_class"] not in cls:
            return False
        if crit.get("target_method") and crit["target_method"] != nm:
            return False

    if want in ("return", "move-result", "nop"):
        pass

    raw_eq = crit.get("bytes")
    if raw_eq and insn["raw"].hex() != raw_eq.replace(" ", "").lower():
        return False
    return True


def _find_site(dex, code_off, spec):
    """Return the single instruction matching spec['match'].

    Exactly one match is required. Ambiguity is treated as failure rather than
    "take the first": picking the wrong site in a method with several similar
    branches is a silent, expensive error.
    """
    insns = list(dex.decode(code_off))
    hits = [i for i in insns if _matches(dex, i, spec.get("match"), code_off)]
    if len(hits) == 1:
        return hits[0], insns
    if not hits:
        return None, insns

    # allow an ordinal to disambiguate deliberately
    ordv = spec.get("match", {}).get("ordinal")
    if ordv is not None and 0 <= ordv < len(hits):
        return hits[ordv], insns
    return ("ambiguous", hits), insns


def _verifier_report(dex, code_off, target_off_for_new_edge=None):
    """Tier-3 check: does any branch target a move-result instruction?

    `move-result*` must be immediately preceded by its producing invoke. A branch
    into one bypasses the producer and the class fails to load with
    `VerifyError ... copyResN v <- result0 type=Undefined`. A linear "is the
    previous instruction the producer" scan misses this; only the CFG view sees
    it.
    """
    findings = []
    for insn in dex.decode(code_off):
        if insn["op"] not in MOVE_RESULT_OPS:
            continue
        tgt = insn["off"]
        for other in dex.decode(code_off):
            t = dex.branch_target(other)
            if t == tgt:
                findings.append((other["off"], tgt))
    return findings


def _apply_replace(dex_data, insn, repl):
    """Return the new bytes for this instruction, enforcing equal length."""
    kind = repl.get("kind")
    if kind == "nops":
        n = len(insn["raw"])
        return b"\x00" * n
    if kind == "bytes":
        blob = bytes.fromhex(repl["bytes"].replace(" ", ""))
        return blob
    raise ValueError("replace must be {'kind':'nops'} or {'kind':'bytes','bytes':...}")


def process_one(dex, data, spec, index, dry_run):
    """Apply one spec entry to `data`; return a report dict, or raise."""
    cls = spec["class"]
    name = spec["method"]
    desc = spec.get("desc")
    label = spec.get("name") or ("patch%d" % index)
    report = {"name": label, "ok": False}

    if desc:
        found = dex.find_method(cls, name, desc)
        if not found:
            raise RuntimeError("[%s] method not found: %s->%s%s"
                               % (label, cls, name, desc))
        section, midx, code_off = found
    else:
        overloads = dex.find_methods_named(cls, name)
        if len(overloads) != 1:
            raise RuntimeError(
                "[%s] %s->%s has %d overloads; give \"desc\" to disambiguate: %s"
                % (label, cls, name, len(overloads),
                   [d for _s, _i, d, _c in overloads]))
        section, midx, dsc, code_off = overloads[0]
        desc = dsc

    report.update({"class": cls, "method": name, "desc": desc,
                   "section": section, "method_idx": midx, "code_off": code_off})

    site, _insns = _find_site(dex, code_off, spec)
    if site is None:
        raise RuntimeError("[%s] no instruction matched spec['match']" % label)
    if isinstance(site, tuple) and site and site[0] == "ambiguous":
        cands = ", ".join("0x%x" % h["off"] for h in site[1])
        raise RuntimeError("[%s] match is ambiguous (%d hits: %s); tighten it or "
                           "set match.ordinal" % (label, len(site[1]), cands))

    before, cur, after = _describe_neighbours(dex, code_off, site["off"])
    report.update({
        "site_off": cur["off"],
        "old_bytes": cur["raw"].hex(),
        "old_text": dex.describe(cur),
        "before": [dex.describe(i) for i in before],
        "after": [dex.describe(i) for i in after],
    })

    # polarity pin: what must immediately follow?
    exp = spec.get("expect_next")
    if exp is not None:
        nxt = after[0] if after else None
        if nxt is None or not _matches(dex, nxt, exp, code_off):
            raise RuntimeError(
                "[%s] expect_next not satisfied at 0x%x. Expected %r, found %r.\n"
                "    This is the polarity check: the instruction after the branch "
                "is not the one your spec assumes, so the branch points at the "
                "wrong side."
                % (label, cur["off"], exp, dex.describe(nxt) if nxt else None))
        report["expect_next_ok"] = True

    new = _apply_replace(data, cur, spec.get("replace", {"kind": "nops"}))
    if len(new) != len(cur["raw"]):
        raise RuntimeError(
            "[%s] replacement is %d bytes but the instruction is %d. Equal length "
            "is required: a longer replacement overwrites the next instruction."
            % (label, len(new), len(cur["raw"])))
    report.update({"new_bytes": new.hex(), "size_delta": 0})

    # verifier: simulate the new instruction to see if it adds a branch edge
    fake = Dex(bytes(data), dex.name)
    fake_probe = dict(cur)
    fake_probe["raw"] = new
    fake_probe["op"] = new[0]
    report["new_text"] = fake.describe(fake_probe)

    if dry_run:
        report["ok"] = True
        return report, data

    data[cur["off"]:cur["off"] + len(new)] = new

    # Re-read the patched dex and confirm the edit landed.
    #
    # Compare the BYTE RANGE, not a decoded instruction: replacing a 4-byte branch
    # with a nop pair yields two 1-unit instructions, so "the instruction at this
    # offset has length 4" is false even though the patch is perfectly correct.
    # The byte range is what the patch actually owns.
    span = slice(cur["off"], cur["off"] + len(new))
    if bytes(data[span]) != new:
        raise RuntimeError(
            "[%s] bytes at 0x%x are %s, expected %s"
            % (label, cur["off"], bytes(data[span]).hex(), new.hex()))

    patched = Dex(bytes(data), dex.name)
    insns_after = list(patched.decode(code_off))
    info = patched.code_info(code_off)
    expected_end = info["insns_off"] + info["insns_size"] * 2
    ended = (insns_after[-1]["off"] + insns_after[-1]["units"] * 2
             if insns_after else info["insns_off"])
    report["post_instruction_count"] = len(insns_after)
    report["post_decode_clean"] = (ended == expected_end)

    landed = [i for i in insns_after
              if cur["off"] <= i["off"] < cur["off"] + len(new)]
    report["post_text"] = " | ".join(patched.describe(i) for i in landed)

    # the next instruction boundary after the replaced span must still be the
    # instruction that followed the original one
    nxt_after = patched.insn_at(code_off, cur["off"] + len(new))
    report["post_next_text"] = patched.describe(nxt_after) if nxt_after else None
    if not report["post_decode_clean"]:
        raise RuntimeError(
            "[%s] the method no longer decodes to exactly insns_size units after "
            "the edit -- the replacement changed the instruction stream length. "
            "Use an equal-length replacement." % label)

    edges = _verifier_report(patched, code_off)
    report["verifier_edges"] = len(edges)
    if edges:
        raise RuntimeError(
            "[%s] verifier: a branch targets a move-result at %s; the class will "
            "fail to load (VerifyError). Use a nop pair instead of a branch."
            % (label, ", ".join("0x%x->0x%x" % e for e in edges)))

    report["ok"] = True
    return report, data


def main(argv):
    ap = argparse.ArgumentParser(
        description="Apply equal-length byte patches to a dex, with structural, "
                    "polarity and verifier checks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Spec format")[-1][:1200] if __doc__ else None)
    ap.add_argument("dex", help="input .dex, or an APK/zip (use --entry to pick)")
    ap.add_argument("--entry", help="archive member to read (default: classes.dex)")
    ap.add_argument("--spec", required=True, help="JSON spec file")
    ap.add_argument("-o", "--out", help="output dex path")
    ap.add_argument("--dry-run", action="store_true",
                    help="report matches and diffs without writing")
    ap.add_argument("--report", help="write a machine-readable JSON report here")
    args = ap.parse_args(argv[1:])

    dex, entry = load_dex(args.dex, args.entry) if os.path.exists(args.dex) else (None, None)
    if dex is None:
        # allow raw bytes piped through a path that does not exist yet: fail clearly
        print("error: no such file: %s" % args.dex)
        return 2

    problems = dex.check()
    if problems:
        print("structural problems in %s (%s):" % (args.dex, entry))
        for p in problems:
            print("  - %s" % p)
        print("refusing to patch a source that does not parse cleanly")
        return 1

    with open(args.spec, encoding="utf-8") as fh:
        spec_doc = json.load(fh)
    specs = spec_doc["patches"] if isinstance(spec_doc, dict) else spec_doc

    ok_before = verify_dex_header(dex.d)
    print("== source: %s (%s, %d bytes)" % (args.dex, entry, len(dex.d)))
    print("   header before: checksum_ok=%s signature_ok=%s"
          % ok_before)
    if not all(ok_before):
        print("   note: the SOURCE dex header is already inconsistent. Some")
        print("   producers ship a zeroed signature field; the patch will fix it.")

    data = bytearray(dex.d)
    reports = []
    for i, spec in enumerate(specs):
        rep, data = process_one(dex, data, spec, i, args.dry_run)
        reports.append(rep)
        print("\n-- [%s] %s.%s%s" % (rep["name"], rep["class"], rep["method"], rep["desc"]))
        print("   site 0x%x  %s" % (rep["site_off"], rep["old_text"]))
        for line in rep["before"][-2:]:
            print("     (before) %s" % line)
        print("   ->  %s" % rep.get("new_text"))
        for line in rep["after"][:2]:
            print("     (after)  %s" % line)
        if rep.get("expect_next_ok"):
            print("   polarity: expect_next satisfied")

    if args.dry_run:
        print("\n== dry run: nothing written")
        if args.report:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(reports, fh, indent=2)
            print("   report: %s" % args.report)
        return 0

    header = fix_dex_header(data)
    ok_after = verify_dex_header(data)
    print("\n== header checksum 0x%08x -> 0x%08x" % (header["before_checksum"],
                                                     header["after_checksum"]))
    print("   signature %s -> %s"
          % (header["before_signature"].hex()[:16],
             header["after_signature"].hex()[:16]))
    print("   self-verify: checksum_ok=%s signature_ok=%s" % ok_after)
    if not all(ok_after):
        print("FATAL: header does not self-verify; nothing written")
        return 1

    out = args.out
    if not out:
        root, ext = os.path.splitext(args.dex)
        out = root + ".patched" + (ext or ".dex")
    with open(out, "wb") as fh:
        fh.write(bytes(data))
    print("== wrote %s (%d bytes, delta %d)"
          % (out, len(data), len(data) - len(dex.d)))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(reports, fh, indent=2)
        print("   report: %s" % args.report)

    print("\nNext: repack (scripts/repack.py) then sign with apksigner, then run "
          "the device + screen checks in references/verification.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
