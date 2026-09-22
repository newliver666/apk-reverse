#!/usr/bin/env python3
"""Decode (and re-encode) an opaque single-value blob cached by an app.

Many apps cache server-issued configuration as ONE opaque string inside a
preferences file or a key-value store. The encoding is usually some stack of:
    outer:      base64, base64url, or hex
    transform:  a cyclic rotation of the byte stream (so the compressed stream
                does not begin at its header), sometimes preceded by a short
                header to skip
    inner:      raw deflate, zlib, or gzip

You do not have to guess the parameters. This script searches them and reports
every combination that decodes to something structured, then can re-encode your
edited payload with the same parameters so it can be written back.

Why rotation matters: a plain base64->inflate attempt fails on these blobs, and
the failure looks like "this value is encrypted". Exhaustively trying cyclic
shifts is cheap and frequently succeeds, which turns an opaque blob into an
editable JSON/XML document.

Usage:
  # decode the value of a key inside a prefs XML
  python blob_decode.py --prefs-xml prefs.xml --name flutter.remoteConfig

  # decode a blob stored in its own file (or piped on stdin)
  python blob_decode.py --file value.txt
  cat value.txt | python blob_decode.py

  # keep searching harder (slower) and write the best result out
  python blob_decode.py --file value.txt --max-skip 64 --out decoded.bin

  # re-encode an edited payload with the parameters that worked
  python blob_decode.py --encode --file decoded.bin --outer base64 --inner raw --cut 15435 --out value.txt

Notes:
  * Output is written to --out; nothing on device is touched.
  * The winning parameters are printed as a copy-pasteable line for --encode.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys
import time
import zlib

INNERS = [("raw", -15), ("zlib", 15), ("gzip", 31)]


# --------------------------------------------------------------------------- #
# outer encodings
# --------------------------------------------------------------------------- #
def outer_decode(text: str, which: str) -> bytes | None:
    t = text.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    try:
        if which == "base64":
            return base64.b64decode(t + "=" * (-len(t) % 4))
        if which == "base64url":
            return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
        if which == "hex":
            return binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", t))
    except Exception:
        return None
    return None


def outer_encode(data: bytes, which: str) -> str:
    if which == "base64":
        return base64.b64encode(data).decode("ascii")
    if which == "base64url":
        return base64.urlsafe_b64encode(data).decode("ascii")
    if which == "hex":
        return binascii.hexlify(data).decode("ascii")
    raise ValueError("unknown outer encoding: %s" % which)


def sniff_outer(text: str) -> list[str]:
    """Cheap guess first so the common case is instant."""
    t = text.strip()
    guesses = []
    if re.fullmatch(r"[0-9a-fA-F\s]+", t) and len(t) >= 16:
        guesses.append("hex")
    if re.fullmatch(r"[A-Za-z0-9+/\s=]+", t):
        guesses.append("base64")
    if re.fullmatch(r"[A-Za-z0-9\-_\s=]+", t):
        guesses.append("base64url")
    # always keep base64 last-resort, then everything else
    for w in ("base64", "base64url", "hex"):
        if w not in guesses:
            guesses.append(w)
    return list(dict.fromkeys(guesses))


# --------------------------------------------------------------------------- #
# inner transforms
# --------------------------------------------------------------------------- #
def try_inflate(body: bytes, max_out: int | None = None) -> tuple[str, bytes] | None:
    best = None
    for name, wbits in INNERS:
        try:
            if max_out is None:
                out = zlib.decompress(body, wbits)
            else:
                d = zlib.decompressobj(wbits)
                out = d.decompress(body, max_out)
            if out:
                if best is None or len(out) > len(best[1]):
                    best = (name, out)
        except Exception:
            continue
    return best


def inflate_raw(data: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def score(out: bytes) -> float:
    """How much does this look like a real document we can edit?"""
    if not out:
        return -1.0
    printable = sum(1 for b in out[:4096] if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / min(len(out), 4096)
    s = ratio * 10.0
    head = out[:64].lstrip()
    if head[:1] in (b"{", b"[", b"<", b"#"):
        s += 6.0
    if b'"' in out[:512] or b"=" in out[:512]:
        s += 2.0
    if len(out) < 32:
        s -= 3.0
    return s


# --------------------------------------------------------------------------- #
def search(blob: bytes, max_skip: int, log) -> list[dict]:
    hits: list[dict] = []
    n = len(blob)
    t0 = time.time()

    for skip in range(0, min(max_skip, n) + 1):
        base = blob[skip:]
        m = len(base)
        if m < 8:
            break
        for k in range(m):
            cand = base[k:] + base[:k]
            got = try_inflate(cand, max_out=8_000_000)
            if got:
                name, out = got
                hits.append({
                    "skip": skip, "cut": k, "inner": name, "size": len(out),
                    "score": round(score(out), 2), "data": out,
                })
        if hits and log and skip == 0:
            log("  first hit found with skip=0 after %.1fs" % (time.time() - t0))
        if log and skip and skip % 16 == 0 and time.time() - t0 > 30:
            log("  ... skip=%d, %.0fs elapsed" % (skip, time.time() - t0))
    log("  search finished in %.1fs (%d candidate(s))" % (time.time() - t0, len(hits)))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--file", help="file containing the encoded value")
    src.add_argument("--prefs-xml", help="a preferences XML file to pull the value out of")
    ap.add_argument("--name", help="key name when using --prefs-xml")
    ap.add_argument("--outer", choices=["base64", "base64url", "hex", "auto"], default="auto")
    ap.add_argument("--max-skip", type=int, default=0,
                    help="also try dropping 0..N leading bytes before the rotation search (slower)")
    ap.add_argument("--min-size", type=int, default=200, help="ignore results smaller than this")
    ap.add_argument("--top", type=int, default=5, help="how many candidates to print")
    ap.add_argument("--out", help="write the best decoded result here")

    ap.add_argument("--encode", action="store_true", help="re-encode instead of decoding")
    ap.add_argument("--inner", choices=[n for n, _ in INNERS], default="raw")
    ap.add_argument("--cut", type=int, default=0, help="rotation used for write-back")
    a = ap.parse_args()

    def log(msg: str) -> None:
        print(msg, file=sys.stderr)

    # ------------------------------------------------------------------ encode
    if a.encode:
        if not a.file:
            log("--encode requires --file (the payload to encode)")
            return 2
        payload = open(a.file, "rb").read()
        body = inflate_raw(payload) if a.inner == "raw" else zlib.compress(payload, 9)
        if a.inner == "zlib":
            body = zlib.compress(payload, 9)
        cut = a.cut % max(len(body), 1)
        rotated = body[-cut:] + body[:-cut] if cut else body
        enc = outer_encode(rotated, "base64" if a.outer == "auto" else a.outer)
        if a.out:
            open(a.out, "w", encoding="utf-8", newline="\n").write(enc)
            log("wrote %d chars to %s" % (len(enc), a.out))
        else:
            print(enc)
        log("write-back parameters: outer=%s inner=%s cut=%d"
            % ("base64" if a.outer == "auto" else a.outer, a.inner, cut))
        return 0

    # ------------------------------------------------------------------ input
    if a.prefs_xml:
        if not a.name:
            log("--prefs-xml requires --name <key>")
            return 2
        xml = open(a.prefs_xml, encoding="utf-8", errors="replace").read()
        m = re.search(r'name="%s"[^>]*>([^<]*)<' % re.escape(a.name), xml)
        if not m:
            log("key not found in XML: %s" % a.name)
            log("keys present: %s" % ", ".join(re.findall(r'name="([^"]+)"', xml)[:40]))
            return 2
        text = m.group(1)
        log("value length: %d" % len(text))
    elif a.file:
        text = open(a.file, encoding="utf-8", errors="replace").read()
    else:
        text = sys.stdin.read()

    if not text.strip():
        log("empty input")
        return 2

    # ------------------------------------------------------------------ decode
    candidates = [a.outer] if a.outer != "auto" else sniff_outer(text)
    for which in candidates:
        blob = outer_decode(text, which)
        if blob is None or len(blob) < 8:
            log("outer=%s -> not decodable, skipping" % which)
            continue
        log("outer=%s -> %d bytes; searching rotation (and skip<=%d)" % (which, len(blob), a.max_skip))
        hits = [h for h in search(blob, a.max_skip, log) if h["size"] >= a.min_size]
        if not hits:
            continue
        hits.sort(key=lambda h: (-h["score"], -h["size"]))
        print("=" * 66)
        print("outer=%s   candidates=%d" % (which, len(hits)))
        for h in hits[:a.top]:
            print("  score=%-6s skip=%-4d cut=%-7d inner=%-5s size=%d"
                  % (h["score"], h["skip"], h["cut"], h["inner"], h["size"]))
        best = hits[0]
        print("-" * 66)
        print("write-back line:")
        print("  python blob_decode.py --encode --file <edited_payload> --outer %s --inner %s --cut %d"
              % (which, best["inner"], best["cut"]))
        print("-" * 66)
        preview = best["data"][:1200]
        try:
            print(preview.decode("utf-8"))
        except UnicodeDecodeError:
            print(preview.decode("latin1"))
            print("(non-UTF-8; first 64 bytes: %s)" % best["data"][:64].hex())
        if a.out:
            open(a.out, "wb").write(best["data"])
            log("wrote %d bytes to %s" % (len(best["data"]), a.out))
        return 0

    print("no decodable candidate found.", file=sys.stderr)
    print("Next steps:", file=sys.stderr)
    print("  * raise --max-skip, or pass --outer explicitly", file=sys.stderr)
    print("  * the blob may be genuinely encrypted (a keyed cipher) rather than merely", file=sys.stderr)
    print("    encoded -- confirm before spending time on it: a keyed blob should look", file=sys.stderr)
    print("    random, whereas an encoded one still has structure once the framing is", file=sys.stderr)
    print("    removed. See references/runtime-data.md.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
