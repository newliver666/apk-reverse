#!/usr/bin/env python3
"""vmp_diff_harness.py -- differential-hardening (known-plaintext) harness for Dex-VMP work.

The idea this implements is the only black-box route to a private opcode table:
compile a fixture whose every instruction is labelled, get the *same* hardening
platform to harden it, align the returned dex against the original
instruction-by-instruction, and read the substitution off the alignment. The
original supplies the instruction boundaries that the hardened stream cannot
supply for itself -- that is the whole trick, and it is also its limit (see
`compare`'s shape verdict and references/vmp-differential-analysis.md).

Subcommands
  build       compile the labelled coverage fixture into a dex (and, with
              --apk, a minimal APK) and report which opcodes it actually covers
  audit       report opcode coverage of any dex
  compare     align an original dex against a hardened one; emit a candidate
              opcode map with per-entry confidence and a run-level verdict
  simulate    forge a "hardened" dex from a *known* private table -- the local
              fixture that proves compare() recovers a table it never saw
  emit-smali  render private-opcode method bodies back into a smali skeleton

What is measured and what is not: `build`, `audit`, `simulate` and the
`compare`/`emit-smali` code paths are exercised against locally produced
fixtures (see docs/tool-verification/EXTENSION-vmp-diff.md). No third-party
hardening platform was used: its output is what `simulate` stands in for. A
`compare` run against a real hardened dex is therefore an inference built on a
measured mechanism, not a measured result.

Dependencies: stdlib only, plus `dexutil.py` next to this file. External
toolchain (javac, d8, aapt2) is only needed by `build` and is passed explicitly.

Examples
  python vmp_diff_harness.py build --build-tools E:\\tools\\android-14 --out work/fixture
  python vmp_diff_harness.py simulate work/fixture/dex/classes.dex --out work/sim.dex --seed 7
  python vmp_diff_harness.py compare work/fixture/dex/classes.dex work/sim.dex
  python vmp_diff_harness.py emit-smali work/sim.dex --table work/map.json --class LOpCoverProbe;
"""
import argparse
import collections
import json
import os
import random
import shutil
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import dexutil
except ImportError:                                       # pragma: no cover
    dexutil = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# opcode reachability, measured (see EXTENSION-vmp-diff.md for the run)
#
# A javac+d8 fixture cannot reach every slot in the format table. The reasons
# are structural, not incidental, and they are what the coverage report is for:
# you cannot read a substitution for an opcode your fixture never emitted.
# ---------------------------------------------------------------------------
UNREACHABLE = {
    0x1B: "const-string/jumbo needs a string_ids index > 65535, i.e. a fixture "
          "carrying 65536+ string constants",
    0x2A: "goto/32 needs a >32767-code-unit backward jump; javac refuses the "
          "method first with 'code too large' (its own 64 KB per-method bytecode cap)",
    0xFE: "const-method-handle has no Java-language literal; reachable only by "
          "hand-written smali or direct dex construction",
    0xFF: "const-method-type has no Java-language literal (same as 0xFE)",
    0x09: "move-object/16 (32x) needs both registers >= 256; the object frame "
          "reaches 256 on the source side only, which d8 encodes as 0x08",
    0xFD: "invoke-custom/range: d8 emitted the 35c form for every lambda shape "
          "tried, including a six-parameter one",
}


# ---------------------------------------------------------------------------
# the fixture
# ---------------------------------------------------------------------------
_JAVA_PROBE = r'''
// OpCoverProbe -- opcode coverage fixture for differential-hardening analysis.
//
// Each method is a labelled probe for one dalvik opcode family. The point is not
// that the code does anything useful: it is that the compiled instruction stream
// contains a known, labelled instance of every opcode a Java compiler can emit,
// so that a hardened counterpart of this dex can be aligned instruction-by-
// instruction against it (known-plaintext attack).
public class OpCoverProbe {

    // ---------------------------------------------------------------- 1. const
    public static int constFamily(int seed) {
        int c4 = 7;                        // const/4
        int c16 = 1000;                    // const/16
        int c32 = 100000;                  // const
        int ch16 = 16777216;               // const/high16
        long w16 = 123L;                   // const-wide/16
        long w32 = 1234567L;               // const-wide/32
        long w = 1234567890123L;           // const-wide
        float fl = 1.5f;                   // const/high16 (float)
        double db = 3.14159;               // const-wide (double)
        String s = "opcover-probe";        // const-string
        Class<?> k = String.class;         // const-class
        int acc = c4 + c16 + c32 + ch16;
        acc += (int) w16 + (int) w32;
        acc += (int) w + (int) fl + (int) db;
        acc += s.length() + k.getName().length();
        return acc + seed;
    }

    // ----------------------------------------------------------- 2. int arith
    public static int arithInt(int x, int y) {
        int r = x + y;      // add-int
        r = r + 1000;       // add-int/lit16
        r = r + 7;          // add-int/lit8
        r = r - y;          // sub-int
        r = r - 1000;       // sub-int/lit16
        r = r * y;          // mul-int
        r = r / (y | 1);    // div-int
        r = r % (x | 3);    // rem-int
        r = r << 2;         // shl-int/lit8
        r = r >> 1;         // shr-int/lit8
        r = r >>> 1;        // ushr-int/lit8
        r = r & x;          // and-int
        r = r | y;          // or-int
        r = r ^ x;          // xor-int
        r = -r;             // neg-int
        r = 0 - r;          // rsub-int
        return r;
    }

    // ------------------------------------------------------ 3. lit8/lit16 forms
    public static int litForms(int x, int y) {
        int r = x;
        r = r * 255;        // mul-int/lit8
        r = r * 1000;       // mul-int/lit16
        r = r + 100000;     // const + add-int (beyond lit16)
        r = r / 3;          // div-int/lit8
        r = r % 5;          // rem-int/lit8
        r = r & 255;        // and-int/lit16
        r = r | 255;        // or-int/lit16
        r = r ^ 255;        // xor-int/lit16
        r = r << y;         // shl-int
        r = r >> y;         // shr-int
        r = r >>> y;        // ushr-int
        return r;
    }

    // -------------------------------------------------------------- 4. wide arith
    public static long arithWide(long a, long b) {
        long r = a * b;     // mul-long
        r = r + a;          // add-long
        r = r - b;          // sub-long
        r = r / (b | 1L);   // div-long
        r = r % (a | 3L);   // rem-long
        r = r & a;          // and-long
        r = r | b;          // or-long
        r = r ^ a;          // xor-long
        r = r << 2;         // shl-long
        r = r >> 1;         // shr-long
        r = r >>> 1;        // ushr-long
        r = -r;             // neg-long
        r = r + 1000L;      // add-long with const-wide
        return r;
    }

    // ----------------------------------------------------------- 5. conversions
    public static double conversions(int i, long l, float f, double d, short sh, byte by, char ch) {
        long a = (long) i;      // int-to-long
        float b = (float) i;    // int-to-float
        double c = (double) i;  // int-to-double
        int e = (int) l;        // long-to-int
        float g = (float) l;    // long-to-float
        double h = (double) l;  // long-to-double
        int j = (int) f;        // float-to-int
        long k = (long) f;      // float-to-long
        double m = (double) f;  // float-to-double
        int n = (int) d;        // double-to-int
        long o = (long) d;      // double-to-long
        float p = (float) d;    // double-to-float
        int q = sh;
        int s = by;
        int t = ch;
        byte u = (byte) i;      // int-to-byte
        char v = (char) i;      // int-to-char
        short w = (short) i;    // int-to-short
        return a + e + j + n + q + s + t + u + v + w + b + c + g + h + k + m + o + p;
    }

    // ------------------------------------------------------- 6. float/double arith
    public static float arithFloat(float a, float b) {
        float r = a + b;    // add-float
        r = r - b;          // sub-float
        r = r * a;          // mul-float
        r = r / b;          // div-float
        r = r % a;          // rem-float
        r = -r;             // neg-float
        return r + 1.5f;
    }

    public static double arithDouble(double a, double b) {
        double r = a + b;   // add-double
        r = r - b;          // sub-double
        r = r * a;          // mul-double
        r = r / b;          // div-double
        r = r % a;          // rem-double
        r = -r;             // neg-double
        return r + 2.5;
    }

    // ------------------------------------------------------------- 7. cmp family
    public static int cmps(long a, long b, float f, float g, double p, double q) {
        int r = 0;
        if (a < b) r += 1;      // cmp-long
        if (f > g) r += 2;      // cmpg-float
        if (f < g) r += 4;      // cmpl-float
        if (p > q) r += 8;      // cmpg-double
        if (p <= q) r += 16;    // cmpl-double
        return r;
    }

    // --------------------------------------------------------------- 8. branches
    public static int branches(int x, int y) {
        int r = 0;
        if (x == 0) r += 1;     // if-eqz
        if (x != 0) r += 2;     // if-nez
        if (x < 0) r += 3;      // if-ltz
        if (x >= 0) r += 4;     // if-gez
        if (x > 0) r += 5;      // if-gtz
        if (x <= 0) r += 6;     // if-lez
        if (x == y) r += 7;     // if-eq
        if (x != y) r += 8;     // if-ne
        if (x < y) r += 9;      // if-lt
        if (x >= y) r += 10;    // if-ge
        if (x > y) r += 11;     // if-gt
        if (x <= y) r += 12;    // if-le
        return r;
    }

    public static int objectBranches(Object a, Object b) {
        int r = 0;
        if (a == null) r += 1;  // if-eqz on an object register
        if (a != null) r += 2;
        if (a == b) r += 3;     // if-eq
        if (a != b) r += 4;     // if-ne
        return r;
    }

    // ---------------------------------------------------------------- 9. switches
    public static int switchPacked(int x) {
        switch (x) {                 // packed-switch + packed-switch-payload
            case 0: return 10;
            case 1: return 11;
            case 2: return 12;
            case 3: return 13;
            case 4: return 14;
            default: return 15;
        }
    }

    public static int switchSparse(int x) {
        switch (x) {                 // sparse-switch + sparse-switch-payload
            case -1000000: return 20;
            case 0: return 21;
            case 12345: return 22;
            case 999999999: return 23;
            default: return 24;
        }
    }

    // ------------------------------------------------------------------ 10. arrays
    public static int arrays(int n, byte by, char ch, short sh, boolean bo,
                             long l, float f, double d, Object o) {
        int[] ia = new int[n];          // new-array
        long[] la = new long[n];
        float[] fa = new float[n];
        double[] da = new double[n];
        byte[] ba = new byte[n];
        char[] ca = new char[n];
        short[] sa = new short[n];
        boolean[] za = new boolean[n];
        Object[] oa = new Object[n];
        ia[0] = 1;      // aput
        la[0] = l;      // aput-wide
        fa[0] = f;
        da[0] = d;
        ba[0] = by;     // aput-byte
        ca[0] = ch;     // aput-char
        sa[0] = sh;     // aput-short
        za[0] = bo;     // aput-boolean
        oa[0] = o;      // aput-object
        int r = ia[0];                          // aget
        r += (int) la[0];                       // aget-wide
        r += (int) fa[0];
        r += (int) da[0];
        r += ba[0];                             // aget-byte
        r += ca[0];                             // aget-char
        r += sa[0];                             // aget-short
        r += za[0] ? 1 : 0;                     // aget-boolean
        r += oa[0] == null ? 0 : 1;             // aget-object
        r += ia.length + la.length + ba.length + oa.length;   // array-length
        return r;
    }

    public static int fillArrayData() {
        int[] a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        long[] b = {11L, 22L, 33L};
        short[] c = {44, 55, 66};
        int s = 0;
        for (int v : a) s += v;
        for (long v : b) s += (int) v;
        for (short v : c) s += v;
        return s;
    }

    public static int filledNewArray() {
        int[] a = new int[]{7, 8, 9};
        return a[0] + a[1] + a[2];
    }

    // ------------------------------------------------------------------ 11. fields
    static int sInt;
    static long sLong;
    static float sFloat;
    static double sDouble;
    static Object sObj;
    static boolean sBool;
    static byte sByte;
    static char sChar;
    static short sShort;
    static String sStr;

    int iInt;
    long iLong;
    float iFloat;
    double iDouble;
    Object iObj;
    boolean iBool;
    byte iByte;
    char iChar;
    short iShort;
    String iStr;

    public static int staticFields(int a) {
        sInt = a;                       // sput
        sLong = a;                      // sput-wide
        sFloat = a;
        sDouble = a;
        sObj = null;                    // sput-object
        sStr = "static-field";
        sBool = true;
        sByte = (byte) a;
        sChar = (char) a;
        sShort = (short) a;
        int r = sInt;                   // sget
        r += (int) sLong;               // sget-wide
        r += (int) sFloat;
        r += (int) sDouble;
        r += sBool ? 1 : 0;
        r += sByte;
        r += sChar;
        r += sShort;
        r += sObj == null ? 0 : 1;      // sget-object
        r += sStr.length();
        return r;
    }

    public int instanceFields(int a) {
        iInt = a;                       // iput
        iLong = a;                      // iput-wide
        iFloat = a;
        iDouble = a;
        iObj = this;                    // iput-object
        iStr = "instance-field";
        iBool = false;
        iByte = (byte) a;
        iChar = (char) a;
        iShort = (short) a;
        int r = iInt;                   // iget
        r += (int) iLong;               // iget-wide
        r += (int) iFloat;
        r += (int) iDouble;
        r += iBool ? 1 : 0;
        r += iByte;
        r += iChar;
        r += iShort;
        r += iObj == null ? 0 : 1;      // iget-object
        r += iStr.length();
        return r;
    }

    // ----------------------------------------------------------------- 12. invokes
    public interface Iface {
        int call(int x);
    }

    public static class Base {
        public int baseCall(int x) { return x + 1; }
    }

    public static class Impl extends Base implements Iface {
        public int call(int x) { return x + 2; }            // invoke-virtual
        private int privateCall(int x) { return x + 4; }    // invoke-direct
        public static int staticCall(int x) { return x + 3; }   // invoke-static
        public int superCall(int x) { return super.baseCall(x); }   // invoke-super
        public int useAll(int x) {
            return call(x) + superCall(x) + staticCall(x) + privateCall(x);
        }
    }

    public static int helper(int x) { return x * 2; }

    public static Iface prov(int x) { return new Impl(); }

    public static int invokeVirtualAndStatic(int x) {
        Impl i = new Impl();
        return i.call(x) + Impl.staticCall(x) + helper(x);
    }

    public static int invokeInterface(Iface f, int x) {
        return f.call(x);               // invoke-interface
    }

    public static int invokeSuper(int x) {
        Impl i = new Impl();
        return i.superCall(x);          // invoke-super
    }

    public static int lambdaProbe(int x) {
        Iface f = (v) -> v + 100;                                        // invoke-custom
        java.util.function.IntUnaryOperator g = (v) -> v * 2;
        java.util.function.IntBinaryOperator h = OpCoverProbe::combine;   // method ref
        return f.call(x) + g.applyAsInt(x) + h.applyAsInt(x, 3);
    }

    public static int combine(int a, int b) { return a + b * 7; }

    // ---------------------------------------------------------------- 13. exceptions
    public static int exceptions(int x) {
        int r = 0;
        try {
            r = 100 / x;                            // div-int inside a try range
        } catch (ArithmeticException e) {           // move-exception
            r = -1;
        } finally {
            r = r + 1;
        }
        try {
            if (x == 0) throw new IllegalStateException("boom");   // throw
            r += 2;
        } catch (IllegalStateException e) {
            r += 3;
        }
        return r;
    }

    public static void rethrow() {
        throw new RuntimeException("always");       // throw on a new-instance
    }

    // ------------------------------------------------------------------ 14. monitor
    public static int monitor(Object lock) {
        synchronized (lock) {                       // monitor-enter / monitor-exit
            return 42;
        }
    }

    public static int monitorOnThis(Object lock, int x) {
        synchronized (OpCoverProbe.class) {
            x += 1;
        }
        synchronized (lock) {
            x += 2;
        }
        return x;
    }

    // ------------------------------------------------------------------- 15. types
    public static int typeOps(Object o, int x) {
        int r = 0;
        if (o instanceof String) r += 1;            // instance-of
        String s = (String) o;                      // check-cast
        r += s.length();
        Object n = new Object();                    // new-instance
        Impl i = new Impl();
        r += i.call(x);
        return r + (n == null ? 0 : 1);
    }

    // ------------------------------------------------------------------- 16. loops
    public static int loops(int n) {
        int s = 0;
        for (int i = 0; i < n; i++) s += i;          // goto + if-lt
        int j = 0;
        while (j < 10) { j++; }
        int k = 0;
        do { k++; } while (k < 5);
        for (int a = 0; a < 3; a++) {
            for (int b = 0; b < 3; b++) {
                for (int c = 0; c < 3; c++) {
                    s += a * b * c;
                }
            }
        }
        return s + j + k;
    }

    // ------------------------------------- 16b. non-2addr (tri-register) forms
    // javac emits the /2addr form whenever the destination is one of the
    // operands. Three distinct locals per operation are what forces the plain
    // three-register opcode to exist in the stream at all.
    public static int triInt(int a1, int a2, int a3, int a4, int a5, int a6, int a7,
                             int a8, int a9, int a10, int a11, int a12, int a13, int a14) {
        int t1 = a1 - a2;              // sub-int
        int t2 = a3 / (a4 | 1);        // div-int
        int t3 = a5 % (a6 | 1);        // rem-int
        int t4 = a7 & a8;              // and-int
        int t5 = a9 | a10;             // or-int
        int t6 = a11 ^ a12;            // xor-int
        int t7 = a13 << (a14 & 7);     // shl-int
        int t8 = a13 >> (a14 & 7);     // shr-int
        int t9 = a13 >>> (a14 & 7);    // ushr-int
        int t10 = ~t1;                 // not-int
        return t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9 + t10;
    }

    public static long triLong(long b1, long b2, long b3, long b4, long b5,
                               long b6, long b7, long b8, long b9, long b10) {
        long u1 = b1 + b2;             // add-long
        long u2 = b3 - b4;             // sub-long
        long u3 = b5 / (b6 | 1L);      // div-long
        long u4 = b7 % (b8 | 1L);      // rem-long
        long u5 = b9 & b10;            // and-long
        long u6 = b1 | b2;             // or-long
        long u7 = b3 ^ b4;             // xor-long
        long u8 = b5 << 2;             // shl-long
        long u9 = b5 >> 2;             // shr-long
        long u10 = b5 >>> 2;           // ushr-long
        long u11 = ~u1;                // not-long
        return u1 + u2 + u3 + u4 + u5 + u6 + u7 + u8 + u9 + u10 + u11;
    }

    public static float triFloat(float f1, float f2, float f3, float f4, float f5, float f6) {
        float g1 = f1 - f2;            // sub-float
        float g2 = f3 * f4;            // mul-float
        float g3 = f5 / f6;            // div-float
        float g4 = f1 % f2;            // rem-float
        return g1 + g2 + g3 + g4;
    }

    public static double triDouble(double d1, double d2, double d3, double d4, double d5, double d6) {
        double h1 = d1 - d2;           // sub-double
        double h2 = d3 * d4;           // mul-double
        double h3 = d5 / d6;           // div-double
        double h4 = d1 % d2;           // rem-double
        return h1 + h2 + h3 + h4;
    }

    // ------------------------------------------------ 16c. literal-width variants
    public static int litVariants(int x) {
        int r = x;
        r = r / 1000;      // div-int/lit16 (beyond lit8)
        r = r % 1000;      // rem-int/lit16
        r = r & 15;        // and-int/lit8
        r = r ^ 15;        // xor-int/lit8
        r = 1000 - r;      // rsub-int
        r = r + 1000;      // add-int/lit16
        return r;
    }

    // ------------------------------------------------- 16d. per-type field access
    // Read straight into a fresh local instead of accumulating: the accumulator
    // form is where d8 collapses a typed access into a narrower one.
    public int fieldVariants(int a, Object o, String s) {
        iBool = true;
        iByte = (byte) a;
        iChar = (char) a;
        iShort = (short) a;
        iObj = o;
        iStr = s;
        long l = iLong;          // iget-wide
        Object ob = iObj;        // iget-object
        boolean b = iBool;       // iget-boolean
        byte by = iByte;         // iget-byte
        char ch = iChar;         // iget-char
        short sh = iShort;       // iget-short
        return (b ? 1 : 0) + by + ch + sh + (int) l + (ob == null ? 0 : 1);
    }

    public static int staticFieldVariants(int a, Object o, String s) {
        sBool = true;
        sByte = (byte) a;
        sChar = (char) a;
        sShort = (short) a;
        sObj = o;
        sStr = s;
        sLong = a;
        long l = sLong;          // sget-wide
        Object ob = sObj;        // sget-object
        boolean b = sBool;       // sget-boolean
        byte by = sByte;         // sget-byte
        char ch = sChar;         // sget-char
        short sh = sShort;       // sget-short
        return (b ? 1 : 0) + by + ch + sh + (int) l + (ob == null ? 0 : 1);
    }

    // ------------------------------------------------------- 16e. /range invokes
    // The 35c invoke forms carry at most 5 argument registers. Seven (this plus
    // six ints) is what makes the /range encoding the only legal one.
    public interface Iface2 { int call6(int a, int b, int c, int d, int e, int f); }

    public static class Base6 {
        public int base6(int a, int b, int c, int d, int e, int f) { return a + b + c + d + e + f; }
    }

    public static class Impl6 extends Base6 implements Iface2 {
        public int call6(int a, int b, int c, int d, int e, int f) { return a * f; }
        private int priv6(int a, int b, int c, int d, int e, int f) { return a - f; }
        public int superRange(int a, int b, int c, int d, int e, int f) { return super.base6(a, b, c, d, e, f); }
        public int directRange(int a, int b, int c, int d, int e, int f) { return priv6(a, b, c, d, e, f); }
    }

    public static int rangeInvokes(int a, int b, int c, int d, int e, int f) {
        Impl6 i = new Impl6();
        int r = i.call6(a, b, c, d, e, f);      // invoke-virtual/range
        r += i.superRange(a, b, c, d, e, f);    // invoke-super/range
        r += i.directRange(a, b, c, d, e, f);   // invoke-direct/range
        Iface2 f2 = i;
        r += f2.call6(a, b, c, d, e, f);        // invoke-interface/range
        return r;
    }

    // ------------------------------------------------- 16f. polymorphic invoke
    public static int polyProbe(int x) {
        try {
            java.lang.invoke.MethodHandle mh = java.lang.invoke.MethodHandles.lookup()
                    .findStatic(OpCoverProbe.class, "combine",
                            java.lang.invoke.MethodType.methodType(int.class, int.class, int.class));
            return (int) mh.invokeExact(x, 3);   // invoke-polymorphic
        } catch (Throwable t) {
            return -1;
        }
    }

    // ------------------------------------- 16g. remaining reachable opcodes
    public static long mulLong2addr(long a, long b) {
        long r = a;
        r = r * b;      // mul-long/2addr (the only /2addr form javac skipped)
        return r;
    }

    public static long moveWide(int seed) {
        long a = seed;
        long b = a;
        long c = b;
        return a + b + c;
    }

    public static Object manyElements(Object o1, Object o2, Object o3, Object o4,
                                      Object o5, Object o6, Object o7) {
        Object[] a = {o1, o2, o3, o4, o5, o6, o7};   // filled-new-array/range
        return a;
    }

    public interface Iface6 { int call6(int a, int b, int c, int d, int e, int f); }

    public static int sum6(int a, int b, int c, int d, int e, int f) {
        return a + b + c + d + e + f;
    }

    public static int polyRangeProbe(int a, int b, int c, int d, int e, int f) {
        try {
            java.lang.invoke.MethodHandle mh = java.lang.invoke.MethodHandles.lookup()
                    .findStatic(OpCoverProbe.class, "sum6",
                            java.lang.invoke.MethodType.methodType(int.class, int.class, int.class,
                                    int.class, int.class, int.class, int.class));
            return (int) mh.invokeExact(a, b, c, d, e, f);   // invoke-polymorphic/range
        } catch (Throwable t) {
            return -1;
        }
    }

    public static int customRangeProbe(int a, int b, int c, int d, int e, int f) {
        Iface6 g = (p1, p2, p3, p4, p5, p6) -> p1 + p2 + p3 + p4 + p5 + p6;
        return g.call6(a, b, c, d, e, f);
    }

    // ---------------------------------------------- 17. many registers / move forms
    public static int manyRegs(int seed) {
        int r0 = seed + 0, r1 = seed + 1, r2 = seed + 2, r3 = seed + 3;
        int r4 = seed + 4, r5 = seed + 5, r6 = seed + 6, r7 = seed + 7;
        int r8 = seed + 8, r9 = seed + 9, r10 = seed + 10, r11 = seed + 11;
        int r12 = seed + 12, r13 = seed + 13, r14 = seed + 14, r15 = seed + 15;
        int r16 = seed + 16, r17 = seed + 17, r18 = seed + 18, r19 = seed + 19;
        int r20 = seed + 20, r21 = seed + 21, r22 = seed + 22, r23 = seed + 23;
        int r24 = seed + 24, r25 = seed + 25, r26 = seed + 26, r27 = seed + 27;
        int r28 = seed + 28, r29 = seed + 29, r30 = seed + 30, r31 = seed + 31;
        int s = 0;
        s += r0;  s += r1;  s += r2;  s += r3;  s += r4;  s += r5;  s += r6;  s += r7;
        s += r8;  s += r9;  s += r10; s += r11; s += r12; s += r13; s += r14; s += r15;
        s += r16; s += r17; s += r18; s += r19; s += r20; s += r21; s += r22; s += r23;
        s += r24; s += r25; s += r26; s += r27; s += r28; s += r29; s += r30; s += r31;
        return s;
    }

    // ------------------------------------------------------- 18. ternary / boolean
    public static int ternaryBoolean(boolean a, boolean b, int x) {
        int r = a ? x : -x;
        r += b ? 1 : 0;
        r += (a && b) ? 2 : 0;
        r += (a || b) ? 4 : 0;
        return r;
    }

    // ------------------------------------------------------------- 19. string ops
    public static int stringOps(String s, int x) {
        int r = s.length();                 // invoke-virtual
        r += s.charAt(0);
        r += s.indexOf('a');
        r += s.equals("abc") ? 1 : 0;
        r += s.hashCode();
        String t = s + x;                   // StringBuilder
        return r + t.length();
    }

    // an entry point that references everything, so nothing is dead-stripped
    public static int runAll(int seed) {
        int r = 0;
        r += constFamily(seed);
        r += arithInt(seed, seed + 1);
        r += litForms(seed, 3);
        r += (int) arithWide(seed, seed + 2);
        r += (int) conversions(seed, seed, seed, seed, (short) seed, (byte) seed, (char) seed);
        r += (int) arithFloat(seed, seed + 1);
        r += (int) arithDouble(seed, seed + 1);
        r += cmps(seed, seed + 1, seed, seed + 1, seed, seed + 1);
        r += branches(seed, seed + 1);
        r += objectBranches(null, null);
        r += switchPacked(seed % 5);
        r += switchSparse(seed);
        r += arrays(4, (byte) 1, 'a', (short) 2, true, 3L, 4f, 5.0, null);
        r += fillArrayData();
        r += filledNewArray();
        r += staticFields(seed);
        r += new OpCoverProbe().instanceFields(seed);
        r += invokeVirtualAndStatic(seed);
        r += invokeInterface(prov(seed), seed);
        r += invokeSuper(seed);
        r += lambdaProbe(seed);
        r += exceptions(seed);
        r += monitor(new Object());
        r += monitorOnThis(new Object(), seed);
        r += typeOps("hello", seed);
        r += loops(seed % 7);
        r += manyRegs(seed);
        r += ternaryBoolean(true, false, seed);
        r += stringOps("abcdef", seed);
        r += triInt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14);
        r += (int) triLong(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 10L);
        r += (int) triFloat(1f, 2f, 3f, 4f, 5f, 6f);
        r += (int) triDouble(1.0, 2.0, 3.0, 4.0, 5.0, 6.0);
        r += litVariants(seed);
        r += new OpCoverProbe().fieldVariants(seed, null, "fv");
        r += staticFieldVariants(seed, null, "sfv");
        r += rangeInvokes(1, 2, 3, 4, 5, 6);
        r += polyProbe(seed);
        r += (int) mulLong2addr(seed, seed + 1);
        r += (int) moveWide(seed);
        r += manyElements(null, null, null, null, null, null, null) == null ? 0 : 1;
        r += polyRangeProbe(1, 2, 3, 4, 5, 6);
        r += customRangeProbe(1, 2, 3, 4, 5, 6);
        return r;
    }

    public static void main(String[] args) {
        int seed = args.length > 0 ? args.length : 1;
        System.out.println(runAll(seed));
    }
}
'''


def gen_big_probe(n_int=300, n_long=140, n_obj=160, goto16_units=200):
    """Generate the part of the fixture a Java compiler can only reach with bulk.

    Three opcode classes exist only past a register-number or branch-distance
    threshold, so no amount of hand-written Java reaches them -- the source has
    to be long:

      move/16, move-wide/16, move-object/from16   register number >= 256
      goto/16                                     backward branch > 127 code units

    Measured thresholds for this generator (see EXTENSION-vmp-diff.md):
    n_int=300 -> move/16 seen 46x; n_long=140 -> move-wide/16 seen 20x;
    n_obj=160 -> move-object/from16 seen 161x; goto16_units=200 -> goto/16 seen 1x.
    """
    src = ["// generated by vmp_diff_harness.py build -- do not edit by hand",
           "public class OpCoverBig {", ""]

    src.append("    // %d locals: register number crosses 8 bits" % n_int)
    src.append("    public static int hugeFrame(int seed) {")
    for i in range(n_int):
        src.append("        int v%d = seed + %d;" % (i, i % 100))
    src.append("        int s = 0;")
    for i in range(n_int):
        src.append("        s += v%d;" % i)
    src.append("        return s;")
    src.append("    }")
    src.append("")

    src.append("    // wide values occupy two slots each, so fewer of them suffice")
    src.append("    public static long hugeWideFrame(long seed) {")
    for i in range(n_long):
        src.append("        long w%d = seed + %dL;" % (i, i % 50))
    src.append("        long s = 0L;")
    for i in range(n_long):
        src.append("        s += w%d;" % i)
    src.append("        return s;")
    src.append("    }")
    src.append("")

    src.append("    // object frame: move-object/from16")
    src.append("    public static int hugeObjectFrame(Object o) {")
    for i in range(n_obj):
        src.append("        Object a%d = o;" % i)
    src.append("        int s = 0;")
    for i in range(n_obj):
        src.append("        if (a%d == null) s += 1;" % i)
    src.append("        return s;")
    src.append("    }")
    src.append("")

    src.append("    // %d statements in the body: the backward branch no longer fits")
    src.append("    // in the 8-bit goto form and must use goto/16")
    src.append("    public static int gotoNear(int x) {")
    src.append("        int r = x;")
    src.append("        while (r > 0) {")
    for i in range(goto16_units):
        src.append("            r += %d;" % (i % 120 + 1))
    src.append("            r -= 1;")
    src.append("        }")
    src.append("        return r;")
    src.append("    }")
    src.append("")

    src.append("    public static int runAll(int seed) {")
    src.append("        int r = hugeFrame(seed);")
    src.append("        r += (int) hugeWideFrame(seed);")
    src.append("        r += hugeObjectFrame(null);")
    src.append("        r += gotoNear(seed % 5);")
    src.append("        return r;")
    src.append("    }")
    src.append("}")
    return "\n".join(src) + "\n"


MINIMAL_MANIFEST = '''<?xml version="1.0" encoding="utf-8"?>
<manifest package="probe.synthetic.vmpdiff">
    <application />
</manifest>
'''


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _require_dexutil():
    if dexutil is None:
        sys.stderr.write("error: dexutil.py is not importable; keep this script "
                         "next to the rest of skills/apk-reverse/scripts/\n")
        raise SystemExit(2)


def _which_in_dir(directory, stem):
    """Locate a build-tool binary under `directory`, tolerating .exe/.bat/.cmd."""
    for suffix in (".exe", ".bat", ".cmd", ""):
        candidate = os.path.join(directory, stem + suffix)
        if os.path.isfile(candidate):
            return candidate
    return None


def _methods(dex):
    """{(class, name, desc): code_off} for every method with a class_def."""
    out = {}
    for i in range(dex.header["class_defs_size"]):
        off = dex.header["class_defs_off"] + i * 32
        for _section, _idx, cls, name, desc, code_off in dex.methods_at(off):
            out[(cls, name, desc)] = code_off
    return out


def _count_opcodes(dex):
    """collections.Counter of decoded opcode byte -> number of instructions."""
    counts = collections.Counter()
    insns = 0
    desync = 0
    for _key, code_off in _methods(dex).items():
        if not code_off:
            continue
        listing, clean, _expected = dex.decode_all(code_off)
        if not clean:
            desync += 1
        for insn in listing:
            counts[insn["op"]] += 1
            insns += 1
    return counts, insns, desync


CLASS_FLAGS = [(0x1, "public"), (0x10, "final"), (0x200, "interface"),
               (0x400, "abstract"), (0x1000, "synthetic"), (0x2000, "annotation"),
               (0x4000, "enum")]
METHOD_FLAGS = [(0x1, "public"), (0x2, "private"), (0x4, "protected"),
                (0x8, "static"), (0x10, "final"), (0x20, "synchronized"),
                (0x40, "bridge"), (0x80, "varargs"), (0x100, "native"),
                (0x400, "abstract"), (0x1000, "synthetic"), (0x10000, "constructor")]


def _flags(value, table):
    return " ".join(name for bit, name in table if value & bit)


def _methods_with_acc(dex, class_def_off):
    """Like Dex.methods_at(), but also yields each method's access_flags.

    `dexutil.Dex.methods_at` reads `_acc` and drops it, which is fine for the
    callers it already has; a smali skeleton needs it, and changing that shared
    generator's tuple shape would break them.
    """
    p = dexutil.u32(dex.d, class_def_off + 24)
    if p == 0:
        return
    sf, p = dexutil.read_uleb(dex.d, p)
    inf, p = dexutil.read_uleb(dex.d, p)
    dm, p = dexutil.read_uleb(dex.d, p)
    vm, p = dexutil.read_uleb(dex.d, p)
    for _ in range(sf + inf):                        # skip field lists
        _i, p = dexutil.read_uleb(dex.d, p)
        _a, p = dexutil.read_uleb(dex.d, p)
    for section, count in (("direct", dm), ("virtual", vm)):
        running = 0
        for _ in range(count):
            diff, p = dexutil.read_uleb(dex.d, p)
            running += diff                          # indices are delta-encoded
            acc, p = dexutil.read_uleb(dex.d, p)
            code_off, p = dexutil.read_uleb(dex.d, p)
            cls, name, desc = dex.method(running)
            yield section, running, cls, name, desc, acc, code_off


def _class_matches(class_type, wanted):
    """Accept 'LOpCoverProbe;', 'LOpCoverProbe' and 'OpCoverProbe' alike.

    The first is how the dex spells it, the third is how a reader thinks of it,
    and a filter that accepts only one of the three silently matches nothing --
    which reads exactly like a class that is not in the file.
    """
    if not wanted:
        return True
    bare = class_type.strip("L;").replace("/", ".")
    return wanted in (class_type, class_type.rstrip(";"), class_type.strip("L;"), bare)


def _fmt_table(rows, columns):
    widths = [max(len(str(r[i])) for r in [columns] + rows) for i in range(len(columns))]
    out = ["  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(columns))]
    out.append("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        out.append("  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# build / audit
# ---------------------------------------------------------------------------

def cmd_audit(args):
    _require_dexutil()
    rc = 0
    for path in args.dex:
        dex, entry = dexutil.load_dex(path)
        problems = dex.check()
        counts, insns, desync = _count_opcodes(dex)
        known = set(dexutil.OP_NAMES)
        covered = sorted(set(counts) & known)
        missing = sorted(known - set(counts))
        print("== %s (entry %s, %d bytes) ==" % (path, entry, len(dex.d)))
        for p in problems:
            print("  [structure] %s" % p)
        print("  classes=%d methods_with_code=%d instructions=%d desynced=%d"
              % (dex.header["class_defs_size"],
                 sum(1 for v in _methods(dex).values() if v), insns, desync))
        print("  opcode coverage: %d/%d (%.1f%%)"
              % (len(covered), len(known), 100.0 * len(covered) / max(1, len(known))))
        if missing:
            print("  not emitted by this fixture (%d):" % len(missing))
            for op in missing:
                note = UNREACHABLE.get(op)
                print("    0x%02x %-24s %s"
                      % (op, dexutil.OP_NAMES[op], note or "(no recorded reason)"))
        if args.json:
            payload = {
                "dex": path,
                "classes": dex.header["class_defs_size"],
                "instructions": insns,
                "desynced_methods": desync,
                "structural_problems": problems,
                "covered": len(covered),
                "total_known": len(known),
                "missing": [{"op": "0x%02x" % op, "name": dexutil.OP_NAMES[op],
                             "reason": UNREACHABLE.get(op)} for op in missing],
                "counts": {"0x%02x" % op: n for op, n in sorted(counts.items())},
            }
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
            print("  wrote %s" % args.json)
        if problems or desync:
            rc = 1
    return rc


def cmd_build(args):
    _require_dexutil()
    out = args.out
    src_dir = os.path.join(out, "src")
    cls_dir = os.path.join(out, "classes")
    dex_dir = os.path.join(out, "dex")
    for d in (src_dir, cls_dir, dex_dir):
        os.makedirs(d, exist_ok=True)

    # --- toolchain -------------------------------------------------------
    javac = args.javac or shutil.which("javac")
    if not javac:
        sys.stderr.write("error: javac not found; pass --javac (the JDK's bin/"
                         "javac, not the Oracle javapath forwarder)\n")
        return 2
    if not args.build_tools:
        sys.stderr.write("error: --build-tools is required (the directory holding "
                         "d8 and aapt2); this script does not guess at a path\n")
        return 2
    d8 = _which_in_dir(args.build_tools, "d8")
    aapt2 = _which_in_dir(args.build_tools, "aapt2")
    if not d8:
        sys.stderr.write("error: d8/d8.bat not found in %s\n" % args.build_tools)
        return 2
    if args.apk and not aapt2:
        sys.stderr.write("error: aapt2 not found in %s (needed for --apk)\n"
                         % args.build_tools)
        return 2
    print("javac:      %s" % javac)
    print("d8:         %s" % d8)
    if args.apk:
        print("aapt2:      %s" % aapt2)

    # --- source ----------------------------------------------------------
    probe_java = os.path.join(src_dir, "OpCoverProbe.java")
    with open(probe_java, "w", encoding="utf-8") as fh:
        fh.write(_JAVA_PROBE.strip() + "\n")
    sources = [probe_java]
    if args.with_big:
        big_java = os.path.join(src_dir, "OpCoverBig.java")
        with open(big_java, "w", encoding="utf-8") as fh:
            fh.write(gen_big_probe(args.n_int, args.n_long, args.n_obj, args.goto16))
        sources.append(big_java)
        print("generated:  %s (%d B)" % (big_java, os.path.getsize(big_java)))

    # --- javac -----------------------------------------------------------
    cmd = [javac, "-g", "--release", "11", "-d", cls_dir] + sources
    print("\n$ %s" % " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout.strip():
        print(proc.stdout.strip())
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.strip() + "\n")
        sys.stderr.write("error: javac failed (rc=%d)\n" % proc.returncode)
        return 1

    classes = []
    for root, _dirs, files in os.walk(cls_dir):
        classes += [os.path.join(root, f) for f in sorted(files) if f.endswith(".class")]
    if not classes:
        sys.stderr.write("error: javac produced no .class files\n")
        return 1
    print("javac ok:   %d class files" % len(classes))

    # --- d8 (the output directory must already exist) ---------------------
    cmd = [d8, "--min-api", str(args.min_api)]
    if not args.desugar:
        cmd.append("--no-desugaring")
    cmd += ["--output", dex_dir] + classes
    print("\n$ %s" % " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout.strip():
        print(proc.stdout.strip())
    if proc.returncode != 0:
        sys.stderr.write((proc.stderr or "").strip()[:2000] + "\n")
        sys.stderr.write("error: d8 failed (rc=%d)\n" % proc.returncode)
        return 1
    dex_path = os.path.join(dex_dir, "classes.dex")
    if not os.path.isfile(dex_path):
        sys.stderr.write("error: d8 reported success but %s does not exist\n" % dex_path)
        return 1
    print("d8 ok:      %s (%d B)" % (dex_path, os.path.getsize(dex_path)))

    audit_args = argparse.Namespace(dex=[dex_path], json=os.path.join(out, "audit.json"))
    audit_rc = cmd_audit(audit_args)

    # --- optional APK ----------------------------------------------------
    apk_rc = 0
    if args.apk:
        apk_dir = os.path.join(out, "apk")
        os.makedirs(apk_dir, exist_ok=True)
        manifest = os.path.join(apk_dir, "AndroidManifest.xml")
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write(MINIMAL_MANIFEST)
        base = os.path.join(apk_dir, "base.apk")
        # No -I android.jar: the manifest deliberately uses no android: attribute,
        # because aapt2 refuses to link resource references it has no framework
        # package to resolve (measured: "attribute android:versionCode not found").
        cmd = [aapt2, "link", "--manifest", manifest, "-o", base]
        print("\n$ %s" % " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.stdout.strip():
            print(proc.stdout.strip())
        if proc.returncode != 0:
            sys.stderr.write((proc.stderr or "").strip()[:2000] + "\n")
            sys.stderr.write("error: aapt2 link failed (rc=%d)\n" % proc.returncode)
            apk_rc = 1
        else:
            apk_path = os.path.join(out, "probe.apk")
            with zipfile.ZipFile(base) as zin, \
                    zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.namelist():
                    zout.writestr(item, zin.read(item))
                zout.write(dex_path, "classes.dex")
            print("aapt2 ok:   %s (%d B, unsigned)" % (apk_path, os.path.getsize(apk_path)))
            print("            unsigned by design: add your own signing step before "
                  "handing this to a hardening platform that demands it")
    return max(audit_rc, apk_rc)


# ---------------------------------------------------------------------------
# simulate -- the local stand-in for a hardening platform
# ---------------------------------------------------------------------------

def _private_permutation(seed):
    """A deterministic bijection over 0..255 standing in for a private opcode space.

    Real engines do not merely relabel bytes -- they re-encode the stream and
    carry their own length table. `simulate` deliberately does the *weakest*
    version of the attack (relabel only, lengths preserved) because that is the
    only version this harness can check itself against; see the reference file
    for why the stronger version is where the method earns its limits.
    """
    rng = random.Random(seed)
    targets = [b for b in range(256) if b != 0x00]
    shuffled = targets[:]
    rng.shuffle(shuffled)
    table = {0x00: 0x00}
    for src, dst in zip(targets, shuffled):
        table[src] = dst
    return table


def cmd_simulate(args):
    _require_dexutil()
    with open(args.dex, "rb") as fh:
        data = bytearray(fh.read())
    dex = dexutil.Dex(bytes(data))
    problems = dex.check()
    if problems:
        for p in problems:
            sys.stderr.write("error: refusing to simulate on a broken read: %s\n" % p)
        return 1

    table = _private_permutation(args.seed)
    out = bytearray(data)
    rewritten = 0
    if args.mode == "relabel":
        for _key, code_off in _methods(dex).items():
            if not code_off:
                continue
            # Boundaries come from the dex we are rewriting, which is still in the
            # clear at this point -- that is exactly the advantage simulate gives
            # compare, and exactly what is missing against a real hardened sample.
            for insn in dex.decode(code_off):
                out[insn["off"]] = table[insn["op"]]
                rewritten += 1
    elif args.mode == "stub":
        # The extraction shape: every body is replaced by a filler stub of the
        # same length. Instruction counts still line up, so compare will align
        # happily -- and every original opcode will claim the same private byte,
        # which is the signal that this is not a relabelling at all.
        for _key, code_off in _methods(dex).items():
            if not code_off:
                continue
            info = dex.code_info(code_off)
            pos, end = info["insns_off"], info["insns_off"] + info["insns_size"] * 2
            while pos + 2 <= end:
                out[pos], out[pos + 1] = 0x0E, 0x00          # return-void
                pos += 2
            rewritten += 1
    elif args.mode == "shrink":
        # The length-changing shape. This builds a deliberately structurally
        # inconsistent image -- insns_size is rewritten without moving the bytes
        # -- purely to drive compare's `resized` branch on demand. It is a probe
        # for the detector, not something you could load.
        for _key, code_off in _methods(dex).items():
            if not code_off:
                continue
            info = dex.code_info(code_off)
            new_size = max(1, info["insns_size"] // 2)
            out[code_off + 12:code_off + 16] = new_size.to_bytes(4, "little")
            rewritten += 1
    if not args.keep_header:
        dexutil.fix_dex_header(out)
    with open(args.out, "wb") as fh:
        fh.write(bytes(out))
    print("simulated:   %s -> %s" % (args.dex, args.out))
    print("             mode=%s, %d method body(ies)/instruction(s) touched (seed %d)"
          % (args.mode, rewritten, args.seed))
    if args.mode == "shrink":
        print("             NOTE: mode=shrink writes a structurally inconsistent dex "
              "on purpose; it exists to exercise compare's resized detector")
    if not args.keep_header:
        ck, sg = dexutil.verify_dex_header(out)
        print("             header recomputed: checksum_ok=%s signature_ok=%s" % (ck, sg))
    if args.table and args.mode == "relabel":
        with open(args.table, "w", encoding="utf-8") as fh:
            json.dump({"seed": args.seed,
                       "note": "ground-truth private table (orig opcode -> private byte)",
                       "map": {"0x%02x" % k: "0x%02x" % v for k, v in sorted(table.items())}},
                      fh, indent=2, sort_keys=True)
        print("             ground-truth table written to %s (compare must re-derive it)"
              % args.table)
    return 0


# ---------------------------------------------------------------------------
# compare -- the differential itself
# ---------------------------------------------------------------------------

def cmd_compare(args):
    _require_dexutil()
    orig, orig_entry = dexutil.load_dex(args.original)
    hard, hard_entry = dexutil.load_dex(args.hardened)
    for label, dex in (("original", orig), ("hardened", hard)):
        problems = dex.check()
        if problems:
            for p in problems:
                sys.stderr.write("error: %s (%s) does not parse: %s\n"
                                 % (label, dex.name, p))
            return 1

    om = _methods(orig)
    hm = _methods(hard)

    shape = collections.Counter()
    pairs = collections.defaultdict(collections.Counter)
    per_method = []
    total_slots = 0

    for key in sorted(set(om) | set(hm)):
        cls, name, desc = key
        label = "%s->%s%s" % (cls, name, desc)
        if key not in hm:
            shape["missing"] += 1
            per_method.append((label, "missing", 0, 0))
            continue
        if key not in om:
            shape["added"] += 1
            per_method.append((label, "added", 0, 0))
            continue
        o_off, h_off = om[key], hm[key]
        if not o_off:
            shape["no-original-body"] += 1
            continue
        if not h_off:
            # The body left the dex entirely: native sink, or extracted to an
            # interpreter. There is no byte stream to align against.
            shape["stripped"] += 1
            per_method.append((label, "stripped", 0, 0))
            continue
        o_info = orig.code_info(o_off)
        h_info = hard.code_info(h_off)
        o_size = o_info["insns_size"]
        h_size = h_info["insns_size"]
        if o_size != h_size:
            shape["resized"] += 1
            per_method.append((label, "resized", o_size, h_size))
            continue
        shape["aligned"] += 1
        shifted = 0
        for insn in orig.decode(o_off):
            pos = h_info["insns_off"] + (insn["off"] - o_info["insns_off"])
            byte = hard.d[pos]
            pairs[insn["op"]][byte] += 1
            total_slots += 1
            shifted += 1
        per_method.append((label, "aligned", o_size, shifted))

    # --- aggregate into a table -----------------------------------------
    rows = []
    undetermined = []
    conflicts = 0
    for op in sorted(pairs):
        cands = pairs[op]
        ranked = sorted(cands.items(), key=lambda kv: (-kv[1], kv[0]))
        samples = sum(cands.values())
        if len(ranked) == 1:
            verdict = "high"
        else:
            verdict = "conflict"
            conflicts += 1
        rows.append({
            "orig": op,
            "orig_hex": "0x%02x" % op,
            "name": dexutil.OP_NAMES.get(op, "op_%02x" % op),
            "samples": samples,
            "candidates": ["0x%02x" % b for b, _n in ranked],
            "candidate_counts": {"0x%02x" % b: n for b, n in ranked},
            "verdict": verdict,
        })
    seen = set(pairs)
    for op in sorted(set(dexutil.OP_NAMES) - seen):
        undetermined.append({
            "orig": op, "orig_hex": "0x%02x" % op,
            "name": dexutil.OP_NAMES[op],
            "reason": UNREACHABLE.get(op) or
                      "the original never emits this opcode, so there is no "
                      "known-plaintext instance to read a substitution from",
        })

    # reverse direction: a private byte claimed by two different originals
    reverse = collections.defaultdict(set)
    for op, cands in pairs.items():
        if len(cands) == 1:
            reverse[next(iter(cands))].add(op)
    non_injective = {("0x%02x" % b): sorted("0x%02x" % o for o in ops)
                     for b, ops in reverse.items() if len(ops) > 1}

    # --- run-level verdict ----------------------------------------------
    comparable = shape["aligned"]
    decided = len(rows)
    notes = []
    if comparable == 0:
        verdict = "not-applicable"
        if shape["stripped"]:
            notes.append(
                "%d method(s) lost their code_item: the hardened build moved the "
                "bodies out of the dex. There is no byte stream to align, so "
                "opcode differencing cannot start -- this is the extraction/VMP "
                "shape, and the differential route stops here." % shape["stripped"])
        if shape["resized"]:
            notes.append(
                "%d method(s) kept a body but changed its length. Boundaries "
                "cannot be projected across a length change; a private opcode "
                "stream with its own length table is not reachable this way."
                % shape["resized"])
        if not notes:
            notes.append("no method pair was comparable; inspect --json per-method rows")
    elif decided == 0:
        verdict = "not-applicable"
        notes.append("bodies align by length but no opcode pair was accumulated")
    else:
        conflict_ratio = conflicts / float(decided)
        worst_share = max((len(v) for v in non_injective.values()), default=0)
        if worst_share >= 3:
            # The stub shape. Every original opcode maps to the *same* private
            # byte, so `conflicts` is zero and the per-opcode reading looks
            # perfect -- the only thing that gives it away is the reverse
            # direction. This is why the map is checked for injectivity at all.
            verdict = "not-usable"
            notes.append(
                "%d private byte(s) are claimed by up to %d original opcodes each. "
                "No injective relabelling can do that: it is the signature of method "
                "bodies replaced by one common stub, and any substitution read off "
                "such a pair describes the stub, not a private opcode space."
                % (len(non_injective), worst_share))
        elif conflict_ratio > 0.30:
            verdict = "not-usable"
            notes.append("%d of %d opcode(s) saw more than one candidate byte; a "
                         "stable map cannot be read off this pair"
                         % (conflicts, decided))
        elif conflict_ratio > 0.05 or non_injective:
            verdict = "partially-usable"
            if conflicts:
                notes.append("%d of %d opcode(s) saw more than one candidate byte; the "
                             "substitution is not a pure opcode relabelling (or the "
                             "alignment slipped) -- treat those rows as unknown"
                             % (conflicts, decided))
            if non_injective:
                notes.append("%d private byte(s) are claimed by more than one original "
                             "opcode (%d-way at worst), which no injective relabelling "
                             "can produce" % (len(non_injective), worst_share))
        else:
            verdict = "usable"

    # --- report ----------------------------------------------------------
    print("== differential hardening: %s (%s) vs %s (%s) =="
          % (args.original, orig_entry, args.hardened, hard_entry))
    print("   aligned=%d resized=%d stripped=%d missing=%d added=%d"
          % (shape["aligned"], shape["resized"], shape["stripped"],
             shape["missing"], shape["added"]))
    print("   aligned slots compared: %d" % total_slots)
    print("   verdict: %s" % verdict.upper())
    for n in notes:
        print("     ! %s" % n)
    if not args.quiet:
        print("\n-- candidate opcode map (original -> private byte) --")
        table_rows = []
        for r in rows:
            table_rows.append((r["orig_hex"], r["name"], r["samples"],
                               ",".join(r["candidates"]), r["verdict"]))
        if table_rows:
            print(_fmt_table(table_rows, ["orig", "name", "samples", "candidate(s)", "verdict"]))
        else:
            print("  (none: no aligned instruction pairs)")
        if undetermined:
            print("\n-- undetermined opcodes (%d) --" % len(undetermined))
            for u in undetermined:
                print("   %s %-24s %s" % (u["orig_hex"], u["name"], u["reason"]))
        if non_injective:
            print("\n-- non-injective private bytes --")
            for b, ops in sorted(non_injective.items()):
                print("   %s <- %s" % (b, ",".join(ops)))
        if args.verbose:
            print("\n-- per-method --")
            rows2 = [(m[0], m[1], m[2], m[3]) for m in per_method]
            print(_fmt_table(rows2, ["method", "state", "orig_size", "compared"]))

    if args.json:
        payload = {
            "original": args.original,
            "hardened": args.hardened,
            "verdict": verdict,
            "shape": dict(shape),
            "aligned_slots": total_slots,
            "map": rows,
            "undetermined": undetermined,
            "non_injective": non_injective,
            "notes": notes,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        print("\nwrote %s" % args.json)
    return 0 if verdict in ("usable", "partially-usable") else 1


# ---------------------------------------------------------------------------
# emit-smali
# ---------------------------------------------------------------------------

def _load_table(path):
    """Build private-byte -> standard-opcode from a compare/simulate JSON table.

    Two shapes are accepted, because the two producers differ: `simulate` writes
    its ground truth as {"map": {"0x90": "0xe1"}} (original -> private), while
    `compare` writes a list of rows carrying candidates and a verdict. Only
    rows whose verdict is `high` are usable -- a conflict row would have to pick
    a winner, and guessing here is how a wrong table gets laundered into a
    confident-looking disassembly.
    """
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    priv2std = {}
    skipped = []
    raw_map = doc.get("map")
    if isinstance(raw_map, dict):
        for orig_hex, priv_hex in raw_map.items():
            priv2std[int(priv_hex, 0)] = int(orig_hex, 0)
        return priv2std, skipped, doc
    for row in raw_map or []:
        orig = row.get("orig")
        cands = row.get("candidates", [])
        verdict = row.get("verdict")
        if orig is None or not cands:
            continue
        if verdict != "high" or len(cands) != 1:
            skipped.append((orig, verdict, cands))
            continue
        priv2std[int(cands[0], 0)] = int(orig)
    return priv2std, skipped, doc


def _restore(data, priv2std):
    """Rewrite private opcode bytes to their standard values, in place.

    Boundaries come from the table itself: once a byte is mapped back to a
    standard opcode, the standard length table applies to that instruction and
    the walk can step to the next one. An unmapped byte ends the walk for that
    method -- and the count of such events is the honest measure of how much of
    the body the table actually covers.
    """
    dex = dexutil.Dex(bytes(data))
    out = bytearray(data)
    unknown = collections.Counter()
    resolved = 0
    for _key, code_off in _methods(dex).items():
        if not code_off:
            continue
        info = dex.code_info(code_off)
        pos = info["insns_off"]
        end = pos + info["insns_size"] * 2
        while pos < end:
            byte = data[pos]
            std = priv2std.get(byte)
            if std is None:
                if byte == 0x00:
                    # a genuine nop or a payload header: the payload's own layout
                    # is data, not opcodes, so its leading byte stays as it is
                    std = 0x00
                else:
                    unknown[byte] += 1
                    break
            out[pos] = std
            resolved += 1
            units = dexutil.insn_units(std, data, pos, end)
            if units < 1 or pos + units * 2 > end:
                break
            pos += units * 2
    return out, unknown, resolved


def cmd_emit_smali(args):
    _require_dexutil()
    with open(args.dex, "rb") as fh:
        data = bytearray(fh.read())
    priv2std, skipped, _doc = _load_table(args.table)
    restored, unknown, resolved = _restore(data, priv2std)
    if not args.keep_header:
        dexutil.fix_dex_header(restored)
    dex = dexutil.Dex(bytes(restored))
    problems = dex.check()

    lines = []
    lines.append("; smali skeleton -- generated by vmp_diff_harness.py emit-smali")
    lines.append("; source dex : %s" % args.dex)
    lines.append("; table      : %s (%d private bytes mapped, %d entries skipped as "
                 "non-high-confidence)" % (args.table, len(priv2std), len(skipped)))
    lines.append("; instructions restored: %d ; unmapped-opcode stops: %d"
                 % (resolved, sum(unknown.values())))
    lines.append(";")
    lines.append("; THIS IS A READING SKELETON, NOT ASSEMBLABLE SMALI.")
    lines.append("; Instruction boundaries and opcode names are restored from the")
    lines.append("; differential table; the operands below are rendered by the standard")
    lines.append("; dex format. Register numbers, field/method/string indices and any")
    lines.append("; register re-allocation the engine performed are NOT recovered --")
    lines.append("; no map for those exists in this method.")
    if unknown:
        lines.append("; UNMAPPED private bytes encountered (%d kind(s)):"
                     % len(unknown))
        for byte, n in sorted(unknown.items()):
            lines.append(";   0x%02x x%d -- body truncated at the first occurrence" % (byte, n))
    lines.append("")
    for p in problems:
        lines.append("; [structure] %s" % p)
    if problems:
        lines.append("")

    classes = 0
    methods_out = 0
    for i in range(dex.header["class_defs_size"]):
        off = dex.header["class_defs_off"] + i * 32
        class_type = dex.type_(dexutil.u32(dex.d, off))
        if not _class_matches(class_type, args.cls):
            continue
        classes += 1
        super_idx = dexutil.u32(dex.d, off + 8)
        access = dexutil.u32(dex.d, off + 4)
        lines.append("# access_flags=0x%x" % access)
        lines.append(".class %s%s" % (_flags(access, CLASS_FLAGS) + " "
                                      if _flags(access, CLASS_FLAGS) else "", class_type))
        if super_idx:
            lines.append(".super %s" % dex.type_(super_idx))
        source_idx = dexutil.u32(dex.d, off + 16)
        if source_idx:
            lines.append('.source "%s"' % dex.string_safe(source_idx))
        lines.append("")
        for _section, _idx, _cls, name, desc, acc, code_off in _methods_with_acc(dex, off):
            if args.method and name != args.method:
                continue
            mflags = _flags(acc, METHOD_FLAGS)
            head = ".method %s%s%s" % (mflags + " " if mflags else "", name, desc)
            if not code_off:
                lines.append(head)
                lines.append("    # no code_item (abstract or native)")
                lines.append(".end method")
                lines.append("")
                methods_out += 1
                continue
            info = dex.code_info(code_off)
            listing, clean, expected = dex.decode_all(code_off)
            lines.append("# ---- %s%s  registers=%d insns_size=%d %s"
                         % (name, desc, info["registers"], info["insns_size"],
                            "" if clean else "DECODE-DID-NOT-END-CLEANLY"))
            lines.append(head)
            lines.append("    .registers %d" % info["registers"])
            for insn in listing:
                text = dex.describe(insn)
                body = text.split(": ", 1)[1] if ": " in text else text
                lines.append("    # 0x%04x  %s"
                             % (insn["off"] - info["insns_off"], body))
            lines.append(".end method")
            lines.append("")
            methods_out += 1

    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote %s (%d classes matched, %d methods)" % (args.out, classes, methods_out))
    else:
        sys.stdout.write(text)
    return 0


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vmp_diff_harness.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("build", help="compile the labelled opcode-coverage fixture",
                       description="Compile a fixture dex whose every instruction is "
                                   "known and labelled. Needs an explicit toolchain.")
    p.add_argument("--out", required=True, help="output directory")
    p.add_argument("--build-tools", default=None,
                   help="directory holding d8 and aapt2 (not guessed)")
    p.add_argument("--javac", default=None, help="path to javac (default: PATH)")
    p.add_argument("--min-api", type=int, default=26,
                   help="d8 --min-api (26 keeps invoke-custom/invoke-polymorphic "
                        "instead of desugaring them away); default 26")
    p.add_argument("--desugar", action="store_true",
                   help="allow d8 desugaring (default: --no-desugaring)")
    p.add_argument("--with-big", action="store_true", default=True,
                   help="also generate the bulk fixture (wide registers, long jump); "
                        "default on")
    p.add_argument("--no-big", dest="with_big", action="store_false",
                   help="skip the bulk fixture")
    p.add_argument("--n-int", type=int, default=300, help="int locals in the wide frame")
    p.add_argument("--n-long", type=int, default=140, help="long locals in the wide frame")
    p.add_argument("--n-obj", type=int, default=160, help="object locals in the wide frame")
    p.add_argument("--goto16", type=int, default=200,
                   help="statements in the long-jump loop body")
    p.add_argument("--apk", action="store_true",
                   help="also pack classes.dex into a minimal unsigned APK via aapt2")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("audit", help="report opcode coverage of a dex",
                       description="Count decoded opcodes and report the gap against "
                                   "the format table, with the reason each gap exists.")
    p.add_argument("dex", nargs="+", help="dex or APK to audit")
    p.add_argument("--json", default=None, help="write the report as JSON here")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("compare", help="align original vs hardened dex; emit a candidate opcode map",
                       description="Project the original's instruction boundaries onto the "
                                   "hardened body and read the opcode substitution off the "
                                   "alignment. Reports a run-level verdict so a shape the "
                                   "method cannot handle is said out loud instead of "
                                   "producing a plausible map.")
    p.add_argument("original", help="the pre-hardening dex (or APK)")
    p.add_argument("hardened", help="the post-hardening dex (or APK)")
    p.add_argument("--json", default=None, help="write the full report here")
    p.add_argument("--quiet", action="store_true", help="suppress the map listing")
    p.add_argument("--verbose", action="store_true", help="also print per-method rows")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("simulate", help="forge a hardened dex from a known private table",
                       description="Local fixture that makes compare() falsifiable: relabel "
                                   "every opcode through a known bijection, then require "
                                   "compare to re-derive that table. This is NOT a hardening "
                                   "engine -- it preserves instruction lengths, which a real "
                                   "one need not do.")
    p.add_argument("dex", help="the dex to relabel")
    p.add_argument("--out", required=True, help="where to write the simulated dex")
    p.add_argument("--mode", choices=("relabel", "stub", "shrink"), default="relabel",
                   help="relabel: private opcode bytes, lengths preserved (the shape "
                        "the differential can actually crack); stub: every body "
                        "replaced by an equal-length return-void fill (the extraction "
                        "shape -- compare must refuse it); shrink: rewrite insns_size "
                        "to drive compare's length-mismatch detector (writes a "
                        "deliberately inconsistent image)")
    p.add_argument("--seed", type=int, default=1, help="bijection seed")
    p.add_argument("--table", default=None,
                   help="also write the ground-truth table here (orig -> private)")
    p.add_argument("--keep-header", action="store_true",
                   help="do not recompute checksum/signature (default: recompute)")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("emit-smali", help="render private-opcode bodies into a smali skeleton",
                       description="Restore opcode bytes through a differential table and "
                                   "render method bodies as an annotated smali reading "
                                   "skeleton. The output is NOT assembliable.")
    p.add_argument("dex", help="the hardened dex")
    p.add_argument("--table", required=True, help="table JSON from compare/simulate")
    p.add_argument("--class", dest="cls", default=None,
                   help="only this class (Lpkg/Name; or pkg.Name)")
    p.add_argument("--method", default=None, help="only this method name")
    p.add_argument("--out", default=None, help="output file (default: stdout)")
    p.add_argument("--keep-header", action="store_true",
                   help="do not recompute the restored dex header")
    p.set_defaults(func=cmd_emit_smali)

    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
