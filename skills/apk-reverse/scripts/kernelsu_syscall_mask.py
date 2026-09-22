#!/usr/bin/env python3
"""kernelsu_syscall_mask.py -- generate a configurable kernel-side syscall-masking scaffold.

What this generates, and the correction it exists to make
---------------------------------------------------------
There is a widespread misreading worth killing early: **a KernelSU module is a
Magisk-compatible userspace module and cannot change what a syscall returns.**
Its `post-fs-data.sh` / `service.sh` run as root in the normal world; nothing in
that format reaches the kernel's return path. Everything a module of that shape
can do is userspace work -- bind mounts, setting props, starting a daemon,
writing config.

Actually rewriting what `openat`/`read`/`stat` return for `/proc/self/maps` or
`/proc/self/status` needs one of exactly three things:

  kpm    KernelPatch / APatch Kernel Patch Module -- pointer replacement in the
         syscall table (`fp_hook_syscalln`) or inline hooks (`hook_wrapN`).
         Built with a bare-metal ARM64 toolchain (aarch64-none-elf-gcc) into a
         relocatable .kpm ELF. Needs a KernelPatch-patched boot image.
  lkm    An out-of-tree kernel module. Needs kernel source matching the device's
         exact version and vermagic, and a loader path.
  ebpf   A BPF program attached to a syscall tracepoint or kprobe. Needs a GKI
         kernel with the tracing/BTF machinery -- 5.10+ in Android practice.

So this script emits a **module directory that is honest about which half is
loadable**: the userspace skeleton (module.prop + scripts + config) is real and
installable, and each kernel-side target is a template with its toolchain gate
stated in its own header. None of the kernel-side code is compiled or loaded
anywhere by this script.

What is measured vs unverified
------------------------------
`generate`, `gates` and `verify` are exercised on the host (see
docs/tool-verification/EXTENSION-kernel-weapons.md). **Whether the kernel-side
code compiles or loads is unverified** -- that needs a device with the matching
kernel and the matching toolchain, and the reference device is a 4.14.186 Magisk
build where all three routes are closed.

Examples
  python kernelsu_syscall_mask.py gates
  python kernelsu_syscall_mask.py generate --out work/sysmask --package <PKG>
  python kernelsu_syscall_mask.py verify --dir work/sysmask
"""
import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Kernel gate table. Every number here is either a toolchain fact or a
# documented platform threshold; the "how to check" column is what turns it
# from trivia into a test you run on your own device.
# ---------------------------------------------------------------------------
GATES = [
    {
        "route": "eBPF tracepoint/kprobe",
        "gate": "GKI kernel 5.10+ (Android 12+)",
        "why": "Android's BPF/tracing support as bpftrace-class tooling and "
               "stackplz expect it is a GKI-era feature; BTF is required for "
               "CO-RE style probes.",
        "check": "uname -r  ->  expect 5.10.x or newer; ls /sys/kernel/btf/vmlinux",
        "ref": "https://source.android.com/docs/core/architecture/kernel/bpf",
    },
    {
        "route": "KernelPatch / APatch KPM",
        "gate": "KernelPatch-patched boot image + kpm toolchain",
        "why": "KPMs load through kpimg injected into the kernel image's payload "
               "segment; building one needs a bare-metal ARM64 compiler "
               "(aarch64-none-elf-gcc), not the NDK.",
        "check": "ls /data/adb/ | grep -i apatch ; which aarch64-none-elf-gcc",
        "ref": "https://github.com/bmax121/KernelPatch",
    },
    {
        "route": "Out-of-tree LKM",
        "gate": "Kernel source matching the device's exact version + vermagic",
        "why": "A module built against a different kernel revision is refused at "
               "load time on a mismatched vermagic, and the device's kernel "
               "source is frequently not published at all.",
        "check": "uname -r ; look for a matching kernel source tree for the device",
        "ref": "https://source.android.com/docs/core/architecture/kernel/android-common",
    },
    {
        "route": "seccomp-BPF (for contrast)",
        "gate": "any modern kernel, but it is not this route",
        "why": "seccomp can make a syscall FAIL (SECCOMP_RET_ERRNO/TRAP); it "
               "cannot rewrite the CONTENT a successful read returns. It closes "
               "doors, it does not paint them -- which is the whole requirement "
               "for a spoofed /proc read.",
        "check": "n/a -- this is a capability ceiling, not a version check",
        "ref": "references/kernel-and-environment-hardening.md",
    },
]

DEFAULT_RULES = [
    {
        "syscall": "openat",
        "path": "/proc/self/maps",
        "action": "deny",
        "errno": "ENOENT",
        "note": "hides the mapping list a userspace instrumentation agent "
                "advertises itself in",
    },
    {
        "syscall": "newfstatat",
        "path": "/proc/self/maps",
        "action": "fake_size",
        "size": 0,
        "note": "a stat that reports 0 bytes is as good as absent for a reader "
                "that sizes its buffer first",
    },
    {
        "syscall": "openat",
        "path": "/proc/self/status",
        "action": "filter_line",
        "prefix": "TracerPid",
        "note": "the write side owns this field; see "
                "references/kernel-and-environment-hardening.md section 5",
    },
    {
        "syscall": "read",
        "path": "/proc/self/status",
        "action": "filter_line",
        "prefix": "TracerPid",
        "note": "line filter applied to the read once the fd is open",
    },
]

MODULE_PROP = """id={id}
name={name}
version={version}
versionCode=1
author=apk-reverse
description={description}
"""

POST_FS_DATA = """#!/system/bin/sh
# Runs at post-fs-data, as root, in the normal world.
# The kernel side (if you built and loaded one) owns the syscall table; this
# script's whole job is to make the configuration visible to it and to leave a
# record that the module actually ran. Do not put a syscall hook here: this is
# userspace, and nothing here can change what openat/read/stat return.
MODDIR=${{0%/*}}
CONF=$MODDIR/config/syscall_mask.json
LOG=/data/adb/{id}.log

if [ ! -f "$CONF" ]; then
  echo "$(date) missing $CONF" >> "$LOG"
  exit 0
fi
echo "$(date) post-fs-data: config present, $(wc -c < "$CONF") bytes" >> "$LOG"
# The KPM/LKM loader path is intentionally NOT invoked from here. Loading a
# kernel module is a boot-image-level decision with a bricking risk; do it once,
# by hand, and read the evidence file first.
exit 0
"""

SERVICE = """#!/system/bin/sh
# Runs in late_start service mode, as root. Kept minimal and non-blocking on
# purpose: a module that spins here delays boot on every start, and this one
# only reports state.
MODDIR=${{0%/*}}
CONF=$MODDIR/config/syscall_mask.json
LOG=/data/adb/{id}.log

if [ -r /proc/sys/kernel/version ]; then
  echo "$(date) service: kernel $(uname -r)" >> "$LOG"
fi
echo "$(date) service: rules=$(grep -c '"syscall"' "$CONF" 2>/dev/null)" >> "$LOG"
exit 0
"""

UNINSTALL = """#!/system/bin/sh
# Uninstall hook. Deliberately does not attempt to unload a kernel module: if one
# is loaded, unloading it is a separate deliberate act with its own risk, and a
# silent unload during package removal is how a device ends up in a boot loop.
rm -f /data/adb/{id}.log
exit 0
"""

CUSTOMIZE = """#!/system/bin/sh
# KernelSU/Magisk install-time script. Kept as a no-op so the module always
# installs; see the module README for why nothing is set up here.
exit 0
"""

KPM_C = r'''// SPDX-License-Identifier: GPL-2.0
/*
 * syscall_mask.c -- config-driven syscall return masking, KernelPatch/APatch KPM.
 *
 * Generated by skills/apk-reverse/scripts/kernelsu_syscall_mask.py
 *
 * STATUS: TEMPLATE, NOT COMPILED AND NOT LOADED. Every hook below follows the
 * KernelPatch KPM interface as documented in public KPM development write-ups
 * (KPM_NAME/KPM_INIT/KPM_EXIT sections, kfunc_def symbol resolution without
 * `extern`, fp_hook_syscalln pointer replacement, hook_fargs4_t callbacks with
 * args->skip_origin / args->ret). VERIFY EVERY NAME AND SIGNATURE against the
 * kpmodule.h of the KernelPatch revision you build against -- this file was not
 * compiled anywhere, and an interface that has drifted produces a module that
 * fails to load, or worse, loads and faults.
 *
 * Build (bare-metal ARM64, NOT the NDK):
 *     aarch64-none-elf-gcc -O2 -fno-stack-protector -c syscall_mask.c
 *     ... link into a relocatable ELF per the KernelPatch module docs
 * Load: push the .kpm and add it through the APatch app's KPM manager.
 *
 * Design notes that are load-bearing rather than stylistic:
 *   - Callbacks run on EVERY syscall of their number, system-wide. The first
 *     thing each one does is reject the overwhelmingly common case, because a
 *     hook that does real work on every write is how a device locks up.
 *   - Inline hooks (hook_wrapN) rewrite the target's prologue. On an LTO kernel
 *     the exported symbol is frequently NOT the call site (the call got inlined),
 *     so an inline hook installs cleanly and never fires. Pointer replacement in
 *     the syscall table (fp_hook_syscalln) does not have that failure mode,
 *     because the syscall entry path must go through the table.
 *   - Never sleep in these callbacks except where the syscall itself runs in
 *     process context and the copy helper is the sleeping variant.
 */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <kpmodule.h>

KPM_NAME("{id}");
KPM_VERSION("{version}");
KPM_LICENSE("GPL");
KPM_AUTHOR("apk-reverse");
KPM_DESCRIPTION("{description}");

/* kfunc declarations must NOT carry `extern`: an extern declaration compiles to
 * an undefined reference (*UND*) and the loader rejects the module with
 * "unknown symbol". Letting it be a tentative definition allocates the slot in
 * .bss and the loader fills it in. Measured and documented in public KPM work. */
int kfunc_def(strncpy_from_user)(char *dst, const char __user *src, long count);

/* ------------------------------------------------------------------ rules --
 * Generated from config/syscall_mask.json. Keep this table in sync by
 * re-running the generator rather than by hand-editing it.
 */
#define MASK_DENY        1   /* return -err before the real syscall runs      */
#define MASK_FAKE_SIZE   2   /* openat succeeds, stat reports a bogus size    */
#define MASK_FILTER_LINE 3   /* strip lines with this prefix from read()      */

struct mask_rule {
    const char *path;        /* userspace path to match, NULL = any          */
    const char *prefix;      /* line prefix for MASK_FILTER_LINE, else NULL  */
    int         action;
    int         err;         /* -errno for MASK_DENY                          */
    long        value;       /* size for MASK_FAKE_SIZE                       */
};

static const struct mask_rule rules[] = {
{RULE_TABLE}
};

#define NRULES (sizeof(rules) / sizeof(rules[0]))

/* A bounded, allocation-free matcher. The path is copied in first, so the
 * comparison never touches userspace after the initial copy -- touching
 * userspace memory twice is how a hook races with the caller's own unmapping. */
static int copy_and_match(const char __user *upath, char *kbuf, unsigned long n,
                          const char **matched)
{{
    long copied;
    unsigned long i;

    if (!upath || n == 0)
        return 0;
    if (!kfunc(strncpy_from_user))
        return 0;                       /* symbol unresolved: fail open */
    copied = kfunc(strncpy_from_user)(kbuf, upath, (long)(n - 1));
    if (copied <= 0)
        return 0;
    kbuf[copied] = '\0';

    for (i = 0; i < NRULES; i++) {{
        if (!rules[i].path)
            continue;
        if (strstr(kbuf, rules[i].path)) {{
            *matched = rules[i].path;
            return rules[i].action;
        }}
    }}
    return 0;
}}

/* ------------------------------------------------------------------ openat --
 * The path argument is arg2 on arm64 (dfd, path, flags, mode). If the path is
 * unreadable, the rule is skipped rather than guessed at.
 */
static void before_openat(hook_fargs4_t *args, void *udata)
{{
    const char __user *upath = (const char __user *)syscall_argn(args, 1);
    char kbuf[256];
    const char *matched = 0;
    int action;

    (void)udata;
    action = copy_and_match(upath, kbuf, sizeof(kbuf), &matched);
    if (action == MASK_DENY)
        args->ret = MASK_DENY_ERRNO;
    if (action == MASK_FAKE_SIZE)
        args->skip_origin = 0;          /* let it open; the stat is spoofed */
}}

/* --------------------------------------------------------------- newfstatat --
 * arm64 has no plain `stat` syscall; readers go through newfstatat (or fstatat64
 * on 32-bit). A zero size is what makes a reader that sizes its buffer first
 * decide there is nothing to read.
 */
static void after_newfstatat(hook_fargs4_t *args, void *udata)
{{
    const char __user *upath = (const char __user *)syscall_argn(args, 1);
    char kbuf[256];
    const char *matched = 0;

    (void)udata;
    if (copy_and_match(upath, kbuf, sizeof(kbuf), &matched) != MASK_FAKE_SIZE)
        return;
    /* The struct stat* is arg2; zeroing st_size is the whole point. Field
     * offsets are ABI-specific -- resolve them against the target's headers
     * rather than trusting an offset copied from a different architecture. */
    /* TODO(verify-on-device): zero the size field of the struct at arg2. */
}}

/* -------------------------------------------------------------------- read --
 * Line filtering happens on the read side, once the fd is already open. Doing
 * it here rather than at openat is what lets a reader that opens the file
 * before the filter is installed still be covered.
 */
static void before_read(hook_fargs4_t *args, void *udata)
{{
    long count = (long)syscall_argn(args, 2);
    (void)udata;
    if (count <= 0 || count > 8192)
        return;                          /* first filter: the common case */
    /* TODO(verify-on-device): identify the fd's path, copy the buffer, rewrite
     * it in place minus the filtered lines, and adjust the returned length. */
}}

/* ------------------------------------------------------------------ init -----
 * Registration order matters: install the syscall hooks first, then enable the
 * rules. If the module is unloaded between the two, the hooks must already be
 * gone.
 */
static long mask_init(const char *args, const struct kernel_patch_funcs *kp)
{{
    (void)args;
    (void)kp;

    if (!kfunc(strncpy_from_user)) {{
        /* Failing loudly here is deliberate: a half-armed hook set that cannot
         * read a path would pass every check through, which looks like success
         * and is not. */
        return -EINVAL;
    }}

    /* fp_hook_syscalln(__NR_openat, before_openat, 0, 0);    */
    /* fp_hook_syscalln(__NR_newfstatat, before_newfstatat, 0, 0); */
    /* fp_hook_syscalln(__NR_read, before_read, 0, 0);        */
    /* TODO(verify-on-device): the argument lists above follow the public
     * examples; confirm arity against your kpmodule.h before enabling them. */
    return 0;
}}

static long mask_exit(void *udata)
{{
    (void)udata;
    /* Unhook in the exact reverse order of registration. */
    return 0;
}}

KPM_INIT(mask_init);
KPM_EXIT(mask_exit);
'''

LKM_C = r'''// SPDX-License-Identifier: GPL-2.0
/*
 * syscall_mask.c -- out-of-tree LKM variant of the same idea.
 *
 * STATUS: TEMPLATE, NOT COMPILED. Worse than the KPM variant in one specific
 * way worth understanding before choosing it: to replace a syscall you must
 * reach the syscall table, and `kallsyms_lookup_name` stopped being exported in
 * Linux 5.7. On pre-5.7 kernels a direct call works; after that you need a
 * kprobe to recover the address, or an explicit kernel export. The device's own
 * kernel source must also match its exact vermagic, and an out-of-tree module
 * built against a mismatched tree is refused at insmod.
 *
 * This is genuine kernel development with a bricking risk. It is the most
 * expensive of the three routes and the one least likely to be worth it.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("{description}");
MODULE_AUTHOR("apk-reverse");

/*
 * Pre-5.7: kallsyms_lookup_name() is exported, so the table pointer is
 * recoverable directly. 5.7+: NOT exported -- you must either carry a kprobe to
 * find the symbol or patch the kernel's export list. There is no portable
 * version of this, which is the honest reason this route is rated last.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
static unsigned long *sys_call_table_addr(void)
{
    return (unsigned long *)kallsyms_lookup_name("sys_call_table");
}
#else
static unsigned long *sys_call_table_addr(void)
{
    /* TODO(verify-on-device): recover via kprobe on kallsyms_lookup_name, or
     * enable an explicit export in your own kernel build. */
    return NULL;
}
#endif

static int __init mask_init(void)
{
    unsigned long *table = sys_call_table_addr();
    if (!table) {
        pr_err("syscall_mask: cannot locate sys_call_table on this kernel\n");
        return -EINVAL;
    }
    pr_info("syscall_mask: sys_call_table at %px\n", table);
    /* TODO(verify-on-device): save the original pointer, write CR0 (or use
     * set_memory_rw) to make the table writable, swap in your handler. Getting
     * the write-protect dance wrong takes the device down. */
    return 0;
}

static void __exit mask_exit(void)
{
    /* TODO(verify-on-device): restore the saved pointers. */
}

module_init(mask_init);
module_exit(mask_exit);
'''

EBPF_C = r'''// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * syscall_mask.bpf.c -- eBPF probe template: filter sys_enter_openat, then
 * rewrite the result.
 *
 * STATUS: TEMPLATE, NOT COMPILED AND NOT ATTACHED. Not runnable on a 4.14
 * kernel: see the gate table in the module README (GKI 5.10+ in Android
 * practice, plus BTF for CO-RE style probes).
 *
 * READ THIS BEFORE COUNTING ON THE RESULT REWRITE. There are two different
 * attachment points and they are not interchangeable:
 *
 *   - A *tracepoint* (syscalls/sys_enter_openat) is an observation point. It can
 *     read the arguments and it can emit events, and it CANNOT change the
 *     syscall's return value. A tracepoint-only program gives you visibility,
 *     not spoofing.
 *   - A *kprobe* on the syscall's entry (or a kretprobe on its exit) can modify
 *     a register with bpf_override_return() -- but only for functions flagged
 *     ALLOW_ERROR_INJECTION, which kernel syscall entry points are not, in
 *     general. On many kernels the helper is refused for exactly this target.
 *
 * So the honest eBPF shape for this job is: observe with a tracepoint, and do
 * the rewrite in a place that actually owns the return value. What follows is
 * the observation half done properly, plus the rewrite half marked for the
 * device-side verification it needs.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_PATH 256
#define TARGET_LEN 15            /* strlen("/proc/self/maps") */

struct event {
    __u32 pid;
    __u32 uid;
    __s32 dfd;
    __s64 ret;
    char  path[MAX_PATH];
    char  comm[16];
};
/* /proc/self/status is 17; kept as a separate constant so the two rules can be
 * toggled independently. */
#define TARGET_STATUS_LEN 17

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Filter the target package's processes. Populated from userspace with the
 * uids the app can run as; an empty map means "all processes", which is a
 * deliberate default because a filter that silently matches nothing looks
 * exactly like a probe that is not firing. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);            /* uid */
    __type(value, __u8);
} target_uids SEC(".maps");

static __always_inline int want(void)
{
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u8 *hit = bpf_map_lookup_elem(&target_uids, &uid);
    /* Empty map -> observe everything. Populated map -> only listed uids. */
    return hit || (bpf_map_lookup_elem(&target_uids, &uid) == 0);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *upath = (const char *)ctx->args[1];

    if (!want())
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->dfd = (__s32)ctx->args[0];
    e->ret = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->path, sizeof(e->path), upath);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * The result-rewrite half. Two dead ends are recorded here on purpose so they
 * are not re-derived:
 *
 *   1. bpf_override_return() only works on functions marked
 *      ALLOW_ERROR_INJECTION. A raw syscall entry is not one of them, so the
 *      helper is typically refused for this target -- check the return value
 *      and the verifier message rather than assuming the rewrite happened.
 *   2. A tracepoint cannot rewrite at all. If the rewrite is essential, the
 *      route is a kprobe plus a kernel that permits the override, or one of the
 *      KPM/LKM routes; eBPF's strength here is observation.
 */
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kp_do_sys_openat2, int dfd, const char *filename)
{
    char buf[64];
    if (bpf_probe_read_user_str(&buf, sizeof(buf), filename) <= 0)
        return 0;
    if (buf[0] == '/' && buf[1] == 'p' && buf[2] == 'r') {
        /* TODO(verify-on-device): bpf_override_return(ctx, -ENOENT) here only
         * after confirming ALLOW_ERROR_INJECTION on this target kernel. */
    }
    return 0;
}
'''

KPM_MAKEFILE = """# aarch64-none-elf-gcc is a BARE-METAL ARM64 compiler, not the Android NDK
# toolchain. The NDK targets Android userspace and will not produce a loadable
# KPM. STATUS: untested -- this toolchain is not present on a Magisk-only device.
CROSS   ?= aarch64-none-elf-
CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy

TARGET  := {id}
KPM_DIR ?= ../KernelPatch

CFLAGS  := -O2 -fno-stack-protector -fno-pic -fno-builtin \\
           -I$(KPM_DIR)/kernel/include -I$(KPM_DIR)/include \\
           -Wall -Wno-unused-variable

all: $(TARGET).kpm

$(TARGET).kpm: src/{id}.c
\t$(CC) $(CFLAGS) -c $< -o $@.o
\t$(OBJCOPY) -O binary --only-section=.text $@.o /dev/null 2>/dev/null || true
\t@echo "NOTE: linking follows the KernelPatch module format; see the docs"
\t@echo "      for the current link step before trusting this target."

clean:
\trm -f *.o *.kpm

.PHONY: all clean
"""

MODULE_README = """# {name} -- syscall-return masking scaffold

Generated by `skills/apk-reverse/scripts/kernelsu_syscall_mask.py`.

**Read this first: the userspace module in this directory cannot change what a
syscall returns.** It is a KernelSU/Magisk-compatible module: its scripts run as
root in the normal world. Its only jobs are to carry the configuration, to
record that it ran, and to be a place to put the module metadata. The kernel
side is a separate artifact with a separate toolchain and a separate risk.

## What is here

| Path | Status |
|---|---|
| `module.prop`, `customize.sh`, `post-fs-data.sh`, `service.sh` | real, installable module skeleton |
| `config/syscall_mask.json` | the rule set, read by the kernel side |
| `kpm/{id}.c`, `kpm/Makefile` | APatch/KernelPatch template -- **not compiled, not loaded** |
| `lkm/{id}.c` | out-of-tree module template -- **not compiled, not loaded** |
| `ebpf/syscall_mask.bpf.c` | eBPF probe template -- **not compiled, not attached** |

## Gate table -- check your device before choosing a route

| Route | Gate | How to check | Why |
|---|---|---|---|
{gates}

## Reference device, measured

```
$ adb shell 'uname -r; cat /proc/version'
4.14.186+
Linux version 4.14.186+ (nobody@android-build) (Android (6443078 based on r383902)
clang version 11.0.1 ...) #1 SMP PREEMPT Wed Mar 30 23:32:42 CST 2022
```

On that device **every kernel-side route above is closed**:

- eBPF: kernel 4.14 is well below the 5.10 gate.
- KPM: no KernelPatch-patched image, and no `aarch64-none-elf-gcc` on the host;
  installing APatch means patching the boot image, which is a bricking risk.
- LKM: no kernel source for the device, so no matching vermagic is possible.

That is a **route decision, not a failure** -- and it is why every kernel-side
file here is labelled a template. Nothing in this directory was loaded on
anything.

## If you do take a kernel route

Do it once, deliberately, and read the evidence first:

1. Confirm the gate in the table above on the actual device.
2. Build the kernel side on a machine that has the right toolchain.
3. **Back up the boot image and know the recovery path before loading anything.**
   A kernel module that faults takes the device down before you can read why.
4. Load it by hand, watch `dmesg`, and keep the previous boot image in hand.
5. Only then wire it into boot, and only if the load is repeatable.

`post-fs-data.sh` in this scaffold deliberately does **not** load anything. That
is not an omission.
"""


def _render(template, **kw):
    """Fill a template's {placeholders} without str.format().

    Braces are the common case in C, so using format() here would mean doubling
    every one of them -- and the doubled-brace convention fails silently in the
    other direction the moment somebody next edits the C by hand. `{{` is
    unescaped and only the named placeholders are substituted, so ordinary C
    braces pass through untouched.
    """
    text = template.replace("{{", "{").replace("}}", "}")
    for key, value in kw.items():
        text = text.replace("{%s}" % key, str(value))
    return text


def _rule_table_c(rules):
    """Render the JSON rule set as a C table."""
    errno_map = {"ENOENT": 2, "EACCES": 13, "EINVAL": 22, "EPERM": 1}
    action_map = {"deny": "MASK_DENY", "fake_size": "MASK_FAKE_SIZE",
                  "filter_line": "MASK_FILTER_LINE"}
    lines = []
    for rule in rules:
        path = rule.get("path")
        prefix = rule.get("prefix")
        action = action_map.get(rule.get("action"), "MASK_DENY")
        err = errno_map.get(rule.get("errno", "ENOENT"), 2)
        value = rule.get("size", 0)
        lines.append('    { %s, %s, %s, -%d, %d },'
                     % ('"%s"' % path if path else "0",
                        '"%s"' % prefix if prefix else "0",
                        action, err, value))
    return "\n".join(lines) if lines else "    /* no rules configured */"


def cmd_gates(args):
    """Report the kernel-route gate table, and probe this host where it can be probed."""
    print("== kernel-side routes and their gates ==\n")
    for g in GATES:
        print("  %-28s %s" % (g["route"], g["gate"]))
        print("  %-28s why:  %s" % ("", g["why"]))
        print("  %-28s check: %s" % ("", g["check"]))
        print()
    print("== host probe (what can be checked from here) ==\n")
    cc = None
    import shutil
    for cand in ("aarch64-none-elf-gcc", "aarch64-linux-gnu-gcc", "clang"):
        found = shutil.which(cand)
        if found:
            cc = (cand, found)
            break
    if cc:
        print("  bare-metal ARM64-ish compiler: %s -> %s" % cc)
        if cc[0] == "clang":
            print("     note: clang can target aarch64-none-elf, so this is "
                  "potentially usable for the KPM route")
    else:
        print("  bare-metal ARM64 compiler: NOT FOUND")
        print("     the KPM route cannot be built from this host as configured")
    for name in ("ndk-build", "make"):
        print("  %-12s %s" % (name + ":", shutil.which(name) or "NOT FOUND"))
    print("\n  A kernel source tree, a patched boot image and the device's own "
          "kernel headers cannot be checked from the host; they are device facts.")
    print("  Run the `check` command for each route on the device before "
          "believing any of this applies to it.")
    return 0


def cmd_generate(args):
    out = args.out
    rules = DEFAULT_RULES
    if args.rules:
        with open(args.rules, encoding="utf-8") as fh:
            rules = json.load(fh)
    desc = args.description
    os.makedirs(os.path.join(out, "config"), exist_ok=True)

    written = []

    def put(rel, text, mode=None):
        path = os.path.join(out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        if mode is not None:
            try:
                os.chmod(path, mode)
            except OSError:
                pass
        written.append(rel)

    put("module.prop", _render(MODULE_PROP,
                               id=args.id, name=args.name, version=args.version,
                               description=desc))
    put("customize.sh", CUSTOMIZE, 0o755)
    put("post-fs-data.sh", _render(POST_FS_DATA, id=args.id), 0o755)
    put("service.sh", _render(SERVICE, id=args.id), 0o755)
    put("uninstall.sh", _render(UNINSTALL, id=args.id), 0o755)
    put("config/syscall_mask.json", json.dumps(
        {"version": 1, "id": args.id, "package": args.package,
         "enabled": True, "note": "read by the kernel side, not by the shell "
                                  "scripts -- see the module README",
         "rules": rules}, indent=2) + "\n")

    want = set(args.targets.split(","))
    if "kpm" in want:
        body = _render(KPM_C, id=args.id, version=args.version, description=desc,
                       RULE_TABLE=_rule_table_c(rules))
        put("kpm/%s.c" % args.id, body)
        put("kpm/Makefile", _render(KPM_MAKEFILE, id=args.id))
    if "lkm" in want:
        put("lkm/%s.c" % args.id, _render(LKM_C, id=args.id, description=desc))
    if "ebpf" in want:
        put("ebpf/syscall_mask.bpf.c", EBPF_C)

    gate_rows = "\n".join("| %s | %s | `%s` | %s |"
                          % (g["route"], g["gate"], g["check"], g["why"])
                          for g in GATES)
    put("README.md", _render(MODULE_README, name=args.name, gates=gate_rows,
                             id=args.id))

    print("generated module scaffold in %s" % out)
    for rel in written:
        size = os.path.getsize(os.path.join(out, rel))
        print("  %-28s %7d B" % (rel, size))
    print()
    print("STATUS: the userspace module is installable; every kernel-side file is "
          "an UNVERIFIED template.")
    print("        No kernel code was compiled or loaded. Run `gates` and read the "
          "device README")
    print("        section before assuming any route is open on your target.")
    return 0


def _strip_c_comments(text):
    """Remove /* */ and // comments before any token-level check.

    Not cosmetic: the first version of this check reported a false positive
    because the template's own comment explains why `extern` is forbidden, and a
    naive `extern.*kfunc_def` regex happily matched the prose and then ran on to
    the real declaration's semicolon. A linter that reads comments as code
    produces exactly the kind of report nobody can trust.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def cmd_verify(args):
    """Read-only checks over a generated directory. Everything here is local."""
    d = args.dir
    problems = []
    print("== verifying %s ==" % d)

    prop = os.path.join(d, "module.prop")
    if not os.path.isfile(prop):
        problems.append("module.prop missing")
    else:
        fields = {}
        with open(prop, encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    fields[k] = v
        for req in ("id", "name", "version", "versionCode"):
            if req not in fields:
                problems.append("module.prop missing required field %r" % req)
        if "id" in fields and not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9._-]*", fields["id"]):
            problems.append("module.prop id %r is not a valid module id" % fields["id"])
        print("  module.prop: %s" % ", ".join("%s=%s" % kv for kv in sorted(fields.items())))

    conf = os.path.join(d, "config", "syscall_mask.json")
    if not os.path.isfile(conf):
        problems.append("config/syscall_mask.json missing")
    else:
        try:
            with open(conf, encoding="utf-8") as fh:
                doc = json.load(fh)
            rules = doc.get("rules", [])
            known = {"deny", "fake_size", "filter_line"}
            for i, r in enumerate(rules):
                if r.get("action") not in known:
                    problems.append("rule %d has unknown action %r" % (i, r.get("action")))
                if not r.get("syscall"):
                    problems.append("rule %d names no syscall" % i)
            print("  config: %d rule(s), actions=%s"
                  % (len(rules), sorted({r.get("action") for r in rules})))
        except (ValueError, OSError) as exc:
            problems.append("config/syscall_mask.json unreadable: %s" % exc)

    for rel, want_exec in (("post-fs-data.sh", True), ("service.sh", True),
                           ("customize.sh", True), ("uninstall.sh", True)):
        p = os.path.join(d, rel)
        if not os.path.isfile(p):
            problems.append("%s missing" % rel)
            continue
        if want_exec and not os.access(p, os.X_OK):
            # Not fatal on a filesystem without an exec bit; the installer sets it.
            print("  note: %s is not executable here (the installer chmods it)" % rel)

    for rel in ("kpm", "lkm", "ebpf"):
        p = os.path.join(d, rel)
        if os.path.isdir(p):
            print("  %-4s target present: %s"
                  % (rel, ", ".join(sorted(os.listdir(p)))))
            print("       status: UNVERIFIED TEMPLATE -- not compiled, not loaded")

    # The one static check worth doing on the C: the KPM interface has a
    # documented trap (an extern kfunc declaration compiles to *UND* and the
    # loader refuses the module), so catch it here rather than on a device.
    kpm_dir = os.path.join(d, "kpm")
    if os.path.isdir(kpm_dir):
        for name in sorted(os.listdir(kpm_dir)):
            if not name.endswith(".c"):
                continue
            with open(os.path.join(kpm_dir, name), encoding="utf-8") as fh:
                text = fh.read()
            code = _strip_c_comments(text)
            if re.search(r"\bextern\b[^;]*\bkfunc_def\b", code):
                problems.append("%s declares kfunc_def with `extern`, which the "
                                "loader rejects as an unknown symbol" % name)
            for macro in ("KPM_NAME", "KPM_INIT", "KPM_EXIT"):
                if macro not in code:
                    problems.append("%s is missing %s" % (name, macro))
            print("  kpm/%s: KPM_* lifecycle macros present, kfunc_def not extern"
                  % name)

    print()
    if problems:
        print("== %d problem(s) ==" % len(problems))
        for p in problems:
            print("  - %s" % p)
        return 1
    print("== 0 problem(s): structure is consistent ==")
    print("   (this says nothing about whether the kernel side compiles or loads)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="kernelsu_syscall_mask.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("gates", help="print the kernel-route gate table and probe this host",
                       description="The gate table, plus whatever part of it can be "
                                   "checked from this machine. Device facts still have "
                                   "to be checked on the device.")
    p.set_defaults(func=cmd_gates)

    p = sub.add_parser("generate", help="write the module scaffold",
                       description="Generate a KernelSU/APatch-compatible module "
                                   "directory. The userspace half is installable; the "
                                   "kernel half is a template.")
    p.add_argument("--out", required=True, help="directory to write into")
    p.add_argument("--id", default="syscall-mask", help="module id / artifact name")
    p.add_argument("--name", default="Syscall Mask", help="human-readable module name")
    p.add_argument("--version", default="0.1.0", help="module version string")
    p.add_argument("--description", default="config-driven syscall return masking "
                                            "(openat/read/stat on /proc/self/*)",
                   help="module description")
    p.add_argument("--package", default="<PKG>", help="target package placeholder")
    p.add_argument("--rules", default=None,
                   help="JSON file with a {rules:[...]} rule set (default: built-in)")
    p.add_argument("--targets", default="kpm,lkm,ebpf",
                   help="comma-separated kernel targets to emit (kpm,lkm,ebpf)")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("verify", help="read-only consistency checks over a generated dir",
                       description="Check module.prop fields, the rule JSON, and the "
                                   "static traps in the kernel template. Says nothing "
                                   "about compilation or loading.")
    p.add_argument("--dir", required=True, help="a directory from `generate`")
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
