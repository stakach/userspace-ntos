/*
 * whoruns — a QEMU TCG plugin that answers ONE question: which code is actually retiring
 * instructions?
 *
 * RIP sampling of a round-robin-TCG guest is biased toward interrupt boundaries and cannot tell a
 * halted vCPU from a spinning one (all vCPUs share one host thread, and `info registers` reports
 * the SAVED state of the ones not currently executing). Counting retired instructions per address
 * has neither problem: attribution happens at translation time, it is exact, and a halted CPU
 * retires nothing.
 *
 * Coarse buckets follow this system's address map; kernel translation blocks are ALSO counted
 * individually so the hot loop can be symbolised against the kernel ELF.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum { B_KERNEL, B_EXEC, B_HOSTED_HI, B_HOSTED_LO, B_OTHER, B_N };
static const char *names[B_N] = {"kernel", "exec", "hosted-hi", "hosted-lo", "other"};
static uint64_t counts[B_N];
static uint64_t total, next_dump = 200000000ull;
static FILE *out;
static double t0;

#define HOT_N 16384
static uint64_t hot_pc[HOT_N];
static uint64_t hot_insns[HOT_N];

/* Per-TB payload, allocated once at translation time. */
struct site { uint32_t bucket; uint32_t n; uint64_t pc; uint64_t *cell; };

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int classify(uint64_t pc)
{
    if (pc >= 0xFFFF800000000000ull) return B_KERNEL;
    if (pc >= 0x0000010000400000ull && pc < 0x0000010001000000ull) return B_EXEC;
    if (pc >= 0x0000010001000000ull && pc < 0x0000010200000000ull) return B_HOSTED_HI;
    if (pc < 0x0000000100000000ull) return B_HOSTED_LO;
    return B_OTHER;
}

static uint64_t *hot_slot(uint64_t pc)
{
    uint64_t h = (pc * 0x9E3779B97F4A7C15ull) >> 40;
    for (uint64_t i = 0; i < HOT_N; i++) {
        uint64_t idx = (h + i) & (HOT_N - 1);
        if (hot_pc[idx] == pc) return &hot_insns[idx];
        if (hot_pc[idx] == 0) { hot_pc[idx] = pc; return &hot_insns[idx]; }
    }
    return NULL;
}

static void dump(void)
{
    fprintf(out, "t=%.1f insns total=%" PRIu64, now_s() - t0, total);
    for (int i = 0; i < B_N; i++) fprintf(out, " %s=%" PRIu64, names[i], counts[i]);
    fprintf(out, "\n");
    /* top kernel TBs by retired instructions */
    uint64_t snap[HOT_N];
    memcpy(snap, hot_insns, sizeof(snap));
    for (int rank = 0; rank < 12; rank++) {
        uint64_t best = 0; int bi = -1;
        for (int i = 0; i < HOT_N; i++) if (snap[i] > best) { best = snap[i]; bi = i; }
        if (bi < 0) break;
        fprintf(out, "  hot#%d pc=0x%016" PRIx64 " insns=%" PRIu64 "\n", rank, hot_pc[bi], best);
        snap[bi] = 0;
    }
    fflush(out);
}

static void tb_exec(unsigned int cpu_index, void *udata)
{
    struct site *s = udata;
    counts[s->bucket] += s->n;
    total += s->n;
    if (s->cell) *s->cell += s->n;
    if (total >= next_dump) { next_dump = total + 200000000ull; dump(); }
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct site *s = calloc(1, sizeof(*s));
    s->pc = qemu_plugin_tb_vaddr(tb);
    s->n = (uint32_t)qemu_plugin_tb_n_insns(tb);
    s->bucket = classify(s->pc);
    s->cell = (s->bucket == B_KERNEL) ? hot_slot(s->pc) : NULL;
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS, s);
}

static void at_exit(qemu_plugin_id_t id, void *p) { fprintf(out, "FINAL "); dump(); }

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *path = "whoruns.txt";
    for (int i = 0; i < argc; i++)
        if (strncmp(argv[i], "out=", 4) == 0) path = argv[i] + 4;
    out = fopen(path, "w");
    if (!out) out = stderr;
    t0 = now_s();
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
