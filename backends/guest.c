// The unbound_wasm ABI entry points: a thin adapter between the host's
// exported guest interface (abi/README.md) and libunbound's event API. All
// interpretation of answer packets happens host-side; the guest only hands
// over the security status, rcode, and the wire-format answer.

#include "config.h"
#include "abi/unbound_wasm_abi.h"
#include "libunbound/unbound.h"
#include "libunbound/unbound-event.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Provided by event.c and sockets.c.
struct ub_event_base *uw_event_base(void);
void uw_io_ready(int fd, int flags);
void uw_timer_fired(int64_t tid);
int uw_socket_fd_for_sid(int sid);

// A result_slot tracks one resolution from resolve_start until the host
// collects the result or cancels. The host identifies slots by rid, which is
// index + 1 so that valid rids are positive.
#define MAX_RESULTS 64
struct result_slot {
    int used, ready;
    int ubid; // libunbound async ID, for ub_cancel before the callback fires
    int rcode, sec;
    uint8_t *packet;
    uint32_t packet_len;
    char *why_bogus;
};
static struct result_slot results[MAX_RESULTS];

static struct ub_ctx *ctx;
static int ctx_err; // sticky ensure_ctx failure; poisons every later resolve
static char *saved_cfg, *saved_anchors, *saved_hints;

// ub_errno maps a libunbound error (a negative ub_ctx_err constant) to a
// positive errno, so that the two error domains can't be confused: exports
// report failure as a negative errno, and a negative UB_* value negated
// would look like a success.
static int ub_errno(int r) {
    switch (r) {
    case UB_NOMEM:
        return ENOMEM;
    case UB_SYNTAX:
        return EINVAL;
    default:
        return EIO;
    }
}

static char *copy_input(uint32_t ptr, uint32_t len) {
    char *buf = malloc((size_t)len + 1);
    if (!buf)
        return NULL;
    if (len)
        memcpy(buf, (void *)(uintptr_t)ptr, len);
    buf[len] = 0;
    return buf;
}

// apply_lines feeds a saved init input to the context, one line at a time:
// "option:=value" pairs for the config, trust anchor records, or root hint
// addresses. Blank lines and #-comments are skipped. Modifies text in place.
//
// Root hint addresses become a prime stub for the root zone, libunbound's
// API for custom root hints: it replaces the compiled-in root hints, and
// the full root server set is primed from those addresses like it would be
// from a root-hints file.
enum input_kind { INPUT_CFG, INPUT_ANCHORS, INPUT_HINTS };
static int apply_lines(char *text, enum input_kind kind) {
    for (char *line = text; line && *line;) {
        char *next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        while (*line == ' ' || *line == '\t' || *line == '\r')
            line++;
        if (*line && *line != '#') {
            char *end = line + strlen(line);
            while (end > line && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
                *--end = 0;
            int r;
            if (kind == INPUT_ANCHORS) {
                r = ub_ctx_add_ta(ctx, line);
            } else if (kind == INPUT_HINTS) {
                r = ub_ctx_set_stub(ctx, ".", line, 1);
            } else {
                char *sep = strchr(line, '=');
                if (!sep)
                    return EINVAL;
                *sep++ = 0;
                r = ub_ctx_set_option(ctx, line, sep);
            }
            if (r)
                return ub_errno(r);
        }
        line = next;
    }
    return 0;
}

// ensure_ctx creates the libunbound context on the first resolution, not in
// init, so that init stays free of clock, entropy, socket, and timer imports
// as the ABI requires. The first uw_now_* calls anchor the guest clocks.
//
// A failure is sticky: a partially configured context (say, half of the
// trust anchors applied) would otherwise satisfy the ctx check on the next
// resolution and quietly validate less than it was told to.
static int ensure_ctx(void) {
    if (ctx_err)
        return ctx_err;
    if (ctx)
        return 0;
    (void)uw_now_wall_ms();
    (void)uw_now_mono_ms();
    ctx = ub_ctx_create_ub_event(uw_event_base());
    if (!ctx)
        return ctx_err = ENOMEM;
    int r;
    if (saved_cfg && (r = apply_lines(saved_cfg, INPUT_CFG)) != 0)
        return ctx_err = r;
    if (saved_anchors && (r = apply_lines(saved_anchors, INPUT_ANCHORS)) != 0)
        return ctx_err = r;
    if (saved_hints && (r = apply_lines(saved_hints, INPUT_HINTS)) != 0)
        return ctx_err = r;
    return 0;
}

static void result_cb(void *arg, int rcode, void *packet, int packet_len,
                      int sec, char *why_bogus, int was_ratelimited) {
    (void)was_ratelimited;
    struct result_slot *s = arg;
    if (!s || !s->used)
        return;
    s->rcode = rcode;
    s->sec = sec;
    if (packet && packet_len > 0) {
        s->packet = malloc((size_t)packet_len);
        if (s->packet) {
            memcpy(s->packet, packet, (size_t)packet_len);
            s->packet_len = (uint32_t)packet_len;
        } else {
            s->rcode = 2; // SERVFAIL
        }
    }
    if (why_bogus) {
        size_t n = strlen(why_bogus) + 1;
        s->why_bogus = malloc(n);
        if (s->why_bogus)
            memcpy(s->why_bogus, why_bogus, n);
    }
    s->ubid = 0;
    s->ready = 1;
}

static void clear_result(struct result_slot *s) {
    free(s->packet);
    free(s->why_bogus);
    memset(s, 0, sizeof(*s));
}

UW_EXPORT("unbound_wasm_abi_version")
uint32_t guest_abi_version(void) { return UNBOUND_WASM_ABI_VERSION; }

UW_EXPORT("alloc")
uint32_t guest_alloc(uint32_t n) { return (uint32_t)(uintptr_t)malloc(n ? n : 1); }

UW_EXPORT("dealloc")
void guest_dealloc(uint32_t ptr, uint32_t n) {
    (void)n;
    free((void *)(uintptr_t)ptr);
}

UW_EXPORT("init")
int32_t guest_init(uint32_t cfg, uint32_t cfg_len, uint32_t anchors, uint32_t anchors_len,
                   uint32_t hints, uint32_t hints_len) {
    if (ctx || saved_cfg)
        return -EALREADY;
    saved_cfg = copy_input(cfg, cfg_len);
    saved_anchors = copy_input(anchors, anchors_len);
    saved_hints = copy_input(hints, hints_len);
    if (!saved_cfg || !saved_anchors || !saved_hints)
        return -ENOMEM;
    return 0;
}

UW_EXPORT("resolve_start")
int32_t guest_resolve_start(uint32_t qname, uint32_t len, uint32_t qtype, uint32_t qclass) {
    int r = ensure_ctx();
    if (r)
        return -r;
    char *name = copy_input(qname, len);
    if (!name)
        return -ENOMEM;
    int i;
    for (i = 0; i < MAX_RESULTS; i++)
        if (!results[i].used)
            break;
    if (i == MAX_RESULTS) {
        free(name);
        return -ENOSPC;
    }
    results[i].used = 1;
    int ubid = 0;
    r = ub_resolve_event(ctx, name, (int)qtype, (int)qclass, &results[i], result_cb, &ubid);
    free(name);
    if (r) {
        clear_result(&results[i]);
        return -ub_errno(r);
    }
    results[i].ubid = ubid;
    return i + 1;
}

UW_EXPORT("io_ready")
void guest_io_ready(int32_t sid, int32_t flags) {
    int fd = uw_socket_fd_for_sid(sid);
    if (fd >= 0)
        uw_io_ready(fd, flags);
}

UW_EXPORT("timer_fired")
void guest_timer_fired(int64_t tid) { uw_timer_fired(tid); }

UW_EXPORT("result_get")
int32_t guest_result_get(int32_t rid, uint32_t out_ptr) {
    if (rid <= 0 || rid > MAX_RESULTS || !results[rid - 1].used)
        return -ENOENT;
    struct result_slot *s = &results[rid - 1];
    if (!s->ready)
        return UNBOUND_WASM_RESULT_PENDING;
    struct unbound_wasm_result *out = (void *)(uintptr_t)out_ptr;
    memset(out, 0, sizeof(*out));
    out->sec_status = s->sec == 2   ? UNBOUND_WASM_SEC_SECURE
                      : s->sec == 1 ? UNBOUND_WASM_SEC_BOGUS
                                    : UNBOUND_WASM_SEC_INSECURE;
    out->rcode = (uint32_t)s->rcode;
    out->why_bogus_ptr = (uint32_t)(uintptr_t)s->why_bogus;
    out->why_bogus_len = s->why_bogus ? (uint32_t)strlen(s->why_bogus) : 0;
    out->answer_packet_ptr = (uint32_t)(uintptr_t)s->packet;
    out->answer_packet_len = s->packet_len;
    return UNBOUND_WASM_RESULT_READY;
}

UW_EXPORT("resolve_cancel")
void guest_resolve_cancel(int32_t rid) {
    if (rid <= 0 || rid > MAX_RESULTS)
        return;
    struct result_slot *s = &results[rid - 1];
    if (!s->used)
        return;
    if (ctx && s->ubid)
        ub_cancel(ctx, s->ubid);
    clear_result(s);
}
