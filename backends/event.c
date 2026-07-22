// A pluggable ub_event backend with no event loop of its own: the host
// drives it. Unbound registers interest in socket readiness and timeouts
// through the vmts below; the host delivers both kinds of event by calling
// uw_io_ready and uw_timer_fired (via the guest's io_ready and timer_fired
// exports) between guest export invocations, never reentrantly.

#include "config.h"
#include "abi/unbound_wasm_abi.h"
#include "libunbound/unbound-event.h"
#include <stdint.h>
#include <stdlib.h>

struct uw_event {
    struct ub_event super;
    struct uw_event *next;
    int fd;
    short bits; // UB_EV_* interest set
    void (*cb)(int, short, void *);
    void *arg;
    int active;             // added and not deleted or (non-persistently) fired
    int firing;             // callback on the stack; defer any free
    int freed;              // freed while firing; release on callback return
    int64_t timer_id;       // pending host timer, 0 if none
    uint64_t last_dispatch; // uw_io_ready generation, to fire once per delivery
};

struct uw_base {
    struct ub_event_base super;
    struct uw_event *events;
    uint64_t generation;
};
static struct uw_base base;

static struct uw_event *as_event(struct ub_event *ev) { return (struct uw_event *)ev; }

static void unlink_event(struct uw_event *e) {
    struct uw_event **p = &base.events;
    while (*p && *p != e)
        p = &(*p)->next;
    if (*p == e)
        *p = e->next;
}

static void stop_timer(struct uw_event *e) {
    if (e->timer_id) {
        uw_timer_stop(e->timer_id);
        e->timer_id = 0;
    }
}

static int start_timer(struct uw_event *e, struct timeval *tv) {
    stop_timer(e);
    if (!tv)
        return 0;
    int64_t ms = (int64_t)tv->tv_sec * 1000 + (tv->tv_usec + 999) / 1000;
    if (ms > INT32_MAX)
        ms = INT32_MAX;
    e->timer_id = uw_timer_start((int32_t)ms);
    return e->timer_id ? 0 : -1;
}

// The ub_event vmt. The signal and winsock entry points exist only to
// satisfy the interface; nothing in this build raises signals or uses
// winsock.

static void event_add_bits(struct ub_event *ev, short bits) { as_event(ev)->bits |= bits; }
static void event_del_bits(struct ub_event *ev, short bits) { as_event(ev)->bits &= (short)~bits; }
static void event_set_fd(struct ub_event *ev, int fd) { as_event(ev)->fd = fd; }

static int event_del(struct ub_event *ev) {
    struct uw_event *e = as_event(ev);
    e->active = 0;
    stop_timer(e);
    return 0;
}

static void event_free(struct ub_event *ev) {
    struct uw_event *e = as_event(ev);
    event_del(ev);
    unlink_event(e);
    if (e->firing)
        e->freed = 1;
    else
        free(e);
}

static int event_add(struct ub_event *ev, struct timeval *tv) {
    struct uw_event *e = as_event(ev);
    e->active = 1;
    return start_timer(e, tv);
}

static int event_add_timer(struct ub_event *ev, struct ub_event_base *b,
                           void (*cb)(int, short, void *), void *arg, struct timeval *tv) {
    (void)b;
    struct uw_event *e = as_event(ev);
    e->fd = -1;
    e->bits = UB_EV_TIMEOUT;
    e->cb = cb;
    e->arg = arg;
    e->active = 1;
    return start_timer(e, tv);
}

static int event_del_timer(struct ub_event *ev) {
    stop_timer(as_event(ev));
    return 0;
}

static int event_add_signal(struct ub_event *ev, struct timeval *tv) {
    (void)ev;
    (void)tv;
    return -1;
}

static int event_del_signal(struct ub_event *ev) {
    (void)ev;
    return 0;
}

static void event_wsa_free(struct ub_event *ev) { event_free(ev); }

static void event_wouldblock(struct ub_event *ev, int bit) {
    (void)ev;
    (void)bit;
}

static struct ub_event_vmt event_vmt = {
    event_add_bits,   event_del_bits,   event_set_fd,   event_free,
    event_add,        event_del,        event_add_timer, event_del_timer,
    event_add_signal, event_del_signal, event_wsa_free,  event_wouldblock,
};

// The ub_event_base vmt. dispatch fails by design: the loop belongs to the
// host, and nothing on the libunbound event API path should ever enter it.

static void base_free(struct ub_event_base *b) { (void)b; }

static int base_dispatch(struct ub_event_base *b) {
    (void)b;
    return -1;
}

static int base_loopexit(struct ub_event_base *b, struct timeval *tv) {
    (void)b;
    (void)tv;
    return 0;
}

static struct ub_event *base_new_event(struct ub_event_base *b, int fd, short bits,
                                       void (*cb)(int, short, void *), void *arg) {
    struct uw_base *ub = (struct uw_base *)b;
    struct uw_event *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->super.magic = UB_EVENT_MAGIC;
    e->super.vmt = &event_vmt;
    e->fd = fd;
    e->bits = bits;
    e->cb = cb;
    e->arg = arg;
    e->next = ub->events;
    ub->events = e;
    return &e->super;
}

static struct ub_event *base_new_signal(struct ub_event_base *b, int fd,
                                        void (*cb)(int, short, void *), void *arg) {
    return base_new_event(b, fd, UB_EV_SIGNAL, cb, arg);
}

static struct ub_event *base_wsa(struct ub_event_base *b, void *w,
                                 void (*cb)(int, short, void *), void *arg) {
    (void)w;
    return base_new_event(b, -1, 0, cb, arg);
}

static struct ub_event_base_vmt base_vmt = {
    base_free, base_dispatch, base_loopexit, base_new_event, base_new_signal, base_wsa,
};

struct ub_event_base *uw_event_base(void) {
    if (!base.super.magic) {
        base.super.magic = UB_EVENT_MAGIC;
        base.super.vmt = &base_vmt;
    }
    return &base.super;
}

// uw_io_ready fires every registered event matching the readiness flags for
// fd. Callbacks may add or free events, so the list is rescanned from the
// head after each one; the generation counter keeps an event from firing
// twice in one delivery, and the firing/freed flags defer deallocation while
// a callback is on the stack.
//
// An error condition wakes both readers and writers: ub_event has no error
// bit, and Unbound collects the failure itself through SO_ERROR or a failing
// recv. Without this, an ICMP unreachable would sit undelivered until the
// retry timer, turning a fast failure into a timeout.
void uw_io_ready(int fd, int flags) {
    uint64_t gen = ++base.generation;
    short bits = 0;
    if (flags & UNBOUND_WASM_IO_READ)
        bits |= UB_EV_READ;
    if (flags & UNBOUND_WASM_IO_WRITE)
        bits |= UB_EV_WRITE;
    if (flags & UNBOUND_WASM_IO_ERR)
        bits |= UB_EV_READ | UB_EV_WRITE;
    for (;;) {
        struct uw_event *e;
        for (e = base.events; e; e = e->next)
            if (e->active && !e->firing && e->fd == fd && (e->bits & bits) &&
                e->last_dispatch != gen)
                break;
        if (!e)
            break;
        e->last_dispatch = gen;
        e->firing = 1;
        if (!(e->bits & UB_EV_PERSIST))
            e->active = 0;
        e->cb(e->fd, (short)(e->bits & bits), e->arg);
        if (e->freed)
            free(e);
        else
            e->firing = 0;
    }
}

void uw_timer_fired(int64_t tid) {
    struct uw_event *e;
    for (e = base.events; e; e = e->next)
        if (e->active && e->timer_id == tid)
            break;
    if (!e)
        return;
    e->timer_id = 0;
    e->firing = 1;
    e->cb(e->fd, UB_EV_TIMEOUT, e->arg);
    if (e->freed)
        free(e);
    else
        e->firing = 0;
}
