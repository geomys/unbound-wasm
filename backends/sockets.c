// The uw_* implementations behind sockets_remap.h: a minimal BSD sockets
// veneer over the host's sock_* imports. Descriptors returned to Unbound
// start at FD_BASE so they can never collide with the wasi-libc descriptors
// Unbound also holds. Process-related calls are stubs: the guest is a
// single-threaded library build that never forks, listens, or accepts.

#define UNBOUND_WASM_SOCKETS_IMPL 1
#include "backends/sockets_remap.h"
#include "abi/unbound_wasm_abi.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FD_BASE UNBOUND_WASM_SOCKET_FD_BASE
#define MAX_SOCKETS 128

struct slot {
    int used;
    int sid; // host socket ID
    int af, type;
    unsigned char peer[16]; // connected remote, for getpeername
    int peerlen, peerport;
};
static struct slot slots[MAX_SOCKETS];

static struct slot *lookup(int fd) {
    int n = fd - FD_BASE;
    return n >= 0 && n < MAX_SOCKETS && slots[n].used ? &slots[n] : NULL;
}

// uw_socket_fd_for_sid translates a host socket ID from an io_ready
// delivery back to the descriptor Unbound registered events under.
int uw_socket_fd_for_sid(int sid) {
    for (int i = 0; i < MAX_SOCKETS; i++)
        if (slots[i].used && slots[i].sid == sid)
            return FD_BASE + i;
    return -1;
}

// Host imports return -errno; fail converts that to the -1-and-errno
// convention of the POSIX functions.
static int fail(int r) {
    if (r < 0) {
        errno = -r;
        return -1;
    }
    return r;
}

static int decode(const struct sockaddr *sa, socklen_t n, unsigned char ip[16],
                  int *len, int *port) {
    if (!sa) {
        errno = EFAULT;
        return -1;
    }
    if (sa->sa_family == AF_INET && n >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *a = (const void *)sa;
        memcpy(ip, &a->sin_addr, 4);
        *len = 4;
        *port = ntohs(a->sin_port);
        return 0;
    }
    if (sa->sa_family == AF_INET6 && n >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *a = (const void *)sa;
        memcpy(ip, &a->sin6_addr, 16);
        *len = 16;
        *port = ntohs(a->sin6_port);
        return 0;
    }
    errno = EAFNOSUPPORT;
    return -1;
}

static int encode(struct sockaddr *sa, socklen_t *n, int af,
                  const unsigned char ip[16], int port) {
    if (!sa || !n) {
        errno = EFAULT;
        return -1;
    }
    if (af == AF_INET) {
        struct sockaddr_in a;
        if (*n < sizeof(a)) {
            errno = EINVAL;
            return -1;
        }
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((uint16_t)port);
        memcpy(&a.sin_addr, ip, 4);
        memcpy(sa, &a, sizeof(a));
        *n = sizeof(a);
        return 0;
    }
    struct sockaddr_in6 a;
    if (*n < sizeof(a)) {
        errno = EINVAL;
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_port = htons((uint16_t)port);
    memcpy(&a.sin6_addr, ip, 16);
    memcpy(sa, &a, sizeof(a));
    *n = sizeof(a);
    return 0;
}

int uw_socket(int af, int type, int protocol) {
    (void)protocol;
    // SOCK_DGRAM and SOCK_STREAM are enum values in wasi-libc, not flag
    // bits, so they must be compared, not masked.
    int ht = type == SOCK_DGRAM ? 1 : (type == SOCK_STREAM ? 2 : 0);
    if ((af != AF_INET && af != AF_INET6) || !ht) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    int sid = uw_sock_open(af == AF_INET ? 4 : 6, ht);
    if (sid < 0)
        return fail(sid);
    for (int i = 0; i < MAX_SOCKETS; i++)
        if (!slots[i].used) {
            memset(&slots[i], 0, sizeof(slots[i]));
            slots[i].used = 1;
            slots[i].sid = sid;
            slots[i].af = af;
            slots[i].type = ht;
            return FD_BASE + i;
        }
    uw_sock_close(sid);
    errno = EMFILE;
    return -1;
}

int uw_bind(int fd, const struct sockaddr *sa, socklen_t n) {
    struct slot *s = lookup(fd);
    unsigned char ip[16];
    int l, p;
    if (!s) {
        errno = EBADF;
        return -1;
    }
    if (decode(sa, n, ip, &l, &p))
        return -1;
    return fail(uw_sock_bind(s->sid, p));
}

int uw_connect(int fd, const struct sockaddr *sa, socklen_t n) {
    struct slot *s = lookup(fd);
    unsigned char ip[16];
    int l, p;
    if (!s) {
        errno = EBADF;
        return -1;
    }
    if (decode(sa, n, ip, &l, &p))
        return -1;
    int r = uw_sock_connect(s->sid, ip, l, p);
    if (r < 0)
        return fail(r);
    memcpy(s->peer, ip, l);
    s->peerlen = l;
    s->peerport = p;
    return 0;
}

ssize_t uw_send(int fd, const void *buf, size_t n, int flags) {
    (void)flags;
    struct slot *s = lookup(fd);
    if (!s) {
        errno = EBADF;
        return -1;
    }
    if (n > INT32_MAX)
        n = INT32_MAX;
    return fail(uw_sock_send(s->sid, buf, (int32_t)n));
}

ssize_t uw_sendto(int fd, const void *buf, size_t n, int flags,
                  const struct sockaddr *sa, socklen_t sl) {
    (void)flags;
    struct slot *s = lookup(fd);
    unsigned char ip[16];
    int l, p;
    if (!s) {
        errno = EBADF;
        return -1;
    }
    if (decode(sa, sl, ip, &l, &p))
        return -1;
    if (n > INT32_MAX)
        n = INT32_MAX;
    return fail(uw_sock_send_to(s->sid, ip, l, p, buf, (int32_t)n));
}

ssize_t uw_recv(int fd, void *buf, size_t n, int flags) {
    (void)flags;
    struct slot *s = lookup(fd);
    if (!s) {
        errno = EBADF;
        return -1;
    }
    if (n > INT32_MAX)
        n = INT32_MAX;
    return fail(uw_sock_recv(s->sid, buf, (int32_t)n));
}

ssize_t uw_recvfrom(int fd, void *buf, size_t n, int flags,
                    struct sockaddr *sa, socklen_t *sl) {
    (void)flags;
    struct slot *s = lookup(fd);
    unsigned char ip[16];
    uint32_t p = 0;
    if (!s) {
        errno = EBADF;
        return -1;
    }
    if (n > INT32_MAX)
        n = INT32_MAX;
    int r = uw_sock_recv_from(s->sid, buf, (int32_t)n, ip, &p);
    if (r < 0)
        return fail(r);
    if (sa && sl)
        encode(sa, sl, s->af, ip, (int)p);
    return r;
}

int uw_close(int fd) {
    struct slot *s = lookup(fd);
    if (!s)
        return 0;
    uw_sock_close(s->sid);
    memset(s, 0, sizeof(*s));
    return 0;
}

// uw_getsockname reports only the bound port (used for outgoing-port
// logging); the local address is reported as the wildcard.
int uw_getsockname(int fd, struct sockaddr *sa, socklen_t *n) {
    struct slot *s = lookup(fd);
    unsigned char ip[16] = {0};
    if (!s) {
        errno = EBADF;
        return -1;
    }
    int p = uw_sock_local_port(s->sid);
    if (p < 0)
        return fail(p);
    return encode(sa, n, s->af, ip, p);
}

int uw_getpeername(int fd, struct sockaddr *sa, socklen_t *n) {
    struct slot *s = lookup(fd);
    if (!s || !s->peerlen) {
        errno = ENOTCONN;
        return -1;
    }
    return encode(sa, n, s->af, s->peer, s->peerport);
}

// SO_ERROR reports the pending asynchronous error (TCP connects complete in
// the background host-side); SO_TYPE supports Unbound's socket introspection.
// Other options read as zero.
int uw_getsockopt(int fd, int level, int name, void *v, socklen_t *n) {
    struct slot *s = lookup(fd);
    int r = 0;
    if (!s) {
        errno = EBADF;
        return -1;
    }
    if (!v || !n || *n < sizeof(int)) {
        errno = EINVAL;
        return -1;
    }
    if (level == SOL_SOCKET && name == SO_ERROR)
        r = uw_sock_error(s->sid);
    else if (level == SOL_SOCKET && name == SO_TYPE)
        r = s->type == 1 ? SOCK_DGRAM : SOCK_STREAM;
    memcpy(v, &r, sizeof(r));
    *n = sizeof(r);
    return 0;
}

// Socket options Unbound sets (REUSEADDR, timestamping, buffer sizes, IP
// options) don't apply to host-managed sockets; accept them as no-ops.
int uw_setsockopt(int fd, int level, int name, const void *v, socklen_t n) {
    (void)level;
    (void)name;
    (void)v;
    (void)n;
    if (!lookup(fd)) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

// All host sockets are nonblocking; F_GETFL says so and F_SETFL agrees.
int uw_fcntl(int fd, int cmd, ...) {
    if (fd >= FD_BASE && !lookup(fd)) {
        errno = EBADF;
        return -1;
    }
    if (cmd == F_GETFL)
        return O_NONBLOCK;
    return 0;
}

int uw_shutdown(int fd, int how) {
    (void)fd;
    (void)how;
    return 0;
}

int uw_gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    if (!tv) {
        errno = EFAULT;
        return -1;
    }
    int64_t ms = uw_now_wall_ms();
    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms % 1000) * 1000;
    return 0;
}

// Never exercised on the libunbound event path; present because the code
// that calls them is compiled, not because it runs.

int uw_listen(int fd, int n) {
    (void)fd;
    (void)n;
    errno = ENOSYS;
    return -1;
}

int uw_accept(int fd, struct sockaddr *sa, socklen_t *n) {
    (void)fd;
    (void)sa;
    (void)n;
    errno = ENOSYS;
    return -1;
}

int uw_pipe(int p[2]) {
    (void)p;
    errno = ENOSYS;
    return -1;
}

int uw_socketpair(int af, int type, int protocol, int sv[2]) {
    (void)af;
    (void)type;
    (void)protocol;
    (void)sv;
    errno = ENOSYS;
    return -1;
}

pid_t uw_getpid(void) { return 1; }

pid_t uw_waitpid(pid_t pid, int *status, int options) {
    (void)pid;
    (void)status;
    (void)options;
    errno = ECHILD;
    return -1;
}

pid_t uw_fork(void) {
    errno = ENOSYS;
    return -1;
}
