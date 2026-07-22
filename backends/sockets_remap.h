// Force-included (via -include) into every upstream Unbound translation
// unit, redirecting the POSIX networking and process calls Unbound makes to
// the uw_* implementations in sockets.c, since wasm32-wasi provides none of
// them. sockets.c defines UNBOUND_WASM_SOCKETS_IMPL so that it sees the
// declarations without the renaming macros.
//
// sendmsg and recvmsg are deliberately absent: the build disables
// HAVE_SENDMSG and HAVE_RECVMSG, so no call sites survive preprocessing.

#ifndef UNBOUND_WASM_SOCKETS_REMAP_H
#define UNBOUND_WASM_SOCKETS_REMAP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stddef.h>
#include <stdarg.h>
#include <time.h>
#include "backends/netdb.h"

#ifndef SO_ERROR
#define SO_ERROR 4
#endif

int uw_socket(int, int, int);
int uw_bind(int, const struct sockaddr *, socklen_t);
int uw_connect(int, const struct sockaddr *, socklen_t);
ssize_t uw_send(int, const void *, size_t, int);
ssize_t uw_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t uw_recv(int, void *, size_t, int);
ssize_t uw_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
int uw_close(int);
int uw_getsockname(int, struct sockaddr *, socklen_t *);
int uw_getpeername(int, struct sockaddr *, socklen_t *);
int uw_getsockopt(int, int, int, void *, socklen_t *);
int uw_setsockopt(int, int, int, const void *, socklen_t);
int uw_fcntl(int, int, ...);
int uw_listen(int, int);
int uw_accept(int, struct sockaddr *, socklen_t *);
int uw_pipe(int[2]);
int uw_socketpair(int, int, int, int[2]);
int uw_shutdown(int, int);
int uw_gettimeofday(struct timeval *, void *);
pid_t uw_getpid(void);
pid_t uw_waitpid(pid_t, int *, int);
pid_t uw_fork(void);
char *ctime_r(const time_t *, char *);

#ifndef UNBOUND_WASM_SOCKETS_IMPL
#define socket uw_socket
#define bind uw_bind
#define connect uw_connect
#define send uw_send
#define sendto uw_sendto
#define recv uw_recv
#define recvfrom uw_recvfrom
#define close uw_close
#define getsockname uw_getsockname
#define getpeername uw_getpeername
#define getsockopt uw_getsockopt
#define setsockopt uw_setsockopt
#define fcntl uw_fcntl
#define listen uw_listen
#define accept uw_accept
#define pipe uw_pipe
#define socketpair uw_socketpair
#define shutdown uw_shutdown
#define gettimeofday uw_gettimeofday
#define getpid uw_getpid
#define waitpid uw_waitpid
#define fork uw_fork
#endif

#endif
