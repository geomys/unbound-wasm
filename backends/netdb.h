// wasi-libc ships no <netdb.h>; this provides the subset of its
// declarations that Unbound compiles against, implemented in compat.c.

#ifndef UNBOUND_WASM_NETDB_H
#define UNBOUND_WASM_NETDB_H

#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>

#define AI_PASSIVE 1
#define AI_CANONNAME 2
#define AI_NUMERICHOST 4
#define AI_NUMERICSERV 8

#define NI_NUMERICHOST 1
#define NI_NAMEREQD 2
#define NI_NUMERICSERV 4
#define NI_MAXHOST 1025
#define NI_MAXSERV 32

#define EAI_BADFLAGS -1
#define EAI_NONAME -2
#define EAI_AGAIN -3
#define EAI_FAIL -4
#define EAI_FAMILY -6
#define EAI_SOCKTYPE -7
#define EAI_SERVICE -8
#define EAI_MEMORY -10
#define EAI_SYSTEM -11

struct addrinfo {
    int ai_flags, ai_family, ai_socktype, ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype, h_length;
    char **h_addr_list;
};

struct servent {
    char *s_name;
    char **s_aliases;
    int s_port;
    char *s_proto;
};

struct protoent {
    char *p_name;
    char **p_aliases;
    int p_proto;
};

int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
void freeaddrinfo(struct addrinfo *);
int getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
const char *gai_strerror(int);
struct hostent *gethostbyname(const char *);
struct servent *getservbyname(const char *, const char *);
struct servent *getservbyport(int, const char *);
struct protoent *getprotobyname(const char *);
struct protoent *getprotobynumber(int);
void endservent(void);
void endprotoent(void);

#endif
