// Numeric-only netdb replacements. wasm32-wasi has no name service, and the
// guest must never resolve names through anything but its own iterator, so
// getaddrinfo and getnameinfo handle only IP literals, and the service and
// protocol databases know exactly the entries Unbound asks about.

#include "backends/netdb.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int getaddrinfo(const char *host, const char *service,
                const struct addrinfo *hints, struct addrinfo **out) {
    int af = hints ? hints->ai_family : AF_UNSPEC;
    int port = 0;
    if (!out)
        return EAI_FAIL;
    *out = NULL;
    if (service) {
        char *end;
        long p = strtol(service, &end, 10);
        if (*end || p < 0 || p > 65535)
            return EAI_SERVICE;
        port = (int)p;
    }
    if (!host)
        host = (af == AF_INET6) ? "::" : "0.0.0.0";
    if (af == AF_UNSPEC)
        af = strchr(host, ':') ? AF_INET6 : AF_INET;
    if (af != AF_INET && af != AF_INET6)
        return EAI_FAMILY;

    // A single allocation holds the addrinfo and its sockaddr.
    size_t addrlen = af == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    struct addrinfo *a = calloc(1, sizeof(*a) + addrlen);
    if (!a)
        return EAI_MEMORY;
    a->ai_family = af;
    a->ai_socktype = hints ? hints->ai_socktype : 0;
    a->ai_protocol = hints ? hints->ai_protocol : 0;
    a->ai_addrlen = (socklen_t)addrlen;
    a->ai_addr = (void *)(a + 1);
    if (af == AF_INET) {
        struct sockaddr_in *s = (void *)a->ai_addr;
        s->sin_family = AF_INET;
        s->sin_port = htons((uint16_t)port);
        if (inet_pton(af, host, &s->sin_addr) != 1) {
            free(a);
            return EAI_NONAME;
        }
    } else {
        struct sockaddr_in6 *s = (void *)a->ai_addr;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons((uint16_t)port);
        if (inet_pton(af, host, &s->sin6_addr) != 1) {
            free(a);
            return EAI_NONAME;
        }
    }
    *out = a;
    return 0;
}

void freeaddrinfo(struct addrinfo *a) {
    while (a) {
        struct addrinfo *next = a->ai_next;
        free(a->ai_canonname);
        free(a);
        a = next;
    }
}

int getnameinfo(const struct sockaddr *sa, socklen_t sl, char *host, socklen_t hl,
                char *serv, socklen_t sv, int flags) {
    (void)flags;
    const void *addr;
    uint16_t port;
    if (sa->sa_family == AF_INET && sl >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *s = (const void *)sa;
        addr = &s->sin_addr;
        port = ntohs(s->sin_port);
    } else if (sa->sa_family == AF_INET6 && sl >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *s = (const void *)sa;
        addr = &s->sin6_addr;
        port = ntohs(s->sin6_port);
    } else {
        return EAI_FAMILY;
    }
    if (host && !inet_ntop(sa->sa_family, addr, host, hl))
        return EAI_FAIL;
    if (serv && snprintf(serv, sv, "%u", port) < 0)
        return EAI_FAIL;
    return 0;
}

const char *gai_strerror(int e) {
    (void)e;
    return "name service unavailable";
}

struct hostent *gethostbyname(const char *name) {
    (void)name;
    return NULL;
}

struct servent *getservbyname(const char *name, const char *proto) {
    static struct servent s;
    (void)proto;
    if (strcmp(name, "domain") && strcmp(name, "53"))
        return NULL;
    s.s_port = htons(53);
    return &s;
}

struct servent *getservbyport(int port, const char *proto) {
    static struct servent s;
    (void)proto;
    if (ntohs((uint16_t)port) != 53)
        return NULL;
    s.s_name = "domain";
    s.s_port = port;
    return &s;
}

struct protoent *getprotobyname(const char *name) {
    static struct protoent p;
    if (!strcmp(name, "udp"))
        p.p_proto = IPPROTO_UDP;
    else if (!strcmp(name, "tcp"))
        p.p_proto = IPPROTO_TCP;
    else
        return NULL;
    return &p;
}

struct protoent *getprotobynumber(int proto) {
    static struct protoent p;
    if (proto == IPPROTO_UDP)
        p.p_name = "udp";
    else if (proto == IPPROTO_TCP)
        p.p_name = "tcp";
    else
        return NULL;
    p.p_proto = proto;
    return &p;
}

void endservent(void) {}
void endprotoent(void) {}
