// C declarations for the unbound_wasm host ABI. README.md in this directory
// is the normative definition; the comments here are a summary for guest
// code. Host calls return -errno on failure unless noted otherwise, using
// WASI errno numbering on both sides of the boundary (the guest's libc is
// wasi-libc, so its errno constants are already the right values).

#ifndef UNBOUND_WASM_ABI_H
#define UNBOUND_WASM_ABI_H

#include <stdint.h>

// ABI v0 is unstable: any signature or layout may change without notice,
// and a host only accepts the exact version it was built against. Version
// numbering with compatibility rules will come with stabilization.
#define UNBOUND_WASM_ABI_VERSION 0u

// Guest-internal convention: the descriptors sockets.c hands to Unbound
// start here, above any wasi-libc descriptor.
#define UNBOUND_WASM_SOCKET_FD_BASE 0x40000000

// Readiness flags delivered to the io_ready export.
#define UNBOUND_WASM_IO_READ  1
#define UNBOUND_WASM_IO_WRITE 2
#define UNBOUND_WASM_IO_ERR   4

// unbound_wasm_result.sec_status values.
#define UNBOUND_WASM_SEC_INSECURE 0
#define UNBOUND_WASM_SEC_SECURE   1
#define UNBOUND_WASM_SEC_BOGUS    2

// result_get return values (or negative errno).
#define UNBOUND_WASM_RESULT_PENDING 0
#define UNBOUND_WASM_RESULT_READY   1

#if defined(__wasm__)
#define UW_IMPORT(name) __attribute__((import_module("unbound_wasm"), import_name(name)))
#define UW_EXPORT(name) __attribute__((visibility("default"), export_name(name)))
#else
#define UW_IMPORT(name)
#define UW_EXPORT(name)
#endif

// Written by the result_get export. The ptr/len pairs point into guest
// memory owned by the guest; they stay valid until resolve_cancel for the
// same rid or instance teardown, and the host copies them before returning.
struct unbound_wasm_result {
    uint32_t sec_status;
    uint32_t rcode;
    uint32_t why_bogus_ptr; // validation failure explanation, UTF-8, no NUL
    uint32_t why_bogus_len;
    uint32_t answer_packet_ptr; // full wire-format DNS answer message
    uint32_t answer_packet_len;
    uint32_t reserved[2]; // must be zero
};

// Sockets. af is 4 or 6; type is 1 for UDP, 2 for TCP. IP buffers are
// exactly 4 or 16 network-order bytes. All sockets are nonblocking: sends
// return the byte count, recv returns -EAGAIN when drained, and TCP
// connect completes in the background (poll uw_sock_error, SO_ERROR
// semantics, on the ERR readiness flag). Every connect/send destination is
// subject to host egress policy, which denies with -EACCES.
int32_t uw_sock_open(int32_t af, int32_t type) UW_IMPORT("sock_open");
int32_t uw_sock_bind(int32_t sid, int32_t port) UW_IMPORT("sock_bind");
int32_t uw_sock_connect(int32_t sid, const void *ip, int32_t iplen, int32_t port) UW_IMPORT("sock_connect");
int32_t uw_sock_send(int32_t sid, const void *buf, int32_t len) UW_IMPORT("sock_send");
int32_t uw_sock_send_to(int32_t sid, const void *ip, int32_t iplen, int32_t port, const void *buf, int32_t len) UW_IMPORT("sock_send_to");
int32_t uw_sock_recv(int32_t sid, void *buf, int32_t cap) UW_IMPORT("sock_recv");
// uw_sock_recv_from writes 16 bytes at ip_out (IPv4 in the first four,
// rest zero) and a little-endian u32 port at port_out.
int32_t uw_sock_recv_from(int32_t sid, void *buf, int32_t cap, void *ip_out, void *port_out) UW_IMPORT("sock_recv_from");
int32_t uw_sock_error(int32_t sid) UW_IMPORT("sock_error");
int32_t uw_sock_local_port(int32_t sid) UW_IMPORT("sock_local_port");
void uw_sock_close(int32_t sid) UW_IMPORT("sock_close");

// One-shot timers: the host calls the timer_fired export with tid after at
// least ms milliseconds. Returns a positive tid, or 0 on failure.
int64_t uw_timer_start(int32_t ms) UW_IMPORT("timer_start");
void uw_timer_stop(int64_t tid) UW_IMPORT("timer_stop");

int64_t uw_now_wall_ms(void) UW_IMPORT("now_wall_ms");  // ms since Unix epoch
int64_t uw_now_mono_ms(void) UW_IMPORT("now_mono_ms");  // monotonic ms
void uw_entropy(void *buf, int32_t len) UW_IMPORT("entropy");

// Cryptography. alg is an IANA DNSSEC algorithm number for supported and
// verify, and a DS digest type for digest (1 SHA-1, 2 SHA-256, 4 SHA-384;
// selector 5 is an ABI-private streaming SHA-512). Boolean results: 1
// supported/valid/done, 0 not. uw_nsec3_hash computes SHA-1 over
// name || salt, then iters additional rounds over previous || salt, and
// writes 20 bytes at out.
int32_t uw_crypto_supported(int32_t alg) UW_IMPORT("crypto_supported");
int32_t uw_crypto_verify(int32_t alg, const void *key, int32_t klen, const void *data, int32_t dlen, const void *sig, int32_t slen) UW_IMPORT("crypto_verify");
int32_t uw_crypto_digest(int32_t alg, const void *data, int32_t len, void *out) UW_IMPORT("crypto_digest");
int32_t uw_nsec3_hash(const void *salt, int32_t slen, int32_t iters, const void *name, int32_t nlen, void *out) UW_IMPORT("nsec3_hash");

// Logging. Levels: <= 0 debug, 1 info, 2 warning, >= 3 error.
// uw_abort_msg reports a fatal guest error; the host terminates the
// instance and the call does not return.
void uw_log_msg(int32_t level, const void *msg, int32_t len) UW_IMPORT("log_msg");
void uw_abort_msg(int32_t code, const void *msg, int32_t len) UW_IMPORT("abort_msg");

#endif
