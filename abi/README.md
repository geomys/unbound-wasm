# unbound-wasm ABI v0 (normative)

All integers are little-endian WebAssembly values. `ptr` is an offset into the
calling module's linear memory. Import module names are exactly
`unbound_wasm` and `wasi_snapshot_preview1`. Host calls return `-errno` on
failure unless stated otherwise; errno values use the WASI
(`wasi_snapshot_preview1`) numbering on both sides of the boundary, matching
the guest's wasi-libc. Unknown socket options may be accepted as no-ops, but
policy-denied operations return `-EACCES`.

The guest exports `unbound_wasm_abi_version() -> i32`, currently 0. The ABI
is unstable while at v0: it carries no compatibility promises, any signature
or layout may change without notice, and a host must reject any version other
than the one it was built against — host and module are expected to come from
the same source tree. Version numbering with compatibility rules will come
with stabilization.

## Imports

```text
sock_open(af, type) -> sid                 af: 4 or 6; type: 1 UDP, 2 TCP
sock_bind(sid, port) -> errno
sock_connect(sid, ip, iplen, port) -> errno
sock_send(sid, buf, len) -> bytes
sock_send_to(sid, ip, iplen, port, buf, len) -> bytes
sock_recv(sid, buf, cap) -> bytes
sock_recv_from(sid, buf, cap, ip_out, port_out) -> bytes
sock_error(sid) -> errno                   SO_ERROR semantics
sock_local_port(sid) -> port
sock_close(sid)
timer_start(ms) -> tid                     one-shot
timer_stop(tid)
now_wall_ms() -> milliseconds since Unix epoch
now_mono_ms() -> monotonic milliseconds
entropy(buf, len)
crypto_supported(algorithm) -> bool
crypto_verify(algorithm, key, klen, data, dlen, sig, slen) -> bool
crypto_digest(digest, data, len, out) -> bool
nsec3_hash(salt, slen, iterations, name, nlen, out) -> bool
log_msg(level, msg, len)
abort_msg(code, msg, len)                   host terminates instance
```

IP buffers are exactly 4 or 16 network-order bytes. `sock_recv_from` writes 16
bytes at `ip_out` (IPv4 occupies the first four and the rest are zero) and a
little-endian `u32` port at `port_out`. Socket readiness flags are READ=1,
WRITE=2, ERR=4.

DNSSEC algorithm numbers follow IANA DNS SECURITY ALGORITHM NUMBERS. Digest
numbers follow DS RR digest types. `nsec3_hash` computes SHA-1 over `name ||
salt`, then `iterations` additional rounds over `previous || salt`, and writes
20 bytes.

## Exports

```text
unbound_wasm_abi_version() -> i32
alloc(len) -> ptr
dealloc(ptr, len)
init(cfg, clen, anchors, alen, hints, hlen) -> errno
resolve_start(qname, len, qtype, qclass) -> rid
io_ready(sid, flags)
timer_fired(tid)
result_get(rid, out) -> 0 pending | 1 ready | negative errno
resolve_cancel(rid)
```

`init` is called exactly once and must not call clock, entropy, socket, or timer
imports. Names passed to `resolve_start` are presentation-format absolute DNS
names and include a trailing dot. The guest owns result buffers until
`resolve_cancel`, instance close, or a later documented invalidation; the host
copies them before returning.

## Result layout

`result_get` writes 32 bytes:

| Offset | Type | Field |
|---:|---|---|
| 0 | u32 | sec_status: 0 insecure, 1 secure, 2 bogus |
| 4 | u32 | rcode |
| 8/12 | ptr/u32 | why_bogus |
| 16/20 | ptr/u32 | full wire-format answer packet |
| 24..31 | u32[2] | reserved, must be zero |

Everything else about an answer — records, TTLs, CNAME chains, presence of
data — is derived by the host from the answer packet.

## Minimal WASI

The reference host implements only `clock_time_get`, `random_get`, `fd_write`
for stdout/stderr, `proc_exit`, `environ_sizes_get`, and `environ_get`.
Unimplemented functions are not linked; modules requesting them fail
instantiation. No filesystem, arguments, environment, or polling capability is
provided.

## Embedder guide

The reference Go host is intentionally not required. A conforming embedder:

1. Instantiates one guest per isolation domain and rejects any ABI version
   other than the one it was built for.
2. Exposes only the imports above; no stock WASI environment.
3. Serializes every guest export. Imports must never re-enter the guest.
4. Delivers readiness and timer events only by calling `io_ready` and
   `timer_fired` after the active export returns.
5. Treats every connect/send destination as a policy checkpoint.
6. Copies result data while the guest allocation is valid.
7. Tears the instance down after a trap, abort, deadline, or memory limit.

The guest uses high-numbered libc descriptors internally, but import `sid`
values are opaque host handles. IP addresses are 4 or 16 raw network-order
bytes. All socket operations are nonblocking.

### Initialization inputs

The reference guest accepts canonical config as newline-delimited
`option:=value` pairs, trust anchors as newline-delimited presentation-format
RRs, and root hints as newline-delimited literal IP addresses. Blank lines and
`#` comments are ignored. An empty root-hints input selects Unbound's built-in
root hints; a non-empty one replaces them, and the current root server set is
primed from the given addresses. Context creation is deferred until the first
query so `init` consumes no clock, entropy, sockets, or timers.

### Restricted WASI

Filesystem and polling imports return `ENOSYS` or trap. The guest performs
networking exclusively through `unbound_wasm`; linking a stock WASI provider
would violate the capability model.
