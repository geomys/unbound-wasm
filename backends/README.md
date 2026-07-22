# backends

The C sources that connect stock Unbound, compiled as a `wasm32-wasi`
reactor, to the `unbound_wasm` host ABI (`abi/README.md`). They fall into
three groups, wired up by `build/build-module.sh`:

- **Linked alongside Unbound:** `guest.c`, `event.c`, `sockets.c`,
  `compat.c` are compiled as standalone objects.
- **Replacing upstream sources:** `random.c` overwrites `util/random.c` and
  `secalgo.c` overwrites `validator/val_secalgo.c` before the build.
- **Headers:** `sockets_remap.h` is force-included (`-include`) into every
  upstream translation unit; `netdb.h` provides declarations wasi-libc
  lacks.

The build also disables `HAVE_SENDMSG` and `HAVE_RECVMSG` in `config.h`, so
Unbound falls back to `sendto`/`recvfrom` and no `sendmsg`/`recvmsg`
implementation is needed.

## guest.c — ABI entry points

Implements the guest exports defined in `abi/README.md` (`init`,
`resolve_start`, `result_get`, …) as a thin adapter over libunbound's
`ub_resolve_event` API. Holds the resolution slot table and the saved init
inputs; creates the `ub_ctx` lazily on the first query so `init` performs no
capability calls. All answer interpretation is host-side: the guest returns
only the security status, rcode, `why_bogus`, and the wire-format packet.

## event.c — host-driven event backend

| Symbol | Why |
|---|---|
| `uw_event_base` | The `ub_event_base` handed to `ub_ctx_create_ub_event`; its `dispatch` fails by design because the host owns the loop |
| `uw_io_ready` | Called from the `io_ready` export; fires registered read/write events for a socket, at most once per delivery. ERR wakes both readers and writers, which collect the failure via `SO_ERROR`/`recv` |
| `uw_timer_fired` | Called from the `timer_fired` export; fires the matching timeout event |
| `ub_event` / `ub_event_base` vmts | Registration bookkeeping only — interest bits, host timer start/stop via `timer_start`/`timer_stop`, deferred free while a callback is on the stack. Signal and winsock entries are interface filler |

## sockets.c — BSD sockets veneer

Descriptors start at `0x40000000` (`UNBOUND_WASM_SOCKET_FD_BASE`) so they
never collide with wasi-libc descriptors. Host imports return `-errno`,
translated to the POSIX `-1` + `errno` convention.

| Symbol | Behavior | Why |
|---|---|---|
| `uw_socket`, `uw_bind`, `uw_connect`, `uw_send`, `uw_sendto`, `uw_recv`, `uw_recvfrom`, `uw_close` | Forward to the `sock_*` imports | Unbound's outgoing UDP/TCP traffic |
| `uw_socket_fd_for_sid` | Slot lookup | Routes `io_ready(sid)` deliveries back to the fd Unbound registered events under |
| `uw_getsockname` | Wildcard address + real port from `sock_local_port` | Outgoing-port selection and logging |
| `uw_getpeername` | Remote recorded at `connect` | TCP bookkeeping |
| `uw_getsockopt` | `SO_ERROR` from `sock_error`, `SO_TYPE` from the slot, else 0 | Async TCP connect completion; introspection |
| `uw_setsockopt` | Accept as no-op | REUSEADDR, buffer sizes, IP options don't apply to host-managed sockets |
| `uw_fcntl` | Reports `O_NONBLOCK` | All host sockets are nonblocking |
| `uw_shutdown` | No-op success | Close does the work |
| `uw_gettimeofday` | From `now_wall_ms` | Wall clock without WASI clocks |
| `uw_getpid` | Returns 1 | Log line identity |
| `uw_listen`, `uw_accept`, `uw_pipe`, `uw_socketpair`, `uw_fork`, `uw_waitpid` | `ENOSYS`/`ECHILD` | Compiled but unreachable on the libunbound event path: no listeners, no processes, no tubes |

## compat.c — numeric-only netdb

wasm32-wasi has no name service, and the guest must never resolve names
through anything but its own iterator.

| Symbol | Behavior | Why |
|---|---|---|
| `getaddrinfo` | IP literals only, else `EAI_NONAME` | Parsing addresses from config and root hints |
| `freeaddrinfo` | Frees the single-allocation result | Pairs with the above |
| `getnameinfo` | `inet_ntop` + numeric port | Address formatting for logs |
| `gai_strerror` | Static string | Error logging |
| `gethostbyname` | Always `NULL` | Must not succeed; only numeric lookups are legitimate |
| `getservbyname`, `getservbyport` | Only `"domain"`/53 | The single service Unbound asks about |
| `getprotobyname`, `getprotobynumber` | Only `udp`/`tcp` | Protocol table lookups |
| `endservent`, `endprotoent` | No-ops | Interface completeness |

## random.c — host entropy (replaces `util/random.c`)

| Symbol | Behavior |
|---|---|
| `ub_initstate`, `ub_randfree` | Allocate/free an empty state; the API requires an object, but there is no seed to keep |
| `ub_random` | 31-bit value from the `entropy` import |
| `ub_random_max` | Uniform in `[0, upper)` by rejection sampling |

## secalgo.c — host crypto (replaces `validator/val_secalgo.c`)

No crypto library is linked into the guest; verification, digests, and
NSEC3 hashing go through host imports. The host decides which DNSKEY
algorithms verify (the reference host: RSA-SHA256/512, ECDSA P-256/P-384,
Ed25519 — 8, 10, 13, 14, 15). The tables here must stay in sync with the
host's `crypto.go`.

| Symbol | Behavior | Why |
|---|---|---|
| `dnskey_algo_id_is_supported` | Asks `crypto_supported` | Unsupported algorithms degrade zones to insecure (RFC 6840) |
| `verify_canonrrset` | `crypto_verify`; unsupported → `unchecked`, failure → `bogus` | The single RRSIG verification entry point |
| `secalgo_ds_digest`, `ds_digest_size_supported` | `crypto_digest` for DS digests 1 (SHA-1), 2 (SHA-256), 4 (SHA-384) | DS-to-DNSKEY matching; GOST (3) unsupported |
| `secalgo_hash_sha256` | One-shot `crypto_digest` | Key tag and miscellaneous digests |
| `secalgo_hash_create_sha384`/`_sha512`, `_update`, `_final`, `_delete` | Buffer, then one-shot digest (selector 5 = SHA-512, ABI-private) | Streaming API used for ZONEMD; inputs are small |
| `secalgo_nsec3_hash`, `nsec3_hash_algo_size_supported` | `nsec3_hash` import, algorithm 1 (SHA-1) only | The host runs the full iterated hash; Unbound passes `name \|\| salt` per iteration |
