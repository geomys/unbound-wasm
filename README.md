# unbound-wasm

> **Independent project:** this is an independent distribution of Unbound. It
> is not an NLnet Labs project and is not endorsed by NLnet Labs.

`unbound-wasm` packages Unbound's recursive resolver and DNSSEC validator as a
capability-oriented `wasm32-wasi` reactor and provides a Go host SDK based on
[wazero]. Every instance has isolated memory and can access the network only
through host imports that permit contacting public unicast addresses on
port 53, and nothing else.

The module path is `geomys.org/unbound-wasm`; the Go package name is `unbound`.

```go
rt, err := unbound.NewRuntime(ctx, unbound.Config{})
if err != nil { /* handle */ }
defer rt.Close(ctx)

inst, err := rt.NewInstance(ctx)
if err != nil { /* handle */ }
defer inst.Close(ctx)

result, err := inst.Resolve(ctx, "example.com.", unbound.TypeA)
```

`abi/README.md` is the normative ABI and embedder guide. The SDK always runs
the embedded `unbound.wasm`, whose SHA-256 is pinned in the package and
checked by tests.

## Build

Requirements: Docker, Go 1.25+, and Make.

```sh
make module        # pinned container build of unbound.wasm
make module-check  # embedded module matches its pinned hash
go test ./...
go vet ./...
```

`make module-local WASI_SDK=/opt/wasi-sdk` is available for development.
Downloaded archives are checksum-verified. The upstream source is not vendored.

# Threat model

The boundary assumes DNS packets and recursive state are hostile. Wasm linear
memory contains all upstream C state, and a new module instance is used for each
validation lifetime. A memory-safety failure can corrupt only that instance.

The design does not defend against a malicious host, or denial of service within
configured time/memory limits.

No guest filesystem, environment, process, listener, or ambient socket API is
provided. The host refuses to send packets anywhere but port 53 at addresses
outside the private and special-purpose ranges (the same list as Let's
Encrypt's Unbound configuration, plus the NAT64 and 6to4 translation
prefixes), so a compromised guest cannot probe internal networks. The guest
configuration mirrors Let's Encrypt's: no caching, 0x20 case randomization,
private-address scrubbing, and strict signature validity times. Hosts are
expected to have working IPv6, like Let's Encrypt's resolvers; on
development machines without it, set `UNBOUND_WASM_DISABLE_IPV6=1` or
resolutions will waste time (and spurious 0x20 fallbacks) on unreachable
IPv6 servers.

RSASHA1 (DNSSEC algorithms 5 and 7) is not supported: zones signed only with
SHA-1 validate as Insecure, per RFC 6840, like on other modern validators
that have disabled SHA-1 — where an OpenSSL-based Unbound build would still
validate them. Off-path spoofing of unsigned and SHA-1-signed zones is
mitigated by source port randomization, 0x20, and the unwanted-reply
threshold; CA deployments should additionally rely on multi-perspective
corroboration.

## Status

The ABI and SDK are at v0 and unstable: there are no compatibility promises
until stabilization, and the embedded module and host must come from the same
source tree.

## License

BSD-3-Clause. See `NOTICE` for upstream attribution.

[wazero]: https://github.com/tetratelabs/wazero
