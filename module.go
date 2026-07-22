package unbound

import _ "embed"

//go:embed unbound.wasm
var embeddedModule []byte

// moduleSHA256 is the SHA-256 of unbound.wasm. It is updated by
// `make module` and checked by TestEmbeddedModuleHash.
const moduleSHA256 = "f9ad30ce4a81ce656f53fb68820392462b329b5058253a83dfd892cad93763ef"

// defaultCanonicalConfig is the resolver configuration, applied line by line
// through ub_ctx_set_option. It matches Let's Encrypt's Unbound configuration
// (https://unboundtest.com/conf) except for options that only apply to a
// standalone daemon, with additions marked below. Notably, following Let's
// Encrypt: caching is disabled so every answer is fetched fresh; 0x20 case
// randomization and the unwanted-reply threshold harden unsigned zones
// against off-path spoofing; qname minimisation and harden-below-nxdomain
// are off for compatibility with broken authoritative servers; and answers
// naming internal addresses are scrubbed (private-address) while internal
// nameservers are never queried (do-not-query-address, also enforced by the
// host egress policy).
var defaultCanonicalConfig = []byte(`module-config:=validator iterator
do-ip4:=yes
do-ip6:=yes
do-udp:=yes
do-tcp:=yes
tcp-upstream:=no
edns-buffer-size:=1232
harden-glue:=yes
harden-dnssec-stripped:=yes
harden-below-nxdomain:=no
use-caps-for-id:=yes
cache-min-ttl:=0
cache-max-ttl:=0
cache-max-negative-ttl:=0
neg-cache-size:=0
prefetch:=no
unwanted-reply-threshold:=10000
do-not-query-localhost:=yes
val-clean-additional:=yes
val-sig-skew-min:=0
val-sig-skew-max:=0
ede:=yes
qname-minimisation:=no
qname-minimisation-strict:=no
val-log-level:=2
log-servfail:=yes
private-address:=192.168.0.0/16
private-address:=172.16.0.0/12
private-address:=10.0.0.0/8
private-address:=127.0.0.0/8
private-address:=0.0.0.0/8
private-address:=169.254.0.0/16
private-address:=192.0.0.0/24
private-address:=192.0.2.0/24
private-address:=198.51.100.0/24
private-address:=203.0.113.0/24
private-address:=192.88.99.0/24
private-address:=198.18.0.0/15
private-address:=224.0.0.0/4
private-address:=240.0.0.0/4
private-address:=255.255.255.255/32
private-address:=100.64.0.0/10
private-address:=::/128
private-address:=::1/128
private-address:=::ffff:0:0/96
private-address:=100::/64
private-address:=2001::/23
private-address:=2001:db8::/32
private-address:=fc00::/7
private-address:=fe80::/10
private-address:=ff00::/8
# Additions over the Let's Encrypt list: NAT64 and 6to4 translation
# prefixes, which can smuggle packets toward internal IPv4 space, the newer
# IPv6 documentation and SRv6 SID ranges, and the deprecated site-local and
# IPv4-compatible ranges, which a stack may still route toward internal space.
private-address:=64:ff9b::/96
private-address:=64:ff9b:1::/48
private-address:=2002::/16
private-address:=3fff::/20
private-address:=5f00::/16
private-address:=fec0::/10
private-address:=::/96
do-not-query-address:=192.168.0.0/16
do-not-query-address:=172.16.0.0/12
do-not-query-address:=10.0.0.0/8
do-not-query-address:=127.0.0.0/8
do-not-query-address:=0.0.0.0/8
do-not-query-address:=169.254.0.0/16
do-not-query-address:=192.0.0.0/24
do-not-query-address:=192.0.2.0/24
do-not-query-address:=198.51.100.0/24
do-not-query-address:=203.0.113.0/24
do-not-query-address:=192.88.99.0/24
do-not-query-address:=198.18.0.0/15
do-not-query-address:=224.0.0.0/4
do-not-query-address:=240.0.0.0/4
do-not-query-address:=255.255.255.255/32
do-not-query-address:=100.64.0.0/10
do-not-query-address:=::/128
do-not-query-address:=::1/128
do-not-query-address:=::ffff:0:0/96
do-not-query-address:=100::/64
do-not-query-address:=2001::/23
do-not-query-address:=2001:db8::/32
do-not-query-address:=fc00::/7
do-not-query-address:=fe80::/10
do-not-query-address:=ff00::/8
do-not-query-address:=64:ff9b::/96
do-not-query-address:=64:ff9b:1::/48
do-not-query-address:=2002::/16
do-not-query-address:=3fff::/20
do-not-query-address:=5f00::/16
do-not-query-address:=fec0::/10
do-not-query-address:=::/96
`)

// IANA root trust-anchor DS records. Both currently published KSKs are kept so
// an instance can validate across the root KSK rollover without filesystem
// state or RFC 5011 persistence.
var defaultTrustAnchors = []byte(`. 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
. 172800 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
`)
