package unbound

import (
	"net/netip"
	"testing"
)

func TestEgressAllowed(t *testing.T) {
	allowed := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
		"[2001:503:ba3e::2:30]:53", // a.root-servers.net
		"[2620:fe::fe]:53",
	}
	denied := []string{
		"8.8.8.8:5353", // only port 53
		"8.8.8.8:853",
		"0.0.0.1:53",
		"10.0.0.1:53",
		"100.64.0.1:53", // RFC 6598 shared address space
		"100.127.255.255:53",
		"127.0.0.1:53",
		"127.8.8.8:53",
		"169.254.1.1:53",
		"172.16.0.1:53",
		"192.0.0.1:53",
		"192.0.2.1:53", // TEST-NET-1
		"192.88.99.1:53",
		"192.168.1.1:53",
		"198.18.0.1:53", // benchmarking
		"198.51.100.1:53",
		"203.0.113.1:53",
		"224.0.0.251:53",
		"240.0.0.1:53",
		"255.255.255.255:53",
		"0.0.0.0:53",
		"[::]:53",
		"[::1]:53",
		"[64:ff9b::a00:1]:53",   // NAT64-mapped 10.0.0.1
		"[64:ff9b:1::1]:53",     // local-use NAT64
		"[100::1]:53",           // discard
		"[2001::5]:53",          // Teredo, inside 2001::/23
		"[2001:2::1]:53",        // benchmarking
		"[2001:db8::1]:53",      // documentation
		"[2002:a00:1::1]:53",    // 6to4-mapped 10.0.0.1
		"[3fff::1]:53",          // documentation
		"[5f00::1]:53",          // SRv6 SIDs
		"[fc00::1]:53",          // unique-local
		"[fd00::1]:53",          // unique-local
		"[fe80::1]:53",          // link-local
		"[ff02::fb]:53",         // multicast
		"[::ffff:10.0.0.1]:53",  // 4-in-6 mapped private
		"[::ffff:127.0.0.1]:53", // 4-in-6 mapped loopback
		"[fec0::1]:53",          // deprecated site-local
		"[::10.0.0.1]:53",       // deprecated IPv4-compatible in ::/96
		"[100:0:0:1::1]:53",     // dummy prefix, outside 2000::/3
		"[4000::1]:53",          // reserved by IETF, outside global unicast
		"[8000::1]:53",          // reserved by IETF, outside global unicast
		"[c000::1]:53",          // reserved by IETF, outside global unicast
	}
	for _, s := range allowed {
		if !egressAllowed(netip.MustParseAddrPort(s)) {
			t.Errorf("egressAllowed(%s) = false, want true", s)
		}
	}
	for _, s := range denied {
		if egressAllowed(netip.MustParseAddrPort(s)) {
			t.Errorf("egressAllowed(%s) = true, want false", s)
		}
	}
}
