package unbound

import (
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type testRR struct {
	name  string
	typ   uint16
	ttl   uint32
	rdata any // dnsmessage resource body, or []byte for unknown types
}

func buildPacket(t *testing.T, qname string, qtype uint16, rrs []testRR) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(qname),
		Type:  dnsmessage.Type(qtype),
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, rr := range rrs {
		h := dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(rr.name),
			Type:  dnsmessage.Type(rr.typ),
			Class: dnsmessage.ClassINET,
			TTL:   rr.ttl,
		}
		var err error
		switch body := rr.rdata.(type) {
		case dnsmessage.AResource:
			err = b.AResource(h, body)
		case dnsmessage.AAAAResource:
			err = b.AAAAResource(h, body)
		case dnsmessage.CNAMEResource:
			err = b.CNAMEResource(h, body)
		case dnsmessage.TXTResource:
			err = b.TXTResource(h, body)
		case []byte:
			err = b.UnknownResource(h, dnsmessage.UnknownResource{Type: dnsmessage.Type(rr.typ), Data: body})
		default:
			t.Fatalf("unhandled rdata type %T", rr.rdata)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	pkt, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func caaRDATA(flags byte, tag, value string) []byte {
	return append(append([]byte{flags, byte(len(tag))}, tag...), value...)
}

func TestParseAnswer(t *testing.T) {
	cname := func(name string, ttl uint32, target string) testRR {
		return testRR{name, uint16(dnsmessage.TypeCNAME), ttl, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}}
	}
	a := func(name string, ttl uint32, ip string) testRR {
		return testRR{name, TypeA, ttl, dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}}
	}
	txt := func(name string, ttl uint32, ss ...string) testRR {
		return testRR{name, TypeTXT, ttl, dnsmessage.TXTResource{TXT: ss}}
	}

	for _, tt := range []struct {
		name     string
		qname    string
		qtype    uint16
		rrs      []testRR
		haveData bool
		addrs    []netip.Addr
		txt      []string
		caa      []CAA
	}{{
		name:     "A",
		qname:    "example.com.",
		qtype:    TypeA,
		rrs:      []testRR{a("example.com.", 300, "192.0.2.1"), a("example.com.", 60, "192.0.2.2")},
		haveData: true,
		addrs:    []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
	}, {
		name:  "AAAA",
		qname: "example.com.",
		qtype: TypeAAAA,
		rrs: []testRR{{"example.com.", TypeAAAA, 300,
			dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}}},
		haveData: true,
		addrs:    []netip.Addr{netip.MustParseAddr("2001:db8::1")},
	}, {
		name:     "CNAME chain to TXT",
		qname:    "_acme-challenge.example.com.",
		qtype:    TypeTXT,
		rrs:      []testRR{cname("_acme-challenge.example.com.", 30, "acme.example.net."), txt("acme.example.net.", 300, "token")},
		haveData: true,
		txt:      []string{"token"},
	}, {
		// The CNAME is in the answer section, but there are no records
		// of the queried type: NODATA, not HaveData.
		name:     "CNAME without data",
		qname:    "_acme-challenge.example.com.",
		qtype:    TypeTXT,
		rrs:      []testRR{cname("_acme-challenge.example.com.", 30, "acme.example.net.")},
		haveData: false,
	}, {
		name:     "CNAME loop",
		qname:    "a.example.com.",
		qtype:    TypeTXT,
		rrs:      []testRR{cname("a.example.com.", 30, "b.example.com."), cname("b.example.com.", 30, "a.example.com.")},
		haveData: false,
	}, {
		name:     "CNAME query",
		qname:    "a.example.com.",
		qtype:    uint16(dnsmessage.TypeCNAME),
		rrs:      []testRR{cname("a.example.com.", 30, "b.example.com.")},
		haveData: true,
	}, {
		name:     "TXT character-strings concatenated",
		qname:    "example.com.",
		qtype:    TypeTXT,
		rrs:      []testRR{txt("example.com.", 60, "v=spf1 ", "-all")},
		haveData: true,
		txt:      []string{"v=spf1 -all"},
	}, {
		name:     "CAA",
		qname:    "example.com.",
		qtype:    TypeCAA,
		rrs:      []testRR{{"example.com.", TypeCAA, 3600, caaRDATA(0, "issue", "ca.example.net")}},
		haveData: true,
		caa:      []CAA{{Flags: 0, Tag: "issue", Value: "ca.example.net"}},
	}, {
		name:     "case-insensitive owner",
		qname:    "example.com.",
		qtype:    TypeA,
		rrs:      []testRR{a("EXAMPLE.com.", 300, "192.0.2.1")},
		haveData: true,
		addrs:    []netip.Addr{netip.MustParseAddr("192.0.2.1")},
	}, {
		name:     "records for other names ignored",
		qname:    "example.com.",
		qtype:    TypeA,
		rrs:      []testRR{a("other.example.com.", 300, "192.0.2.1")},
		haveData: false,
	}, {
		name:     "empty answer",
		qname:    "example.com.",
		qtype:    TypeA,
		haveData: false,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			res := &Result{AnswerPacket: buildPacket(t, tt.qname, tt.qtype, tt.rrs)}
			if err := res.parseAnswer(tt.qname, tt.qtype); err != nil {
				t.Fatal(err)
			}
			if res.HaveData != tt.haveData {
				t.Errorf("HaveData = %v, want %v", res.HaveData, tt.haveData)
			}
			if !reflect.DeepEqual(res.Addrs(), tt.addrs) {
				t.Errorf("Addrs() = %v, want %v", res.Addrs(), tt.addrs)
			}
			if !reflect.DeepEqual(res.TXT(), tt.txt) {
				t.Errorf("TXT() = %v, want %v", res.TXT(), tt.txt)
			}
			if !reflect.DeepEqual(res.CAA(), tt.caa) {
				t.Errorf("CAA() = %v, want %v", res.CAA(), tt.caa)
			}
		})
	}
}

func TestParseEDE(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeServerFailure})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	var h dnsmessage.ResourceHeader
	if err := h.SetEDNS0(1232, dnsmessage.RCodeSuccess, true); err != nil {
		t.Fatal(err)
	}
	ede := append([]byte{0, 22}, "no servers could be reached"...)
	if err := b.OPTResource(h, dnsmessage.OPTResource{Options: []dnsmessage.Option{
		{Code: 15, Data: ede},
		{Code: 10, Data: []byte{1, 2, 3}}, // not an EDE, ignored
	}}); err != nil {
		t.Fatal(err)
	}
	pkt, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	want := []EDE{{Code: 22, Text: "no servers could be reached"}}
	if got := parseEDE(pkt); !reflect.DeepEqual(got, want) {
		t.Errorf("parseEDE() = %v, want %v", got, want)
	}
	if s := want[0].String(); s != "No Reachable Authority: no servers could be reached" {
		t.Errorf("String() = %q", s)
	}

	if got := parseEDE([]byte{0, 1, 2}); got != nil {
		t.Errorf("parseEDE() = %v on malformed packet", got)
	}
}

func TestParseAnswerMalformed(t *testing.T) {
	for _, tt := range []struct {
		name string
		pkt  []byte
	}{
		{"truncated header", []byte{0, 0, 0}},
		{"garbage", []byte("not a dns message, definitely long enough")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := &Result{AnswerPacket: tt.pkt}
			if err := res.parseAnswer("example.com.", TypeA); err == nil {
				t.Error("parseAnswer succeeded on malformed packet")
			}
		})
	}

	t.Run("truncated", func(t *testing.T) {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Truncated: true})
		if err := b.StartQuestions(); err != nil {
			t.Fatal(err)
		}
		pkt, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		res := &Result{AnswerPacket: pkt}
		if err := res.parseAnswer("example.com.", TypeCAA); err == nil {
			t.Error("parseAnswer accepted a truncated answer")
		}
	})

	t.Run("malformed CAA rdata", func(t *testing.T) {
		res := &Result{AnswerPacket: buildPacket(t, "example.com.", TypeCAA, []testRR{
			{"example.com.", TypeCAA, 60, []byte{0}}, // too short for flags+tag
		})}
		if err := res.parseAnswer("example.com.", TypeCAA); err == nil {
			t.Error("parseAnswer succeeded on malformed CAA record")
		}
	})
}
