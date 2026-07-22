// Package unbound embeds the Unbound recursive DNS resolver and DNSSEC
// validator, compiled to WebAssembly, and runs it in-process. Each resolver
// instance is confined to its own linear memory, and the host only lets it
// send packets to public unicast addresses on port 53.
//
// This is an independent distribution of Unbound and is not an NLnet Labs
// project.
package unbound

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
)

// DNS resource record types with first-class support in [Result]. A qtype is
// a plain IANA RR type number, so any other type can be queried directly; its
// records are then only available through [Result.AnswerPacket].
const (
	TypeA    uint16 = 1
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
	TypeCAA  uint16 = 257
)

// A Result is the answer to a single [Instance.Resolve] query that
// concluded with a NOERROR or NXDOMAIN response; every other outcome is an
// error.
type Result struct {
	// Secure reports whether the answer was DNSSEC-validated, like the AD
	// (Authenticated Data) flag of a validating resolver.
	Secure bool
	// HaveData reports whether the answer holds records of the queried
	// type, possibly after following a CNAME chain.
	HaveData bool
	// NXDomain reports whether the name was denied to exist.
	NXDomain bool
	// AnswerPacket is the full DNS answer message, in wire format.
	// Its record TTLs are clamped to zero by the resolver configuration,
	// which disables caching.
	AnswerPacket []byte

	addrs []netip.Addr
	txt   []string
	caa   []CAA
}

// Addrs returns the addresses in the answer, for [TypeA] and [TypeAAAA]
// queries.
func (r *Result) Addrs() []netip.Addr { return r.addrs }

// TXT returns the text records in the answer, for [TypeTXT] queries. The
// character-strings of each record are concatenated without separators.
func (r *Result) TXT() []string { return r.txt }

// CAA returns the Certification Authority Authorization records in the
// answer, for [TypeCAA] queries.
func (r *Result) CAA() []CAA { return r.caa }

// A CAA is a Certification Authority Authorization record (RFC 8659).
//
// Tag is returned as it appeared on the wire; RFC 8659 requires matching it
// case-insensitively. The high bit of Flags is the issuer critical flag
// (RFC 8659, Section 4.1): a consumer that does not recognize Tag must reject
// issuance when that bit is set, so callers must inspect Flags themselves.
type CAA struct {
	Flags uint8
	Tag   string
	Value string
}

// A BogusError is returned by [Instance.Resolve] when an answer fails DNSSEC
// validation.
type BogusError struct {
	// Reason is the validator's explanation of the failure.
	Reason string
	// EDE holds the Extended DNS Errors attached to the answer, if any.
	EDE []EDE
}

func (e *BogusError) Error() string { return "unbound: DNSSEC validation failed: " + e.Reason }

// A ResponseError is returned by [Instance.Resolve] when resolution concludes
// with a response code other than NOERROR or NXDOMAIN — most commonly
// 2 (SERVFAIL), which covers most resolution failures, from unreachable
// authoritative servers to expired signatures.
type ResponseError struct {
	// RCode is the DNS response code.
	RCode int
	// EDE holds the Extended DNS Errors attached to the failure, if any.
	EDE []EDE
}

func (e *ResponseError) Error() string {
	msg := "unbound: resolution failed: "
	switch e.RCode {
	case 1:
		msg += "FORMERR"
	case 2:
		msg += "SERVFAIL"
	case 4:
		msg += "NOTIMP"
	case 5:
		msg += "REFUSED"
	default:
		msg += fmt.Sprintf("rcode %d", e.RCode)
	}
	for _, ede := range e.EDE {
		msg += " (" + ede.String() + ")"
	}
	return msg
}

// An EDE is an Extended DNS Error (RFC 8914), a structured reason attached
// to an answer or a failure.
type EDE struct {
	// Code is an extended DNS error code (RFC 8914, Section 4).
	Code uint16
	// Text optionally holds human-readable additional information.
	Text string
}

// String returns the RFC 8914 name of Code, followed by Text.
func (e EDE) String() string {
	s := "EDE " + strconv.Itoa(int(e.Code))
	if int(e.Code) < len(edeNames) {
		s = edeNames[e.Code]
	}
	if e.Text != "" {
		s += ": " + e.Text
	}
	return s
}

// edeNames are the RFC 8914, Section 4 error names, indexed by code.
var edeNames = []string{
	"Other Error",
	"Unsupported DNSKEY Algorithm",
	"Unsupported DS Digest Type",
	"Stale Answer",
	"Forged Answer",
	"DNSSEC Indeterminate",
	"DNSSEC Bogus",
	"Signature Expired",
	"Signature Not Yet Valid",
	"DNSKEY Missing",
	"RRSIGs Missing",
	"No Zone Key Bit Set",
	"NSEC Missing",
	"Cached Error",
	"Not Ready",
	"Blocked",
	"Censored",
	"Filtered",
	"Prohibited",
	"Stale NXDOMAIN Answer",
	"Not Authoritative",
	"Not Supported",
	"No Reachable Authority",
	"Network Error",
	"Invalid Data",
}

// Config configures a Runtime. The zero value is a working default.
type Config struct {
	// MemoryLimit is the maximum memory of each Instance, in bytes,
	// rounded up to the wasm page size. If zero, it defaults to 64 MiB.
	MemoryLimit int64
	// TrustAnchors overrides the built-in IANA root trust anchors. It is
	// a list of DS or DNSKEY records in zone file format.
	TrustAnchors []byte
	// RootHints overrides the built-in root name server addresses, for
	// deployments that need to track root server renumberings ahead of a
	// package update. Each entry is a literal, public unicast IPv4 or
	// IPv6 address; the current root server set is fetched and validated
	// from those addresses when an Instance first resolves.
	RootHints []string
	// Log, if not nil, receives resolver log output.
	Log *slog.Logger
}

// ErrClosed is returned by methods of an [Instance] that has been closed,
// including one closed indirectly by a context cancellation or an internal
// error during a resolution.
var ErrClosed = errors.New("unbound: instance closed")
