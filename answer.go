package unbound

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// parseAnswer extracts the records for qname and qtype from AnswerPacket,
// following any CNAME chain, and fills HaveData and the typed record
// fields. A malformed packet is an error, so lookups fail closed rather than
// report an empty answer.
func (r *Result) parseAnswer(qname string, qtype uint16) error {
	if len(r.AnswerPacket) == 0 {
		return nil
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(r.AnswerPacket)
	if err != nil {
		return fmt.Errorf("unbound: malformed answer packet: %w", err)
	}
	// A truncated answer would normally have been retried over TCP by the
	// resolver; if one leaks through, fail rather than act on a possibly
	// incomplete RRset (a truncated CAA answer could be missing exactly
	// the record that forbids issuance).
	if hdr.Truncated {
		return errors.New("unbound: truncated answer")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return fmt.Errorf("unbound: malformed answer packet: %w", err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return fmt.Errorf("unbound: malformed answer packet: %w", err)
	}

	// Walk the CNAME chain from qname to the owner of the answer records.
	// Each step scans the answer section, so the walk is bounded by its
	// length, which also terminates malicious CNAME loops.
	owner := qname
	if qtype != uint16(dnsmessage.TypeCNAME) {
		for range answers {
			next, ok := cnameTarget(answers, owner)
			if !ok {
				break
			}
			owner = next
		}
	}

	for _, rr := range answers {
		if uint16(rr.Header.Type) != qtype || !nameEqual(rr.Header.Name.String(), owner) {
			continue
		}
		r.HaveData = true
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			r.addrs = append(r.addrs, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			r.addrs = append(r.addrs, netip.AddrFrom16(body.AAAA))
		case *dnsmessage.TXTResource:
			r.txt = append(r.txt, strings.Join(body.TXT, ""))
		case *dnsmessage.UnknownResource:
			if qtype == TypeCAA {
				caa, err := parseCAA(body.Data)
				if err != nil {
					return err
				}
				r.caa = append(r.caa, caa)
			}
		}
	}
	return nil
}

// parseEDE extracts the Extended DNS Errors from the OPT record of a wire
// format message. Extraction is best effort: EDEs are diagnostics, not
// inputs to any decision, so malformed packets or options yield nil rather
// than an error.
func parseEDE(packet []byte) []EDE {
	var edes []EDE
	var p dnsmessage.Parser
	if _, err := p.Start(packet); err != nil {
		return nil
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return nil
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return edes
		}
		if h.Type != dnsmessage.TypeOPT {
			if p.SkipAdditional() != nil {
				return edes
			}
			continue
		}
		opt, err := p.OPTResource()
		if err != nil {
			return edes
		}
		for _, o := range opt.Options {
			const optionEDE = 15 // RFC 8914
			if o.Code != optionEDE || len(o.Data) < 2 {
				continue
			}
			edes = append(edes, EDE{
				Code: binary.BigEndian.Uint16(o.Data),
				Text: strings.TrimSuffix(string(o.Data[2:]), "\x00"),
			})
		}
	}
}

func cnameTarget(answers []dnsmessage.Resource, owner string) (string, bool) {
	for _, rr := range answers {
		if rr.Header.Type == dnsmessage.TypeCNAME && nameEqual(rr.Header.Name.String(), owner) {
			return rr.Body.(*dnsmessage.CNAMEResource).CNAME.String(), true
		}
	}
	return "", false
}

// nameEqual compares domain names case-insensitively (RFC 4343). Names are in
// the dotted, escaped form produced by [dnsmessage.Name.String].
func nameEqual(a, b string) bool { return strings.EqualFold(a, b) }

func parseCAA(data []byte) (CAA, error) {
	if len(data) < 2 || data[1] == 0 || len(data) < 2+int(data[1]) {
		return CAA{}, errors.New("unbound: malformed CAA record")
	}
	tagLen := int(data[1])
	return CAA{Flags: data[0], Tag: string(data[2 : 2+tagLen]), Value: string(data[2+tagLen:])}, nil
}
