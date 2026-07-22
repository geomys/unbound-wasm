// Command unbound-wasm-resolve resolves and validates a single name with the
// embedded resolver and prints the result as JSON, for debugging and smoke
// tests.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	unbound "geomys.org/unbound-wasm"
)

func main() {
	timeout := flag.Duration("timeout", 15*time.Second, "resolution deadline")
	rootHints := flag.String("root-hints", "", "comma-separated root server addresses overriding the built-in root hints")
	verbose := flag.Bool("v", false, "write resolver logs to standard error")
	flag.Parse()
	if flag.NArg() < 1 || flag.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "usage: unbound-wasm-resolve [flags] name [type]")
		os.Exit(2)
	}
	name := flag.Arg(0)
	typ := unbound.TypeA
	if flag.NArg() == 2 {
		var ok bool
		typ, ok = qtype(flag.Arg(1))
		if !ok {
			log.Fatalf("unknown query type %q", flag.Arg(1))
		}
	}

	var cfg unbound.Config
	if *rootHints != "" {
		cfg.RootHints = strings.Split(*rootHints, ",")
	}
	if *verbose {
		cfg.Log = slog.New(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rt, err := unbound.NewRuntime(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(context.Background())
	inst, err := rt.NewInstance(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer inst.Close(context.Background())
	res, err := inst.Resolve(ctx, name, typ)
	if err != nil {
		log.Fatal(err)
	}

	out := struct {
		Name     string        `json:"name"`
		Type     uint16        `json:"type"`
		Secure   bool          `json:"secure"`
		HaveData bool          `json:"have_data"`
		NXDomain bool          `json:"nxdomain"`
		Addrs    []netip.Addr  `json:"addrs,omitempty"`
		TXT      []string      `json:"txt,omitempty"`
		CAA      []unbound.CAA `json:"caa,omitempty"`
		Answer   string        `json:"answer_packet_base64"`
	}{name, typ, res.Secure, res.HaveData, res.NXDomain,
		res.Addrs(), res.TXT(), res.CAA(), base64.StdEncoding.EncodeToString(res.AnswerPacket)}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		log.Fatal(err)
	}
}

// qtype maps the type mnemonics with first-class [unbound.Result] support to
// their numbers; any other type can be queried by its IANA RR type number.
func qtype(s string) (uint16, bool) {
	switch strings.ToUpper(s) {
	case "A":
		return unbound.TypeA, true
	case "AAAA":
		return unbound.TypeAAAA, true
	case "TXT":
		return unbound.TypeTXT, true
	case "CAA":
		return unbound.TypeCAA, true
	}
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n), true
	}
	return 0, false
}
