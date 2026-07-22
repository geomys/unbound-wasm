package unbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tetratelabs/wazero/api"
)

const (
	socketUDP int32 = 1
	socketTCP int32 = 2
	ioRead    int32 = 1
	ioWrite   int32 = 2
	ioErr     int32 = 4
)

// deniedNetworks are the networks the host refuses to send DNS packets to,
// so a compromised guest cannot probe internal or special-purpose address
// space. It matches the do-not-query-address list configured guest-side in
// defaultCanonicalConfig, including the NAT64 and 6to4 translation prefixes,
// which can smuggle packets toward internal IPv4 space, and the newer IPv6
// documentation and SRv6 SID ranges. IPv4-mapped IPv6 addresses are
// unmapped before matching.
var deniedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // RFC 1122: this network
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598: shared address space
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // RFC 3927: link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC 1918
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890: IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // RFC 7526: 6to4 relay anycast
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC 1918
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544: benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and limited broadcast
	netip.MustParsePrefix("::/128"),          // unspecified
	netip.MustParsePrefix("::1/128"),         // loopback
	netip.MustParsePrefix("64:ff9b::/96"),    // RFC 6052: NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"),  // RFC 8215: local-use NAT64
	netip.MustParsePrefix("100::/64"),        // RFC 6666: discard
	netip.MustParsePrefix("2001::/23"),       // RFC 2928: IETF protocol assignments (Teredo, benchmarking, ORCHID)
	netip.MustParsePrefix("2001:db8::/32"),   // RFC 3849: documentation
	netip.MustParsePrefix("2002::/16"),       // RFC 3056: 6to4
	netip.MustParsePrefix("3fff::/20"),       // RFC 9637: documentation
	netip.MustParsePrefix("5f00::/16"),       // RFC 9602: SRv6 SIDs
	netip.MustParsePrefix("fc00::/7"),        // RFC 4193: unique-local
	netip.MustParsePrefix("fe80::/10"),       // link-local
	netip.MustParsePrefix("ff00::/8"),        // multicast
}

// globalUnicastV6 is the only IPv6 range that holds public unicast addresses
// (RFC 4291, Section 2.4). Everything outside it is unspecified, loopback,
// multicast, link-local, unique-local, or reserved by the IETF, so the egress
// policy refuses it fail-closed rather than trusting the deniedNetworks list
// to enumerate the whole non-public IPv6 space.
var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// egressAllowed enforces the fixed egress policy: the guest may only send
// packets to port 53, where authoritative DNS servers live. IPv6 destinations
// must be global unicast; IPv4 destinations may be any address the complete
// deniedNetworks list does not exclude. Both families additionally exclude the
// special-purpose sub-ranges in deniedNetworks. This is a property of the
// package, not a configuration.
func egressAllowed(remote netip.AddrPort) bool {
	if remote.Port() != 53 {
		return false
	}
	ip := remote.Addr().Unmap()
	if !ip.IsValid() {
		return false
	}
	if ip.Is6() && !globalUnicastV6.Contains(ip) {
		return false
	}
	for _, network := range deniedNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func (s *instanceState) checkEgress(ip netip.Addr, port uint16) bool {
	remote := netip.AddrPortFrom(ip, port)
	if !egressAllowed(remote) {
		s.log.Warn("unbound: egress denied", "remote", remote)
		return false
	}
	return true
}

type receivedPacket struct {
	data []byte
	from netip.AddrPort
}

type hostSocket struct {
	state       *instanceState
	id, af, typ int32
	mu          sync.Mutex
	bindPort    uint16
	udp         *net.UDPConn
	tcp         net.Conn
	remote      netip.AddrPort
	queue       []receivedPacket
	err         error
	closed      bool
}

// maxSocketsPerInstance bounds the live host sockets one instance can hold, so
// a memory-corrupted guest cannot exhaust host file descriptors. The guest's
// own sockets veneer caps itself at 128, so a well-behaved guest never reaches
// this; it only backstops a guest that bypasses that cap.
const maxSocketsPerInstance = 256

func (s *instanceState) sockOpen(af, typ int32) int32 {
	if (af != 4 && af != 6) || (typ != socketUDP && typ != socketTCP) {
		return -wasiEAFNOSUPPORT
	}
	s.socketsMu.Lock()
	defer s.socketsMu.Unlock()
	if s.sockets == nil {
		return -wasiEBADF
	}
	if len(s.sockets) >= maxSocketsPerInstance {
		return -wasiEMFILE
	}
	id := s.nextSocket
	s.nextSocket++
	s.sockets[id] = &hostSocket{state: s, id: id, af: af, typ: typ}
	return id
}

func (s *instanceState) socket(id int32) *hostSocket {
	s.socketsMu.Lock()
	defer s.socketsMu.Unlock()
	return s.sockets[id]
}

func (s *instanceState) sockBind(ctx context.Context, id, port int32) int32 {
	if port < 0 || port > 65535 {
		return -wasiEINVAL
	}
	sock := s.socket(id)
	if sock == nil {
		return -wasiEBADF
	}
	sock.mu.Lock()
	defer sock.mu.Unlock()
	if sock.closed {
		return -wasiEBADF
	}
	if sock.udp != nil || sock.tcp != nil {
		return -wasiEINVAL
	}
	sock.bindPort = uint16(port)
	if s.replay != nil {
		return 0
	}
	if sock.typ == socketUDP {
		if err := sock.listenUDPLocked(); err != nil {
			return -wasiErrno(err)
		}
	}
	return 0
}

func (s *instanceState) sockConnect(ctx context.Context, id int32, ip netip.Addr, port int32) int32 {
	if port <= 0 || port > 65535 {
		return -wasiEINVAL
	}
	if s.replay != nil {
		if sock := s.socket(id); sock != nil {
			return s.replay.connect(s, sock, netip.AddrPortFrom(ip, uint16(port)))
		}
		return -wasiEBADF
	}
	if !s.checkEgress(ip, uint16(port)) {
		return -wasiEACCES
	}
	sock := s.socket(id)
	if sock == nil {
		return -wasiEBADF
	}
	sock.mu.Lock()
	if sock.closed {
		sock.mu.Unlock()
		return -wasiEBADF
	}
	sock.remote = netip.AddrPortFrom(ip, uint16(port))
	if sock.typ == socketUDP {
		if sock.udp == nil {
			if err := sock.listenUDPLocked(); err != nil {
				sock.mu.Unlock()
				return -wasiErrno(err)
			}
		}
		sock.mu.Unlock()
		s.enqueue(hostEvent{kind: eventIO, sid: id, flags: ioWrite})
		return 0
	}
	if sock.tcp != nil {
		sock.mu.Unlock()
		return 0
	}
	bindPort, af := sock.bindPort, sock.af
	sock.mu.Unlock()
	go sock.connectTCP(ctx, af, bindPort, ip, uint16(port))
	return 0
}

func (s *instanceState) sockSend(ctx context.Context, id int32, data []byte) int32 {
	sock := s.socket(id)
	if sock == nil {
		return -wasiEBADF
	}
	sock.mu.Lock()
	remote := sock.remote
	sock.mu.Unlock()
	if !remote.IsValid() {
		return -wasiENOTCONN
	}
	return s.sockSendTo(ctx, id, remote.Addr(), int32(remote.Port()), data)
}

func (s *instanceState) sockSendTo(ctx context.Context, id int32, ip netip.Addr, port int32, data []byte) int32 {
	if port <= 0 || port > 65535 {
		return -wasiEINVAL
	}
	if s.replay != nil {
		if sock := s.socket(id); sock != nil {
			return s.replay.sendTo(s, sock, netip.AddrPortFrom(ip, uint16(port)), data)
		}
		return -wasiEBADF
	}
	if !s.checkEgress(ip, uint16(port)) {
		return -wasiEACCES
	}
	sock := s.socket(id)
	if sock == nil {
		return -wasiEBADF
	}
	sock.mu.Lock()
	if sock.closed {
		sock.mu.Unlock()
		return -wasiEBADF
	}
	typ, udp, tcp := sock.typ, sock.udp, sock.tcp
	sock.mu.Unlock()
	var n int
	var err error
	remote := netip.AddrPortFrom(ip, uint16(port))
	if typ == socketUDP {
		if udp == nil {
			sock.mu.Lock()
			err = sock.listenUDPLocked()
			udp = sock.udp
			sock.mu.Unlock()
			if err != nil {
				return -wasiErrno(err)
			}
		}
		n, err = udp.WriteToUDPAddrPort(data, remote)
	} else {
		if tcp == nil {
			return -wasiEAGAIN
		}
		n, err = tcp.Write(data)
	}
	if err != nil {
		return -wasiErrno(err)
	}
	return int32(n)
}

func (s *instanceState) sockRecv(m api.Module, id int32, ptr, capacity uint32, withFrom bool, ipOut, portOut uint32) int32 {
	sock := s.socket(id)
	if sock == nil {
		return -wasiEBADF
	}
	sock.mu.Lock()
	if len(sock.queue) == 0 {
		err := sock.err
		sock.err = nil
		sock.mu.Unlock()
		if err != nil {
			return -wasiErrno(err)
		}
		return -wasiEAGAIN
	}
	pkt := sock.queue[0]
	n := len(pkt.data)
	if uint32(n) > capacity {
		n = int(capacity)
	}
	chunk := append([]byte(nil), pkt.data[:n]...)
	if n == len(pkt.data) || sock.typ == socketUDP {
		// A datagram is consumed whole: bytes past the caller's buffer are
		// discarded, as recvfrom does. Only a TCP stream keeps its unread
		// remainder for the next read.
		sock.queue = sock.queue[1:]
	} else {
		sock.queue[0].data = sock.queue[0].data[n:]
	}
	more := len(sock.queue) > 0
	sock.mu.Unlock()
	if !m.Memory().Write(ptr, chunk) {
		return -wasiEFAULT
	}
	if withFrom && (!writeAddr(m, ipOut, pkt.from.Addr()) || !putU32(m, portOut, uint32(pkt.from.Port()))) {
		return -wasiEFAULT
	}
	if more {
		s.enqueue(hostEvent{kind: eventIO, sid: id, flags: ioRead})
	}
	return int32(n)
}

func (s *instanceState) sockError(id int32) int32 {
	sock := s.socket(id)
	if sock == nil {
		return int32(wasiEBADF)
	}
	sock.mu.Lock()
	defer sock.mu.Unlock()
	if sock.err == nil {
		return 0
	}
	e := wasiErrno(sock.err)
	sock.err = nil
	return e
}

func (s *instanceState) sockLocalPort(id int32) int32 {
	sock := s.socket(id)
	if sock == nil {
		return -wasiEBADF
	}
	if s.replay != nil {
		return s.replay.localPort(sock)
	}
	sock.mu.Lock()
	defer sock.mu.Unlock()
	if sock.udp != nil {
		if a, ok := sock.udp.LocalAddr().(*net.UDPAddr); ok {
			return int32(a.Port)
		}
	}
	if sock.tcp != nil {
		if a, ok := sock.tcp.LocalAddr().(*net.TCPAddr); ok {
			return int32(a.Port)
		}
	}
	return int32(sock.bindPort)
}

func (s *instanceState) sockClose(id int32) {
	s.socketsMu.Lock()
	sock := s.sockets[id]
	delete(s.sockets, id)
	s.socketsMu.Unlock()
	if sock != nil {
		sock.close()
	}
}

func (sock *hostSocket) listenUDPLocked() error {
	if sock.udp != nil {
		return nil
	}
	ip := net.IPv4zero
	network := "udp4"
	if sock.af == 6 {
		ip = net.IPv6zero
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: int(sock.bindPort)})
	if err != nil {
		return err
	}
	sock.udp = conn
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		sock.bindPort = uint16(a.Port)
	}
	go sock.readUDP(conn)
	return nil
}

func (sock *hostSocket) connectTCP(ctx context.Context, af int32, bindPort uint16, ip netip.Addr, port uint16) {
	network := "tcp4"
	localIP := net.IPv4zero
	if af == 6 {
		network = "tcp6"
		localIP = net.IPv6zero
	}
	// The dial timeout is a resource backstop, not query policy: Unbound
	// runs its own, shorter TCP timers and will have moved on before this
	// fires. All DNS timing decisions belong to the resolver.
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: localIP, Port: int(bindPort)}}
	conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(ip, port).String())
	sock.mu.Lock()
	if sock.closed {
		sock.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		return
	}
	sock.err = err
	if err == nil {
		sock.tcp = conn
	}
	sock.mu.Unlock()
	flags := ioWrite
	if err != nil {
		flags |= ioErr
	}
	sock.state.enqueue(hostEvent{kind: eventIO, sid: sock.id, flags: flags})
	if err == nil {
		go sock.readTCP(conn)
	}
}

func (sock *hostSocket) readUDP(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			sock.readError(err)
			return
		}
		sock.push(append([]byte(nil), buf[:n]...), from)
	}
}

func (sock *hostSocket) readTCP(conn net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sock.mu.Lock()
			from := sock.remote
			sock.mu.Unlock()
			sock.push(append([]byte(nil), buf[:n]...), from)
		}
		if err != nil {
			sock.readError(err)
			return
		}
	}
}

func (sock *hostSocket) push(data []byte, from netip.AddrPort) {
	sock.mu.Lock()
	if !sock.closed {
		sock.queue = append(sock.queue, receivedPacket{data: data, from: from})
	}
	sock.mu.Unlock()
	sock.state.enqueue(hostEvent{kind: eventIO, sid: sock.id, flags: ioRead})
}

func (sock *hostSocket) readError(err error) {
	sock.mu.Lock()
	if !sock.closed && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		sock.err = err
	}
	closed := sock.closed
	sock.mu.Unlock()
	if !closed {
		sock.state.enqueue(hostEvent{kind: eventIO, sid: sock.id, flags: ioErr})
	}
}

func (sock *hostSocket) close() {
	sock.mu.Lock()
	if sock.closed {
		sock.mu.Unlock()
		return
	}
	sock.closed = true
	udp, tcp := sock.udp, sock.tcp
	sock.mu.Unlock()
	if udp != nil {
		udp.Close()
	}
	if tcp != nil {
		tcp.Close()
	}
}
