package xray

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type socketScope struct {
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func (s *socketScope) add(conn net.Conn) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return net.ErrClosed
	}

	s.conns = append(s.conns, conn)
	s.mu.Unlock()
	return nil
}

func (s *socketScope) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}

	s.closed = true
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for i := range conns {
		conns[i].Close()
	}
}

type socketDialer struct{}

func (*socketDialer) DestIpAddress() net.IP {
	return nil
}

func (d *socketDialer) Dial(
	ctx context.Context,
	src xnet.Address,
	dest xnet.Destination,
	sockopt *internet.SocketConfig,
) (net.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	scope, ok := ctx.Value(socketScopeKey{}).(*socketScope)
	if !ok || scope == nil {
		return nil, errors.New("xray: missing socket scope")
	}

	owner, err := socketOwnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	switch dest.Network {
	case xnet.Network_TCP:
		conn, err = dialTCP(ctx, owner, src, dest, sockopt)
	case xnet.Network_UDP:
		conn, err = dialUDP(ctx, owner, src, dest, sockopt)
	default:
		return nil, errors.New("xray: unsupported network")
	}
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}

	err = scope.add(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type socketScopeKey struct{}
type socketOwnerKey struct{}

var registerSocketHook = sync.OnceFunc(func() {
	internet.UseAlternativeSystemDialer(&socketDialer{})
})

func (i *Instance) controlSocket(
	network string,
	address string,
	raw syscall.RawConn,
) error {
	i.socketMu.Lock()

	if i.socketCallbacksClosed {
		i.socketMu.Unlock()
		return net.ErrClosed
	}

	i.socketCalls.Add(1)
	i.socketMu.Unlock()

	defer i.socketCalls.Done()

	return raw.Control(func(fd uintptr) {
		i.callbacks.Socket(int(fd))
	})
}

func socketOwnerFromContext(ctx context.Context) (*Instance, error) {
	i, ok := ctx.Value(socketOwnerKey{}).(*Instance)
	if !ok || i == nil {
		return nil, errors.New("xray: missing socket owner")
	}

	return i, nil
}
