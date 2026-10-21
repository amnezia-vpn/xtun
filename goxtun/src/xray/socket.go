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

// protected by once
var socketOwner struct {
	mu              sync.Mutex
	instance        *Instance
	callbacksClosed bool
}

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

type socketDialer struct {
	internet.DefaultSystemDialer
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
	conn, err := d.DefaultSystemDialer.Dial(ctx, src, dest, sockopt)
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

var registerSocketHook = sync.OnceValue(func() error {
	err := internet.RegisterDialerController(controlSocket)
	if err != nil {
		return err
	}
	internet.UseAlternativeSystemDialer(&socketDialer{})
	return nil
})

func controlSocket(network string, address string, raw syscall.RawConn) error {
	socketOwner.mu.Lock()

	i := socketOwner.instance

	if i == nil || socketOwner.callbacksClosed {
		socketOwner.mu.Unlock()
		return nil
	}

	i.socketCalls.Add(1)
	socketOwner.mu.Unlock()

	defer i.socketCalls.Done()

	return raw.Control(func(fd uintptr) {
		i.callbacks.Socket(int(fd))
	})
}

func (i *Instance) waitSocketCallbacks() {
	socketOwner.mu.Lock()
	if socketOwner.instance == i {
		socketOwner.callbacksClosed = true
	}
	socketOwner.mu.Unlock()
	i.socketCalls.Wait()
}

func (i *Instance) releaseSocketOwner() {
	socketOwner.mu.Lock()
	defer socketOwner.mu.Unlock()

	if socketOwner.instance == i {
		socketOwner.instance = nil
	}
}

func claimSocketOwner(i *Instance) error {
	socketOwner.mu.Lock()
	defer socketOwner.mu.Unlock()

	if socketOwner.instance != nil {
		return errors.New("xray instance already exists")
	}

	socketOwner.instance = i
	socketOwner.callbacksClosed = false
	return nil
}
