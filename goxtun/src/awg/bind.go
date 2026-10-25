package awg

import (
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

func NewBind(sockCb BindSockCb) *Bind {
	return &Bind{
		Bind:   conn.NewDefaultBind(),
		sockCb: sockCb,
	}
}

type BindSockCb func(fd int)

type Bind struct {
	conn.Bind

	mu     sync.Mutex
	sockCb BindSockCb
}

func (b *Bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	fns, actualPort, err = b.Bind.Open(port)
	if err != nil {
		return fns, actualPort, err
	}

	if peekable, ok := b.Bind.(conn.PeekLookAtSocketFd); ok {
		if fd, err := peekable.PeekLookAtSocketFd4(); err == nil {
			b.sockCb(fd)
		}

		if fd, err := peekable.PeekLookAtSocketFd6(); err == nil {
			b.sockCb(fd)
		}
	}

	return fns, actualPort, nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Bind.Close()
}
