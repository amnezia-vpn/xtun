package xray

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Event int

const (
	EventUp        Event = 1
	EventDown      Event = 2
	EventMTUUpdate Event = 4
)

type Callbacks struct {
	Read    func([]byte) (int, error)
	Write   func([]byte) (int, error)
	MTU     func() (int, error)
	Verbose func(string)
	Error   func(string)
	Socket  func(int)
}

type Instance struct {
	stack     *stack.Stack
	endpoint  *channel.Endpoint
	nicID     tcpip.NICID
	callbacks Callbacks

	cancel    context.CancelFunc
	closeOnce sync.Once
	workers   sync.WaitGroup

	up     atomic.Bool
	events chan Event
	done   <-chan struct{}
}

func NewInstance(
	ctx context.Context,
	s *stack.Stack,
	endpoint *channel.Endpoint,
	nicID tcpip.NICID,
	callbacks Callbacks,
) *Instance {
	ctx, cancel := context.WithCancel(ctx)

	i := &Instance{
		stack:     s,
		endpoint:  endpoint,
		nicID:     nicID,
		callbacks: callbacks,
		cancel:    cancel,
		events:    make(chan Event),
		done:      ctx.Done(),
	}

	i.workers.Go(func() {
		i.runEvents(ctx)
	})

	i.workers.Go(func() {
		i.runRead(ctx)
	})

	i.workers.Go(func() {
		i.runWrite(ctx)
	})

	return i
}

// Stop requests shutdown without interrupting callbacks or waiting for workers.
func (i *Instance) Stop() {
	i.cancel()
}

// TriggerEvent hands an event to the event loop; it does not wait for processing.
func (i *Instance) TriggerEvent(event Event) {
	select {
	case <-i.done:
		return
	case i.events <- event:
	}
}

// Close waits for callbacks and workers before releasing the stack.
// The caller must unblock pending callbacks and keep their userdata alive until Close returns.
func (i *Instance) Close() {
	i.closeOnce.Do(func() {
		i.Stop()
		i.workers.Wait()
		i.endpoint.Close()
		i.stack.Destroy()
	})
}

func (i *Instance) updateMTU(ctx context.Context) error {
	mtu, err := i.callbacks.MTU()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if mtu <= 0 || uint64(mtu) > math.MaxUint32 {
		return fmt.Errorf("invalid mtu: %d", mtu)
	}

	if err := i.stack.SetNICMTU(i.nicID, uint32(mtu)); err != nil {
		return fmt.Errorf("set NIC MTU: %s", err.String())
	}

	return nil
}

func (i *Instance) runEvents(ctx context.Context) {
	defer i.up.Store(false)

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-i.events:
			if ctx.Err() != nil {
				return
			}
			switch event {
			case EventDown:
				// Readers stay active; packet loops discard packets while down.
				i.up.Store(false)
			case EventUp, EventMTUUpdate:
				err := i.updateMTU(ctx)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					i.callbacks.Error("xray: update MTU: " + err.Error())
					continue
				}

				if event == EventUp {
					i.up.Store(true)
				}
			}
		}
	}
}
