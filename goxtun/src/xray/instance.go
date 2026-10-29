package xray

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
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

	cancel                context.CancelFunc
	closeOnce             sync.Once
	workers               sync.WaitGroup
	socketMu              sync.Mutex
	socketCallbacksClosed bool
	socketCalls           sync.WaitGroup

	up       atomic.Bool
	upNotify chan struct{}
	events   chan Event
	done     <-chan struct{}

	engine     *core.Instance
	dispatcher routing.Dispatcher

	tcpMu       sync.Mutex
	tcpStopping bool
	tcpActive   int
	tcpDone     chan struct{}
}

func NewInstance(
	ctx context.Context,
	s *stack.Stack,
	endpoint *channel.Endpoint,
	nicID tcpip.NICID,
	callbacks Callbacks,
	config *core.Config,
) (*Instance, error) {
	registerSocketHook()

	ctx, cancel := context.WithCancel(ctx)

	i := &Instance{
		stack:     s,
		endpoint:  endpoint,
		nicID:     nicID,
		callbacks: callbacks,
		cancel:    cancel,
		events:    make(chan Event),
		upNotify:  make(chan struct{}, 1),
		done:      ctx.Done(),
		tcpDone:   make(chan struct{}),
	}

	ctx = context.WithValue(ctx, socketOwnerKey{}, i)

	ready := false
	defer func() {
		if ready {
			return
		}

		i.Stop()

		if i.engine != nil {
			if err := i.engine.Close(); err != nil {
				i.callbacks.Error(err.Error())
			}
		}

		i.waitSocketCallbacks()
	}()

	var err error
	i.engine, err = core.NewWithContext(ctx, config)
	if err != nil {
		cancel()
		return nil, err
	}

	err = i.engine.Start()
	if err != nil {
		cancel()
		return nil, err
	}

	if err := i.initTCP(ctx); err != nil {
		return nil, err
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

	ready = true
	return i, nil
}

// Stop requests shutdown without interrupting callbacks or waiting for workers.
func (i *Instance) Stop() {
	i.tcpMu.Lock()
	defer i.tcpMu.Unlock()

	if i.tcpStopping {
		return
	}

	i.tcpStopping = true
	i.cancel()

	if i.tcpActive == 0 {
		close(i.tcpDone)
		return
	}

	i.workers.Go(i.abortTCP)
}

// TriggerEvent hands an event to the event loop; it does not wait for processing.
func (i *Instance) TriggerEvent(event Event) {
	select {
	case <-i.done:
		return
	case i.events <- event:
	}
}

func (i *Instance) waitSocketCallbacks() {
	i.socketMu.Lock()
	i.socketCallbacksClosed = true
	i.socketMu.Unlock()
	i.socketCalls.Wait()
}

// Close waits for callbacks and workers before releasing the stack.
// The caller must unblock pending callbacks and keep their userdata alive until Close returns.
func (i *Instance) Close() {
	i.closeOnce.Do(func() {
		i.Stop()
		i.workers.Wait()
		err := i.engine.Close()
		if err != nil {
			i.callbacks.Error(err.Error())
		}
		i.waitSocketCallbacks()
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

					select {
					case i.upNotify <- struct{}{}:
					default:
					}
				}
			}
		}
	}
}
