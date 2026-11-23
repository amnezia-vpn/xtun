package xray

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
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
	outboundProcesses     map[*outboundProcess]struct{}

	up       atomic.Bool
	upNotify chan struct{}
	events   chan Event
	done     <-chan struct{}

	engine     *core.Instance
	dispatcher routing.Dispatcher

	flowMu         sync.Mutex
	stopping       bool
	activeFlows    int
	flowsDone      chan struct{}
	udpIdleTimeout time.Duration

	xrayctx    context.Context
	inboundTag string
	sniffing   session.SniffingRequest

	downlinkBytes     atomic.Uint64
	hasHealthOutbound bool
}

func NewInstance(
	ctx context.Context,
	s *stack.Stack,
	endpoint *channel.Endpoint,
	nicID tcpip.NICID,
	callbacks Callbacks,
	config *core.Config,
	virtualInbound *conf.InboundDetourConfig,
) (*Instance, error) {
	registerSocketHook()

	ctx, cancel := context.WithCancel(ctx)

	i := &Instance{
		stack:             s,
		endpoint:          endpoint,
		nicID:             nicID,
		callbacks:         callbacks,
		cancel:            cancel,
		events:            make(chan Event),
		upNotify:          make(chan struct{}, 1),
		done:              ctx.Done(),
		flowsDone:         make(chan struct{}),
		outboundProcesses: make(map[*outboundProcess]struct{}),
	}

	ctx = context.WithValue(ctx, socketOwnerKey{}, i)

	ready := false
	defer func() {
		if ready {
			return
		}

		i.Stop()
		i.workers.Wait()

		if i.engine != nil {
			if err := i.engine.Close(); err != nil {
				i.callbacks.Error(err.Error())
			}
		}

		i.waitSocketCallbacks()
	}()

	preparedConfig, err := wrapOutbounds(config)
	if err != nil {
		return nil, err
	}

	var sniffingConfig *proxyman.SniffingConfig
	if virtualInbound != nil {
		i.inboundTag = virtualInbound.Tag
		if virtualInbound.SniffingConfig != nil {
			sniffingConfig, err = virtualInbound.SniffingConfig.Build()
			if err != nil {
				return nil, fmt.Errorf("xray: xtun inbound sniff build error: %w", err)
			}
		}
	} else {
		for idx, inbound := range preparedConfig.Inbound {
			if inbound.GetTag() != "xtun" {
				continue
			}
			if inbound.ReceiverSettings == nil {
				return nil, errors.New("xray: inbound receiver settings are required")
			}

			settings, err := inbound.ReceiverSettings.GetInstance()
			if err != nil {
				return nil, fmt.Errorf("xray: inbound receiver settings: %w", err)
			}

			receiver, ok := settings.(*proxyman.ReceiverConfig)
			if !ok || receiver == nil {
				return nil, fmt.Errorf("xray: unexpected receiver settings %T", settings)
			}

			i.inboundTag = inbound.Tag
			sniffingConfig = receiver.SniffingSettings
			preparedConfig.Inbound = slices.Delete(preparedConfig.Inbound, idx, idx+1)
			break
		}
	}

	for _, outbound := range preparedConfig.Outbound {
		if outbound.GetTag() == "xtun" {
			i.hasHealthOutbound = true
			break
		}
	}

	i.engine, err = core.NewWithContext(ctx, preparedConfig)
	if err != nil {
		cancel()
		return nil, err
	}

	policyManager, ok := i.engine.GetFeature(
		policy.ManagerType(),
	).(policy.Manager)
	if !ok {
		return nil, errors.New("xray: policy manager is not available")
	}

	i.udpIdleTimeout = policyManager.ForLevel(0).Timeouts.ConnectionIdle

	if i.xrayctx == nil {
		return nil, errors.New("xray: instance context is not available")
	}

	i.sniffing, err = proxyman.BuildSniffingRequest(sniffingConfig)
	if err != nil {
		return nil, fmt.Errorf("xray: inbound sniffing: %w", err)
	}

	err = i.engine.Start()
	if err != nil {
		cancel()
		return nil, err
	}

	if err := i.initTCP(i.xrayctx); err != nil {
		return nil, err
	}

	i.initUDP(i.xrayctx)

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
	i.flowMu.Lock()

	if i.stopping {
		i.flowMu.Unlock()
		return
	}

	i.stopping = true
	processes := make([]*outboundProcess, 0, len(i.outboundProcesses))
	for p := range i.outboundProcesses {
		processes = append(processes, p)
	}

	if i.activeFlows == 0 {
		close(i.flowsDone)
	} else {
		i.workers.Go(i.abortFlows)
	}

	i.flowMu.Unlock()

	i.cancel()
	for _, p := range processes {
		p.stop()
	}
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

func (i *Instance) DownlinkBytes() uint64 {
	return i.downlinkBytes.Load()
}
