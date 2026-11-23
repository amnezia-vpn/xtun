package xray

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func (i *Instance) initTCP(ctx context.Context) error {
	dispatcher, ok := i.engine.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	if !ok {
		return fmt.Errorf("xray: dispatcher is not available")
	}

	i.dispatcher = dispatcher

	const MaxTCPInFlight = 2048

	forwarder := tcp.NewForwarder(
		i.stack,
		0,
		MaxTCPInFlight,
		func(request *tcp.ForwarderRequest) {
			i.handleTCP(ctx, request)
		},
	)

	i.stack.SetTransportProtocolHandler(
		tcp.ProtocolNumber,
		forwarder.HandlePacket,
	)

	return nil
}

func (i *Instance) handleTCP(ctx context.Context, request *tcp.ForwarderRequest) {
	if !i.beginFlow(ctx) {
		request.Complete(false)
		return
	}
	defer i.endFlow()

	id := request.ID()

	var queue waiter.Queue

	endpoint, tcpErr := request.CreateEndpoint(&queue)
	if tcpErr != nil {
		stopping := ctx.Err() != nil
		request.Complete(!stopping)

		if !stopping {
			i.callbacks.Error("xray: TCP handshake: " + tcpErr.String())
		}
		return
	}

	request.Complete(false)

	conn := gonet.NewTCPConn(&queue, endpoint)
	defer conn.Close()

	if ctx.Err() != nil {
		return
	}

	destination := xnet.TCPDestination(
		xnet.IPAddress(id.LocalAddress.AsSlice()),
		xnet.Port(id.LocalPort),
	)

	source := xnet.TCPDestination(
		xnet.IPAddress(id.RemoteAddress.AsSlice()),
		xnet.Port(id.RemotePort),
	)

	flowCtx := session.ContextWithInbound(ctx, &session.Inbound{
		Name:          "xtun",
		Tag:           i.inboundTag,
		Source:        source,
		CanSpliceCopy: 3,
	})
	flowCtx = session.ContextWithContent(flowCtx, &session.Content{
		SniffingRequest: i.sniffing,
	})
	flowCtx = session.TrackedConnectionError(flowCtx, i)
	scope := &socketScope{}
	defer scope.Close()

	flowCtx = context.WithValue(flowCtx, socketScopeKey{}, scope)

	outbound := new(session.Outbound)
	flowCtx = session.ContextWithOutbounds(flowCtx, []*session.Outbound{outbound})

	link := &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: buf.NewWriter(NewDownlinkWriter(conn, outbound, &i.downlinkBytes, !i.hasHealthOutbound)),
	}

	if err := i.dispatcher.DispatchLink(
		flowCtx,
		destination,
		link,
	); err != nil && ctx.Err() == nil {
		i.callbacks.Error("xray: TCP dispatch: " + err.Error())
	}
}

func (i *Instance) beginFlow(ctx context.Context) bool {
	i.flowMu.Lock()
	defer i.flowMu.Unlock()

	if i.stopping || ctx.Err() != nil {
		return false
	}

	i.activeFlows++
	return true
}

func (i *Instance) endFlow() {
	i.flowMu.Lock()
	defer i.flowMu.Unlock()

	i.activeFlows--

	if i.stopping && i.activeFlows == 0 {
		close(i.flowsDone)
	}
}

func (i *Instance) SubmitError(err error) {
	if err == nil {
		return
	}

	select {
	case <-i.done:
		return
	default:
	}

	i.callbacks.Error("xray: outbound: " + err.Error())
}

// expl: CreateEndpoint doesn't return ep nor takes the context. So, it's something that we could do about it.
func (i *Instance) abortFlows() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-i.flowsDone:
			return
		default:
		}

		for _, endpoint := range i.stack.RegisteredEndpoints() {
			endpoint.Abort()
		}

		select {
		case <-i.flowsDone:
			return
		case <-ticker.C:
		}
	}
}

type downlinkWriter struct {
	conn             io.Writer
	outbound         *session.Outbound
	downLinkBytesPtr *atomic.Uint64
	countAll         bool
}

func NewDownlinkWriter(conn io.Writer, outbound *session.Outbound, downLinkBytesPtr *atomic.Uint64, countAll bool) *downlinkWriter {
	return &downlinkWriter{
		conn:             conn,
		outbound:         outbound,
		downLinkBytesPtr: downLinkBytesPtr,
		countAll:         countAll,
	}
}

func (d *downlinkWriter) Write(p []byte) (n int, err error) {
	n, err = d.conn.Write(p)
	if n > 0 && (d.countAll || d.outbound.Tag == "xtun") {
		d.downLinkBytesPtr.Add(uint64(n))
	}
	return n, err
}
