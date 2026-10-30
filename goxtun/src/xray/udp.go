package xray

import (
	"context"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func (i *Instance) initUDP(ctx context.Context) {
	i.stack.SetTransportProtocolHandler(
		udp.ProtocolNumber,
		func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
			request := udp.NewForwarderRequest(i.stack, id, pkt)
			return i.acceptUDP(ctx, request)
		},
	)
}

func (i *Instance) acceptUDP(ctx context.Context, request *udp.ForwarderRequest) bool {
	if !i.beginFlow(ctx) {
		return true
	}

	id := request.ID()

	var queue waiter.Queue
	endpoint, udpErr := request.CreateEndpoint(&queue)
	if udpErr != nil {
		stopping := ctx.Err() != nil
		if !stopping {
			i.callbacks.Error("xray: UDP endpoint: " + udpErr.String())
		}

		i.endFlow()
		return stopping
	}

	conn := gonet.NewUDPConn(&queue, endpoint)

	i.workers.Go(func() {
		defer i.endFlow()
		defer conn.Close()

		if ctx.Err() != nil {
			return
		}

		i.handleUDP(ctx, conn, id)
	})

	return true
}

func (i *Instance) handleUDP(ctx context.Context, conn *gonet.UDPConn, id stack.TransportEndpointID) {
	destination := xnet.UDPDestination(
		xnet.IPAddress(id.LocalAddress.AsSlice()),
		xnet.Port(id.LocalPort),
	)
	source := xnet.UDPDestination(
		xnet.IPAddress(id.RemoteAddress.AsSlice()),
		xnet.Port(id.RemotePort),
	)

	flowCtx := session.ContextWithInbound(ctx, &session.Inbound{
		Name:   "xtun",
		Source: source,
	})

	flowCtx = session.TrackedConnectionError(flowCtx, i)

	scope := &socketScope{}
	defer scope.Close()

	flowCtx = context.WithValue(flowCtx, socketScopeKey{}, scope)

	link := &transport.Link{
		Reader: buf.NewPacketReader(conn),
		Writer: buf.NewWriter(conn),
	}

	if err := i.dispatcher.DispatchLink(flowCtx, destination, link); err != nil && ctx.Err() == nil {
		i.callbacks.Error("xray: UDP dispatch: " + err.Error())
	}
}
