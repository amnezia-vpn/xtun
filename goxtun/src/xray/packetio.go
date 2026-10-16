package xray

import (
	"context"
	"fmt"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (i *Instance) runRead(ctx context.Context) {
	defer i.Stop()

	const maxPacketSize = header.IPv6MinimumSize + header.IPv6MaximumPayloadSize

	buf := make([]byte, maxPacketSize)

	for {
		if ctx.Err() != nil {
			return
		}
		n, err := i.callbacks.Read(buf)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			i.callbacks.Error(err.Error())
			return
		}
		if n < 0 || n > len(buf) {
			i.callbacks.Error("xray read buf: out of bounds")
			return
		}
		if n == 0 {
			continue
		}

		if !i.up.Load() {
			continue
		}

		var protocol tcpip.NetworkProtocolNumber

		switch buf[0] >> 4 {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		default:
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf[:n]),
		})

		i.endpoint.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
}

func (i *Instance) runWrite(ctx context.Context) {
	defer i.Stop()

	for {
		pkt := i.endpoint.ReadContext(ctx)
		if pkt == nil {
			return
		}

		if ctx.Err() != nil {
			pkt.DecRef()
			return
		}

		if !i.up.Load() {
			pkt.DecRef()
			continue
		}

		view := pkt.ToView()
		data := view.AsSlice()
		want := len(data)

		n, err := i.callbacks.Write(data)

		view.Release()
		pkt.DecRef()

		if ctx.Err() != nil {
			return
		}
		if err != nil {
			i.callbacks.Error("xray: error with send: " + err.Error())
		} else if n != want {
			i.callbacks.Error(fmt.Sprintf("xray: error with send: n %d != want %d", n, want))
		}
	}
}
