package xray

import (
	"context"
	"net"
	"slices"
	"syscall"
	"time"
	_ "unsafe"

	xerrors "github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// the best way to impl idea of xtun is to make our custom dialer (with respect to our sockets) and steal their private func

//go:linkname applyXrayOutboundSocketOptions github.com/xtls/xray-core/transport/internet.applyOutboundSocketOptions
func applyXrayOutboundSocketOptions(
	network, address string,
	fd uintptr,
	config *internet.SocketConfig,
) error

func resolveSrcAddr(network xnet.Network, src xnet.Address) net.Addr {
	if src == nil || src == xnet.AnyIP {
		return nil
	}

	if network == xnet.Network_TCP {
		return &net.TCPAddr{
			IP:   src.IP(),
			Port: 0,
		}
	}

	return &net.UDPAddr{
		IP:   src.IP(),
		Port: 0,
	}
}

func dialTCP(
	ctx context.Context,
	owner *Instance,
	src xnet.Address,
	dest xnet.Destination,
	sockopt *internet.SocketConfig,
) (net.Conn, error) {
	keepAliveConfig := net.KeepAliveConfig{
		Enable:   true,
		Idle:     45 * time.Second,
		Interval: 45 * time.Second,
		Count:    -1,
	}

	keepAlive := time.Duration(0)

	if sockopt != nil {
		if sockopt.TcpKeepAliveIdle*sockopt.TcpKeepAliveInterval < 0 {
			return nil, xerrors.New(
				"invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: ",
				sockopt.TcpKeepAliveIdle, " ", sockopt.TcpKeepAliveInterval,
			)
		}

		if sockopt.TcpKeepAliveIdle < 0 || sockopt.TcpKeepAliveInterval < 0 {
			keepAlive = -1
			keepAliveConfig.Enable = false
		}

		if sockopt.TcpKeepAliveIdle > 0 {
			keepAliveConfig.Idle = time.Duration(sockopt.TcpKeepAliveIdle) * time.Second
		}

		if sockopt.TcpKeepAliveInterval > 0 {
			keepAliveConfig.Interval = time.Duration(sockopt.TcpKeepAliveInterval) * time.Second
		}
	}

	dialer := net.Dialer{
		Timeout:         16 * time.Second,
		LocalAddr:       resolveSrcAddr(xnet.Network_TCP, src),
		KeepAlive:       keepAlive,
		KeepAliveConfig: keepAliveConfig,
	}

	if sockopt != nil && sockopt.TcpMptcp {
		dialer.SetMultipathTCP(true)
	}

	internet.ControllersLock.Lock()
	controllers := slices.Clone(internet.Controllers)
	internet.ControllersLock.Unlock()

	dialer.Control = func(network, address string, raw syscall.RawConn) error {
		if err := owner.controlSocket(network, address, raw); err != nil {
			return err
		}

		for _, controller := range controllers {
			if err := controller(network, address, raw); err != nil {
				xerrors.LogInfoInner(
					ctx, err, "failed to apply external controller",
				)
			}
		}

		return raw.Control(func(fd uintptr) {
			if sockopt == nil {
				return
			}

			if err := applyXrayOutboundSocketOptions(network, address, fd, sockopt); err != nil {
				xerrors.LogInfoInner(
					ctx, err, "failed to apply socket options",
				)
			}
		})
	}

	return dialer.DialContext(ctx, "tcp", dest.NetAddr())
}

func dialUDP(
	ctx context.Context,
	owner *Instance,
	src xnet.Address,
	dest xnet.Destination,
	sockopt *internet.SocketConfig,
) (net.Conn, error) {
	srcAddr := resolveSrcAddr(xnet.Network_UDP, src)
	if srcAddr == nil {
		srcAddr = &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		}
	}

	destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
	if err != nil {
		return nil, err
	}

	internet.ControllersLock.Lock()
	controllers := slices.Clone(internet.Controllers)
	internet.ControllersLock.Unlock()

	var lc net.ListenConfig

	lc.Control = func(network, address string, raw syscall.RawConn) error {
		if err := owner.controlSocket(network, address, raw); err != nil {
			return err
		}

		for _, controller := range controllers {
			if err := controller(network, address, raw); err != nil {
				xerrors.LogInfoInner(
					ctx, err, "failed to apply external controller",
				)
			}
		}

		return raw.Control(func(fd uintptr) {
			if sockopt == nil {
				return
			}

			if err := applyXrayOutboundSocketOptions(network, destAddr.String(), fd, sockopt); err != nil {
				xerrors.LogInfoInner(
					ctx, err, "failed to apply socket options",
				)
			}
		})
	}

	packetConn, err := lc.ListenPacket(
		ctx,
		srcAddr.Network(),
		srcAddr.String(),
	)
	if err != nil {
		return nil, err
	}

	return &internet.PacketConnWrapper{
		PacketConn: packetConn,
		Dest:       destAddr,
	}, nil
}
