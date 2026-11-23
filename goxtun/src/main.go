package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef GOXTUN_DEF
#define GOXTUN_DEF

#ifdef _MSC_VER
// MSVC does not support complex type definitions
// So here is a workaround to bypass this behavior
// See go.dev/issues/36233
typedef float _Fcomplex;
typedef double _Dcomplex;
#endif

typedef int (*goxtun_readcb)(void* b, int len, void *priv);
static inline int goxtun_readcb_invoke(goxtun_readcb cb, void* b, int len, void *priv)
{
	return cb(b, len, priv);
}

typedef int (*goxtun_writecb)(void* b, int len, void *priv);
static inline int goxtun_writecb_invoke(goxtun_writecb cb, void* b, int len, void *priv)
{
	return cb(b, len, priv);
}

typedef int (*goxtun_mtucb)(void *priv);
static inline int goxtun_mtucb_invoke(goxtun_mtucb cb, void *priv)
{
	return cb(priv);
}

typedef void (*goxtun_logcb)(char *str, void *priv);
static inline void goxtun_logcb_invoke(goxtun_logcb cb, char *str, void *priv)
{
	cb(str, priv);
}

typedef void (*goxtun_sockcb)(int fd, void *priv);
static inline void goxtun_sockcb_invoke(goxtun_sockcb cb, int fd, void *priv)
{
	cb(fd, priv);
}

#endif
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/cgo"
	"slices"
	"strings"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/libxtun/goxtun/awg"
	"github.com/amnezia-vpn/libxtun/goxtun/xray"
	"github.com/xtls/xray-core/infra/conf"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

//export goxtun_free
func goxtun_free(ptr unsafe.Pointer) {
	C.free(ptr)
}

func toCtx(v any) unsafe.Pointer {
	h := cgo.NewHandle(v)
	return unsafe.Pointer(h)
}

func fromCtx[K any](ctx unsafe.Pointer) (*K, cgo.Handle) {
	h := cgo.Handle(uintptr(ctx))
	o, _ := h.Value().(*K)
	return o, h
}

//export goxtun_awg_new
func goxtun_awg_new(
	readCb C.goxtun_readcb,
	writeCb C.goxtun_writecb,
	mtuCb C.goxtun_mtucb,
	tunPriv unsafe.Pointer,
	verbosefCb C.goxtun_logcb,
	errorfCb C.goxtun_logcb,
	logPriv unsafe.Pointer,
	sockCb C.goxtun_sockcb,
	sockPriv unsafe.Pointer,
) unsafe.Pointer {
	tun := awg.NewTun(
		func(bufs [][]byte, sizes []int, offset int) (n int, err error) {
			buf := bufs[0][offset:]
			ret := int(C.goxtun_readcb_invoke(readCb, unsafe.Pointer(&buf[0]), C.int(len(buf)), tunPriv))
			if ret < 0 {
				return 0, fmt.Errorf("failed to read from xtun: %d", ret)
			}
			sizes[0] = ret
			return 1, nil
		},
		func(bufs [][]byte, offset int) (int, error) {
			for i := range bufs {
				buf := bufs[i][offset:]
				ret := int(C.goxtun_writecb_invoke(writeCb, unsafe.Pointer(&buf[0]), C.int(len(buf)), tunPriv))
				if ret < 0 {
					return i, fmt.Errorf("failed to write to xtun: %d", ret)
				}
			}
			return len(bufs), nil
		},
		func() (int, error) {
			ret := int(C.goxtun_mtucb_invoke(mtuCb, tunPriv))
			if ret < 0 {
				return 0, fmt.Errorf("failed to get mtu from xtun: %d", ret)
			}
			return ret, nil
		},
	)

	bind := awg.NewBind(func(fd int) {
		C.goxtun_sockcb_invoke(sockCb, C.int(fd), sockPriv)
	})

	log := awg.NewLogger(
		func(format string, args ...any) {
			str := fmt.Sprintf(format, args...)
			cstr := C.CString(str)
			C.goxtun_logcb_invoke(verbosefCb, cstr, logPriv)
			C.free(unsafe.Pointer(cstr))
		},
		func(format string, args ...any) {
			str := fmt.Sprintf(format, args...)
			cstr := C.CString(str)
			C.goxtun_logcb_invoke(errorfCb, cstr, logPriv)
			C.free(unsafe.Pointer(cstr))
		},
	)

	i := awg.NewInstance(tun, bind, log)
	return toCtx(i)
}

//export goxtun_awg_free
func goxtun_awg_free(ctx unsafe.Pointer) {
	i, h := fromCtx[awg.Instance](ctx)

	defer h.Delete()
	i.Close()
}

//export goxtun_awg_event
func goxtun_awg_event(ctx unsafe.Pointer, event C.int) {
	i, _ := fromCtx[awg.Instance](ctx)

	i.TriggerEvent(tun.Event(event))
}

//export goxtun_awg_setconf
func goxtun_awg_setconf(ctx unsafe.Pointer, uapi *C.char) *C.char {
	i, _ := fromCtx[awg.Instance](ctx)

	if err := i.SetConf(C.GoString(uapi)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func takeXTunInbound(cfg *conf.Config) (*conf.InboundDetourConfig, error) {
	var inbound conf.InboundDetourConfig
	foundIdx := -1
	for idx, inb := range cfg.InboundConfigs {
		if strings.ToLower(inb.Protocol) == "xtun" {
			if foundIdx >= 0 {
				return nil, errors.New("only 1 xtun inbound supported")
			}
			inbound = inb
			foundIdx = idx
		}
	}
	if foundIdx == -1 {
		return nil, nil
	}

	cfg.InboundConfigs = slices.Delete(cfg.InboundConfigs, foundIdx, foundIdx+1)

	return &inbound, nil
}

const (
	outboundQueueSize             = 1024
	initialMTU        uint32      = 1500
	nicID             tcpip.NICID = 1
)

//export goxtun_xray_new
func goxtun_xray_new(
	readCb C.goxtun_readcb,
	writeCb C.goxtun_writecb,
	mtuCb C.goxtun_mtucb,
	tunPriv unsafe.Pointer,
	verbosefCb C.goxtun_logcb,
	errorfCb C.goxtun_logcb,
	logPriv unsafe.Pointer,
	sockCb C.goxtun_sockcb,
	sockPriv unsafe.Pointer,
	configJSON *C.char,
) unsafe.Pointer {
	logError := wrapLog(errorfCb, logPriv)

	if configJSON == nil {
		logError("xray: configJSON is required")
		return nil
	}

	if readCb == nil || mtuCb == nil || writeCb == nil {
		logError("xray: read, write and mtu callbacks are required")
		return nil
	}

	callbacks := xray.Callbacks{
		Read:    wrapRead(readCb, tunPriv),
		Write:   wrapWrite(writeCb, tunPriv),
		MTU:     wrapMTU(mtuCb, tunPriv),
		Verbose: wrapLog(verbosefCb, logPriv),
		Error:   logError,
		Socket:  wrapSocket(sockCb, sockPriv),
	}

	confStr := C.GoString(configJSON)
	decodedCfg, err := confserial.DecodeJSONConfig(strings.NewReader(confStr))
	if err != nil {
		callbacks.Error("xray: decode config: " + err.Error())
		return nil
	}

	virtualInbound, err := takeXTunInbound(decodedCfg)
	if err != nil {
		callbacks.Error("xray: xtun inbound decode: " + err.Error())
		return nil
	}

	if virtualInbound == nil && len(decodedCfg.InboundConfigs) == 1 {
		inbound := &decodedCfg.InboundConfigs[0]
		if strings.ToLower(inbound.Protocol) == "socks" && inbound.Tag != "xtun" {
			virtualInbound = inbound
		}
	}

	cfg, err := decodedCfg.Build()
	if err != nil {
		callbacks.Error("xray: build config: " + err.Error())
		return nil
	}

	endpoint := channel.New(outboundQueueSize, initialMTU, "")

	gStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	transferred := false

	defer func() {
		if !transferred {
			endpoint.Close()
			gStack.Destroy()
		}
	}()

	if err := gStack.CreateNIC(nicID, endpoint); err != nil {
		callbacks.Error("xray: create nic: " + err.String())
		return nil
	}

	gStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	if err := gStack.SetPromiscuousMode(nicID, true); err != nil {
		callbacks.Error("xray: enable promiscuous mode: " + err.String())
		return nil
	}

	if err := gStack.SetSpoofing(nicID, true); err != nil {
		callbacks.Error("xray: enable spoofing: " + err.String())
		return nil
	}

	instance, err := xray.NewInstance(context.Background(), gStack, endpoint, nicID, callbacks, cfg, virtualInbound)
	if err != nil {
		callbacks.Error("xray: new instance: " + err.Error())
		return nil
	}

	handle := toCtx(instance)

	transferred = true
	return handle
}

//export goxtun_xray_free
func goxtun_xray_free(ctx unsafe.Pointer) {
	if ctx == nil {
		return
	}

	instance, h := fromCtx[xray.Instance](ctx)

	instance.Close()
	h.Delete()
}

//export goxtun_xray_event
func goxtun_xray_event(ctx unsafe.Pointer, event C.int) {
	if ctx == nil {
		return
	}

	instance, _ := fromCtx[xray.Instance](ctx)

	instance.TriggerEvent(xray.Event(event))
}

//export goxtun_xray_downlink_bytes
func goxtun_xray_downlink_bytes(ctx unsafe.Pointer) C.uint64_t {
	if ctx == nil {
		return 0
	}

	instance, _ := fromCtx[xray.Instance](ctx)

	return C.uint64_t(instance.DownlinkBytes())
}

func wrapLog(cb C.goxtun_logcb, priv unsafe.Pointer) func(string) {
	if cb == nil {
		return func(string) {}
	}

	return func(msg string) {
		cstr := C.CString(msg)
		defer C.free(unsafe.Pointer(cstr))
		C.goxtun_logcb_invoke(cb, cstr, priv)
	}
}

func wrapRead(
	cb C.goxtun_readcb,
	priv unsafe.Pointer,
) func([]byte) (int, error) {
	return func(buf []byte) (int, error) {
		if len(buf) == 0 {
			return 0, nil
		}
		size := C.int(len(buf))
		if int(size) != len(buf) {
			return 0, fmt.Errorf("xray read: buffer too large: %d", len(buf))
		}

		n := int(C.goxtun_readcb_invoke(
			cb,
			unsafe.Pointer(&buf[0]),
			size,
			priv,
		))

		switch {
		case n < 0:
			return 0, fmt.Errorf("xray read: readcb err %d", n)
		case n == 0:
			return 0, nil
		case n > len(buf):
			return 0, fmt.Errorf("xray read: readcb n too large %d", n)
		default:
			return n, nil
		}
	}
}

func wrapWrite(
	cb C.goxtun_writecb,
	priv unsafe.Pointer,
) func([]byte) (int, error) {
	return func(buf []byte) (int, error) {
		if len(buf) == 0 {
			return 0, nil
		}
		size := C.int(len(buf))
		if int(size) != len(buf) {
			return 0, fmt.Errorf("xray write: buffer too large: %d", len(buf))
		}

		n := int(C.goxtun_writecb_invoke(
			cb,
			unsafe.Pointer(&buf[0]),
			size,
			priv,
		))

		switch {
		case n < 0:
			return 0, fmt.Errorf("xray write: writecb err %d", n)
		case n > len(buf):
			return 0, fmt.Errorf("xray write: writecb n too large %d", n)
		case n >= 0 && n < len(buf):
			return n, io.ErrShortWrite
		default:
			return n, nil
		}
	}
}

func wrapMTU(
	cb C.goxtun_mtucb,
	priv unsafe.Pointer,
) func() (int, error) {
	return func() (int, error) {
		mtu := int(C.goxtun_mtucb_invoke(cb, priv))
		if mtu < 0 {
			return 0, fmt.Errorf("xray mtu error: %d", mtu)
		}
		return mtu, nil
	}
}

func wrapSocket(
	cb C.goxtun_sockcb,
	priv unsafe.Pointer,
) func(int) {
	if cb == nil {
		return func(i int) {}
	}
	return func(fd int) {
		C.goxtun_sockcb_invoke(cb, C.int(fd), priv)
	}
}

func main() {}
