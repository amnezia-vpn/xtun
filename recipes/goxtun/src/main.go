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

#endif
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime/cgo"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/libxtun/goxtun/awg"
)

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
	debugfCb C.goxtun_logcb,
	logPriv unsafe.Pointer,
) unsafe.Pointer {
	tun := awg.NewTun(
		func(bufs [][]byte, sizes []int, offset int) (n int, err error) {
			buf := bufs[0][offset:]
			ret := int(C.goxtun_readcb_invoke(readCb, unsafe.Pointer(&buf[0]), C.int(len(buf)), tunPriv))
			if ret < 0 {
				return 0, errors.New("failed")
			}
			sizes[0] = ret
			return 1, nil
		}, func(bufs [][]byte, offset int) (int, error) {
			buf := bufs[0][offset:]
			ret := int(C.goxtun_writecb_invoke(writeCb, unsafe.Pointer(&buf[0]), C.int(len(buf)), tunPriv))
			if ret < 0 {
				return 0, errors.New("failed")
			}
			return 1, nil
		},
		func() (int, error) {
			ret := int(C.goxtun_mtucb_invoke(mtuCb, tunPriv))
			if ret < 0 {
				return 0, errors.New("failed")
			}
			return ret, nil
		},
	)

	log := &device.Logger{
		Verbosef: func(format string, args ...any) {
			str := fmt.Sprintf(format, args...)
			cstr := C.CString(str)
			C.goxtun_logcb_invoke(verbosefCb, cstr, logPriv)
			C.free(unsafe.Pointer(cstr))
		},
		Errorf: func(format string, args ...any) {
			str := fmt.Sprintf(format, args...)
			cstr := C.CString(str)
			C.goxtun_logcb_invoke(debugfCb, cstr, logPriv)
			C.free(unsafe.Pointer(cstr))
		},
	}

	i := awg.NewInstance(tun, log)
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

//export goxtun_awg_serve_uapi
func goxtun_awg_serve_uapi(ctx unsafe.Pointer, name *C.char) *C.char {
	i, _ := fromCtx[awg.Instance](ctx)

	if err := i.ServeUAPI(C.GoString(name)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func main() {}
