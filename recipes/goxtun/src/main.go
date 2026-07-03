package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef GOGLUE_DEF
#define GOGLUE_DEF

#ifdef _MSC_VER
// MSVC does not support complex type definitions
// So here is a workaround to bypass this behavior
// See go.dev/issues/36233
typedef float _Fcomplex;
typedef double _Dcomplex;
#endif

typedef int (*goglue_readcb)(void* b, int len, void *priv);
static inline int goglue_readcb_invoke(goglue_readcb cb, void* b, int len, void *priv)
{
	return cb(b, len, priv);
}

typedef int (*goglue_writecb)(void* b, int len, void *priv);
static inline int goglue_writecb_invoke(goglue_writecb cb, void* b, int len, void *priv)
{
	return cb(b, len, priv);
}

typedef int (*goglue_mtucb)(void *priv);
static inline int goglue_mtucb_invoke(goglue_mtucb cb, void *priv)
{
	return cb(priv);
}

typedef void (*goglue_logcb)(char *str, void *priv);
static inline void goglue_logcb_invoke(goglue_logcb cb, char *str, void *priv)
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
	"github.com/amnezia-vpn/libxtun/goglue/awg"
)

func toCtx(v any) unsafe.Pointer {
	h := cgo.NewHandle(v)
	return unsafe.Pointer(h)
}

func fromCtx[K any](ctx unsafe.Pointer) (*K, cgo.Handle) {
	h := *(*cgo.Handle)(ctx)
	o, _ := h.Value().(*K)
	return o, h
}

//export goglue_awg_new
func goglue_awg_new(
	readCb C.goglue_readcb,
	writeCb C.goglue_writecb,
	mtuCb C.goglue_mtucb,
	tunPriv unsafe.Pointer,
	verbosefCb C.goglue_logcb,
	debugfCb C.goglue_logcb,
	logPriv unsafe.Pointer,
) unsafe.Pointer {
	tun := awg.NewTun(
		func(bufs [][]byte, sizes []int, offset int) (n int, err error) {
			buf := bufs[0][offset:]
			ret := int(C.goglue_readcb_invoke(readCb, unsafe.Pointer(&buf[0]), C.int(len(buf)), tunPriv))
			if ret < 0 {
				return 0, errors.New("failed")
			}
			sizes[0] = ret
			return 1, nil
		}, func(bufs [][]byte, offset int) (int, error) {
			buf := bufs[0][offset:]
			ret := int(C.goglue_writecb_invoke(writeCb, unsafe.Pointer(&buf[0]), C.int(len(buf)), tunPriv))
			if ret < 0 {
				return 0, errors.New("failed")
			}
			return 1, nil
		},
		func() (int, error) {
			ret := int(C.goglue_mtucb_invoke(mtuCb, tunPriv))
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
			C.goglue_logcb_invoke(verbosefCb, cstr, logPriv)
			C.free(unsafe.Pointer(cstr))
		},
		Errorf: func(format string, args ...any) {
			str := fmt.Sprintf(format, args...)
			cstr := C.CString(str)
			C.goglue_logcb_invoke(debugfCb, cstr, logPriv)
			C.free(unsafe.Pointer(cstr))
		},
	}

	i := awg.NewInstance(tun, log)
	return toCtx(i)
}

//export goglue_awg_free
func goglue_awg_free(ctx unsafe.Pointer) {
	i, h := fromCtx[awg.Instance](ctx)

	defer h.Delete()
	i.Close()
}

//export goglue_awg_event
func goglue_awg_event(ctx unsafe.Pointer, event C.int) {
	i, _ := fromCtx[awg.Instance](ctx)

	i.TriggerEvent(tun.Event(event))
}

//export goglue_awg_set_ipc
func goglue_awg_set_ipc(ctx unsafe.Pointer, ipc *C.char) *C.char {
	i, _ := fromCtx[awg.Instance](ctx)

	goIpc := C.GoString(ipc)
	if err := i.IpcSet(goIpc); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func main() {}
