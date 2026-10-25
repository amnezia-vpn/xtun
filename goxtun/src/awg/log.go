package awg

import (
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

func NewLogger(verbosef func(format string, args ...any), debugf func(format string, args ...any)) *Logger {
	l := &Logger{}

	l.Logger.Verbosef = func(format string, args ...any) {
		if l.closed.Load() {
			return
		}
		l.wg.Add(1)
		if l.closed.Load() {
			l.wg.Done()
			return
		}
		defer l.wg.Done()
		verbosef(format, args...)
	}
	l.Logger.Errorf = func(format string, args ...any) {
		if l.closed.Load() {
			return
		}
		l.wg.Add(1)
		if l.closed.Load() {
			l.wg.Done()
			return
		}
		defer l.wg.Done()
		verbosef(format, args...)
	}

	return l
}

type Logger struct {
	device.Logger
	closed atomic.Bool
	wg     sync.WaitGroup
}

func (l *Logger) Close() {
	l.closed.Store(true)
	l.wg.Wait()
}
