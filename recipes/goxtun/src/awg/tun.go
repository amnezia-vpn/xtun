package awg

import (
	"os"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func NewTun(readCb TunReadCb, writeCb TunWriteCb, mtuCb TunMtuCb) *Tun {
	return &Tun{
		events:  make(chan tun.Event),
		readCb:  readCb,
		writeCb: writeCb,
		mtuCb:   mtuCb,
	}
}

var _ tun.Device = (*Tun)(nil)

type TunReadCb func(bufs [][]byte, sizes []int, offset int) (n int, err error)
type TunWriteCb func(bufs [][]byte, offset int) (int, error)
type TunMtuCb func() (int, error)

type Tun struct {
	events  chan tun.Event
	readCb  TunReadCb
	writeCb TunWriteCb
	mtuCb   TunMtuCb
}

func (t *Tun) File() *os.File {
	return nil
}

func (t *Tun) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	return t.readCb(bufs, sizes, offset)
}

func (t *Tun) Write(bufs [][]byte, offset int) (int, error) {
	return t.writeCb(bufs, offset)
}

func (t *Tun) MTU() (int, error) {
	return t.mtuCb()
}

func (t *Tun) Name() (string, error) {
	return "xtun", nil
}

func (t *Tun) Events() <-chan tun.Event {
	return t.events
}

func (t *Tun) TriggerEvent(event tun.Event) {
	t.events <- event
}

func (t *Tun) Close() error {
	close(t.events)
	return nil
}

func (t *Tun) BatchSize() int {
	return 1
}
