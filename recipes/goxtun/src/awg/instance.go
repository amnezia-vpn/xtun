package awg

import (
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Built in two steps because the callbacks the device is started with have to be
// able to reach Call, and the workers start logging inside device.NewDevice.
func NewInstance() *Instance {
	return &Instance{}
}

type Instance struct {
	*device.Device
	tun *Tun

	mu     sync.Mutex
	closed bool
}

func (i *Instance) Start(tun *Tun, bind *Bind, logger *device.Logger) {
	i.tun = tun
	i.Device = device.NewDevice(tun, bind, logger)
}

// Call runs fn unless the device is closed. Close takes the same lock, so once it
// returns nothing is in flight and nothing new starts: the caller may then free
// whatever the callbacks point at.
func (i *Instance) Call(fn func()) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return
	}
	fn()
}

func (i *Instance) SetConf(uapi string) error {
	return i.IpcSet(uapi)
}

func (i *Instance) Close() {
	i.Device.Close()

	i.mu.Lock()
	defer i.mu.Unlock()

	i.closed = true
}

func (i *Instance) TriggerEvent(event tun.Event) {
	i.tun.TriggerEvent(event)
}
