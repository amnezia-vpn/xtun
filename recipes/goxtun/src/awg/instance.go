package awg

import (
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func NewInstance(tun *Tun, logger *device.Logger) *Instance {
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	return &Instance{
		Device: dev,
		tun:    tun,
	}
}

type Instance struct {
	*device.Device
	tun *Tun
}

func (i *Instance) SetConf(uapi string) error {
	return i.IpcSet(uapi)
}

func (i *Instance) Close() {
	i.Device.Close()
}

func (i *Instance) TriggerEvent(event tun.Event) {
	i.tun.TriggerEvent(event)
}
