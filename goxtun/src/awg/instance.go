package awg

import (
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func NewInstance(tun *Tun, bind *Bind, log *Logger) *Instance {
	dev := device.NewDevice(tun, bind, &log.Logger)
	return &Instance{
		Device: dev,
		tun:    tun,
		log:    log,
	}
}

type Instance struct {
	*device.Device
	tun *Tun
	log *Logger
}

func (i *Instance) SetConf(uapi string) error {
	return i.IpcSet(uapi)
}

func (i *Instance) Close() {
	i.Device.Close()
	i.log.Close()
}

func (i *Instance) TriggerEvent(event tun.Event) {
	i.tun.TriggerEvent(event)
}
