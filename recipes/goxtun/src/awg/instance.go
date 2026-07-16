package awg

import (
	"net"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
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
	tun  *Tun
	uapi net.Listener
}

func (i *Instance) ServeUAPI(name string) error {
	file, err := ipc.UAPIOpen(name)
	if err != nil {
		return err
	}

	listener, err := ipc.UAPIListen(name, file)
	if err != nil {
		file.Close()
		return err
	}
	i.uapi = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go i.Device.IpcHandle(conn)
		}
	}()
	return nil
}

func (i *Instance) Close() {
	if i.uapi != nil {
		i.uapi.Close()
		i.uapi = nil
	}
	i.Device.Close()
}

func (i *Instance) TriggerEvent(event tun.Event) {
	i.tun.TriggerEvent(event)
}
