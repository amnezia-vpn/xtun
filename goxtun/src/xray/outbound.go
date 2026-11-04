package xray

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func init() {
	common.Must(common.RegisterConfig(
		(*OwnerOutboundConfig)(nil),
		func(ctx context.Context, config any) (any, error) {
			return newOwnedOutbound(ctx, config.(*OwnerOutboundConfig))
		},
	))
}

type ownedOutbound struct {
	owner *Instance
	inner proxy.Outbound
}

var _ proxy.Outbound = (*ownedOutbound)(nil)
var _ common.Closable = (*ownedOutbound)(nil)

func (o *ownedOutbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	ctx, p, err := o.owner.beginOutbound(ctx)
	if err != nil {
		return err
	}
	defer o.owner.endOutbound(p)

	ctx = context.WithValue(ctx, socketOwnerKey{}, o.owner)
	ctx = context.WithValue(ctx, socketScopeKey{}, &p.scope)

	return o.inner.Process(ctx, link, dialer)
}

func (o *ownedOutbound) Close() error {
	return common.Close(o.inner)
}

func newOwnedOutbound(ctx context.Context, config *OwnerOutboundConfig) (*ownedOutbound, error) {
	if config == nil || config.Inner == nil {
		return nil, errors.New("xray: inner outbound config is required")
	}

	owner, err := socketOwnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	innerConfig, err := config.Inner.GetInstance()
	if err != nil {
		return nil, err
	}

	raw, err := common.CreateObject(ctx, innerConfig)
	if err != nil {
		return nil, err
	}

	inner, ok := raw.(proxy.Outbound)
	if !ok {
		common.Close(raw)
		return nil, fmt.Errorf("xray: inner wrong type %T", raw)
	}

	return &ownedOutbound{owner: owner, inner: inner}, nil
}

type outboundProcess struct {
	cancel   context.CancelFunc
	scope    socketScope
	stopOnce sync.Once
}

func (p *outboundProcess) stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		p.scope.Close()
	})
}

func (i *Instance) beginOutbound(ctx context.Context) (context.Context, *outboundProcess, error) {
	i.flowMu.Lock()
	defer i.flowMu.Unlock()

	if ctx.Err() != nil {
		return ctx, nil, ctx.Err()
	}

	if i.stopping {
		return ctx, nil, context.Canceled
	}

	ctx, cancel := context.WithCancel(ctx)

	outboundProcess := &outboundProcess{
		cancel: cancel,
		scope:  socketScope{},
	}

	i.outboundProcesses[outboundProcess] = struct{}{}

	i.workers.Add(1)

	return ctx, outboundProcess, nil
}

func (i *Instance) endOutbound(p *outboundProcess) {
	p.stop()
	i.flowMu.Lock()
	delete(i.outboundProcesses, p)
	i.flowMu.Unlock()
	i.workers.Done()
}

func wrapOutbounds(config *core.Config) (*core.Config, error) {
	if config == nil {
		return nil, errors.New("xray: config is required")
	}

	prepared := proto.CloneOf(config)

	for index, outbound := range prepared.Outbound {
		if outbound == nil || outbound.ProxySettings == nil {
			return nil, fmt.Errorf(
				"xray: outbound[%d]: proxy settings are required",
				index,
			)
		}
		outbound.ProxySettings = serial.ToTypedMessage(
			&OwnerOutboundConfig{
				Inner: outbound.ProxySettings,
			},
		)
	}

	return prepared, nil
}
