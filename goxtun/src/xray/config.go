package xray

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/vless"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

type Config struct {
	ServerIP   string `json:"serverIP"`
	ServerPort uint16 `json:"serverPort"`
	UUID       string `json:"uuid"`
	ServerName string `json:"serverName"`
	PublicKey  string `json:"publicKey"`
	ShortID    string `json:"shortId"`
}

func (c Config) Validate() error {
	addr, err := netip.ParseAddr(c.ServerIP)
	if err != nil {
		return errors.New("xray: invalid server IP")
	}
	if addr.Zone() != "" {
		return errors.New("xray: IPv6 zones are not supported")
	}

	if c.ServerPort == 0 {
		return errors.New("xray: server port must be non-zero")
	}

	id, err := uuid.ParseString(c.UUID)
	if err != nil || id.String() != strings.ToLower(c.UUID) {
		return errors.New("xray: invalid uuid")
	}

	if c.ServerName == "" || strings.ContainsAny(c.ServerName, " \t\r\n/:") {
		return errors.New("xray: invalid server name")
	}

	key, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
	if err != nil || len(key) != 32 {
		return errors.New("xray: public key must decode to 32 bytes")
	}

	if len(c.ShortID) > 16 {
		return errors.New("xray: short ID must be at most 16 hex characters")
	}
	if _, err := hex.DecodeString(c.ShortID); err != nil {
		return errors.New("xray: invalid short ID")
	}

	return nil
}

const (
	FingerprintChrome = "chrome"
)

func (c Config) Build() (*core.Config, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	key, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("xray: public key must decode to 32 bytes")
	}

	shortID, err := hex.DecodeString(c.ShortID)
	if err != nil {
		return nil, errors.New("xray: invalid short ID")
	}

	realitySettings := serial.ToTypedMessage(&reality.Config{
		ServerName:  c.ServerName,
		Fingerprint: FingerprintChrome,
		PublicKey:   key,
		ShortId:     shortID,
		Show:        false,
		SpiderX:     "/",
		SpiderY:     make([]int64, 10),
	})

	acc := vless.Account{
		Id:         c.UUID,
		Encryption: "none",
		Flow:       vless.XRV + "-udp443",
	}
	user := protocol.User{
		Level:   0,
		Account: serial.ToTypedMessage(&acc),
	}
	serverEndpoint := &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.ParseAddress(c.ServerIP)),
		Port:    uint32(c.ServerPort),
		User:    &user,
	}

	outConf := core.OutboundHandlerConfig{
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			StreamSettings: &internet.StreamConfig{
				ProtocolName: "tcp",
				SecurityType: realitySettings.Type,
				SecuritySettings: []*serial.TypedMessage{
					realitySettings,
				},
			},
		}),
		ProxySettings: serial.ToTypedMessage(&vlessoutbound.Config{
			Vnext: serverEndpoint,
		}),
	}

	app := []*serial.TypedMessage{
		serial.ToTypedMessage(&xlog.Config{
			ErrorLogType:  xlog.LogType_None,
			AccessLogType: xlog.LogType_None,
		}),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&policy.Config{
			Level: map[uint32]*policy.Policy{
				0: {
					Timeout: &policy.Policy_Timeout{
						DownlinkOnly: &policy.Second{Value: 30},
					},
				},
			},
		}),
	}

	return &core.Config{
		App:      app,
		Outbound: []*core.OutboundHandlerConfig{&outConf},
	}, nil
}

func ParseConfig(raw string) (Config, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("xray: decode config: %w", err)
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("xray: unexpected data after config")
	}

	return cfg, nil
}
