package cmd

import (
	"testing"

	"github.com/musix/backhaul/config"
)

func TestDetectConfigType(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Config
		want string
	}{
		{
			name: "server by bind_addr",
			cfg:  config.Config{Server: config.ServerConfig{BindAddr: "0.0.0.0:443"}},
			want: "server",
		},
		{
			name: "client by single remote_addr",
			cfg:  config.Config{Client: config.ClientConfig{RemoteAddr: "ir.aosky.ir:443"}},
			want: "client",
		},
		{
			name: "client by remote_addrs only",
			cfg:  config.Config{Client: config.ClientConfig{RemoteAddrs: []string{"a:443", "b:443"}}},
			want: "client",
		},
		{
			name: "neither set",
			cfg:  config.Config{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectConfigType(&tc.cfg); got != tc.want {
				t.Errorf("detectConfigType = %q, want %q", got, tc.want)
			}
		})
	}
}
