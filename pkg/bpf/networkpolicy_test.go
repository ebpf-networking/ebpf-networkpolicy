package bpf

import (
	"net"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func mustParseCIDR(cidrStr string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		panic(err.Error())
	}
	return cidr
}

func TestNetworkPolicyRule_MarshalBinary(t *testing.T) {
	testcases := []struct{
		name   string
		rule   *NetworkPolicyRule
		binary []byte
	}{
		{
			name: "basic",
			rule: &NetworkPolicyRule{
				PodIP: net.ParseIP("1.2.3.4"),
				Peer:  mustParseCIDR("5.6.7.8/32"),
			},
			binary: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08,
				0xFF, 0xFF, 0xFF, 0xFF,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "subnet",
			rule: &NetworkPolicyRule{
				PodIP: net.ParseIP("1.2.3.4"),
				Peer:  mustParseCIDR("5.6.7.0/24"),
			},
			binary: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x00,
				0xFF, 0xFF, 0xFF, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "no peer",
			rule: &NetworkPolicyRule{
				PodIP: net.ParseIP("1.2.3.4"),
				Peer:  nil,
			},
			binary: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "single port",
			rule: &NetworkPolicyRule{
				PodIP: net.ParseIP("1.2.3.4"),
				Peer:  mustParseCIDR("5.6.7.0/24"),

				Protocol: unix.IPPROTO_TCP,
				Port:     8080,
				PortMask: 0xFFFF,
			},
			binary: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x00,
				0xFF, 0xFF, 0xFF, 0x00,
				0x1F, 0x90, 0xFF, 0xFF,
				0x06, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "port range",
			rule: &NetworkPolicyRule{
				PodIP: net.ParseIP("1.2.3.4"),
				Peer:  mustParseCIDR("5.6.7.0/24"),

				Protocol: unix.IPPROTO_TCP,
				Port:     8080,
				PortMask: 0xFFF0,
			},
			binary: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x00,
				0xFF, 0xFF, 0xFF, 0x00,
				0x1F, 0x90, 0xFF, 0xF0,
				0x06, 0x00, 0x00, 0x00,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			binary, err := tc.rule.MarshalBinary()
			if err != nil {
				t.Errorf("unexpected error")
			}
			if !reflect.DeepEqual(binary, tc.binary) {
				t.Errorf("marshalling mismatch: expected\n%#v\ngot\n%#v", tc.binary, binary)
			}
		})
	}
}
