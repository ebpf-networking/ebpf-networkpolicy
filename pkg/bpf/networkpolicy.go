package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"k8s.io/klog/v2"
)

//go:generate go run -mod=vendor github.com/cilium/ebpf/cmd/bpf2go networkpolicy networkpolicy.c -- -I./include

func InitBPF(bpfs string) (map[string]*ebpf.Map, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		klog.ErrorS(err, "Could not remove memlock")
	}

	objs := networkpolicyObjects{}
	if err := loadNetworkpolicyObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("could not load objects: %v", err)
	}

	err := objs.IfNetworkPolicyBlocks.Pin(bpfs + "/if_network_policy_blocks")
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("could not pin object: %v", err)
	}

	return map[string]*ebpf.Map{
		"ingress_policy_map": objs.IngressPolicyMap,
		"egress_policy_map": objs.EgressPolicyMap,
	}, nil
}

type NetworkPolicyRule struct {
	PodIP net.IP
	Peer *net.IPNet

	Port     uint16
	PortMask uint16
	Protocol uint8
}

// struct networkpolicy_rule {
//   u32 pod_ip;
//   u32 peer_cidr;
//   u32 peer_mask;
//   u16 port;
//   u16 port_mask;
//   u8 protocol;
//   u8 pad1;
//   u16 pad2;
// };

func (rule *NetworkPolicyRule) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}

	ip4 := rule.PodIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("FIXME: no IPv6 support")
	}
	buf.Write(ip4)

	if rule.Peer != nil {
		ip4 = rule.Peer.IP.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("FIXME: no IPv6 support")
		}
		buf.Write(ip4)
		buf.Write(rule.Peer.Mask)
	} else {
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	}

	binary.Write(buf, binary.BigEndian, rule.Port)
	binary.Write(buf, binary.BigEndian, rule.PortMask)
	binary.Write(buf, binary.BigEndian, rule.Protocol)

	// padding
	buf.Write([]byte{0x00, 0x00, 0x00})

	return buf.Bytes(), nil
}
