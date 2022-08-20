//go:build ignore
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// There are two top-level policy maps, `ingress_policy_map` and `egress_policy_map`, of
// type `struct gress_policy_map`. Each maps from pod ID to the `struct peer_allowed_map`
// for that pod. (The pod ID is a `u32`; for the moment, the code only handles IPv4 and
// the pod ID is just the pod IP, but when we add IPv6 support, the idea is that the pod
// ID will still be 32 bits, not 128.)
//
// The `struct peer_allowed_map` is an LPM trie mapping from peer IP (currently a `u32`,
// but eventually a `struct in6_addr`, or maybe we will have separate IPv4 and IPv6 maps?)
// to a `struct peer_verdict`. If the verdict's `type` is `ALLOW_ALL`, then all traffic
// to/from that peer is allowed (and the verdict's `protocol` and `port` are ignored). If
// it is `SINGLE_PORT` then traffic with the given `protocol` and destination `port` is
// allowed (and other traffic is not). If it is `PORT_LIST` then `protocol` is ignored and
// `port` is an ID to look up in `port_allowed_map`.
//
// `port_allowed_map` is an LPM trie mapping from `struct port_allowed_key` to a yes/no
// verdict. The `port_list_id` and `protocol` will always be matched in full, but the
// `port` may be partially matched. The actual map value is currently ignored; if the key
// exists in the map then the traffic is allowed, and if it doesn't then it's not.

struct peer_key {
	struct bpf_lpm_trie_key lpm;
	u32 ip;
};

struct peer_verdict {
	u8 type;
	u8 protocol;
	u16 port;
};

#define PEER_VERDICT_ALLOW_ALL 0
#define PEER_VERDICT_SINGLE_PORT 1
#define PEER_VERDICT_PORT_LIST 2

struct peer_allowed_map {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct peer_key);
	__type(value, struct peer_verdict);
	__uint(max_entries, 10000);
	// XXX we get EINVAL if we don't specify this?
	__uint(map_flags, BPF_F_NO_PREALLOC);
};

// XXX Need to define an unused object of type struct peer_allowed_map to get BTF
// generation to work correctly for gress_policy_map.  Not clear if this is expected or if
// it's a bug in cilium/ebpf's codegen.
struct peer_allowed_map dummy SEC(".maps");

struct gress_policy_map {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 10000);
	__array(values, struct peer_allowed_map);
};

struct gress_policy_map ingress_policy_map SEC(".maps");
struct gress_policy_map egress_policy_map SEC(".maps");

struct port_allowed_key {
	struct bpf_lpm_trie_key lpm;
	u16 port_list_id;
	u16 port;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct port_allowed_key);
	__type(value, u8);
	__uint(max_entries, 10000);
	// XXX we get EINVAL if we don't specify this?
	__uint(map_flags, BPF_F_NO_PREALLOC);
}  port_allowed_map SEC(".maps");

static int __always_inline check_networkpolicy_direction(void *policy_map, u32 pod_ip, u32 peer_ip, u8 protocol, u16 port)
{
	struct peer_allowed_map *peer_map;
	struct peer_verdict *verdict;
	struct port_allowed_key port_key;

	peer_map = bpf_map_lookup_elem(policy_map, &pod_ip);
	if (!peer_map)
		return true;

	verdict = bpf_map_lookup_elem(peer_map, &peer_ip);
	if (!verdict)
		return false;

	switch (verdict->type) {
	case PEER_VERDICT_ALLOW_ALL:
		return true;
	case PEER_VERDICT_SINGLE_PORT:
		return verdict->protocol == protocol && verdict->port == port;
	case PEER_VERDICT_PORT_LIST:
		port_key.port_list_id = verdict->port;
		port_key.port = port;
		return bpf_map_lookup_elem(&port_allowed_map, &port_key) != NULL;
	}

	// should not be reached
	return false;
}

static int __always_inline check_networkpolicy(u32 src_ip, u32 dst_ip, u8 protocol, u16 port)
{
	if (!check_networkpolicy_direction(&egress_policy_map, src_ip, dst_ip, protocol, port))
		return false;
	return check_networkpolicy_direction(&ingress_policy_map, dst_ip, src_ip, protocol, port);
}

SEC("socket/if_network_policy_blocks")
int if_network_policy_blocks(struct __sk_buff *skb)
{
	u16 port;

	// Parse the packet; socket filter programs aren't allowed to read
	// skb->data directly, so we have to do this the old-fashioned way.

	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) != 0)
		return false;
	// no IP options; but this doesn't work under cilium/ebpf because it's a bitfield
	// if (iph.ihl != 5)
	//        return false;

	switch (iph.protocol) {
	case IPPROTO_UDP:
	{
		struct udphdr udp;
		if (bpf_skb_load_bytes(skb, sizeof(iph), &udp, sizeof(udp)) != 0)
			return false;
		port = udp.dest;
		break;
	}

	case IPPROTO_TCP:
	{
		struct tcphdr tcp;
		if (bpf_skb_load_bytes(skb, sizeof(iph), &tcp, sizeof(tcp)) != 0)
			return false;
		port = tcp.dest;
		break;
	}

	case IPPROTO_SCTP:
	{
		struct sctphdr sctp;
		if (bpf_skb_load_bytes(skb, sizeof(iph), &sctp, sizeof(sctp)) != 0)
			return false;
		port = sctp.dest;
		break;
	}

	default:
		return false;
	}

	// negate, because iptables wants a program that returns true if the
	// packet is NOT allowed
	return !check_networkpolicy(iph.saddr, iph.daddr, iph.protocol, port);
}
