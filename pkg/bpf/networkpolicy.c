//go:build ignore
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u8);
  __uint(max_entries, 1000);
} egress_isolation_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u8);
  __uint(max_entries, 1000);
} ingress_isolation_map SEC(".maps");

struct networkpolicy_rule {
  u32 pod_ip;
  u32 peer_cidr;
  u32 peer_mask;
  u16 port;
  u16 port_mask;
  u8 protocol;
  u8 pad1;
  u16 pad2;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct networkpolicy_rule);
  __uint(max_entries, 1000);
} egress_rule_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct networkpolicy_rule);
  __uint(max_entries, 1000);
} ingress_rule_map SEC(".maps");

static int __always_inline check_networkpolicy_direction(void *isolation_map, void *rule_map, u32 pod_ip, u32 peer_ip, u8 protocol, u16 port)
{
  struct networkpolicy_rule *rule;
  u32 i;
  u8 *isolated;

  isolated = bpf_map_lookup_elem(isolation_map, &pod_ip);
  if (isolated == NULL || !*isolated)
    return true;

  for (i = 0; i < 1000; i++)
    {
      rule = bpf_map_lookup_elem(&rule_map, &i);
      if (rule == NULL)
        break;

      if (pod_ip != rule->pod_ip)
        continue;
      if ((peer_ip & rule->peer_mask) != rule->peer_cidr)
        continue;
      if (rule->protocol != 0)
        {
          if (protocol != rule->protocol)
            continue;
          if ((port & rule->port_mask) != rule->port)
            continue;
        }

      return true;
    }

  return false;
}

static int __always_inline check_networkpolicy(u32 src_ip, u32 dst_ip, u8 protocol, u16 port)
{
  if (!check_networkpolicy_direction(&egress_isolation_map, &egress_rule_map, src_ip, dst_ip, protocol, port))
    return false;
  return check_networkpolicy_direction(&ingress_isolation_map, &ingress_rule_map, dst_ip, src_ip, protocol, port);
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
