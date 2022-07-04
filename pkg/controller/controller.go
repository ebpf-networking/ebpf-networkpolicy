package controller

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/bpf"
	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/util"
)

// Run is the main entrypoint from the command lien
func Run() {
	// FIXME: set up to exit cleanly on SIGHUP

	stopCh := make(chan struct{})

	client, informers, err := newClients()
	if err != nil {
		klog.Fatalf("Could not create kubernetes clients: %v", err)
	}

	maps, err := bpf.InitBPF("/sys/fs/bpf")
	if err != nil {
		klog.Fatalf("Could not initialize eBPF: %v", err)
	}

	npc := newNetworkPolicyController(client, informers, stopCh)

	if !informers.Start(stopCh) {
		// This will only fail if stopCh was signalled, in which case something
		// else should already have been printed
		return
	}		

	npc.Run()

	go syncNetworkPolicy(npc, maps, stopCh)

	<- stopCh
}

func newClients() (kubernetes.Interface, *util.InformerManager, error) {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, nil)
        config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, nil, err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	informers := util.NewInformerManager(client)

	return client, informers, nil
}

func syncNetworkPolicy(npc *networkPolicyController, maps map[string]*ebpf.Map, stop <-chan struct{}) {
	ingressIsolationMap := maps["ingress_isolation_map"]
	egressIsolationMap := maps["egress_isolation_map"]
	ingressRuleMap := maps["ingress_rule_map"]
	egressRuleMap := maps["egress_rule_map"]

	select {
	case <-stop:
		return
	case <-npc.Updates():
		ingressPolicies, egressPolicies := npc.GetPodNetworkPolicies()
		err := updateMap("ingress", ingressPolicies, ingressIsolationMap, ingressRuleMap)
		if err != nil {
			klog.ErrorS(err, "Error updating ingress maps")
		}
		err = updateMap("egress", egressPolicies, egressIsolationMap, egressRuleMap)
		if err != nil {
			klog.ErrorS(err, "Error updating egress maps")
		}
	}
}

func updateMap(direction string, policies map[string][]bpf.NetworkPolicyRule, isolationMap, ruleMap *ebpf.Map) error {
	var isolationKeys, ruleKeys []uint32
	var isolationValues []uint8
	var ruleValues []bpf.NetworkPolicyRule

	for podIPStr, rules := range policies {
		podIP := net.ParseIP(podIPStr).To4()
		if podIP == nil {
			// FIXME IPv6
			continue
		}
		podIPu32 := binary.BigEndian.Uint32(podIP)

		isolationKeys = append(isolationKeys, podIPu32)
		isolationValues = append(isolationValues, uint8(1))

		for _, rule := range rules {
			ruleKeys = append(ruleKeys, uint32(len(ruleKeys)))
			ruleValues = append(ruleValues, rule)
		}
	}

	if len(isolationKeys) > 1024 {
		klog.ErrorS(nil, "Discarding isolation info for some pods",
			"direction", direction,
			"num_pods", len(isolationKeys) - 1024,
		)
		isolationKeys = isolationKeys[:1024]
		isolationValues = isolationValues[:1024]
	}
	_, err := isolationMap.BatchUpdate(isolationKeys, isolationValues, nil)
	if err != nil {
		return err
	}

	if len(ruleKeys) > 1024 {
		klog.ErrorS(nil, "Discarding some allow rules",
			"direction", direction,
			"num_rules", len(ruleKeys) - 1024,
		)
		ruleKeys = ruleKeys[:1024]
		ruleValues = ruleValues[:1024]
	}
	_, err = ruleMap.BatchUpdate(ruleKeys, ruleValues, nil)
	if err != nil {
		return err
	}

	return nil
}
