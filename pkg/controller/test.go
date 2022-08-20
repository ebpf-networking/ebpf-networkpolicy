package controller

import (
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/bpf"
	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/util"
)

// Test is the entrypoint for test-ebpf-networkpolicy
func Test() {
	// FIXME: set up to exit cleanly on SIGHUP

	stopCh := make(chan struct{})

	client := fake.NewSimpleClientset()
	informers := util.NewInformerManager(client)

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

