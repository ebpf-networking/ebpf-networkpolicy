package controller

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/util"
)

// Run is the main entrypoint from the command lien
func Run() {
	// FIXME: set up to exit cleanly on SIGHUP

	stopCh := make(chan struct{})

	client, informers, err := newClients()
	if err != nil {
		klog.Fatal("Could not create kubernetes clients: %v", err)
	}

	npc := newNetworkPolicyController(client, informers, stopCh)

	if !informers.Start(stopCh) {
		// This will only fail if stopCh was signalled, in which case something
		// else should already have been printed
		return
	}		

	npc.Run()

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
