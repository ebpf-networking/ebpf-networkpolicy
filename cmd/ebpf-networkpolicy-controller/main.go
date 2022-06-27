package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"

	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/controller"
)

func main() {
	cmd := &cobra.Command{
		Use:   "ebpf-networkpolicy-controller",
		Short: "Start eBPF NetworkPolicy Controller",
		Long:  "Start eBPF NetworkPolicy Controller",
		Run:   func (c *cobra.Command, _ []string) {
			controller.Run()
		},
	}
	code := cli.Run(cmd)
	os.Exit(code)
}
