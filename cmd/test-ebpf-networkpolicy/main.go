package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"

	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/controller"
)

func main() {
	cmd := &cobra.Command{
		Use:   "test-ebpf-networkpolicy",
		Short: "Test eBPF NetworkPolicy Controller",
		Long:  "Test eBPF NetworkPolicy Controller",
		Run:   func (c *cobra.Command, _ []string) {
			controller.Test()
		},
	}
	code := cli.Run(cmd)
	os.Exit(code)
}
