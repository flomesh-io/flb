package main

import "C"
import (
	"net"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/config"
)

func loadAttachEBpf() {
	if ret := bpf.LinkTapDev(config.TapDevName); ret == 0 {
		bpf.LoadXdpProg()

		setupCrc32cMap()
		setupCtCtrMap(config.NodeNo)
		setupCpuMap()
		setupLiveCpuMap()

		bpf.AttachXdpProg(config.TapDevName)
		bpf.AttachTcProg(config.TapDevName)
	}

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == config.TapDevName {
				continue
			}
			bpf.AttachTcProg(intf.Name)
		}
	}
}

func unloadEBpf() {
	bpf.DetachTcProg(config.TapDevName)
	bpf.DetachXdpProg(config.TapDevName)
	bpf.UnlinkTapDev(config.TapDevName)

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == config.TapDevName {
				continue
			}
			bpf.DetachTcProg(intf.Name)
		}
	}
	bpf.RemoveEBpfMaps()
	bpf.UnloadXdpProg()
}
