package main

import "C"
import (
	"fmt"
	"net"
	"os"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/config"
	dp "github.com/flomesh-io/flb/pkg/datapath"
)

func loadAttachEBpf() {
	if ret := bpf.LinkTapDev(config.FLB_TAP_NAME); ret == 0 {
		bpf.LoadXdpProg()

		setupCrc32cMap()
		setupCtCtrMap(config.NodeNo)
		setupCpuMap()
		setupLiveCpuMap()

		bpf.AttachXdpProg(config.FLB_TAP_NAME)
		bpf.AttachTcProg(config.FLB_TAP_NAME)
	}

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == config.FLB_TAP_NAME {
				continue
			}
			bpf.AttachTcProg(intf.Name)
		}
	}
}

func unloadEBpf() {
	bpf.DetachTcProg(config.FLB_TAP_NAME)
	bpf.DetachXdpProg(config.FLB_TAP_NAME)
	bpf.UnlinkTapDev(config.FLB_TAP_NAME)

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == config.FLB_TAP_NAME {
				continue
			}
			bpf.DetachTcProg(intf.Name)
		}
	}
	removeEBpfMaps()
	bpf.UnloadXdpProg()
}

func removeEBpfMaps() {
	folders := []string{
		config.BPF_FS_BASE,
		fmt.Sprintf(`%s/tc/globals`, config.BPF_FS_BASE),
	}

	for _, folder := range folders {
		dp.EachMap(func(emap *dp.DpMap) {
			os.Remove(fmt.Sprintf(`%s/%s`, folder, emap.Name()))
		})
	}
}
