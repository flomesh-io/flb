package main

import "C"
import (
	"fmt"
	"net"
	"os"

	"github.com/flomesh-io/flb/pkg/bpf"
	dp "github.com/flomesh-io/flb/pkg/datapath"
)

func loadAttachEBpf(nodeNo uint32) {
	if ret := bpf.LinkTapDev(dp.FLB_MGMT_CHANNEL); ret == 0 {
		bpf.LoadXdpProg()

		dp.DpInit(nodeNo)

		bpf.AttachXdpProg(dp.FLB_MGMT_CHANNEL)
		bpf.AttachTcProg(dp.FLB_MGMT_CHANNEL)
	}

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == dp.FLB_MGMT_CHANNEL {
				continue
			}
			bpf.AttachTcProg(intf.Name)
		}
	}
}

func unloadEBpf() {
	bpf.DetachTcProg(dp.FLB_MGMT_CHANNEL)
	bpf.DetachXdpProg(dp.FLB_MGMT_CHANNEL)
	bpf.UnlinkTapDev(dp.FLB_MGMT_CHANNEL)

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == dp.FLB_MGMT_CHANNEL {
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
		dp.FLB_DB_MAP_PDIR,
		fmt.Sprintf(`%s/tc/globals`, dp.FLB_DB_MAP_PDIR),
	}

	for _, folder := range folders {
		dp.EachMap(func(emap *dp.DpMap) {
			os.Remove(fmt.Sprintf(`%s/%s`, folder, emap.Name()))
		})
	}
}
