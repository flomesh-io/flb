package main

import "C"
import (
	"net"

	dp "github.com/flomesh-io/flb/pkg/datapath"
)

func loadAttachEBpf(nodeNo uint32) {
	if ret := dp.LinkTapDev(dp.FLB_MGMT_CHANNEL); ret == 0 {
		dp.LoadXdpProg()
		dp.AttachXdpProg(dp.FLB_MGMT_CHANNEL)
		dp.AttachTcProg(dp.FLB_MGMT_CHANNEL)
	}

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == dp.FLB_MGMT_CHANNEL {
				continue
			}
			dp.AttachTcProg(intf.Name)
		}
	}
}

func unloadEBpf() {
	dp.DetachTcProg(dp.FLB_MGMT_CHANNEL)
	dp.DetachXdpProg(dp.FLB_MGMT_CHANNEL)
	dp.UnlinkTapDev(dp.FLB_MGMT_CHANNEL)

	ifList, err := net.Interfaces()
	if err == nil {
		for _, intf := range ifList {
			if intf.Name == dp.FLB_MGMT_CHANNEL {
				continue
			}
			dp.DetachTcProg(intf.Name)
		}
	}
	dp.RemoveEBpfMaps()
	dp.UnloadXdpProg()
}
