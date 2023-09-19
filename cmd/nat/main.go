package main

import (
	"fmt"
	"net"

	"github.comflomesh-io/flb/pkg/api"
)

func main() {

	natWorkQ := new(api.NatDpWorkQ)
	natWorkQ.ZoneNum = 1
	natWorkQ.ServiceIP = net.ParseIP("20.20.20.1")
	natWorkQ.L4Port = 8080
	natWorkQ.BlockNum = 0
	natWorkQ.DsrMode = false
	natWorkQ.CsumDis = false
	natWorkQ.Proto = 6
	natWorkQ.Mark = 1
	natWorkQ.NatType = 2
	natWorkQ.EpSel = 1
	natWorkQ.InActTo = 240
	natWorkQ.EndPoints = make([]api.NatEP, 3)

	natWorkQ.EndPoints[0].XIP = net.ParseIP("31.31.31.1")
	natWorkQ.EndPoints[0].RIP = net.ParseIP("0.0.0.0")
	natWorkQ.EndPoints[0].XPort = 8080
	natWorkQ.EndPoints[0].Weight = 1
	natWorkQ.EndPoints[0].InActive = false

	natWorkQ.EndPoints[1].XIP = net.ParseIP("32.32.32.1")
	natWorkQ.EndPoints[1].RIP = net.ParseIP("0.0.0.0")
	natWorkQ.EndPoints[1].XPort = 8080
	natWorkQ.EndPoints[1].Weight = 1
	natWorkQ.EndPoints[1].InActive = false

	natWorkQ.EndPoints[2].XIP = net.ParseIP("33.33.33.1")
	natWorkQ.EndPoints[2].RIP = net.ParseIP("0.0.0.0")
	natWorkQ.EndPoints[2].XPort = 8080
	natWorkQ.EndPoints[2].Weight = 1
	natWorkQ.EndPoints[2].InActive = false

	natWorkQ.Work = api.DpMapShow

	ret := api.DpNatLbRuleMod(natWorkQ)
	fmt.Println(ret)

	//bpf.ShowMap("pgm_tbl", new(uint32), new(uint32))
	//bpf.ShowMap("cpu_map", new(uint32), new(uint32))
	//bpf.ShowMap("live_cpu_map", new(uint32), new(uint32))
	//bpf.ShowMap("nat_map", new(nat.Key), new(nat.Acts))
}
