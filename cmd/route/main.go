package main

import (
	"fmt"
	"net"

	"github.comflomesh-io/flb/pkg/api"
)

func main() {
	_, dst, _ := net.ParseCIDR("31.31.31.0/24")
	routeWorkQ := api.RouteDpWorkQ{
		Work:    api.DpMapShow,
		ZoneNum: 1,
		Dst:     *dst,
		RtType:  4,
		RtMark:  15,
		NMark:   -1,
	}
	ret := api.DpRouteMod(&routeWorkQ)
	fmt.Println(ret)
}
