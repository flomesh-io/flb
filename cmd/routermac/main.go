package main

import (
	"fmt"

	"github.comflomesh-io/flb/pkg/api"
)

func main() {
	routerMacWorkQ := api.RouterMacDpWorkQ{
		Work:    api.DpMapShow,
		L2Addr:  [6]uint8{0, 12, 41, 121, 171, 87},
		PortNum: 3,
		BD:      0,
		TunID:   0,
		TunType: 0,
		NhNum:   0,
	}
	ret := api.DpRouterMacMod(&routerMacWorkQ)
	fmt.Println(ret)
}
