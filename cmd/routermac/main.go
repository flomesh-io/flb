package main

import (
	"fmt"

	"github.com/flomesh-io/flb/pkg/api"
	. "github.com/flomesh-io/flb/pkg/wq"
)

func main() {
	routerMacWorkQ := RouterMacDpWorkQ{
		Work:    DpCreate,
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
