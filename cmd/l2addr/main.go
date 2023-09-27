package main

import (
	"fmt"

	"github.com/flomesh-io/flb/pkg/api"
	. "github.com/flomesh-io/flb/pkg/wq"
)

func main() {
	l2AddrWorkQ := L2AddrDpWorkQ{
		Work:    DpCreate,
		L2Addr:  [6]uint8{94, 82, 48, 106, 195, 100},
		Tun:     0,
		NhNum:   0,
		PortNum: 5,
		BD:      3805,
		Tagged:  0,
	}

	ret := api.DpL2AddrMod(&l2AddrWorkQ)
	fmt.Println(ret)
}
