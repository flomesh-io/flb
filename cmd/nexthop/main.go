package main

import (
	"fmt"

	"github.com/flomesh-io/flb/pkg/api"
)

func main() {
	nextHopWorkQ := api.NextHopDpWorkQ{
		Work:        api.DpMapShow,
		TunNh:       false,
		TunID:       0,
		TunType:     0,
		NNextHopNum: 0,
		NextHopNum:  2,
		Resolved:    true,
		DstAddr:     [6]uint8{84, 82, 132, 195, 119, 217},
		SrcAddr:     [6]uint8{0, 12, 41, 121, 171, 87},
		BD:          3803,
	}
	ret := api.DpNextHopMod(&nextHopWorkQ)
	fmt.Println(ret)
}
