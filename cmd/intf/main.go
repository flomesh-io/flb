package main

import (
	"fmt"

	"github.comflomesh-io/flb/pkg/api"
)

func main() {
	portWorkQ := api.PortDpWorkQ{
		Work:       api.DpMapShow,
		OsPortNum:  1,
		PortNum:    1,
		IngVlan:    0,
		SetBD:      3801,
		SetZoneNum: 1,
		Prop:       0,
		SetMirr:    0,
		SetPol:     0,
		LoadEbpf:   "lo",
	}
	ret := api.DpPortPropMod(&portWorkQ)
	fmt.Println(ret)
}
