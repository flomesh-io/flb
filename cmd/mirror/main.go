package main

import (
	"fmt"

	"github.comflomesh-io/flb/pkg/api"
)

func main() {
	mirrWorkQ := api.MirrDpWorkQ{
		Work: api.DpMapShow,
		Mark: 31,
	}
	ret := api.DpMirrMod(&mirrWorkQ)
	fmt.Println(ret)
}
