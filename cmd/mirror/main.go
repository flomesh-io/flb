package main

import (
	"fmt"

	"github.com/flomesh-io/flb/pkg/api"
	. "github.com/flomesh-io/flb/pkg/wq"
)

func main() {
	mirrWorkQ := MirrDpWorkQ{
		Work: DpCreate,
		Mark: 31,
	}
	ret := api.DpMirrMod(&mirrWorkQ)
	fmt.Println(ret)
}
