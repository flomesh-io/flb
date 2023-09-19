package main

import (
	"fmt"

	"github.com/flomesh-io/flb/pkg/api"
)

func main() {
	polWorkQ := api.PolDpWorkQ{
		Work: api.DpMapShow,
		Mark: 8191,
	}
	ret := api.DpPolMod(&polWorkQ)
	fmt.Println(ret)
}
