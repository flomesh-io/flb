package main

import (
	"fmt"

	"github.com/flomesh-io/flb/pkg/api"
	. "github.com/flomesh-io/flb/pkg/wq"
)

func main() {
	polWorkQ := PolDpWorkQ{
		Work: DpCreate,
		Mark: 8191,
	}
	ret := api.DpPolMod(&polWorkQ)
	fmt.Println(ret)
}
