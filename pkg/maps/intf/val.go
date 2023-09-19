package intf

import "github.comflomesh-io/flb/pkg/maps"

type Value Act

type Act struct {
	Ca    maps.CmnAct `json:"ca"`
	Anon0 [16]uint8   `json:"anon0"`
}

type ActSetIfi struct {
	XdpIfIdx uint16   `json:"xdp_ifidx"`
	Zone     uint16   `json:"zone"`
	Bd       uint16   `json:"bd"`
	Mirr     uint16   `json:"mirr"`
	Polid    uint16   `json:"polid"`
	Pprop    uint8    `json:"pprop"`
	Pten     uint8    `json:"pten"`
	R        [4]uint8 `json:"r"`
}
