package nat

import (
	"github.comflomesh-io/flb/pkg/config"
	"github.comflomesh-io/flb/pkg/maps"
)

type Value Acts

type Acts struct {
	Ca      maps.CmnAct                      `json:"ca"`
	Ito     uint64                           `json:"ito"`
	Lock    maps.SpinLock                    `json:"daddr"`
	Nxfrm   uint16                           `json:"nxfrm"`
	Cdis    uint8                            `json:"cdis"`
	Npmhh   uint8                            `json:"npmhh"`
	SelHint uint16                           `json:"sel_hint"`
	SelType uint16                           `json:"sel_type"`
	Pmhh    [config.FLB_MAX_MHOSTS]uint32    `json:"pmhh"`
	Nxfrms  [config.FLB_MAX_NXFRMS]MfXfrmInf `json:"nxfrms"`
}

type MfXfrmInf struct {
	NatFlags uint8     `json:"nat_flags"`
	Inactive uint8     `json:"inactive"`
	WPrio    uint8     `json:"wprio"`
	Nv6      uint8     `json:"nv6"`
	Dsr      uint8     `json:"dsr"`
	Mhon     uint8     `json:"mhon"`
	NatXPort uint16    `json:"nat_xport"`
	NatXIp   [4]uint32 `json:"nat_xip"`
	NatRIp   [4]uint32 `json:"nat_rip"`
}
