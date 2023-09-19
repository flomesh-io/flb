package polx

import "github.comflomesh-io/flb/pkg/maps"

type Value Act

type Act struct {
	Ca    maps.CmnAct   `json:"ca"`
	Lock  maps.SpinLock `json:"lock"`
	_     [4]byte
	Anon0 [72]uint8 `json:"anon0"`
}

type PolicerAct struct {
	Trtcm       uint8    `json:"trtcm"`
	Color_aware uint8    `json:"color_aware"`
	Drop_prio   uint16   `json:"drop_prio"`
	Pad         uint32   `json:"pad"`
	Cbs         uint32   `json:"cbs"`
	Ebs         uint32   `json:"ebs"`
	Tok_c       uint32   `json:"tok_c"`
	Tok_e       uint32   `json:"tok_e"`
	Toksc_pus   uint64   `json:"toksc_pus"`
	Tokse_pus   uint64   `json:"tokse_pus"`
	Lastc_uts   uint64   `json:"lastc_uts"`
	Laste_uts   uint64   `json:"laste_uts"`
	Ps          PolStats `json:"ps"`
}

type PolStats struct {
	DropPackets uint64 `json:"drop_packets"`
	PassPackets uint64 `json:"pass_packets"`
}
