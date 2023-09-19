package maps

type SpinLock struct {
	Val uint32 `json:"val"`
}

type CmnAct struct {
	ActType uint8  `json:"act_type"`
	FTrap   uint8  `json:"ftrap"`
	OAux    uint16 `json:"oaux"`
	CIdx    uint32 `json:"cidx"`
	FwRid   uint32 `json:"fwrid"`
	Mark    uint16 `json:"mark"`
	Record  uint16 `json:"record"`
}

type L2VlanAct struct {
	Vlan  uint16 `json:"vlan"`
	OPort uint16 `json:"oport"`
}

type LpmTrieKey struct {
	PrefixLen uint32 `json:"prefixlen"`
}

type RtL2NhAct struct {
	Dmac   [6]uint8 `json:"dmac"`
	Smac   [6]uint8 `json:"smac"`
	Bd     uint16   `json:"bd"`
	RnhNum uint16   `json:"rnh_num"`
}

type RtL3TunAct struct {
	RIp uint32 `json:"rip"`
	SIp uint32 `json:"sip"`
	TId uint32 `json:"tid"`
	Aux uint32 `json:"aux"`
}

type RtNhAct struct {
	NhNum uint16    `json:"nh_num"`
	Bd    uint16    `json:"bd"`
	TId   uint32    `json:"tid"`
	L2Nh  RtL2NhAct `json:"l2nh"`
}

type RtTunNhAct struct {
	L3t  RtL3TunAct `json:"l3t"`
	L2Nh RtL2NhAct  `json:"l2nh"`
}
