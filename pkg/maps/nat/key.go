package nat

type Key struct {
	DAddr   [4]uint32 `json:"daddr"`
	DPort   uint16    `json:"dport"`
	Zone    uint16    `json:"zone"`
	Mark    uint16    `json:"mark"`
	L4Proto uint8     `json:"l4proto"`
	V6      uint8     `json:"v6"`
}
