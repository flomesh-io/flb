package intf

type Key struct {
	IfIndex uint32 `json:"ifindex"`
	IngVId  uint16 `json:"ing_vid"`
	Pad     uint16 `json:"pad"`
}
