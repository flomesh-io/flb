package ctctr

import "github.com/flomesh-io/flb/pkg/maps"

type Value Act

type Act struct {
	Ca      maps.CmnAct   `json:"ca"`
	Lock    maps.SpinLock `json:"lock"`
	Start   uint32        `json:"start"`
	Counter uint32        `json:"counter"`
	Entries uint32        `json:"entries"`
}
