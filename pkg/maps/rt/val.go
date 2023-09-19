package rt

import "github.com/flomesh-io/flb/pkg/maps"

type Value Act

type Act struct {
	Ca    maps.CmnAct `json:"ca"`
	Anon0 [24]uint8   `json:"anon0"`
}
