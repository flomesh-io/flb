package rtv4

import "github.com/flomesh-io/flb/pkg/maps"

type Key struct {
	L     maps.LpmTrieKey `json:"l"`
	Anon0 [8]byte         `json:"anon0"`
}
