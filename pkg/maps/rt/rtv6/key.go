package rtv6

import "github.com/flomesh-io/flb/pkg/maps"

type Key struct {
	L     maps.LpmTrieKey `json:"l"`
	Anon0 [16]byte        `json:"anon0"`
}
