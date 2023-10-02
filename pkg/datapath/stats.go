package datapath

import (
	"github.com/flomesh-io/flb/internal"
	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/maps"
)

func clearStatsPcpuArr(mapName string, idx uint32) {
	if nrCpus, err := internal.PossibleCPUs(); err == nil {
		key := &idx
		val := make([]maps.PbStats, nrCpus)
		bpf.UpdateMap(mapName, &key, &val)
	}
}
