package datapath

import (
	"github.com/flomesh-io/flb/internal"
	"github.com/flomesh-io/flb/pkg/bpf"
)

func clearStatsPcpuArr(mapName string, idx uint32) {
	if nrCpus, err := internal.PossibleCPUs(); err == nil {
		key := &idx
		val := make([]PbStats, nrCpus)
		bpf.UpdateMap(mapName, &key, &val)
	}
}
