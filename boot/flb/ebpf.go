package main

/*

#include <sys/resource.h>

static int flb_set_rlims(void)
{
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    return -1;
  }

  return 0;
}

*/
import "C"
import (
	"fmt"

	"github.com/flomesh-io/flb/internal"
	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/config"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps/cpu"
	"github.com/flomesh-io/flb/pkg/maps/ctctr"
)

func setResourceLimit() bool {
	ret := C.flb_set_rlims()
	return ret == 0
}

func setupCrc32cMap() {
	var i uint32
	var crc uint32

	// Generate crc32c table
	for i = 0; i < 256; i++ {
		crc = i
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		for n := 0; n < 8; n++ {
			if crc&1 > 0 {
				crc = (crc >> 1) ^ 0x82f63b78
			} else {
				crc = crc >> 1
			}
		}
		bpf.UpdateMap(consts.DP_CRC32C_MAP, &i, &crc)
	}
}

func setupCtCtrMap(nodeNo uint32) {
	key := ctctr.Key(0)
	ctr := new(ctctr.Act)
	ctr.Start = uint32(config.FLB_CT_MAP_ENTRIES/config.FLB_MAX_LB_NODES) * nodeNo
	ctr.Counter = ctr.Start
	ctr.Entries = ctr.Start + uint32(config.FLB_CT_MAP_ENTRIES/config.FLB_MAX_LB_NODES)
	bpf.UpdateMap(consts.DP_CTCTR_MAP, &key, ctr)
}

func setupCpuMap() {
	if liveCpus, err := internal.PossibleCPUs(); err == nil {
		val := cpu.Value(2048)
		for i := 0; i < liveCpus; i++ {
			key := cpu.Key(i)
			bpf.UpdateMap(consts.DP_CPU_MAP, &key, &val)
		}
	} else {
		fmt.Println(err.Error())
	}
}

func setupLiveCpuMap() {
	if liveCpus, err := internal.PossibleCPUs(); err == nil {
		key := cpu.Key(0)
		val := cpu.Value(liveCpus)
		bpf.UpdateMap(consts.DP_LIVE_CPU_MAP, &key, &val)
	} else {
		fmt.Println(err.Error())
	}
}
