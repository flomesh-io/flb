package api

import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.comflomesh-io/flb/pkg/bpf"
	"github.comflomesh-io/flb/pkg/consts"
	"github.comflomesh-io/flb/pkg/maps/polx"
)

// PolDpWorkQ - work queue entry for policer related operation
type PolDpWorkQ struct {
	Work   DpWorkT
	Name   string
	Mark   int
	Cir    uint64
	Pir    uint64
	Cbs    uint64
	Ebs    uint64
	Color  bool
	Srt    bool
	Status *DpStatusT
}

// DpPolMod - routine to work on a ebpf policer change request
func DpPolMod(w *PolDpWorkQ) int {
	key := polx.Key(w.Mark)

	if w.Work == DpCreate {
		dat := new(polx.Act)
		dat.Ca.ActType = consts.DP_SET_DO_POLICER
		pa := (*polx.PolicerAct)(unsafe.Pointer(&dat.Anon0[0]))

		if w.Srt == false {
			pa.Trtcm = 1
		} else {
			pa.Trtcm = 0
		}

		if w.Color == false {
			pa.Color_aware = 0
		} else {
			pa.Color_aware = 1
		}

		pa.Toksc_pus = w.Cir / 8000000
		pa.Tokse_pus = w.Pir / 8000000
		pa.Cbs = uint32(w.Cbs)
		pa.Ebs = uint32(w.Ebs)
		pa.Tok_c = pa.Cbs
		pa.Tok_e = pa.Ebs
		// TODO 使用 c 获取
		/*
			unsigned long long
			get_os_usecs(void)
			{
			  struct timespec ts;
			  clock_gettime(CLOCK_MONOTONIC, &ts);
			  return ((unsigned long long)ts.tv_sec * 1000000UL) + ts.tv_nsec/1000;
			}
		*/
		//pa.Lastc_uts = C.get_os_usecs():
		pa.Laste_uts = pa.Toksc_pus
		pa.Drop_prio = consts.FLB_PIPE_COL_YELLOW

		err := bpf.UpdateMap(consts.DP_POL_MAP, &key, dat)
		if err != nil {
			*w.Status = 1
			return consts.EbpfErrPolAdd
		}

		*w.Status = 0

	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(polx.Act)
		bpf.UpdateMap(consts.DP_POL_MAP, &key, dat)
		return 0
	} else if w.Work == DpMapShow {
		outValue := new(polx.Act)
		if err := bpf.GetMap(consts.DP_POL_MAP, key, outValue); err == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(outValue, "", " ")
			fmt.Println(consts.DP_POL_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}
	return 0
}
