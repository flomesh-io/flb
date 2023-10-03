package datapath

import "C"
import (
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps/polx"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpPolMod - routine to work on a ebpf policer change request
func DpPolMod(w *PolDpWorkQ) int {
	key := polx.Key(w.Mark)

	if w.Work == DpCreate {
		dat := new(polx.Act)
		dat.Ca.ActType = consts.DP_SET_DO_POLICER
		pa := (*polx.PolicerAct)(unsafe.Pointer(&dat.Anon0[0]))

		if !w.Srt {
			pa.Trtcm = 1
		} else {
			pa.Trtcm = 0
		}

		if !w.Color {
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
		pa.Lastc_uts = bpf.GetOsUSecs()
		pa.Laste_uts = pa.Toksc_pus
		pa.Drop_prio = consts.FLB_PIPE_COL_YELLOW

		err := add_map_elem(consts.LL_DP_POL_MAP, &key, dat)
		if err != nil {
			*w.Status = 1
			return consts.EbpfErrPolAdd
		}
		*w.Status = 0
	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(polx.Act)
		add_map_elem(consts.LL_DP_POL_MAP, &key, dat)
		del_map_elem(consts.LL_DP_POL_MAP, &key)
		return 0
	}
	return 0
}
