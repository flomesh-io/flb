package datapath

import (
	"unsafe"

	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps"
	"github.com/flomesh-io/flb/pkg/maps/mirr"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpMirrMod - routine to work on a ebpf mirror modify request
func DpMirrMod(w *MirrDpWorkQ) int {
	key := mirr.Key(w.Mark)
	if w.Work == DpCreate {
		dat := new(mirr.Act)
		if w.MiBD != 0 {
			dat.Ca.ActType = consts.DP_SET_ADD_L2VLAN
		} else {
			dat.Ca.ActType = consts.DP_SET_RM_L2VLAN
		}
		la := (*maps.L2VlanAct)(unsafe.Pointer(&dat.Anon0[0]))
		la.OPort = uint16(w.MiPortNum)
		la.Vlan = uint16(w.MiBD)
		err := add_map_elem(consts.LL_DP_MIRROR_MAP, &key, dat)
		if err != nil {
			*w.Status = 1
			return consts.EbpfErrMirrAdd
		}
		*w.Status = 0
	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(mirr.Act)
		add_map_elem(consts.LL_DP_MIRROR_MAP, &key, dat)
		del_map_elem(consts.LL_DP_MIRROR_MAP, &key)
		return 0
	}
	return 0
}
