package datapath

/*
#include <string.h>
*/
import "C"
import (
	"fmt"
	"unsafe"

	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpMirrMod - routine to work on a ebpf mirror modify request
func DpMirrMod(w *MirrDpWorkQ) int {
	key := C.uint(w.Mark)

	if w.Work == DpCreate {
		dat := new(dp_mirr_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_mirr_tact)

		if w.MiBD != 0 {
			dat.ca.act_type = DP_SET_ADD_L2VLAN
		} else {
			dat.ca.act_type = DP_SET_RM_L2VLAN
		}

		la := (*dp_l2vlan_act)(getPtrOffset(unsafe.Pointer(dat), sizeof_struct_dp_cmn_act))

		la.oport = C.ushort(w.MiPortNum)
		la.vlan = C.ushort(w.MiBD)

		ret := flb_add_map_elem(LL_DP_MIRROR_MAP, unsafe.Pointer(&key), unsafe.Pointer(dat))
		if ret != 0 {
			*w.Status = 1
			fmt.Printf("[DP] MIRROR %s %d add[NOK] error: %d\n", w.Name, w.Mark, ret)
			return EbpfErrMirrAdd
		}

		*w.Status = 0
		fmt.Printf("[DP] MIRROR %s %d add[OK]\n", w.Name, w.Mark)
	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(dp_mirr_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_mirr_tact)
		flb_add_map_elem(LL_DP_MIRROR_MAP, unsafe.Pointer(&key), unsafe.Pointer(dat))
		flb_del_map_elem(LL_DP_MIRROR_MAP, unsafe.Pointer(&key))
		return 0
	}
	return 0
}
