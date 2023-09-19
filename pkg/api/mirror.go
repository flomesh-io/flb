package api

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps"
	"github.com/flomesh-io/flb/pkg/maps/mirr"
)

// MirrDpWorkQ - work queue entry for mirror operation
type MirrDpWorkQ struct {
	Work      DpWorkT
	Name      string
	Mark      int
	MiPortNum int
	MiBD      int
	Status    *DpStatusT
}

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

		err := bpf.UpdateMap(consts.DP_MIRROR_MAP, &key, dat)
		if err != nil {
			*w.Status = 1
			return consts.EbpfErrMirrAdd
		}

		*w.Status = 0

	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(mirr.Act)
		bpf.UpdateMap(consts.DP_MIRROR_MAP, &key, dat)
		return 0
	} else if w.Work == DpMapShow {
		outValue := new(mirr.Act)
		if err := bpf.GetMap(consts.DP_MIRROR_MAP, key, outValue); err == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(outValue, "", " ")
			fmt.Println(consts.DP_MIRROR_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}
	return 0
}
