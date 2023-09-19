package api

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.comflomesh-io/flb/pkg/bpf"
	"github.comflomesh-io/flb/pkg/consts"
	"github.comflomesh-io/flb/pkg/maps"
	"github.comflomesh-io/flb/pkg/maps/tmac"
	"github.comflomesh-io/flb/pkg/tk"
)

// RouterMacDpWorkQ - work queue entry for rt-mac operation
type RouterMacDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	L2Addr  [6]uint8
	PortNum int
	BD      int
	TunID   uint32
	TunType DpTunT
	NhNum   int
}

// DpRouterMacMod - routine to work on a ebpf rt-mac change request
func DpRouterMacMod(w *RouterMacDpWorkQ) int {
	key := new(tmac.Key)
	copy(key.Mac[:], w.L2Addr[:])
	switch {
	case w.TunType == DpTunVxlan:
		key.TunType = consts.FLB_TUN_VXLAN
	case w.TunType == DpTunGre:
		key.TunType = consts.FLB_TUN_GRE
	case w.TunType == DpTunGtp:
		key.TunType = consts.FLB_TUN_GTP
	case w.TunType == DpTunStt:
		key.TunType = consts.FLB_TUN_STT
	}

	key.TunnelId = w.TunID

	if w.Work == DpCreate {
		dat := new(tmac.Act)
		if w.TunID != 0 {
			if w.NhNum == 0 {
				dat.Ca.ActType = consts.DP_SET_RM_VXLAN
				rtNhAct := (*maps.RtNhAct)(unsafe.Pointer(&dat.Anon0[0]))
				rtNhAct.NhNum = 0
				rtNhAct.TId = 0
				rtNhAct.Bd = uint16(w.BD)
			} else {
				/* No need for tunnel ID in case of Access side */
				key.TunnelId = 0
				key.TunType = 0
				dat.Ca.ActType = consts.DP_SET_RT_TUN_NH
				rtNhAct := (*maps.RtNhAct)(unsafe.Pointer(&dat.Anon0[0]))
				rtNhAct.NhNum = uint16(w.NhNum)
				tid := (w.TunID << 8) & 0xffffff00
				rtNhAct.TId = tk.Htonl(tid)
			}
		} else {
			dat.Ca.ActType = consts.DP_SET_L3_EN
		}

		err := bpf.UpdateMap(consts.DP_TMAC_MAP, key, dat)
		if err != nil {
			return consts.EbpfErrTmacAdd
		}

		return 0
	} else if w.Work == DpRemove {
		bpf.DeleteMap(consts.DP_TMAC_MAP, key)
	} else if w.Work == DpMapShow {
		outValue := new(tmac.Act)
		if err := bpf.GetMap(consts.DP_TMAC_MAP, key, outValue); err == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(outValue, "", " ")
			fmt.Println(consts.DP_TMAC_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}

	return consts.EbpfErrWqUnk
}
