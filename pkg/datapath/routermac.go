package datapath

/*
#include <string.h>
*/
import "C"
import (
	"fmt"
	"net"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpRouterMacMod - routine to work on a ebpf rt-mac change request
func DpRouterMacMod(w *RouterMacDpWorkQ) int {
	key := new(dp_tmac_key)
	C.memcpy(unsafe.Pointer(&key.mac[0]), unsafe.Pointer(&w.L2Addr[0]), 6)
	switch {
	case w.TunType == DpTunVxlan:
		key.tun_type = FLB_TUN_VXLAN
	case w.TunType == DpTunGre:
		key.tun_type = FLB_TUN_GRE
	case w.TunType == DpTunGtp:
		key.tun_type = FLB_TUN_GTP
	case w.TunType == DpTunStt:
		key.tun_type = FLB_TUN_STT
	}

	key.tunnel_id = C.uint(w.TunID)

	if w.Work == DpCreate {
		dat := new(dp_tmac_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_dmac_tact)
		if w.TunID != 0 {
			if w.NhNum == 0 {
				dat.ca.act_type = DP_SET_RM_VXLAN
				rtNhAct := (*dp_rt_nh_act)(getPtrOffset(unsafe.Pointer(dat),
					sizeof_struct_dp_cmn_act))
				C.memset(unsafe.Pointer(rtNhAct), 0, sizeof_struct_dp_rt_nh_act)
				rtNhAct.nh_num = 0
				rtNhAct.tid = 0
				rtNhAct.bd = C.ushort(w.BD)
			} else {
				/* No need for tunnel ID in case of Access side */
				key.tunnel_id = 0
				key.tun_type = 0
				dat.ca.act_type = DP_SET_RT_TUN_NH
				rtNhAct := (*dp_rt_nh_act)(getPtrOffset(unsafe.Pointer(dat),
					sizeof_struct_dp_cmn_act))
				C.memset(unsafe.Pointer(rtNhAct), 0, sizeof_struct_dp_rt_nh_act)

				rtNhAct.nh_num = C.ushort(w.NhNum)
				tid := (w.TunID << 8) & 0xffffff00
				rtNhAct.tid = C.uint(tk.Htonl(tid))
			}
		} else {
			dat.ca.act_type = DP_SET_L3_EN
		}

		hwAddr := net.HardwareAddr(w.L2Addr[:])

		ret := flb_add_map_elem(LL_DP_TMAC_MAP, unsafe.Pointer(key), unsafe.Pointer(dat))
		if ret != 0 {
			fmt.Printf("[DP] TMAC %s add[NOK] error: %d\n", hwAddr.String(), ret)
			return EbpfErrTmacAdd
		}

		fmt.Printf("[DP] TMAC %s add[OK]\n", hwAddr.String())
		return 0
	} else if w.Work == DpRemove {
		flb_del_map_elem(LL_DP_TMAC_MAP, unsafe.Pointer(key))
	}

	return EbpfErrWqUnk
}
