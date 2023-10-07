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

// DpNextHopMod - routine to work on a ebpf next-hop change request
func DpNextHopMod(w *NextHopDpWorkQ) int {
	var act *dp_rt_l2nh_act
	var tunAct *dp_rt_tunnh_act

	key := new(dp_nh_key)
	key.nh_num = C.uint(w.NextHopNum)

	if w.Work == DpCreate {
		dat := new(dp_nh_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_nh_tact)
		if !w.Resolved {
			dat.ca.act_type = DP_SET_TOCP
		} else {
			if w.TunNh {
				tk.LogIt(tk.LogDebug, "Setting tunNh 0x%x\n", key.nh_num)
				if w.TunType == DpTunIPIP {
					dat.ca.act_type = DP_SET_NEIGH_IPIP
				} else {
					dat.ca.act_type = DP_SET_NEIGH_VXLAN
				}
				tunAct = (*dp_rt_tunnh_act)(getPtrOffset(unsafe.Pointer(dat),
					sizeof_struct_dp_cmn_act))

				ipAddr := tk.IPtonl(w.RIP)
				tunAct.l3t.rip = C.uint(ipAddr)
				tunAct.l3t.sip = C.uint(tk.IPtonl(w.SIP))
				tid := (w.TunID << 8) & 0xffffff00
				tunAct.l3t.tid = C.uint(tk.Htonl(tid))

				act = (*dp_rt_l2nh_act)(&tunAct.l2nh)
				C.memcpy(unsafe.Pointer(&act.dmac[0]), unsafe.Pointer(&w.DstAddr[0]), 6)
				C.memcpy(unsafe.Pointer(&act.smac[0]), unsafe.Pointer(&w.SrcAddr[0]), 6)
				act.bd = C.ushort(w.BD)
			} else {
				dat.ca.act_type = DP_SET_NEIGH_L2
				act = (*dp_rt_l2nh_act)(getPtrOffset(unsafe.Pointer(dat),
					sizeof_struct_dp_cmn_act))
				C.memcpy(unsafe.Pointer(&act.dmac[0]), unsafe.Pointer(&w.DstAddr[0]), 6)
				C.memcpy(unsafe.Pointer(&act.smac[0]), unsafe.Pointer(&w.SrcAddr[0]), 6)
				act.bd = C.ushort(w.BD)
				act.rnh_num = C.ushort(w.NNextHopNum)
			}
		}

		srcHwAddr := net.HardwareAddr(w.SrcAddr[:])
		dstHwAddr := net.HardwareAddr(w.DstAddr[:])
		sErr := flb_add_map_elem(LL_DP_NH_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))
		if sErr != 0 {
			fmt.Printf("[DP] Nexthop %5d %s %s add[NOK] %d\n", w.NextHopNum, srcHwAddr.String(), dstHwAddr.String(), sErr)
			return EbpfErrNhAdd
		}
		fmt.Printf("[DP] Nexthop %5d %s %s add[OK]\n", w.NextHopNum, srcHwAddr.String(), dstHwAddr.String())
		return 0
	} else if w.Work == DpRemove {
		dat := new(dp_nh_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_nh_tact)
		// eBPF array elements cant be deleted. Instead we just reset it
		flb_add_map_elem(LL_DP_NH_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))
		return 0
	}

	return EbpfErrWqUnk
}
