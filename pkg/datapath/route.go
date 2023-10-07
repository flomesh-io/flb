package datapath

/*
#include <string.h>
*/
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpRouteMod - routine to work on a ebpf route change request
func DpRouteMod(w *RouteDpWorkQ) int {
	var mapNum int
	var mapSnum int
	var act *dp_rt_l3nh_act
	var kPtr *[6]uint8
	var key unsafe.Pointer

	if w.ZoneNum == 0 {
		tk.LogIt(tk.LogError, "ZoneNum must be specified\n")
		syscall.Exit(1)
	}

	if tk.IsNetIPv4(w.Dst.IP.String()) {
		key4 := new(dp_rtv4_key)

		length, _ := w.Dst.Mask.Size()
		length += 16 /* 16-bit ZoneNum + prefix-len */
		key4.l.prefixlen = C.uint(length)
		kPtr = (*[6]uint8)(getPtrOffset(unsafe.Pointer(key4),
			sizeof_struct_bpf_lpm_trie_key))

		kPtr[0] = uint8(w.ZoneNum >> 8 & 0xff)
		kPtr[1] = uint8(w.ZoneNum & 0xff)
		kPtr[2] = uint8(w.Dst.IP[12])
		kPtr[3] = uint8(w.Dst.IP[13])
		kPtr[4] = uint8(w.Dst.IP[14])
		kPtr[5] = uint8(w.Dst.IP[15])
		key = unsafe.Pointer(key4)
		mapNum = LL_DP_RTV4_MAP
		mapSnum = LL_DP_RTV4_STATS_MAP
	} else {
		key6 := new(dp_rtv6_key)

		length, _ := w.Dst.Mask.Size()
		key6.l.prefixlen = C.uint(length)

		k6Ptr := (*C.uchar)(getPtrOffset(unsafe.Pointer(key6),
			sizeof_struct_bpf_lpm_trie_key))

		for bp := 0; bp < 16; bp++ {
			*k6Ptr = C.uchar(w.Dst.IP[bp])
			k6Ptr = (*C.uchar)(getPtrOffset(unsafe.Pointer(k6Ptr),
				C.sizeof_uchar))
		}
		key = unsafe.Pointer(key6)
		mapNum = LL_DP_RTV6_MAP
		mapSnum = LL_DP_RTV6_STATS_MAP
	}

	if w.Work == DpCreate {
		dat := new(dp_rt_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_rt_tact)

		if w.NMark >= 0 {
			dat.ca.act_type = DP_SET_RT_NHNUM
			act = (*dp_rt_l3nh_act)(getPtrOffset(unsafe.Pointer(dat),
				sizeof_struct_dp_cmn_act))
			act.nh_num = C.ushort(w.NMark)
		} else {
			dat.ca.act_type = DP_SET_TOCP
		}

		if w.RtMark > 0 {
			dat.ca.cidx = C.uint(w.RtMark)
		}

		ret := flb_add_map_elem(mapNum, unsafe.Pointer(key), unsafe.Pointer(dat))
		if ret != 0 {
			fmt.Printf("[DP] ROUTE %s add[NOK] error: %d\n", w.Dst.String(), ret)
			return EbpfErrRt4Add
		}
		fmt.Printf("[DP] ROUTE %s add[OK] \n", w.Dst.String())
		return 0
	} else if w.Work == DpRemove {
		flb_del_map_elem(mapNum, unsafe.Pointer(key))
		if w.RtMark > 0 {
			flb_clear_map_stats(mapSnum, uint32(w.RtMark))
		}
		return 0
	}

	return EbpfErrWqUnk
}
