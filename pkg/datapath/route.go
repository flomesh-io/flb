package datapath

import "C"
import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps"
	"github.com/flomesh-io/flb/pkg/maps/rt"
	"github.com/flomesh-io/flb/pkg/maps/rt/rtv4"
	"github.com/flomesh-io/flb/pkg/maps/rt/rtv6"
	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpRouteMod - routine to work on a ebpf route change request
func DpRouteMod(w *RouteDpWorkQ) int {
	var mapNum int
	var mapSNum int
	var act *maps.RtNhAct
	var kPtr *[6]uint8
	var key interface{}

	if w.ZoneNum == 0 {
		tk.LogIt(tk.LogError, "ZoneNum must be specified\n")
		syscall.Exit(1)
	}

	if tk.IsNetIPv4(w.Dst.IP.String()) {
		key4 := new(rtv4.Key)

		length, _ := w.Dst.Mask.Size()
		length += 16 /* 16-bit ZoneNum + prefix-len */
		key4.L.PrefixLen = uint32(length)
		kPtr = (*[6]uint8)(unsafe.Pointer(&key4.Anon0[0]))

		kPtr[0] = uint8(w.ZoneNum >> 8 & 0xff)
		kPtr[1] = uint8(w.ZoneNum & 0xff)
		kPtr[2] = uint8(w.Dst.IP[12])
		kPtr[3] = uint8(w.Dst.IP[13])
		kPtr[4] = uint8(w.Dst.IP[14])
		kPtr[5] = uint8(w.Dst.IP[15])
		key = key4
		mapNum = consts.LL_DP_RTV4_MAP
		mapSNum = consts.LL_DP_RTV4_STATS_MAP
	} else {
		key6 := new(rtv6.Key)

		length, _ := w.Dst.Mask.Size()
		key6.L.PrefixLen = uint32(length)

		for bp := 0; bp < 16; bp++ {
			key6.Anon0[bp] = w.Dst.IP[bp]
		}
		key = key6
		mapNum = consts.LL_DP_RTV6_MAP
		mapSNum = consts.LL_DP_RTV6_STATS_MAP
	}

	if w.Work == DpCreate {
		dat := new(rt.Act)

		if w.NMark >= 0 {
			dat.Ca.ActType = consts.DP_SET_RT_NHNUM
			act = (*maps.RtNhAct)(unsafe.Pointer(&dat.Anon0[0]))
			act.NhNum = uint16(w.NMark)
		} else {
			dat.Ca.ActType = consts.DP_SET_TOCP
		}

		if w.RtMark > 0 {
			dat.Ca.CIdx = uint32(w.RtMark)
		}

		err := llb_add_map_elem(mapNum, key, dat)
		if err != nil {
			fmt.Printf("[DP] RT %s add[NOK] %v\n", w.Dst, err)
			return consts.EbpfErrRt4Add
		}
		return 0
	} else if w.Work == DpRemove {
		llb_del_map_elem(mapNum, key)
		if w.RtMark > 0 {
			llb_clear_map_stats(mapSNum, uint32(w.RtMark))
		}
		return 0
	}
	return consts.EbpfErrWqUnk
}
