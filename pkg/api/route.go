package api

import (
	"encoding/json"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps"
	"github.com/flomesh-io/flb/pkg/maps/rt"
	"github.com/flomesh-io/flb/pkg/maps/rt/rtv4"
	"github.com/flomesh-io/flb/pkg/maps/rt/rtv6"
	"github.com/flomesh-io/flb/pkg/tk"
)

// RouteDpWorkQ - work queue entry for rt operation
type RouteDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	ZoneNum int
	Dst     net.IPNet
	RtType  int
	RtMark  int
	NMark   int
}

// DpRouteMod - routine to work on a ebpf route change request
func DpRouteMod(w *RouteDpWorkQ) int {
	var mapName string
	var statsMapName string
	var act *maps.RtNhAct
	var kPtr *[6]uint8
	var key interface{}

	if w.ZoneNum == 0 {
		fmt.Print("ZoneNum must be specified\n")
		syscall.Exit(1)
	}

	if tk.IsNetIPv4(w.Dst.IP.String()) {
		key4 := new(rtv4.Key)

		len, _ := w.Dst.Mask.Size()
		len += 16 /* 16-bit ZoneNum + prefix-len */
		key4.L.PrefixLen = uint32(len)
		kPtr = (*[6]uint8)(unsafe.Pointer(&key4.Anon0[0]))

		kPtr[0] = uint8(w.ZoneNum >> 8 & 0xff)
		kPtr[1] = uint8(w.ZoneNum & 0xff)
		kPtr[2] = uint8(w.Dst.IP[0])
		kPtr[3] = uint8(w.Dst.IP[1])
		kPtr[4] = uint8(w.Dst.IP[2])
		kPtr[5] = uint8(w.Dst.IP[3])
		key = key4
		mapName = consts.DP_RTV4_MAP
		statsMapName = consts.DP_RTV4_STATS_MAP
	} else {
		key6 := new(rtv6.Key)

		len, _ := w.Dst.Mask.Size()
		key6.L.PrefixLen = uint32(len)

		for bp := 0; bp < 16; bp++ {
			key6.Anon0[bp] = w.Dst.IP[bp]
		}
		key = key6
		mapName = consts.DP_RTV6_MAP
		statsMapName = consts.DP_RTV6_STATS_MAP
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

		err := bpf.UpdateMap(mapName, key, dat)
		if err != nil {
			return consts.EbpfErrRt4Add
		}
		return 0
	} else if w.Work == DpRemove {
		bpf.DeleteMap(mapName, key)

		if w.RtMark > 0 {
			// TODO pending
			fmt.Println(statsMapName)
			//C.llb_clear_map_stats(statsMapName, C.uint(w.RtMark))
		}
		return 0
	} else if w.Work == DpMapShow {
		outValue := new(rt.Act)
		if err := bpf.GetMap(mapName, key, outValue); err == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(outValue, "", " ")
			fmt.Println(mapName, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}
		return 0
	}

	return consts.EbpfErrWqUnk
}
