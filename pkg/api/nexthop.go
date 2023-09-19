package api

import (
	"encoding/json"
	"fmt"
	"net"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps"
	"github.com/flomesh-io/flb/pkg/maps/nh"
	"github.com/flomesh-io/flb/pkg/tk"
)

// NextHopDpWorkQ - work queue entry for nexthop operation
type NextHopDpWorkQ struct {
	Work        DpWorkT
	Status      *DpStatusT
	TunNh       bool
	TunID       uint32
	TunType     DpTunT
	RIP         net.IP
	SIP         net.IP
	NNextHopNum int
	NextHopNum  int
	Resolved    bool
	DstAddr     [6]uint8
	SrcAddr     [6]uint8
	BD          int
}

// DpNextHopMod - routine to work on a ebpf next-hop change request
func DpNextHopMod(w *NextHopDpWorkQ) int {
	var act *maps.RtL2NhAct
	var tunAct *maps.RtTunNhAct

	key := new(nh.Key)
	key.NhNum = uint32(w.NextHopNum)

	if w.Work == DpCreate {
		dat := new(nh.Act)
		if !w.Resolved {
			dat.Ca.ActType = consts.DP_SET_TOCP
		} else {
			if w.TunNh {
				fmt.Printf("Setting tunNh 0x%x\n", key.NhNum)
				if w.TunType == DpTunIPIP {
					dat.Ca.ActType = consts.DP_SET_NEIGH_IPIP
				} else {
					dat.Ca.ActType = consts.DP_SET_NEIGH_VXLAN
				}
				tunAct = (*maps.RtTunNhAct)(unsafe.Pointer(&dat.Anon0[0]))

				ipAddr := tk.IPtonl(w.RIP)
				tunAct.L3t.RIp = ipAddr
				tunAct.L3t.SIp = tk.IPtonl(w.SIP)
				tid := (w.TunID << 8) & 0xffffff00
				tunAct.L3t.TId = tk.Htonl(tid)

				act = &tunAct.L2Nh
				copy(act.Dmac[:], w.DstAddr[:])
				copy(act.Smac[:], w.SrcAddr[:])
				act.Bd = uint16(w.BD)
			} else {
				dat.Ca.ActType = consts.DP_SET_NEIGH_L2
				act = (*maps.RtL2NhAct)(unsafe.Pointer(&dat.Anon0[0]))
				copy(act.Dmac[:], w.DstAddr[:])
				copy(act.Smac[:], w.SrcAddr[:])
				act.Bd = uint16(w.BD)
				act.RnhNum = uint16(w.NNextHopNum)
			}
		}

		err := bpf.UpdateMap(consts.DP_NH_MAP, key, dat)
		if err != nil {
			return consts.EbpfErrNhAdd
		}
		return 0
	} else if w.Work == DpRemove {
		dat := new(nh.Act)
		// eBPF array elements cant be deleted. Instead we just reset it
		bpf.UpdateMap(consts.DP_NH_MAP, key, dat)
		return 0
	} else if w.Work == DpMapShow {
		outValue := new(nh.Act)
		if err := bpf.GetMap(consts.DP_NH_MAP, key, outValue); err == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(outValue, "", " ")
			fmt.Println(consts.DP_NH_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}

	return consts.EbpfErrWqUnk
}
