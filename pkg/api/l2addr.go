package api

import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.comflomesh-io/flb/pkg/bpf"
	"github.comflomesh-io/flb/pkg/consts"
	"github.comflomesh-io/flb/pkg/maps"
	"github.comflomesh-io/flb/pkg/maps/dmac"
	"github.comflomesh-io/flb/pkg/maps/smac"
	"github.comflomesh-io/flb/pkg/tk"
)

// DpTunT - type of a dp tunnel
type DpTunT uint8

// tunnel type constants
const (
	DpTunVxlan DpTunT = iota + 1
	DpTunGre
	DpTunGtp
	DpTunStt
	DpTunIPIP
)

// L2AddrDpWorkQ - work queue entry for l2 address operation
type L2AddrDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	L2Addr  [6]uint8
	Tun     DpTunT
	NhNum   int
	PortNum int
	BD      int
	Tagged  int
}

// DpL2AddrMod - routine to work on a ebpf l2 addr request
func DpL2AddrMod(w *L2AddrDpWorkQ) int {
	var l2va *maps.L2VlanAct

	skey := new(smac.Key)
	copy(skey.Smac[:], w.L2Addr[:])
	skey.Bd = uint16(w.BD)

	dkey := new(dmac.Key)
	copy(dkey.Dmac[:], w.L2Addr[:])
	dkey.Bd = uint16(w.BD)

	if w.Work == DpCreate {
		sval := new(smac.Act)
		sval.ActType = consts.DP_SET_NOP

		dval := new(dmac.Act)

		if w.Tun == 0 {
			l2va = (*maps.L2VlanAct)(unsafe.Pointer(&dval.Anon0[0]))
			if w.Tagged != 0 {
				dval.Ca.ActType = consts.DP_SET_ADD_L2VLAN
				l2va.Vlan = tk.Htons(uint16(w.BD))
				l2va.OPort = uint16(w.PortNum)
			} else {
				dval.Ca.ActType = consts.DP_SET_RM_L2VLAN
				l2va.Vlan = tk.Htons(uint16(w.BD))
				l2va.OPort = uint16(w.PortNum)
			}
		}
		serr := bpf.UpdateMap(consts.DP_SMAC_MAP, skey, sval)
		if serr != nil {
			return consts.EbpfErrL2AddrAdd
		}

		if w.Tun == 0 {
			derr := bpf.UpdateMap(consts.DP_DMAC_MAP, dkey, dval)
			if derr != nil {
				bpf.DeleteMap(consts.DP_SMAC_MAP, skey)
				return consts.EbpfErrL2AddrAdd
			}
		}

		return 0
	} else if w.Work == DpRemove {
		bpf.DeleteMap(consts.DP_SMAC_MAP, skey)
		if w.Tun == 0 {
			bpf.DeleteMap(consts.DP_DMAC_MAP, dkey)
		}

		return 0
	} else if w.Work == DpMapShow {
		outsValue := new(smac.Act)
		if err := bpf.GetMap(consts.DP_SMAC_MAP, skey, outsValue); err == nil {
			keyBytes, _ := json.MarshalIndent(skey, "", " ")
			valueBytes, _ := json.MarshalIndent(outsValue, "", " ")
			fmt.Println(consts.DP_SMAC_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		outdValue := new(dmac.Act)
		if err := bpf.GetMap(consts.DP_DMAC_MAP, dkey, outdValue); err == nil {
			keyBytes, _ := json.MarshalIndent(dkey, "", " ")
			valueBytes, _ := json.MarshalIndent(outdValue, "", " ")
			fmt.Println(consts.DP_DMAC_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}

	return consts.EbpfErrWqUnk
}
