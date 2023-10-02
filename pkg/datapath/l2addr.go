package datapath

import "C"
import (
	"encoding/json"
	"fmt"
	"net"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps"
	"github.com/flomesh-io/flb/pkg/maps/dmac"
	"github.com/flomesh-io/flb/pkg/maps/smac"
	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

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

		hwAddr := net.HardwareAddr(w.L2Addr[:])
		sErr := bpf.UpdateMap(consts.DP_SMAC_MAP, skey, sval)
		if sErr != nil {
			fmt.Printf("[DP] L2 SMAC %s add[NOK] %x\n", hwAddr.String(), sErr)
			return consts.EbpfErrL2AddrAdd
		}

		if w.Tun == 0 {
			dErr := bpf.UpdateMap(consts.DP_DMAC_MAP, dkey, dval)
			if dErr != nil {
				fmt.Printf("[DP] L2 DMAC %s add[NOK] %x\n", hwAddr.String(), sErr)
				bpf.DeleteMap(consts.DP_SMAC_MAP, skey)
				return consts.EbpfErrL2AddrAdd
			}
		}

		fmt.Printf("[DP] L2 SMAC & DMAC %s add[OK]\n", hwAddr.String())

		return 0
	} else if w.Work == DpRemove {
		bpf.DeleteMap(consts.DP_SMAC_MAP, skey)
		if w.Tun == 0 {
			bpf.DeleteMap(consts.DP_DMAC_MAP, dkey)
		}

		return 0
	} else {
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
