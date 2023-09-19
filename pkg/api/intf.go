package api

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps/intf"
	"github.com/flomesh-io/flb/pkg/maps/txintf"
	"github.com/flomesh-io/flb/pkg/tk"
)

// PortProp - Defines auxiliary port properties
type PortProp uint8

const (
	// PortPropUpp - User-plane processing enabled
	PortPropUpp PortProp = 1 << iota
	// PortPropSpan - SPAN is enabled
	PortPropSpan
	// PortPropPol - Policer is active
	PortPropPol
)

// PortDpWorkQ - work queue entry for port operation
type PortDpWorkQ struct {
	Work       DpWorkT
	Status     *DpStatusT
	OsPortNum  int
	PortNum    int
	IngVlan    int
	SetBD      int
	SetZoneNum int
	Prop       PortProp
	SetMirr    int
	SetPol     int
	LoadEbpf   string
}

// DpPortPropMod - routine to work on a ebpf port property request
func DpPortPropMod(w *PortDpWorkQ) int {
	var txK txintf.Key
	var txV txintf.Act
	var setIfi *intf.ActSetIfi

	// This is a special case
	if w.LoadEbpf == "flb0" {
		w.PortNum = consts.FLB_INTERFACES - 1
	}

	key := new(intf.Key)
	key.IngVId = tk.Htons(uint16(w.IngVlan))
	key.IfIndex = uint32(w.OsPortNum)

	txK = txintf.Key(w.PortNum)

	if w.Work == DpCreate {

		if w.LoadEbpf != "" && w.LoadEbpf != "lo" && w.LoadEbpf != "flb0" {
			lRet := bpf.LoadEbpfPgm(w.LoadEbpf)
			if lRet != 0 {
				fmt.Printf("ebpf load - %d error\n", w.PortNum)
				return consts.EbpfErrEbpfLoad
			}
		}
		data := new(intf.Act)
		data.Ca.ActType = consts.DP_SET_IFI
		setIfi = (*intf.ActSetIfi)(unsafe.Pointer(&data.Anon0[0]))

		setIfi.XdpIfIdx = uint16(w.PortNum)
		setIfi.Zone = uint16(w.SetZoneNum)

		setIfi.Bd = uint16(w.SetBD)
		setIfi.Mirr = uint16(w.SetMirr)
		setIfi.Polid = uint16(w.SetPol)

		if w.Prop&PortPropUpp == PortPropUpp {
			setIfi.Pprop = consts.FLB_DP_PORT_UPP
		}

		err := bpf.UpdateMap(consts.DP_INTF_MAP, key, data)
		if err != nil {
			fmt.Printf("ebpf intfmap - %d vlan %d error\n", w.OsPortNum, w.IngVlan)
			return consts.EbpfErrPortPropAdd
		}

		fmt.Printf("ebpf intfmap added - %d vlan %d -> %d\n", w.OsPortNum, w.IngVlan, w.PortNum)

		txV = txintf.Act(w.OsPortNum)
		err = bpf.UpdateMap(consts.DP_TX_INTF_MAP, &txK, &txV)
		if err != nil {
			bpf.DeleteMap(consts.DP_INTF_MAP, key)
			fmt.Printf("ebpf txintfmap - %d error\n", w.OsPortNum)
			return consts.EbpfErrPortPropAdd
		}
		fmt.Printf("ebpf txintfmap added - %d -> %d\n", w.PortNum, w.OsPortNum)
		return 0
	} else if w.Work == DpRemove {

		// TX_INTF_MAP is array type so we can't delete it
		// Rather we need to zero it out first
		txV = txintf.Act(0)
		bpf.UpdateMap(consts.DP_TX_INTF_MAP, &txK, &txV)
		bpf.DeleteMap(consts.DP_TX_INTF_MAP, &txK)
		bpf.DeleteMap(consts.DP_INTF_MAP, key)

		if w.LoadEbpf != "" {
			lRet := bpf.UnLoadEbpfPgm(w.LoadEbpf)
			if lRet != 0 {
				fmt.Printf("ebpf unload - ifi %d error\n", w.OsPortNum)
				return consts.EbpfErrEbpfLoad
			}
			fmt.Printf("ebpf unloaded - ifi %d\n", w.OsPortNum)
		}

		return 0
	} else if w.Work == DpMapShow {
		outValue := new(intf.Act)
		if err := bpf.GetMap(consts.DP_INTF_MAP, key, outValue); err == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(outValue, "", " ")
			fmt.Println(consts.DP_INTF_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}

	return consts.EbpfErrWqUnk
}
