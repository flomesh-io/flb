package datapath

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/cmn"
	"github.com/flomesh-io/flb/pkg/config"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps/intf"
	"github.com/flomesh-io/flb/pkg/maps/txintf"
	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpPortPropMod - routine to work on a ebpf port property request
func DpPortPropMod(w *PortDpWorkQ) int {
	var txK txintf.Key
	var txV txintf.Act
	var setIfi *intf.ActSetIfi

	// This is a special case
	if w.LoadEbpf == config.FLB_TAP_NAME {
		w.PortNum = consts.FLB_INTERFACES - 1
	}

	key := new(intf.Key)
	key.IngVId = tk.Htons(uint16(w.IngVlan))
	key.IfIndex = uint32(w.OsPortNum)

	txK = txintf.Key(w.PortNum)

	if w.Work == DpCreate {
		if w.LoadEbpf != "" && w.LoadEbpf != "lo" && w.LoadEbpf != config.FLB_TAP_NAME {
			lRet := bpf.AttachTcProg(w.LoadEbpf)
			if lRet != 0 {
				tk.LogIt(tk.LogError, "ebpf load - %d error\n", w.PortNum)
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

		if w.Prop&cmn.PortPropUpp == cmn.PortPropUpp {
			setIfi.Pprop = consts.FLB_DP_PORT_UPP
		}

		err := bpf.UpdateMap(consts.DP_INTF_MAP, key, data)
		if err != nil {
			tk.LogIt(tk.LogError, "ebpf intfmap - %d vlan %d error\n", w.OsPortNum, w.IngVlan)
			fmt.Printf("[DP] Link %d vlan %d -> %d add[NOK] %v\n", w.OsPortNum, w.IngVlan, w.PortNum, err)
			return consts.EbpfErrPortPropAdd
		}

		tk.LogIt(tk.LogDebug, "ebpf intfmap added - %d vlan %d -> %d\n", w.OsPortNum, w.IngVlan, w.PortNum)
		fmt.Printf("[DP] Link %d vlan %d -> %d add[OK]\n", w.OsPortNum, w.IngVlan, w.PortNum)

		txV = txintf.Act(w.OsPortNum)
		err = bpf.UpdateMap(consts.DP_TX_INTF_MAP, &txK, &txV)
		if err != nil {
			bpf.DeleteMap(consts.DP_INTF_MAP, key)
			tk.LogIt(tk.LogError, "ebpf txintfmap - %d error\n", w.OsPortNum)
			return consts.EbpfErrPortPropAdd
		}
		tk.LogIt(tk.LogDebug, "ebpf txintfmap added - %d -> %d\n", w.PortNum, w.OsPortNum)
		return 0
	} else if w.Work == DpRemove {

		// TX_INTF_MAP is array type so we can't delete it
		// Rather we need to zero it out first
		txV = txintf.Act(0)
		bpf.UpdateMap(consts.DP_TX_INTF_MAP, &txK, &txV)
		bpf.DeleteMap(consts.DP_TX_INTF_MAP, &txK)
		bpf.DeleteMap(consts.DP_INTF_MAP, key)

		if w.LoadEbpf != "" {
			lRet := bpf.DetachTcProg(w.LoadEbpf)
			if lRet != 0 {
				tk.LogIt(tk.LogError, "ebpf unload - ifi %d error\n", w.OsPortNum)
				return consts.EbpfErrEbpfLoad
			}
			tk.LogIt(tk.LogDebug, "ebpf unloaded - ifi %d\n", w.OsPortNum)
		}

		return 0
	} else {
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
