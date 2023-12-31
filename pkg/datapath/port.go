package datapath

/*
#include <string.h>
*/
import "C"
import (
	"syscall"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/cmn"
	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpPortPropMod - routine to work on a ebpf port property request
func DpPortPropMod(w *PortDpWorkQ) int {
	var txK C.uint
	var txV C.uint
	var setIfi *dp_intf_tact_set_ifi

	// This is a special case
	if w.LoadEbpf == FLB_MGMT_CHANNEL {
		w.PortNum = FLB_INTERFACES - 1
	}

	key := new(dp_intf_key)
	key.ing_vid = C.ushort(tk.Htons(uint16(w.IngVlan)))
	key.ifindex = C.uint(w.OsPortNum)

	txK = C.uint(w.PortNum)

	if w.Work == DpCreate {

		if w.LoadEbpf != "" && w.LoadEbpf != "lo" && w.LoadEbpf != FLB_MGMT_CHANNEL {
			lRet := AttachTcProg(w.LoadEbpf)
			if lRet != 0 {
				tk.LogIt(tk.LogError, "ebpf load - %d error\n", w.PortNum)
				syscall.Exit(1)
			}
		}
		data := new(dp_intf_tact)
		C.memset(unsafe.Pointer(data), 0, sizeof_struct_dp_intf_tact)
		data.ca.act_type = DP_SET_IFI
		setIfi = (*dp_intf_tact_set_ifi)(getPtrOffset(unsafe.Pointer(data),
			sizeof_struct_dp_cmn_act))

		setIfi.xdp_ifidx = C.ushort(w.PortNum)
		setIfi.zone = C.ushort(w.SetZoneNum)

		setIfi.bd = C.ushort(uint16(w.SetBD))
		setIfi.mirr = C.ushort(w.SetMirr)
		setIfi.polid = C.ushort(w.SetPol)

		if w.Prop&cmn.PortPropUpp == cmn.PortPropUpp {
			setIfi.pprop = FLB_DP_PORT_UPP
		}

		ret := flb_add_map_elem(LL_DP_INTF_MAP, unsafe.Pointer(key), unsafe.Pointer(data))
		if ret != 0 {
			tk.LogIt(tk.LogError, "ebpf intfmap - %d vlan %d error: %d\n", w.OsPortNum, w.IngVlan, ret)
			return EbpfErrPortPropAdd
		}

		tk.LogIt(tk.LogDebug, "ebpf intfmap added - %d vlan %d -> %d\n", w.OsPortNum, w.IngVlan, w.PortNum)

		txV = C.uint(w.OsPortNum)
		ret = flb_add_map_elem(LL_DP_TX_INTF_MAP, unsafe.Pointer(&txK), unsafe.Pointer(&txV))
		if ret != 0 {
			flb_del_map_elem(LL_DP_INTF_MAP, unsafe.Pointer(key))
			tk.LogIt(tk.LogError, "ebpf txintfmap - %d error: %d\n", w.OsPortNum, ret)
			return EbpfErrPortPropAdd
		}
		tk.LogIt(tk.LogDebug, "ebpf txintfmap added - %d -> %d\n", w.PortNum, w.OsPortNum)
		return 0
	} else if w.Work == DpRemove {

		// TX_INTF_MAP is array type so we can't delete it
		// Rather we need to zero it out first
		txV = C.uint(0)
		flb_add_map_elem(LL_DP_TX_INTF_MAP, unsafe.Pointer(&txK), unsafe.Pointer(&txV))
		flb_del_map_elem(LL_DP_INTF_MAP, unsafe.Pointer(key))

		if w.LoadEbpf != "" {
			lRet := DetachTcProg(w.LoadEbpf)
			if lRet != 0 {
				tk.LogIt(tk.LogError, "ebpf unload - ifi %d error\n", w.OsPortNum)
				return EbpfErrEbpfLoad
			}
			tk.LogIt(tk.LogDebug, "ebpf unloaded - ifi %d\n", w.OsPortNum)
		}

		return 0
	}

	return EbpfErrWqUnk
}
