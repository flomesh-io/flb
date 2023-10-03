package datapath

import "C"
import (
	"fmt"
	"net"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpL2AddrMod - routine to work on a ebpf l2 addr request
func DpL2AddrMod(w *L2AddrDpWorkQ) int {
	var l2va *dp_l2vlan_act

	skey := new(dp_smac_key)
	memcpy(unsafe.Pointer(&skey.smac[0]), unsafe.Pointer(&w.L2Addr[0]), 6)
	skey.bd = C.ushort(uint16(w.BD))

	dkey := new(dp_dmac_key)
	memcpy(unsafe.Pointer(&dkey.dmac[0]), unsafe.Pointer(&w.L2Addr[0]), 6)
	dkey.bd = C.ushort(uint16(w.BD))

	if w.Work == DpCreate {
		sdat := new(dp_cmn_act)
		sdat.act_type = C.DP_SET_NOP

		ddat := new(dp_dmac_tact)
		memset(unsafe.Pointer(ddat), 0, sizeof_struct_dp_dmac_tact)

		if w.Tun == 0 {
			l2va = (*dp_l2vlan_act)(getPtrOffset(unsafe.Pointer(ddat),
				sizeof_struct_dp_cmn_act))
			if w.Tagged != 0 {
				ddat.ca.act_type = DP_SET_ADD_L2VLAN
				l2va.vlan = C.ushort(tk.Htons(uint16(w.BD)))
				l2va.oport = C.ushort(w.PortNum)
			} else {
				ddat.ca.act_type = DP_SET_RM_L2VLAN
				l2va.vlan = C.ushort(tk.Htons(uint16(w.BD)))
				l2va.oport = C.ushort(w.PortNum)
			}
		}

		hwAddr := net.HardwareAddr(w.L2Addr[:])

		sErr := llb_add_map_elem(LL_DP_SMAC_MAP,
			unsafe.Pointer(skey),
			unsafe.Pointer(sdat))
		if sErr != nil {
			fmt.Printf("[DP] L2 SMAC %s add[NOK] %x\n", hwAddr.String(), sErr)
			return EbpfErrL2AddrAdd
		}

		if w.Tun == 0 {
			dErr := llb_add_map_elem(LL_DP_DMAC_MAP,
				unsafe.Pointer(dkey),
				unsafe.Pointer(ddat))
			if dErr != nil {
				fmt.Printf("[DP] L2 DMAC %s add[NOK] %x\n", hwAddr.String(), sErr)
				llb_del_map_elem(LL_DP_SMAC_MAP, unsafe.Pointer(skey))
				return EbpfErrL2AddrAdd
			}
		}
		fmt.Printf("[DP] L2 SMAC & DMAC %s add[OK]\n", hwAddr.String())

		return 0
	} else if w.Work == DpRemove {
		llb_del_map_elem(LL_DP_SMAC_MAP, unsafe.Pointer(skey))
		if w.Tun == 0 {
			llb_del_map_elem(LL_DP_DMAC_MAP, unsafe.Pointer(dkey))
		}
		return 0
	}

	return EbpfErrWqUnk
}
