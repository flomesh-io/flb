package datapath

/*
#include <string.h>
*/
import "C"
import (
	"fmt"
	"net"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpFwRuleMod - routine to work on a ebpf fw mod request
func DpFwRuleMod(w *FwDpWorkQ) int {
	fwe := new(dp_fwv4_ent)

	C.memset(unsafe.Pointer(fwe), 0, sizeof_struct_dp_fwv4_ent)

	if len(w.DstIP.IP) != 0 {
		fwe.k.dest.val = C.uint(tk.Ntohl(tk.IPtonl(w.DstIP.IP)))
		fwe.k.dest.valid = C.uint(tk.Ntohl(tk.IPtonl(net.IP(w.DstIP.Mask))))
	}

	if len(w.SrcIP.IP) != 0 {
		fwe.k.source.val = C.uint(tk.Ntohl(tk.IPtonl(w.SrcIP.IP)))
		fwe.k.source.valid = C.uint(tk.Ntohl(tk.IPtonl(net.IP(w.SrcIP.Mask))))
	}

	if w.L4SrcMin == w.L4SrcMax {
		if w.L4SrcMin != 0 {
			fwe.k.sport.has_range = C.uint(0)
			ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[0]))
			*ptr = C.ushort(w.L4SrcMin)
			ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[2]))
			*ptr = C.ushort(0xffff)
		}
	} else {
		fwe.k.sport.has_range = C.uint(1)
		ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[0]))
		*ptr = C.ushort(w.L4SrcMin)
		ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[2]))
		*ptr = C.ushort(w.L4SrcMax)
	}

	if w.L4DstMin == w.L4DstMax {
		if w.L4DstMin != 0 {
			fwe.k.dport.has_range = C.uint(0)
			ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[0]))
			*ptr = C.ushort(w.L4DstMin)
			ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[2]))
			*ptr = C.ushort(0xffff)
		}
	} else {
		fwe.k.dport.has_range = C.uint(1)
		ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[0]))
		*ptr = C.ushort(w.L4DstMin)
		ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[2]))
		*ptr = C.ushort(w.L4DstMax)
	}

	if w.Port != 0 {
		fwe.k.inport.val = C.ushort(w.Port)
		fwe.k.inport.valid = C.ushort(0xffff)
	}

	if w.Proto != 0 {
		fwe.k.protocol.val = C.uchar(w.Proto)
		fwe.k.protocol.valid = C.uchar(255)
	}

	if w.ZoneNum != 0 {
		fwe.k.zone.val = C.ushort(w.ZoneNum)
		fwe.k.zone.valid = C.ushort(0xffff)
	}

	fwe.fwa.ca.cidx = C.uint(w.Mark)
	fwe.fwa.ca.oaux = C.ushort(w.Pref) // Overloaded field

	if w.Work == DpCreate {
		if w.FwType == DpFwFwd {
			fwe.fwa.ca.act_type = DP_SET_NOP
		} else if w.FwType == DpFwDrop {
			fwe.fwa.ca.act_type = DP_SET_DROP
		} else if w.FwType == DpFwRdr {
			fwe.fwa.ca.act_type = DP_SET_RDR_PORT
			pRdr := (*dp_rdr_act)(getPtrOffset(unsafe.Pointer(&fwe.fwa),
				sizeof_struct_dp_cmn_act))
			pRdr.oport = C.ushort(w.FwVal1)
		} else if w.FwType == DpFwTrap {
			fwe.fwa.ca.act_type = DP_SET_TOCP
		}
		fwe.fwa.ca.mark = C.ushort(w.FwVal2)
		if w.FwRecord {
			fwe.fwa.ca.record = C.ushort(1)
		}
		sErr := llb_add_map_elem(LL_DP_FW4_MAP, unsafe.Pointer(fwe), unsafe.Pointer(nil))
		if sErr != nil {
			fmt.Printf("[DP] FW %d add[NOK] error: %s\n", w.Mark, sErr.Error())
			tk.LogIt(tk.LogError, "ebpf fw error\n")
			return EbpfErrFwAdd
		}
		fmt.Printf("[DP] FW %d add[OK]\n", w.Mark)
	} else if w.Work == DpRemove {
		llb_del_map_elem(LL_DP_FW4_MAP, unsafe.Pointer(fwe))
	}

	return 0
}
