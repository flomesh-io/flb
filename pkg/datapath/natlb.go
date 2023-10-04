package datapath

/*
#include <string.h>
#include <sys/types.h>
#include <linux/types.h>
*/
import "C"
import (
	"net"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpNatLbRuleMod - routine to work on a ebpf nat-lb change request
func DpNatLbRuleMod(w *NatDpWorkQ) int {
	key := new(dp_nat_key)

	key.daddr = [4]C.uint{0, 0, 0, 0}
	if tk.IsNetIPv4(w.ServiceIP.String()) {
		key.daddr[0] = C.uint(tk.IPtonl(w.ServiceIP))
		key.v6 = 0
	} else {
		convNetIP2DPv6Addr(unsafe.Pointer(&key.daddr[0]), w.ServiceIP)
		key.v6 = 1
	}
	key.mark = C.ushort(w.BlockNum)
	key.dport = C.ushort(tk.Htons(w.L4Port))
	key.l4proto = C.uchar(w.Proto)
	key.zone = C.ushort(w.ZoneNum)

	if w.Work == DpCreate {
		dat := new(dp_nat_tacts)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_nat_tacts)
		if w.NatType == DpSnat {
			dat.ca.act_type = DP_SET_SNAT
		} else if w.NatType == DpDnat || w.NatType == DpFullNat {
			dat.ca.act_type = DP_SET_DNAT
		} else {
			tk.LogIt(tk.LogDebug, "[DP] LB rule %s add[NOK] - EbpfErrNat4Add\n", w.ServiceIP.String())
			return EbpfErrNat4Add
		}

		// seconds to nanoseconds
		dat.ito = C.uint64_t(w.InActTo * 1000000000)

		/*dat.npmhh = 2
		dat.pmhh[0] = 0x64646464
		dat.pmhh[1] = 0x65656565*/
		for i, k := range w.SecIP {
			dat.pmhh[i] = C.uint(tk.IPtonl(k))
		}
		dat.npmhh = C.uchar(len(w.SecIP))

		switch {
		case w.EpSel == EpRR:
			dat.sel_type = NAT_LB_SEL_RR
		case w.EpSel == EpHash:
			dat.sel_type = NAT_LB_SEL_HASH
		/* Currently not implemented in DP */
		/*case w.EpSel == EP_PRIO:
		  dat.sel_type = NAT_LB_SEL_PRIO*/
		default:
			dat.sel_type = NAT_LB_SEL_RR
		}
		dat.ca.cidx = C.uint(w.Mark)
		if w.DsrMode {
			dat.ca.oaux = 1
		}

		nxfa := (*dp_mf_xfrm_inf)(unsafe.Pointer(&dat.nxfrms[0]))

		for _, k := range w.EndPoints {
			nxfa.wprio = C.uchar(k.Weight)
			nxfa.nat_xport = C.ushort(tk.Htons(k.XPort))
			if tk.IsNetIPv6(k.XIP.String()) {
				convNetIP2DPv6Addr(unsafe.Pointer(&nxfa.nat_xip[0]), k.XIP)
				if tk.IsNetIPv6(k.RIP.String()) {
					convNetIP2DPv6Addr(unsafe.Pointer(&nxfa.nat_rip[0]), k.RIP)
				}
				nxfa.nv6 = 1
			} else {
				nxfa.nat_xip[0] = C.uint(tk.IPtonl(k.XIP))
				nxfa.nat_rip[0] = C.uint(tk.IPtonl(k.RIP))
				nxfa.nv6 = 0
			}

			if k.InActive {
				nxfa.inactive = 1
			}

			nxfa = (*dp_mf_xfrm_inf)(getPtrOffset(unsafe.Pointer(nxfa),
				sizeof_struct_mf_xfrm_inf))
		}

		// Any unused end-points should be marked inactive
		for i := len(w.EndPoints); i < LLB_MAX_NXFRMS; i++ {
			nxfa := (*dp_mf_xfrm_inf)(unsafe.Pointer(&dat.nxfrms[i]))
			nxfa.inactive = 1
		}

		dat.nxfrm = C.ushort(len(w.EndPoints))
		if w.CsumDis {
			dat.cdis = 1
		} else {
			dat.cdis = 0
		}

		sErr := llb_add_map_elem(LL_DP_NAT_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))

		if sErr != nil {
			tk.LogIt(tk.LogDebug, "[DP] LB rule %s add[NOK] error: %s\n", w.ServiceIP.String(), sErr.Error())
			return EbpfErrTmacAdd
		}
		tk.LogIt(tk.LogDebug, "[DP] LB rule %s add[OK]\n", w.ServiceIP.String())
		return 0
	} else if w.Work == DpRemove {
		llb_del_map_elem(LL_DP_NAT_MAP, unsafe.Pointer(key))
		return 0
	}

	return EbpfErrWqUnk
}

func convNetIP2DPv6Addr(addr unsafe.Pointer, goIP net.IP) {
	aPtr := (*C.uchar)(addr)
	for bp := 0; bp < 16; bp++ {
		*aPtr = C.uchar(goIP[bp])
		aPtr = (*C.uchar)(getPtrOffset(unsafe.Pointer(aPtr),
			C.sizeof_uchar))
	}
}

func convDPv6Addr2NetIP(addr unsafe.Pointer) net.IP {
	var goIP net.IP
	aPtr := (*C.uchar)(addr)

	for i := 0; i < 16; i++ {
		goIP = append(goIP, uint8(*aPtr))
		aPtr = (*C.uchar)(getPtrOffset(unsafe.Pointer(aPtr),
			C.sizeof_uchar))
	}
	return goIP
}
