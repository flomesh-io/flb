package api

import "C"
import (
	"encoding/json"
	"fmt"
	"net"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/config"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps/nat"
	"github.com/flomesh-io/flb/pkg/tk"
)

// NatT - type of NAT
type NatT uint8

// nat type constants
const (
	DpSnat NatT = iota + 1
	DpDnat
	DpHsnat
	DpHdnat
	DpFullNat
)

// NatSel - type of nat end-point selection algorithm
type NatSel uint8

// nat selection algorithm constants
const (
	EpRR NatSel = iota + 1
	EpHash
	EpPrio
)

// NatEP - a nat end-point
type NatEP struct {
	XIP      net.IP
	RIP      net.IP
	XPort    uint16
	Weight   uint8
	InActive bool
}

// NatDpWorkQ - work queue entry for nat related operation
type NatDpWorkQ struct {
	Work      DpWorkT
	Status    *DpStatusT
	ZoneNum   int
	ServiceIP net.IP
	L4Port    uint16
	BlockNum  uint16
	DsrMode   bool
	CsumDis   bool
	Proto     uint8
	Mark      int
	NatType   NatT
	EpSel     NatSel
	InActTo   uint64
	EndPoints []NatEP
	SecIP     []net.IP
}

// DpNatLbRuleMod - routine to work on a ebpf nat-lb change request
func DpNatLbRuleMod(w *NatDpWorkQ) int {
	key := new(nat.Key)

	key.DAddr = [4]uint32{0, 0, 0, 0}
	if tk.IsNetIPv4(w.ServiceIP.String()) {
		key.DAddr[0] = tk.IPtonl(w.ServiceIP)
		key.V6 = 0
	} else {
		tk.ConvNetIP2DPv6Addr(unsafe.Pointer(&key.DAddr[0]), w.ServiceIP)
		key.V6 = 1
	}
	key.Mark = w.BlockNum
	key.DPort = tk.Htons(w.L4Port)
	key.L4Proto = w.Proto
	key.Zone = uint16(w.ZoneNum)

	if w.Work == DpCreate {
		acts := new(nat.Acts)
		if w.NatType == DpSnat {
			acts.Ca.ActType = consts.DP_SET_SNAT
		} else if w.NatType == DpDnat || w.NatType == DpFullNat {
			acts.Ca.ActType = consts.DP_SET_DNAT
		} else {
			fmt.Sprintf("[DP] LB rule %s add[NOK] - EbpfErrNat4Add\n", w.ServiceIP.String())
			return consts.EbpfErrNat4Add
		}

		// seconds to nanoseconds
		acts.Ito = w.InActTo * 1000000000

		/*acts.npmhh = 2
		acts.pmhh[0] = 0x64646464
		acts.pmhh[1] = 0x65656565*/
		for i, k := range w.SecIP {
			acts.Pmhh[i] = tk.IPtonl(k)
		}
		acts.Npmhh = uint8(len(w.SecIP))

		switch {
		case w.EpSel == EpRR:
			acts.SelType = consts.NAT_LB_SEL_RR
		case w.EpSel == EpHash:
			acts.SelType = consts.NAT_LB_SEL_HASH
		/* Currently not implemented in DP */
		/*case w.EpSel == EpPrio:
		acts.SelType = consts.NAT_LB_SEL_PRIO*/
		default:
			acts.SelType = consts.NAT_LB_SEL_RR
		}
		acts.Ca.CIdx = uint32(w.Mark)
		if w.DsrMode {
			acts.Ca.OAux = 1
		}

		nxfa := &acts.Nxfrms[0]

		for _, k := range w.EndPoints {
			nxfa.WPrio = k.Weight
			nxfa.NatXPort = tk.Htons(k.XPort)
			if tk.IsNetIPv6(k.XIP.String()) {
				tk.ConvNetIP2DPv6Addr(unsafe.Pointer(&nxfa.NatXIp[0]), k.XIP)

				if tk.IsNetIPv6(k.RIP.String()) {
					tk.ConvNetIP2DPv6Addr(unsafe.Pointer(&nxfa.NatRIp[0]), k.RIP)
				}
				nxfa.Nv6 = 1
			} else {
				nxfa.NatXIp[0] = tk.IPtonl(k.XIP)
				nxfa.NatRIp[0] = tk.IPtonl(k.RIP)
				nxfa.Nv6 = 0
			}

			if k.InActive {
				nxfa.Inactive = 1
			}

			nxfa = (*nat.MfXfrmInf)(tk.GetPtrOffset(unsafe.Pointer(nxfa), 0x28))
		}

		// Any unused end-points should be marked inactive
		for i := len(w.EndPoints); i < config.FLB_MAX_NXFRMS; i++ {
			nxfa := &acts.Nxfrms[i]
			nxfa.Inactive = 1
		}

		acts.Nxfrm = uint16(len(w.EndPoints))
		if w.CsumDis {
			acts.Cdis = 1
		} else {
			acts.Cdis = 0
		}

		err := bpf.UpdateMap(consts.DP_NAT_MAP, key, acts)
		if err != nil {
			fmt.Sprintf("[DP] LB rule %s add[NOK]\n", w.ServiceIP.String())
			return consts.EbpfErrTmacAdd
		}
		fmt.Sprintf("[DP] LB rule %s add[OK]\n", w.ServiceIP.String())
		return 0
	} else if w.Work == DpRemove {
		bpf.DeleteMap(consts.DP_NAT_MAP, key)
		return 0
	} else if w.Work == DpMapShow {
		outValue := new(nat.Acts)
		if err := bpf.GetMap(consts.DP_NAT_MAP, key, outValue); err == nil {
			keyBytes, _ := json.MarshalIndent(key, "", " ")
			valueBytes, _ := json.MarshalIndent(outValue, "", " ")
			fmt.Println(consts.DP_NAT_MAP, "key:", string(keyBytes), "=", "value:", string(valueBytes))
		} else {
			fmt.Println(err.Error())
		}

		return 0
	}

	return consts.EbpfErrWqUnk
}
