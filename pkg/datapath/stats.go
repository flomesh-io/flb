package datapath

import "C"
import (
	"unsafe"

	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpStat - routine to work on a ebpf map statistics request
func DpStat(w *StatDpWorkQ) int {
	var packets, bytes, dropPackets uint64
	var tbl []int
	var polTbl []int
	sync := 0
	switch {
	case w.Name == MapNameNat4:
		tbl = append(tbl, int(LL_DP_NAT_STATS_MAP))
		sync = 1
	case w.Name == MapNameBD:
		tbl = append(tbl, int(LL_DP_BD_STATS_MAP), int(LL_DP_TX_BD_STATS_MAP))
	case w.Name == MapNameRxBD:
		tbl = append(tbl, int(LL_DP_BD_STATS_MAP))
	case w.Name == MapNameTxBD:
		tbl = append(tbl, int(LL_DP_TX_BD_STATS_MAP))
	case w.Name == MapNameRt4:
		tbl = append(tbl, int(LL_DP_RTV4_MAP))
	case w.Name == MapNameULCL:
		tbl = append(tbl, int(LL_DP_SESS4_MAP))
	case w.Name == MapNameIpol:
		polTbl = append(polTbl, int(LL_DP_POL_MAP))
	case w.Name == MapNameFw4:
		tbl = append(tbl, int(LL_DP_FW4_MAP))
	default:
		return EbpfErrWqUnk
	}

	if w.Work == DpStatsGet {
		var b C.longlong
		var p C.longlong

		packets = 0
		bytes = 0
		dropPackets = 0

		for _, t := range tbl {

			ret := flb_fetch_map_stats_cached(t, w.Mark, sync, unsafe.Pointer(&b), unsafe.Pointer(&p))
			if ret != 0 {
				return EbpfErrTmacAdd
			}

			packets += uint64(p)
			bytes += uint64(b)
		}

		for _, t := range polTbl {

			ret := flb_fetch_pol_map_stats(t, w.Mark, unsafe.Pointer(&p), unsafe.Pointer(&b))
			if ret != 0 {
				return EbpfErrTmacAdd
			}

			packets += uint64(p)
			dropPackets += uint64(b)
		}

		if packets != 0 || bytes != 0 || dropPackets != 0 {
			if w.Packets != nil {
				*w.Packets = packets
			}
			if w.Bytes != nil {
				*w.Bytes = bytes
			}
			if w.DropPackets != nil {
				*w.DropPackets = dropPackets
			}
		}
	} else if w.Work == DpStatsClr {
		for _, t := range tbl {
			flb_clear_map_stats(t, w.Mark)
		}
	}

	return 0
}
