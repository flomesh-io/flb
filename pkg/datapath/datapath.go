package datapath

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/flb/internal"
	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/maps"
	"github.com/flomesh-io/flb/pkg/tk"
)

type DpMap struct {
	map_fd      int
	map_name    string
	max_entries uint32
	emap        *ebpf.Map
	has_pb      bool
	pb_xtid     int
	pbs         []maps.PbcStats
	has_pol     int
	//struct dp_pol_stats *pls;
	stat_lock sync.Mutex
}

func (m *DpMap) loadMap(mapName string) (*DpMap, error) {
	emap, err := bpf.LoadMap(mapName)
	if err == nil {
		m.emap = emap
		m.map_name = mapName
		m.map_fd = emap.FD()
		m.max_entries = emap.MaxEntries()
	}
	return m, err
}

func (m *DpMap) Name() string {
	return m.map_name
}

func (m *DpMap) FD() int {
	return m.map_fd
}

var (
	xh *dp
)

func XH_LOCK() {
	xh.lock.Lock()
}

func XH_UNLOCK() {
	xh.lock.Unlock()
}

func XH_RD_LOCK() {
	xh.lock.RLock()
}

func XH_RD_UNLOCK() {
	xh.lock.RUnlock()
}

func XH_MP_LOCK() {
	xh.mplock.Lock()
}

func XH_MP_UNLOCK() {
	xh.mplock.Unlock()
}

func EachMap(f func(emap *DpMap)) {
	if xh == nil || f == nil {
		return
	}
	for _, emap := range xh.maps {
		f(emap)
	}
}

func GetMap(mapIndex int) *DpMap {
	XH_MP_LOCK()
	defer XH_MP_UNLOCK()
	emap := xh.maps[mapIndex]
	if emap == nil {
		emap = new(DpMap)
		xh.maps[mapIndex] = emap
	}
	return emap
}

func DpInit(nodeNo uint32) {
	xh = new(dp)

	if emap, err := GetMap(LL_DP_INTF_MAP).loadMap(`intf_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_INTF_STATS_MAP).loadMap(`intf_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_BD_STATS_MAP).loadMap(`bd_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_SMAC_MAP).loadMap(`smac_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_TMAC_MAP).loadMap(`tmac_map`); err == nil {
		emap.has_pb = true
		emap.pb_xtid = LL_DP_TMAC_STATS_MAP
	}

	if emap, err := GetMap(LL_DP_TMAC_STATS_MAP).loadMap(`tmac_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_CT_MAP).loadMap(`ct_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_CT_STATS_MAP).loadMap(`ct_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_RTV4_MAP).loadMap(`rt_v4_map`); err == nil {
		emap.has_pb = true
		emap.pb_xtid = LL_DP_RTV4_STATS_MAP
	}

	if emap, err := GetMap(LL_DP_RTV4_STATS_MAP).loadMap(`rt_v4_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_RTV6_MAP).loadMap(`rt_v6_map`); err == nil {
		emap.has_pb = true
		emap.pb_xtid = LL_DP_RTV6_STATS_MAP
	}

	if emap, err := GetMap(LL_DP_RTV6_STATS_MAP).loadMap(`rt_v6_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_NH_MAP).loadMap(`nh_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_DMAC_MAP).loadMap(`dmac_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_TX_INTF_MAP).loadMap(`tx_intf_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_MIRROR_MAP).loadMap(`mirr_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_TX_INTF_STATS_MAP).loadMap(`tx_intf_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_TX_BD_STATS_MAP).loadMap(`tx_bd_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_FCV4_MAP).loadMap(`fc_v4_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_FCV4_STATS_MAP).loadMap(`fc_v4_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_PGM_MAP).loadMap(`pgm_tbl`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_POL_MAP).loadMap(`polx_map`); err == nil {
		emap.has_pb = false
		emap.has_pol = 1
	}

	if emap, err := GetMap(LL_DP_NAT_MAP).loadMap(`nat_map`); err == nil {
		emap.has_pb = true
		emap.pb_xtid = LL_DP_NAT_STATS_MAP
	}

	if emap, err := GetMap(LL_DP_NAT_STATS_MAP).loadMap(`nat_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_PKT_PERF_RING).loadMap(`pkt_ring`); err == nil {
		emap.has_pb = false
		emap.max_entries = 128 /* MAX_CPUS */
	}

	if emap, err := GetMap(LL_DP_SESS4_MAP).loadMap(`sess_v4_map`); err == nil {
		emap.has_pb = true
		emap.pb_xtid = LL_DP_SESS4_STATS_MAP
	}

	if emap, err := GetMap(LL_DP_SESS4_STATS_MAP).loadMap(`sess_v4_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_FW4_MAP).loadMap(`fw_v4_map`); err == nil {
		emap.has_pb = true
		emap.pb_xtid = LL_DP_FW4_STATS_MAP
	}

	if emap, err := GetMap(LL_DP_FW4_STATS_MAP).loadMap(`fw_v4_stats_map`); err == nil {
		emap.has_pb = true
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := GetMap(LL_DP_CRC32C_MAP).loadMap(`crc32c_map`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_CTCTR_MAP).loadMap(`ct_ctr`); err == nil {
		emap.has_pb = false
		emap.max_entries = 1
	}

	if emap, err := GetMap(LL_DP_CPU_MAP).loadMap(`cpu_map`); err == nil {
		emap.has_pb = false
		emap.max_entries = 128
	}

	if emap, err := GetMap(LL_DP_LCPU_MAP).loadMap(`live_cpu_map`); err == nil {
		emap.has_pb = false
		emap.max_entries = 128
	}

	if emap, err := GetMap(LL_DP_XFIS_MAP).loadMap(`xfis`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_PKTS_MAP).loadMap(`pkts`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_FCAS_MAP).loadMap(`fcas`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_XFCK_MAP).loadMap(`xfck`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_XCTK_MAP).loadMap(`xctk`); err == nil {
		emap.has_pb = false
	}

	if emap, err := GetMap(LL_DP_GPARSER_MAP).loadMap(`gparser`); err == nil {
		emap.has_pb = false
	}

	setupCrc32cMap()
	setupCtCtrMap(nodeNo)
	setupCpuMap()
	setupLiveCpuMap()
	setupUfw4PdiMap()
	setupUfw6PdiMap()
}

func llb_del_map_elem(tbl int, k interface{}) error {
	return nil
}

func llb_add_map_elem(tbl int, k, v interface{}) error {
	if tbl < 0 || tbl >= LL_DP_MAX_MAP {
		return fmt.Errorf(`invalid ebpf map index: %d`, tbl)
	}

	XH_LOCK()
	defer XH_UNLOCK()

	/* Any table which has stats pb needs to get stats cleared before use */
	if tbl == LL_DP_NAT_MAP ||
		tbl == LL_DP_TMAC_MAP ||
		tbl == LL_DP_FW4_MAP ||
		tbl == LL_DP_RTV4_MAP {
		cidx := uint32(0)

		if tbl == LL_DP_FW4_MAP {
			e := (*dp_fwv4_ent)(k.(unsafe.Pointer))
			cidx = uint32(e.fwa.ca.cidx)
		} else {
			ca := (*dp_cmn_act)(v.(unsafe.Pointer))
			cidx = uint32(ca.cidx)
		}
		llb_clear_map_stats(tbl, cidx)
	}

	if tbl == LL_DP_FW4_MAP {
		//ret = llb_add_mf_map_elem__(tbl, k, v)
	} else {
		if err := xh.maps[tbl].emap.Update(k, v, ebpf.UpdateAny); err != nil {
			return err
		}
		/* Need some post-processing for certain maps */
		if tbl == LL_DP_NAT_MAP {
			llb_add_map_elem_nat_post_proc(k, v)
		}
	}

	return nil
}

func llb_clear_map_stats(tid int, idx uint32) {
	llb_clear_map_stats_internal(tid, idx, false)
}

func llb_clear_map_stats_internal(tid int, idx uint32, wipe bool) {
	if tid < 0 || tid >= LL_DP_MAX_MAP {
		return
	}
	t := xh.maps[tid]
	if t.has_pb {
		if t.pb_xtid > 0 {
			if t.pb_xtid >= LL_DP_MAX_MAP {
				return
			}

			t = xh.maps[t.pb_xtid]
			if !t.has_pb || t.pb_xtid > 0 {
				return
			}
		}
		/* FIXME : Handle non-pcpu */
		if !wipe {
			llb_clear_stats_pcpu_arr(t.emap, idx)
		} else {
			for e := uint32(0); e < t.max_entries; e++ {
				llb_clear_stats_pcpu_arr(t.emap, e)
			}
		}
	}
}

func llb_clear_stats_pcpu_arr(pinMap *ebpf.Map, idx uint32) {
	if nrCpus, err := internal.PossibleCPUs(); err == nil {
		values := make([]maps.PbStats, nrCpus)
		if err = pinMap.Update(&idx, values, ebpf.UpdateAny); err != nil {
			tk.LogIt(tk.LogError, "bpf_map_lookup_elem failed, error:%s\n", err.Error())
		}
	} else {
		tk.LogIt(tk.LogError, "bpf_map_lookup_elem failed, error:%s\n", err.Error())
	}
}

func llb_add_map_elem_nat_post_proc(k, v interface{}) {
	//TODO benne
	//struct dp_nat_tacts *na = v;
	//struct mf_xfrm_inf *ep_arm;
	//uint32_t inact_aids[LLB_MAX_NXFRMS];
	//int i = 0;
	//int j = 0;
	//
	//memset(inact_aids, 0, sizeof(inact_aids));
	//
	//for (i = 0; i < na->nxfrm && i < LLB_MAX_NXFRMS; i++) {
	//ep_arm = &na->nxfrms[i];
	//
	//if (ep_arm->inactive) {
	//inact_aids[j++] = i;
	//}
	//}
	//
	//if (j > 0) {
	//ll_map_ct_rm_related(na->ca.cidx, inact_aids, j);
	//}
	//
	//return 0;

}

func setupCrc32cMap() {
	var i uint32
	var crc uint32

	// Generate crc32c table
	for i = 0; i < 256; i++ {
		crc = i
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		//crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
		for n := 0; n < 8; n++ {
			if crc&1 > 0 {
				crc = (crc >> 1) ^ 0x82f63b78
			} else {
				crc = crc >> 1
			}
		}
		xh.maps[LL_DP_CRC32C_MAP].emap.Update(&i, &crc, ebpf.UpdateAny)
	}
}

func setupCtCtrMap(nodeNo uint32) {
	key := uint32(0)
	ctr := new(dp_ct_ctrtact)
	ctr.start = uint32(FLB_CT_MAP_ENTRIES/FLB_MAX_LB_NODES) * nodeNo
	ctr.counter = ctr.start
	ctr.entries = ctr.start + uint32(FLB_CT_MAP_ENTRIES/FLB_MAX_LB_NODES)
	xh.maps[LL_DP_CTCTR_MAP].emap.Update(&key, ctr, ebpf.UpdateAny)
}

func setupCpuMap() {
	if possibleCpus, err := internal.PossibleCPUs(); err == nil {
		val := uint32(2048)
		for i := 0; i < possibleCpus; i++ {
			key := uint32(i)
			xh.maps[LL_DP_CPU_MAP].emap.Update(&key, &val, ebpf.UpdateAny)
			xh.maps[LL_DP_CPU_MAP].max_entries = uint32(possibleCpus)
		}
	} else {
		fmt.Println(err.Error())
	}
}

func setupLiveCpuMap() {
	if liveCpus, err := internal.PossibleCPUs(); err == nil {
		key := uint32(0)
		val := uint32(liveCpus)
		xh.maps[LL_DP_LCPU_MAP].emap.Update(&key, &val, ebpf.UpdateAny)
	} else {
		fmt.Println(err.Error())
	}
}
