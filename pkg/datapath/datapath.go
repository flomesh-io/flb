package datapath

import (
	"sync"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/flb/pkg/bpf"
	"github.com/flomesh-io/flb/pkg/consts"
	"github.com/flomesh-io/flb/pkg/maps"
)

type DpMap struct {
	map_fd      int
	map_name    string
	max_entries uint32
	emap        *ebpf.Map
	has_pb      int
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

type DP struct {
	lock   sync.Mutex
	mplock sync.Mutex
	maps   [consts.LL_DP_MAX_MAP]DpMap
}

func DpInit() *DP {
	xh := new(DP)

	if emap, err := xh.maps[consts.LL_DP_INTF_MAP].loadMap(`intf_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_INTF_STATS_MAP].loadMap(`intf_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_BD_STATS_MAP].loadMap(`bd_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_SMAC_MAP].loadMap(`smac_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_TMAC_MAP].loadMap(`tmac_map`); err == nil {
		emap.has_pb = 1
		emap.pb_xtid = consts.LL_DP_TMAC_STATS_MAP
	}

	if emap, err := xh.maps[consts.LL_DP_TMAC_STATS_MAP].loadMap(`tmac_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_CT_MAP].loadMap(`ct_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_CT_STATS_MAP].loadMap(`ct_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_RTV4_MAP].loadMap(`rt_v4_map`); err == nil {
		emap.has_pb = 1
		emap.pb_xtid = consts.LL_DP_RTV4_STATS_MAP
	}

	if emap, err := xh.maps[consts.LL_DP_RTV4_STATS_MAP].loadMap(`rt_v4_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_RTV6_MAP].loadMap(`rt_v6_map`); err == nil {
		emap.has_pb = 1
		emap.pb_xtid = consts.LL_DP_RTV6_STATS_MAP
	}

	if emap, err := xh.maps[consts.LL_DP_RTV6_STATS_MAP].loadMap(`rt_v6_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_NH_MAP].loadMap(`nh_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_DMAC_MAP].loadMap(`dmac_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_TX_INTF_MAP].loadMap(`tx_intf_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_MIRROR_MAP].loadMap(`mirr_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_TX_INTF_STATS_MAP].loadMap(`tx_intf_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_TX_BD_STATS_MAP].loadMap(`tx_bd_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_FCV4_MAP].loadMap(`fc_v4_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_FCV4_STATS_MAP].loadMap(`fc_v4_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_PGM_MAP].loadMap(`pgm_tbl`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_POL_MAP].loadMap(`polx_map`); err == nil {
		emap.has_pb = 0
		emap.has_pol = 1
	}

	if emap, err := xh.maps[consts.LL_DP_NAT_MAP].loadMap(`nat_map`); err == nil {
		emap.has_pb = 1
		emap.pb_xtid = consts.LL_DP_NAT_STATS_MAP
	}

	if emap, err := xh.maps[consts.LL_DP_NAT_STATS_MAP].loadMap(`nat_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_PKT_PERF_RING].loadMap(`pkt_ring`); err == nil {
		emap.has_pb = 0
		emap.max_entries = 128 /* MAX_CPUS */
	}

	if emap, err := xh.maps[consts.LL_DP_SESS4_MAP].loadMap(`sess_v4_map`); err == nil {
		emap.has_pb = 1
		emap.pb_xtid = consts.LL_DP_SESS4_STATS_MAP
	}

	if emap, err := xh.maps[consts.LL_DP_SESS4_STATS_MAP].loadMap(`sess_v4_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_FW4_MAP].loadMap(`fw_v4_map`); err == nil {
		emap.has_pb = 1
		emap.pb_xtid = consts.LL_DP_FW4_STATS_MAP
	}

	if emap, err := xh.maps[consts.LL_DP_FW4_STATS_MAP].loadMap(`fw_v4_stats_map`); err == nil {
		emap.has_pb = 1
		emap.pbs = make([]maps.PbcStats, emap.max_entries)
	}

	if emap, err := xh.maps[consts.LL_DP_CRC32C_MAP].loadMap(`crc32c_map`); err == nil {
		emap.has_pb = 0
	}

	if emap, err := xh.maps[consts.LL_DP_CTCTR_MAP].loadMap(`ct_ctr`); err == nil {
		emap.has_pb = 0
		emap.max_entries = 1
	}

	if emap, err := xh.maps[consts.LL_DP_CPU_MAP].loadMap(`cpu_map`); err == nil {
		emap.has_pb = 0
		emap.max_entries = 128
	}

	if emap, err := xh.maps[consts.LL_DP_LCPU_MAP].loadMap(`live_cpu_map`); err == nil {
		emap.has_pb = 0
		emap.max_entries = 128
	}

	return xh
}
