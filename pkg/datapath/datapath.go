package datapath

import "C"
import (
	"sync"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/flb/pkg/bpf"
)

type DpMap struct {
	map_fd      int
	map_name    string
	max_entries uint32
	emap        *ebpf.Map
	has_pb      bool
	pb_xtid     int
	pbs         []PbcStats
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
}
