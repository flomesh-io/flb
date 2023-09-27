package lbnet

import (
	"runtime/debug"
	"sync"
	"time"

	"github.com/flomesh-io/flb/pkg/cmn"
	"github.com/flomesh-io/flb/pkg/tk"
	. "github.com/flomesh-io/flb/pkg/wq"
)

// error codes
const (
	DpErrBase = iota - L3ErrBase - 1000
	DpWqUnkErr
)

// maximum dp work queue lengths
const (
	DpWorkQLen = 1024
	DpTiVal    = 20
)

// DpHookInterface - represents a go interface which should be implemented to
// integrate with flbnet realm
type DpHookInterface interface {
	DpMirrAdd(*MirrDpWorkQ) int
	DpMirrDel(*MirrDpWorkQ) int
	DpPolAdd(*PolDpWorkQ) int
	DpPolDel(*PolDpWorkQ) int
	DpPortPropAdd(*PortDpWorkQ) int
	DpPortPropDel(*PortDpWorkQ) int
	DpL2AddrAdd(*L2AddrDpWorkQ) int
	DpL2AddrDel(*L2AddrDpWorkQ) int
	DpRouterMacAdd(*RouterMacDpWorkQ) int
	DpRouterMacDel(*RouterMacDpWorkQ) int
	DpNextHopAdd(*NextHopDpWorkQ) int
	DpNextHopDel(*NextHopDpWorkQ) int
	DpRouteAdd(*RouteDpWorkQ) int
	DpRouteDel(*RouteDpWorkQ) int
	DpNatLbRuleAdd(*NatDpWorkQ) int
	DpNatLbRuleDel(*NatDpWorkQ) int
	DpFwRuleAdd(w *FwDpWorkQ) int
	DpFwRuleDel(w *FwDpWorkQ) int
	DpStat(*StatDpWorkQ) int
	DpUlClAdd(w *UlClDpWorkQ) int
	DpUlClDel(w *UlClDpWorkQ) int
	DpTableGet(w *TableDpWorkQ) (DpRetT, error)
	DpCtAdd(w *DpCtInfo) int
	DpCtDel(w *DpCtInfo) int
	DpCtGetAsync()
	DpGetLock()
	DpRelLock()
}

// DpH - datapath context container
type DpH struct {
	ToDpCh  chan interface{}
	ToFinCh chan int
	DpHooks DpHookInterface
	SyncMtx sync.RWMutex
}

// DpBrokerInit - initialize the DP broker subsystem
func DpBrokerInit(dph DpHookInterface) *DpH {
	nDp := new(DpH)

	nDp.ToDpCh = make(chan interface{}, DpWorkQLen)
	nDp.ToFinCh = make(chan int)
	nDp.DpHooks = dph

	go DpWorker(nDp, nDp.ToFinCh, nDp.ToDpCh)

	return nDp
}

// DpWorkOnPort - routine to work on a port work queue request
func (dp *DpH) DpWorkOnPort(pWq *PortDpWorkQ) DpRetT {
	if pWq.Work == DpCreate {
		return dp.DpHooks.DpPortPropAdd(pWq)
	} else if pWq.Work == DpRemove {
		return dp.DpHooks.DpPortPropDel(pWq)
	}

	return DpWqUnkErr
}

// DpWorkOnL2Addr - routine to work on a l2 addr work queue request
func (dp *DpH) DpWorkOnL2Addr(pWq *L2AddrDpWorkQ) DpRetT {
	if pWq.Work == DpCreate {
		return dp.DpHooks.DpL2AddrAdd(pWq)
	} else if pWq.Work == DpRemove {
		return dp.DpHooks.DpL2AddrDel(pWq)
	}

	return DpWqUnkErr
}

// DpWorkOnRtMac - routine to work on a rt-mac work queue request
func (dp *DpH) DpWorkOnRtMac(rmWq *RouterMacDpWorkQ) DpRetT {
	if rmWq.Work == DpCreate {
		return dp.DpHooks.DpRouterMacAdd(rmWq)
	} else if rmWq.Work == DpRemove {
		return dp.DpHooks.DpRouterMacDel(rmWq)
	}

	return DpWqUnkErr
}

// DpWorkOnNextHop - routine to work on a nexthop work queue request
func (dp *DpH) DpWorkOnNextHop(nhWq *NextHopDpWorkQ) DpRetT {
	if nhWq.Work == DpCreate {
		return dp.DpHooks.DpNextHopAdd(nhWq)
	} else if nhWq.Work == DpRemove {
		return dp.DpHooks.DpNextHopDel(nhWq)
	}

	return DpWqUnkErr
}

// DpWorkOnRoute - routine to work on a route work queue request
func (dp *DpH) DpWorkOnRoute(rtWq *RouteDpWorkQ) DpRetT {
	if rtWq.Work == DpCreate {
		return dp.DpHooks.DpRouteAdd(rtWq)
	} else if rtWq.Work == DpRemove {
		return dp.DpHooks.DpRouteDel(rtWq)
	}

	return DpWqUnkErr
}

// DpWorkOnNatLb - routine  to work on a NAT lb work queue request
func (dp *DpH) DpWorkOnNatLb(nWq *NatDpWorkQ) DpRetT {
	if nWq.Work == DpCreate {
		return dp.DpHooks.DpNatLbRuleAdd(nWq)
	} else if nWq.Work == DpRemove {
		return dp.DpHooks.DpNatLbRuleDel(nWq)
	}

	return DpWqUnkErr
}

// DpWorkOnUlCl - routine to work on a ulcl work queue request
func (dp *DpH) DpWorkOnUlCl(nWq *UlClDpWorkQ) DpRetT {
	if nWq.Work == DpCreate {
		return dp.DpHooks.DpUlClAdd(nWq)
	} else if nWq.Work == DpRemove {
		return dp.DpHooks.DpUlClDel(nWq)
	}

	return DpWqUnkErr
}

// DpWorkOnStat - routine to work on a stat work queue request
func (dp *DpH) DpWorkOnStat(nWq *StatDpWorkQ) DpRetT {
	return dp.DpHooks.DpStat(nWq)
}

// DpWorkOnTableOp - routine to work on a table work queue request
func (dp *DpH) DpWorkOnTableOp(nWq *TableDpWorkQ) (DpRetT, error) {
	return dp.DpHooks.DpTableGet(nWq)
}

// DpWorkOnPol - routine to work on a policer work queue request
func (dp *DpH) DpWorkOnPol(pWq *PolDpWorkQ) DpRetT {
	if pWq.Work == DpCreate {
		return dp.DpHooks.DpPolAdd(pWq)
	} else if pWq.Work == DpRemove {
		return dp.DpHooks.DpPolDel(pWq)
	}

	return DpWqUnkErr
}

// DpWorkOnMirr - routine to work on a mirror work queue request
func (dp *DpH) DpWorkOnMirr(mWq *MirrDpWorkQ) DpRetT {
	if mWq.Work == DpCreate {
		return dp.DpHooks.DpMirrAdd(mWq)
	} else if mWq.Work == DpRemove {
		return dp.DpHooks.DpMirrDel(mWq)
	}

	return DpWqUnkErr
}

// DpWorkOnFw - routine to work on a firewall work queue request
func (dp *DpH) DpWorkOnFw(fWq *FwDpWorkQ) DpRetT {
	if fWq.Work == DpCreate {
		return dp.DpHooks.DpFwRuleAdd(fWq)
	} else if fWq.Work == DpRemove {
		return dp.DpHooks.DpFwRuleDel(fWq)
	}

	return DpWqUnkErr
}

// DpWorkSingle - routine to work on a single dp work queue request
func DpWorkSingle(dp *DpH, m interface{}) DpRetT {
	var ret DpRetT
	switch mq := m.(type) {
	case *MirrDpWorkQ:
		ret = dp.DpWorkOnMirr(mq)
	case *PolDpWorkQ:
		ret = dp.DpWorkOnPol(mq)
	case *PortDpWorkQ:
		ret = dp.DpWorkOnPort(mq)
	case *L2AddrDpWorkQ:
		ret = dp.DpWorkOnL2Addr(mq)
	case *RouterMacDpWorkQ:
		ret = dp.DpWorkOnRtMac(mq)
	case *NextHopDpWorkQ:
		ret = dp.DpWorkOnNextHop(mq)
	case *RouteDpWorkQ:
		ret = dp.DpWorkOnRoute(mq)
	case *NatDpWorkQ:
		ret = dp.DpWorkOnNatLb(mq)
	case *UlClDpWorkQ:
		ret = dp.DpWorkOnUlCl(mq)
	case *StatDpWorkQ:
		ret = dp.DpWorkOnStat(mq)
	case *TableDpWorkQ:
		ret, _ = dp.DpWorkOnTableOp(mq)
	case *FwDpWorkQ:
		ret = dp.DpWorkOnFw(mq)
	default:
		tk.LogIt(tk.LogError, "unexpected type %T\n", mq)
		ret = DpWqUnkErr
	}
	return ret
}

// DpWorker - DP worker routine listening on a channel
func DpWorker(dp *DpH, f chan int, ch chan interface{}) {
	// Stack trace logger
	defer func() {
		if e := recover(); e != nil {
			tk.LogIt(tk.LogCritical, "%s: %s", e, debug.Stack())
		}
	}()
	for {
		for n := 0; n < DpWorkQLen; n++ {
			select {
			case m := <-ch:
				DpWorkSingle(dp, m)
			case <-f:
				return
			default:
				continue
			}
		}
		time.Sleep(1000 * time.Millisecond)
	}
}

// DpMapGetCt4 - get DP conntrack information as a map
func (dp *DpH) DpMapGetCt4() []cmn.CtInfo {
	var CtInfoArr []cmn.CtInfo
	nTable := new(TableDpWorkQ)
	nTable.Work = DpMapGet
	nTable.Name = MapNameCt4

	ret, err := mh.dp.DpWorkOnTableOp(nTable)
	if err != nil {
		return nil
	}

	switch r := ret.(type) {
	case map[string]*DpCtInfo:
		for _, dCti := range r {
			cti := cmn.CtInfo{Dip: dCti.DIP, Sip: dCti.SIP, Dport: dCti.Dport, Sport: dCti.Sport,
				Proto: dCti.Proto, CState: dCti.CState, CAct: dCti.CAct,
				Pkts: dCti.Packets, Bytes: dCti.Bytes}
			CtInfoArr = append(CtInfoArr, cti)
		}
	}

	return CtInfoArr
}
