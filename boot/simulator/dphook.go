package main

import (
	"fmt"

	. "github.com/flomesh-io/flb/pkg/wq"
)

type DpCacheH struct {
	DpIgnore

	MapMeta
}

func initDpCacheH() *DpCacheH {
	h := new(DpCacheH)
	h.PortDpWorkQ = make(map[string]PortDpWorkQ)
	h.L2AddrDpWorkQ = make(map[string]L2AddrDpWorkQ)
	h.NextHopDpWorkQ = make(map[string]NextHopDpWorkQ)
	h.RouteDpWorkQ = make(map[string]RouteDpWorkQ)
	h.RouterMacDpWorkQ = make(map[string]RouterMacDpWorkQ)
	return h
}

func (d *DpCacheH) DpPortPropAdd(q *PortDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpPortPropAdd:", key)
	d.PortDpWorkQ[key] = *q
	return 0
}

func (d *DpCacheH) DpPortPropDel(q *PortDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpPortPropDel:", key)
	delete(d.PortDpWorkQ, key)
	return 0
}

func (d *DpCacheH) DpL2AddrAdd(q *L2AddrDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpL2AddrAdd:", key)
	d.L2AddrDpWorkQ[key] = *q
	return 0
}

func (d *DpCacheH) DpL2AddrDel(q *L2AddrDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpL2AddrDel:", key)
	delete(d.L2AddrDpWorkQ, key)
	return 0
}

func (d *DpCacheH) DpRouterMacAdd(q *RouterMacDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpRouterMacAdd:", key)
	d.RouterMacDpWorkQ[key] = *q
	return 0
}

func (d *DpCacheH) DpRouterMacDel(q *RouterMacDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpRouterMacDel:", key)
	delete(d.RouterMacDpWorkQ, key)
	return 0
}

func (d *DpCacheH) DpNextHopAdd(q *NextHopDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpNextHopAdd:", key)
	d.NextHopDpWorkQ[key] = *q
	return 0
}

func (d *DpCacheH) DpNextHopDel(q *NextHopDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpNextHopDel:", key)
	delete(d.NextHopDpWorkQ, key)
	return 0
}

func (d *DpCacheH) DpRouteAdd(q *RouteDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpRouteAdd:", key)
	d.RouteDpWorkQ[key] = *q
	return 0
}

func (d *DpCacheH) DpRouteDel(q *RouteDpWorkQ) int {
	key := q.Key()
	fmt.Println("DpRouteDel:", key)
	delete(d.RouteDpWorkQ, key)
	return 0
}
