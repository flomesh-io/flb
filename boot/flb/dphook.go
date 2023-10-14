package main

import (
	"github.com/flomesh-io/flb/pkg/datapath"
	. "github.com/flomesh-io/flb/pkg/wq"
)

type DpEbpfH struct {
}

func (e DpEbpfH) DpPortPropAdd(w *PortDpWorkQ) int {
	return datapath.DpPortPropMod(w)
}

func (e DpEbpfH) DpPortPropDel(w *PortDpWorkQ) int {
	return datapath.DpPortPropMod(w)
}

func (e DpEbpfH) DpL2AddrAdd(w *L2AddrDpWorkQ) int {
	return datapath.DpL2AddrMod(w)
}

func (e DpEbpfH) DpL2AddrDel(w *L2AddrDpWorkQ) int {
	return datapath.DpL2AddrMod(w)
}

func (e DpEbpfH) DpRouterMacAdd(w *RouterMacDpWorkQ) int {
	return datapath.DpRouterMacMod(w)
}

func (e DpEbpfH) DpRouterMacDel(w *RouterMacDpWorkQ) int {
	return datapath.DpRouterMacMod(w)
}

func (e DpEbpfH) DpNextHopAdd(w *NextHopDpWorkQ) int {
	return datapath.DpNextHopMod(w)
}

func (e DpEbpfH) DpNextHopDel(w *NextHopDpWorkQ) int {
	return datapath.DpNextHopMod(w)
}

func (e DpEbpfH) DpRouteAdd(w *RouteDpWorkQ) int {
	return datapath.DpRouteMod(w)
}

func (e DpEbpfH) DpRouteDel(w *RouteDpWorkQ) int {
	return datapath.DpRouteMod(w)
}

func (e DpEbpfH) DpNatLbRuleAdd(w *NatDpWorkQ) int {
	return datapath.DpNatLbRuleMod(w)
}

func (e DpEbpfH) DpNatLbRuleDel(w *NatDpWorkQ) int {
	return datapath.DpNatLbRuleMod(w)
}
