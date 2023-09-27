package main

import (
	"github.com/flomesh-io/flb/pkg/api"
	. "github.com/flomesh-io/flb/pkg/wq"
)

type DpEbpfH struct {
}

func (e DpEbpfH) DpMirrAdd(w *MirrDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpMirrDel(w *MirrDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpPolAdd(w *PolDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpPolDel(w *PolDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpPortPropAdd(w *PortDpWorkQ) int {
	return api.DpPortPropMod(w)
}

func (e DpEbpfH) DpPortPropDel(w *PortDpWorkQ) int {
	return api.DpPortPropMod(w)
}

func (e DpEbpfH) DpL2AddrAdd(w *L2AddrDpWorkQ) int {
	return api.DpL2AddrMod(w)
}

func (e DpEbpfH) DpL2AddrDel(w *L2AddrDpWorkQ) int {
	return api.DpL2AddrMod(w)
}

func (e DpEbpfH) DpRouterMacAdd(w *RouterMacDpWorkQ) int {
	return api.DpRouterMacMod(w)
}

func (e DpEbpfH) DpRouterMacDel(w *RouterMacDpWorkQ) int {
	return api.DpRouterMacMod(w)
}

func (e DpEbpfH) DpNextHopAdd(w *NextHopDpWorkQ) int {
	return api.DpNextHopMod(w)
}

func (e DpEbpfH) DpNextHopDel(w *NextHopDpWorkQ) int {
	return api.DpNextHopMod(w)
}

func (e DpEbpfH) DpRouteAdd(w *RouteDpWorkQ) int {
	return api.DpRouteMod(w)
}

func (e DpEbpfH) DpRouteDel(w *RouteDpWorkQ) int {
	return api.DpRouteMod(w)
}

func (e DpEbpfH) DpNatLbRuleAdd(w *NatDpWorkQ) int {
	return api.DpNatLbRuleMod(w)
}

func (e DpEbpfH) DpNatLbRuleDel(w *NatDpWorkQ) int {
	return api.DpNatLbRuleMod(w)
}

func (e DpEbpfH) DpFwRuleAdd(w *FwDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpFwRuleDel(w *FwDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpStat(w *StatDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpUlClAdd(w *UlClDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpUlClDel(w *UlClDpWorkQ) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpTableGet(w *TableDpWorkQ) (DpRetT, error) {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpCtAdd(w *DpCtInfo) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpCtDel(w *DpCtInfo) int {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpCtGetAsync() {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpGetLock() {
	//TODO implement me
	panic("implement me")
}

func (e DpEbpfH) DpRelLock() {
	//TODO implement me
	panic("implement me")
}
