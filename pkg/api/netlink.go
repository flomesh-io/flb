package api

import nlf "github.com/flomesh-io/flb/pkg/netlink"

// This file implements interface defined in NetHookInterface
// The implementation is thread-safe and can be called by multiple-clients at once

// NetAPIStruct - empty struct for anchoring client routines
type NetAPIStruct struct {
}

// NetAPIInit - Initialize a new instance of NetAPI
func NetAPIInit() *NetAPIStruct {
	na := new(NetAPIStruct)
	return na
}

func (n NetAPIStruct) NetPortAdd(mod *nlf.PortMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetPortDel(mod *nlf.PortMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetVlanAdd(mod *nlf.VlanMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetVlanDel(mod *nlf.VlanMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetVlanPortAdd(mod *nlf.VlanPortMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetVlanPortDel(mod *nlf.VlanPortMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetFdbAdd(mod *nlf.FdbMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetFdbDel(mod *nlf.FdbMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetAddrAdd(mod *nlf.IpAddrMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetAddrDel(mod *nlf.IpAddrMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetNeighAdd(mod *nlf.NeighMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetNeighDel(mod *nlf.NeighMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetRouteAdd(mod *nlf.RouteMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetRouteDel(mod *nlf.RouteMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetLbRuleAdd(mod *nlf.LbRuleMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetSessionAdd(mod *nlf.SessionMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetSessionUlClAdd(mod *nlf.SessionUlClMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetFwRuleAdd(mod *nlf.FwRuleMod) (int, error) {
	//TODO implement me
	panic("implement me")
}

func (n NetAPIStruct) NetEpHostAdd(fm *nlf.EndPointMod) (int, error) {
	//TODO implement me
	panic("implement me")
}
