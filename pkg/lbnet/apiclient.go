package lbnet

import (
	"github.com/flomesh-io/flb/pkg/cmn"
)

// This file implements interface defined in cmn.NetHookInterface
// The implementation is thread-safe and can be called by multiple-clients at once

// NetAPIStruct - empty struct for anchoring client routines
type NetAPIStruct struct {
}

// NetAPIInit - Initialize a new instance of NetAPI
func NetAPIInit() *NetAPIStruct {
	na := new(NetAPIStruct)
	return na
}

// NetMirrorGet - Get a mirror in lbnet
func (*NetAPIStruct) NetMirrorGet() ([]cmn.MirrGetMod, error) {
	// There is no locking requirement for this operation
	ret, _ := mh.zr.Mirrs.MirrGet()
	return ret, nil
}

// NetMirrorAdd - Add a mirror in lbnet
func (*NetAPIStruct) NetMirrorAdd(mm *cmn.MirrMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Mirrs.MirrAdd(mm.Ident, mm.Info, mm.Target)
	return ret, err
}

// NetMirrorDel - Delete a mirror in lbnet
func (*NetAPIStruct) NetMirrorDel(mm *cmn.MirrMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Mirrs.MirrDelete(mm.Ident)
	return ret, err
}

// NetPortGet - Get Port Information of lbnet
func (*NetAPIStruct) NetPortGet() ([]cmn.PortDump, error) {
	ret, err := mh.zr.Ports.PortsToGet()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// NetPortAdd - Add a port in lbnet
func (na *NetAPIStruct) NetPortAdd(pm *cmn.PortMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Ports.PortAdd(pm.Dev, pm.LinkIndex, pm.Ptype, RootZone,
		PortHwInfo{pm.MacAddr, pm.Link, pm.State, pm.Mtu, pm.Master, pm.Real,
			uint32(pm.TunID), pm.TunSrc, pm.TunDst}, PortLayer2Info{false, 0})

	return ret, err
}

// NetPortDel - Delete port from lbnet
func (na *NetAPIStruct) NetPortDel(pm *cmn.PortMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Ports.PortDel(pm.Dev, pm.Ptype)
	return ret, err
}

// NetVlanGet - Get Vlan Information of lbnet
func (na *NetAPIStruct) NetVlanGet() ([]cmn.VlanGet, error) {
	ret, err := mh.zr.Vlans.VlanGet()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// NetVlanAdd - Add vlan info to lbnet
func (na *NetAPIStruct) NetVlanAdd(vm *cmn.VlanMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanAdd(vm.Vid, vm.Dev, RootZone, vm.LinkIndex,
		PortHwInfo{vm.MacAddr, vm.Link, vm.State, vm.Mtu, "", "", vm.TunID, nil, nil})
	if ret == VlanExistsErr {
		ret = 0
	}

	return ret, err
}

// NetVlanDel - Delete vlan info from lbnet
func (na *NetAPIStruct) NetVlanDel(vm *cmn.VlanMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanDelete(vm.Vid)
	return ret, err
}

// NetVlanPortAdd - Add a port to vlan in lbnet
func (na *NetAPIStruct) NetVlanPortAdd(vm *cmn.VlanPortMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanPortAdd(vm.Vid, vm.Dev, vm.Tagged)
	return ret, err
}

// NetVlanPortDel - Delete a port from vlan in lbnet
func (na *NetAPIStruct) NetVlanPortDel(vm *cmn.VlanPortMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanPortDelete(vm.Vid, vm.Dev, vm.Tagged)
	return ret, err
}

// NetAddrGet - Get an IPv4 Address info from lbnet
func (na *NetAPIStruct) NetAddrGet() ([]cmn.IPAddrGet, error) {
	// There is no locking requirement for this operation
	ret := mh.zr.L3.IfaGet()
	return ret, nil
}

// NetAddrAdd - Add an ipv4 address in lbnet
func (na *NetAPIStruct) NetAddrAdd(am *cmn.IPAddrMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.L3.IfaAdd(am.Dev, am.IP)
	return ret, err
}

// NetAddrDel - Delete an ipv4 address in lbnet
func (na *NetAPIStruct) NetAddrDel(am *cmn.IPAddrMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.L3.IfaDelete(am.Dev, am.IP)
	return ret, err
}

// NetNeighGet - Get a neighbor in lbnet
func (na *NetAPIStruct) NetNeighGet() ([]cmn.NeighMod, error) {
	ret, err := mh.zr.Nh.NeighGet()
	return ret, err
}

// NetNeighAdd - Add a neighbor in lbnet
func (na *NetAPIStruct) NetNeighAdd(nm *cmn.NeighMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Nh.NeighAdd(nm.IP, RootZone, NeighAttr{nm.LinkIndex, nm.State, nm.HardwareAddr})
	if err != nil {
		if ret != NeighExistsErr {
			return ret, err
		}
	}

	return 0, nil
}

// NetNeighDel - Delete a neighbor in lbnet
func (na *NetAPIStruct) NetNeighDel(nm *cmn.NeighMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Nh.NeighDelete(nm.IP, RootZone)
	return ret, err
}

// NetFdbAdd - Add a forwarding database entry in lbnet
func (na *NetAPIStruct) NetFdbAdd(fm *cmn.FdbMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	fdbKey := FdbKey{fm.MacAddr, fm.BridgeID}
	fdbAttr := FdbAttr{fm.Dev, fm.Dst, fm.Type}
	ret, err := mh.zr.L2.L2FdbAdd(fdbKey, fdbAttr)
	return ret, err
}

// NetFdbDel - Delete a forwarding database entry in lbnet
func (na *NetAPIStruct) NetFdbDel(fm *cmn.FdbMod) (int, error) {
	fdbKey := FdbKey{fm.MacAddr, fm.BridgeID}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.L2.L2FdbDel(fdbKey)
	return ret, err
}

// NetRouteGet - Get Route info from lbnet
func (na *NetAPIStruct) NetRouteGet() ([]cmn.RouteGet, error) {
	// There is no locking requirement for this operation
	ret, _ := mh.zr.Rt.RouteGet()
	return ret, nil
}

// NetRouteAdd - Add a route in lbnet
func (na *NetAPIStruct) NetRouteAdd(rm *cmn.RouteMod) (int, error) {
	var ret int
	var err error

	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ra := RtAttr{rm.Protocol, rm.Flags, false, rm.LinkIndex}
	if rm.Gw != nil {
		na := []RtNhAttr{{rm.Gw, rm.LinkIndex}}
		ret, err = mh.zr.Rt.RtAdd(rm.Dst, RootZone, ra, na)
	} else {
		ret, err = mh.zr.Rt.RtAdd(rm.Dst, RootZone, ra, nil)
	}

	return ret, err
}

// NetRouteDel - Delete a route in lbnet
func (na *NetAPIStruct) NetRouteDel(rm *cmn.RouteMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rt.RtDelete(rm.Dst, RootZone)
	return ret, err
}

// NetLbRuleAdd - Add a load-balancer rule in lbnet
func (na *NetAPIStruct) NetLbRuleAdd(lm *cmn.LbRuleMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	ret, err := mh.zr.Rules.AddNatLbRule(lm.Serv, lm.SecIPs[:], lm.Eps[:])
	return ret, err
}

// NetLbRuleDel - Delete a load-balancer rule in lbnet
func (na *NetAPIStruct) NetLbRuleDel(lm *cmn.LbRuleMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.DeleteNatLbRule(lm.Serv)
	return ret, err
}

// NetLbRuleGet - Get a load-balancer rule from lbnet
func (na *NetAPIStruct) NetLbRuleGet() ([]cmn.LbRuleMod, error) {
	ret, err := mh.zr.Rules.GetNatLbRule()
	return ret, err
}

// NetCtInfoGet - Get connection track info from lbnet
func (na *NetAPIStruct) NetCtInfoGet() ([]cmn.CtInfo, error) {
	// There is no locking requirement for this operation
	ret := mh.dp.DpMapGetCt4()
	return ret, nil
}

// NetSessionAdd - Add a 3gpp user-session info in lbnet
func (na *NetAPIStruct) NetSessionAdd(sm *cmn.SessionMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.SessAdd(sm.Ident, sm.IP, sm.AnTun, sm.CnTun)
	return ret, err
}

// NetSessionDel - Delete a 3gpp user-session info in lbnet
func (na *NetAPIStruct) NetSessionDel(sm *cmn.SessionMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.SessDelete(sm.Ident)
	return ret, err
}

// NetSessionUlClAdd - Add a 3gpp ulcl-filter info in lbnet
func (na *NetAPIStruct) NetSessionUlClAdd(sr *cmn.SessionUlClMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.UlClAddCls(sr.Ident, sr.Args)
	return ret, err
}

// NetSessionUlClDel - Delete a 3gpp ulcl-filter info in lbnet
func (na *NetAPIStruct) NetSessionUlClDel(sr *cmn.SessionUlClMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.UlClDeleteCls(sr.Ident, sr.Args)
	return ret, err
}

// NetSessionGet - Get 3gpp user-session info in lbnet
func (na *NetAPIStruct) NetSessionGet() ([]cmn.SessionMod, error) {
	// There is no locking requirement for this operation
	ret, err := mh.zr.Sess.SessGet()
	return ret, err
}

// NetSessionUlClGet - Get 3gpp ulcl filter info from lbnet
func (na *NetAPIStruct) NetSessionUlClGet() ([]cmn.SessionUlClMod, error) {
	// There is no locking requirement for this operation
	ret, err := mh.zr.Sess.SessUlclGet()
	return ret, err
}

// NetPolicerGet - Get a policer in lbnet
func (na *NetAPIStruct) NetPolicerGet() ([]cmn.PolMod, error) {
	// There is no locking requirement for this operation
	ret, err := mh.zr.Pols.PolGetAll()
	return ret, err
}

// NetPolicerAdd - Add a policer in lbnet
func (na *NetAPIStruct) NetPolicerAdd(pm *cmn.PolMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Pols.PolAdd(pm.Ident, pm.Info, pm.Target)
	return ret, err
}

// NetPolicerDel - Delete a policer in lbnet
func (na *NetAPIStruct) NetPolicerDel(pm *cmn.PolMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Pols.PolDelete(pm.Ident)
	return ret, err
}

// NetFwRuleAdd - Add a firewall rule in lbnet
func (na *NetAPIStruct) NetFwRuleAdd(fm *cmn.FwRuleMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.AddFwRule(fm.Rule, fm.Opts)
	return ret, err
}

// NetFwRuleDel - Delete a firewall rule in lbnet
func (na *NetAPIStruct) NetFwRuleDel(fm *cmn.FwRuleMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.DeleteFwRule(fm.Rule)
	return ret, err
}

// NetFwRuleGet - Get a firewall rule from lbnet
func (na *NetAPIStruct) NetFwRuleGet() ([]cmn.FwRuleMod, error) {
	ret, err := mh.zr.Rules.GetFwRule()
	return ret, err
}

// NetEpHostAdd - Add a LB end-point in lbnet
func (na *NetAPIStruct) NetEpHostAdd(em *cmn.EndPointMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	epArgs := epHostOpts{inActTryThr: em.InActTries, probeType: em.ProbeType,
		probeReq: em.ProbeReq, probeResp: em.ProbeResp,
		probeDuration: em.ProbeDuration, probePort: em.ProbePort,
	}
	ret, err := mh.zr.Rules.AddEPHost(true, em.HostName, em.Name, epArgs)
	return ret, err
}

// NetEpHostDel - Delete a LB end-point in lbnet
func (na *NetAPIStruct) NetEpHostDel(em *cmn.EndPointMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.DeleteEPHost(true, em.Name, em.HostName, em.ProbeType, em.ProbePort)
	return ret, err
}

// NetEpHostGet - Get LB end-points from lbnet
func (na *NetAPIStruct) NetEpHostGet() ([]cmn.EndPointMod, error) {
	ret, err := mh.zr.Rules.GetEpHosts()
	return ret, err
}
