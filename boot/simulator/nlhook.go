package main

import (
	"sync"

	"github.com/flomesh-io/flb/pkg/cmn"
	"github.com/flomesh-io/flb/pkg/lbnet"
)

// This file implements interface defined in cmn.NetHookInterface
// The implementation is thread-safe and can be called by multiple-clients at once

// NetAPIStruct - empty struct for anchoring client routines
type NetAPIStruct struct {
	zr  *lbnet.Zone
	mtx *sync.RWMutex
}

// netAPIInit - Initialize a new instance of NetAPI
func netAPIInit(zr *lbnet.Zone, mtx *sync.RWMutex) *NetAPIStruct {
	na := new(NetAPIStruct)
	na.zr = zr
	na.mtx = mtx
	return na
}

func (na *NetAPIStruct) NetPortAdd(pm *cmn.PortMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Ports.PortAdd(pm.Dev, pm.LinkIndex, pm.Ptype, lbnet.RootZone,
		lbnet.PortHwInfo{
			MacAddr: pm.MacAddr,
			Link:    pm.Link,
			State:   pm.State,
			Mtu:     pm.Mtu,
			Master:  pm.Master,
			Real:    pm.Real,
			TunID:   uint32(pm.TunID),
			TunSrc:  pm.TunSrc,
			TunDst:  pm.TunDst,
		},
		lbnet.PortLayer2Info{IsPvid: false, Vid: 0})

	return ret, err
}

func (na *NetAPIStruct) NetPortDel(pm *cmn.PortMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Ports.PortDel(pm.Dev, pm.Ptype)
	return ret, err
}

func (na *NetAPIStruct) NetVlanAdd(vm *cmn.VlanMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Vlans.VlanAdd(vm.Vid, vm.Dev, lbnet.RootZone, vm.LinkIndex,
		lbnet.PortHwInfo{
			MacAddr: vm.MacAddr,
			Link:    vm.Link,
			State:   vm.State,
			Mtu:     vm.Mtu,
			TunID:   vm.TunID})
	if ret == lbnet.VlanExistsErr {
		ret = 0
	}

	return ret, err
}

func (na *NetAPIStruct) NetVlanDel(vm *cmn.VlanMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Vlans.VlanDelete(vm.Vid)
	return ret, err
}

func (na *NetAPIStruct) NetVlanPortAdd(vm *cmn.VlanPortMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Vlans.VlanPortAdd(vm.Vid, vm.Dev, vm.Tagged)
	return ret, err
}

func (na *NetAPIStruct) NetVlanPortDel(vm *cmn.VlanPortMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Vlans.VlanPortDelete(vm.Vid, vm.Dev, vm.Tagged)
	return ret, err
}

func (na *NetAPIStruct) NetAddrAdd(am *cmn.IPAddrMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.L3.IfaAdd(am.Dev, am.IP)
	return ret, err
}

func (na *NetAPIStruct) NetAddrDel(am *cmn.IPAddrMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.L3.IfaDelete(am.Dev, am.IP)
	return ret, err
}

func (na *NetAPIStruct) NetNeighAdd(nm *cmn.NeighMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Nh.NeighAdd(nm.IP, lbnet.RootZone,
		lbnet.NeighAttr{
			OSLinkIndex:  nm.LinkIndex,
			OSState:      nm.State,
			HardwareAddr: nm.HardwareAddr})
	if err != nil {
		if ret != lbnet.NeighExistsErr {
			return ret, err
		}
	}

	return 0, nil
}

func (na *NetAPIStruct) NetNeighDel(nm *cmn.NeighMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Nh.NeighDelete(nm.IP, lbnet.RootZone)
	return ret, err
}

func (na *NetAPIStruct) NetRouteAdd(rm *cmn.RouteMod) (int, error) {
	var ret int
	var err error

	na.mtx.Lock()
	defer na.mtx.Unlock()

	ra := lbnet.RtAttr{rm.Protocol, rm.Flags, false, rm.LinkIndex}
	if rm.Gw != nil {
		rna := []lbnet.RtNhAttr{{rm.Gw, rm.LinkIndex}}
		ret, err = na.zr.Rt.RtAdd(rm.Dst, lbnet.RootZone, ra, rna)
	} else {
		ret, err = na.zr.Rt.RtAdd(rm.Dst, lbnet.RootZone, ra, nil)
	}

	return ret, err
}

func (na *NetAPIStruct) NetRouteDel(rm *cmn.RouteMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.Rt.RtDelete(rm.Dst, lbnet.RootZone)
	return ret, err
}

func (na *NetAPIStruct) NetFdbAdd(fm *cmn.FdbMod) (int, error) {
	na.mtx.Lock()
	defer na.mtx.Unlock()
	fdbKey := lbnet.FdbKey{MacAddr: fm.MacAddr, BridgeID: fm.BridgeID}
	fdbAttr := lbnet.FdbAttr{Oif: fm.Dev, Dst: fm.Dst, FdbType: fm.Type}
	ret, err := na.zr.L2.L2FdbAdd(fdbKey, fdbAttr)
	return ret, err
}

func (na *NetAPIStruct) NetFdbDel(fm *cmn.FdbMod) (int, error) {
	fdbKey := lbnet.FdbKey{MacAddr: fm.MacAddr, BridgeID: fm.BridgeID}
	na.mtx.Lock()
	defer na.mtx.Unlock()

	ret, err := na.zr.L2.L2FdbDel(fdbKey)
	return ret, err
}
