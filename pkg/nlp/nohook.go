package nlp

import (
	"fmt"
	"net"
	"syscall"
	"time"

	netlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/flb/pkg/tk"
)

func AddFDBNoHook(macAddress, ifName string) int {
	var ret int
	MacAddress, err := net.ParseMAC(macAddress)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] MacAddress Parse %s Fail\n", macAddress)
		return -1
	}
	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}

	// Make Neigh
	neigh := netlink.Neigh{
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}
	err = netlink.NeighAppend(&neigh)
	if err != nil {
		fmt.Printf("err.Error(): %v\n", err.Error())
		tk.LogIt(tk.LogWarning, "[NLP] FDB added Fail\n")
		return -1
	}
	return ret
}

func DelFDBNoHook(macAddress, ifName string) int {
	var ret int
	MacAddress, err := net.ParseMAC(macAddress)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}

	// Make Neigh
	neigh := netlink.Neigh{
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}
	err = netlink.NeighDel(&neigh)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] FDB delete Fail\n")
		return -1
	}
	return ret
}

func AddNeighNoHook(address, ifName, macAddress string) int {
	var ret int
	Address := net.ParseIP(address)

	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	MacAddress, err := net.ParseMAC(macAddress)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	// Make Neigh
	neigh := netlink.Neigh{
		IP:           Address,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
	}

	err = netlink.NeighAdd(&neigh)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Neighbor added Fail\n")
		return -1
	}
	return ret
}

func DelNeighNoHook(address, ifName string) int {
	var ret int
	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	Address := net.ParseIP(address)

	// Make Neigh
	neigh := netlink.Neigh{
		IP:        Address,
		LinkIndex: IfName.Attrs().Index,
	}
	err = netlink.NeighDel(&neigh)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Neighbor delete Fail\n")
		return -1
	}
	return ret
}

func AddVLANNoHook(vlanid int) int {
	var ret int
	// Check Vlan interface has been added.
	// Vlan Name : vlan$vlanid (vlan10, vlan100...)
	VlanName := fmt.Sprintf("vlan%d", vlanid)
	_, err := netlink.LinkByName(VlanName)
	if err != nil {
		newBr := &netlink.Bridge{
			LinkAttrs: netlink.LinkAttrs{
				Name: VlanName,
				MTU:  9000, // Static value for VxLAN
			},
		}
		if err := netlink.LinkAdd(newBr); err != nil {
			tk.LogIt(tk.LogWarning, "[NLP] Vlan Bridge added Fail\n")
			ret = -1
		}
		netlink.LinkSetUp(newBr)
	}
	return ret
}

func DelVLANNoHook(vlanid int) int {
	var ret int
	VlanName := fmt.Sprintf("vlan%d", vlanid)
	vlanLink, err := netlink.LinkByName(VlanName)
	if err != nil {
		ret = -1
		tk.LogIt(tk.LogWarning, "[NLP] Vlan Bridge get Fail: %s\n", err.Error())
	}
	err = netlink.LinkSetDown(vlanLink)
	if err != nil {
		ret = -1
		tk.LogIt(tk.LogWarning, "[NLP] Vlan Bridge Link Down Fail: %s\n", err.Error())
	}
	err = netlink.LinkDel(vlanLink)
	if err != nil {
		ret = -1
		tk.LogIt(tk.LogWarning, "[NLP] Vlan Bridge delete Fail: %s\n", err.Error())
	}

	return ret
}

func AddVLANMemberNoHook(vlanid int, intfName string, tagged bool) int {
	var ret int
	var VlanDevName string
	// Check Vlan interface has been added.
	VlanBridgeName := fmt.Sprintf("vlan%d", vlanid)
	VlanLink, err := netlink.LinkByName(VlanBridgeName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Vlan Bridge added Fail\n")
		return 404
	}
	ParentInterface, err := netlink.LinkByName(intfName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Parent interface finding Fail\n")
		return 404
	}
	if tagged {
		VlanDevName = fmt.Sprintf("%s.%d", intfName, vlanid)
		VlanDev := &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        VlanDevName,
				ParentIndex: ParentInterface.Attrs().Index,
			},
			VlanId: vlanid,
		}
		if err := netlink.LinkAdd(VlanDev); err != nil {
			tk.LogIt(tk.LogWarning, "failed to create VlanDev: [ %v ] with the error: %s", VlanDev, err)
			ret = -1
		}
	} else {
		VlanDevName = intfName
	}

	VlanDevNonPointer, _ := netlink.LinkByName(VlanDevName)
	netlink.LinkSetUp(VlanDevNonPointer)
	err = netlink.LinkSetMaster(VlanDevNonPointer, VlanLink)
	if err != nil {
		tk.LogIt(tk.LogWarning, "failed to master: [ %v ] with the error: %s", VlanDevNonPointer, err)
		ret = -1
	}

	return ret
}

func DelVLANMemberNoHook(vlanid int, intfName string, tagged bool) int {
	var ret int
	var VlanDevName string
	VlanName := fmt.Sprintf("vlan%d", vlanid)
	_, err := netlink.LinkByName(VlanName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Vlan Bridge finding Fail\n")
		return 404
	}
	_, err = netlink.LinkByName(intfName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Parent interface finding Fail\n")
		return 404
	}
	if tagged {
		VlanDevName = fmt.Sprintf("%s.%d", intfName, vlanid)
	} else {
		VlanDevName = intfName
	}
	VlanDevNonPointer, err := netlink.LinkByName(VlanDevName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Vlan interface finding Fail\n")
		return 404
	}
	err = netlink.LinkSetNoMaster(VlanDevNonPointer)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] No master fail \n")
	}
	if tagged {
		netlink.LinkDel(VlanDevNonPointer)
	}
	return ret
}

func AddVxLANBridgeNoHook(vxlanid int, epIntfName string) int {
	var ret int
	// Check Vlan interface has been added.
	VxlanBridgeName := fmt.Sprintf("vxlan%d", vxlanid)
	_, err := netlink.LinkByName(VxlanBridgeName)
	if err != nil {

		EndpointInterface, err := netlink.LinkByName(epIntfName)
		if err != nil {
			tk.LogIt(tk.LogWarning, "[NLP] Endpoint interface finding Fail\n")
			return 404
		}
		LocalIPs, err := netlink.AddrList(EndpointInterface, netlink.FAMILY_V4)
		if err != nil || len(LocalIPs) == 0 {
			tk.LogIt(tk.LogWarning, "[NLP] Endpoint interface dosen't have Local IP address\n")
			return 403
		}
		VxlanDev := &netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{
				Name: VxlanBridgeName,
				MTU:  9000, // Static Value for Vxlan in fLB
			},
			SrcAddr:      LocalIPs[0].IP,
			VtepDevIndex: EndpointInterface.Attrs().Index,
			VxlanId:      vxlanid,
			Port:         4789, // VxLAN default port
		}
		if err := netlink.LinkAdd(VxlanDev); err != nil {
			tk.LogIt(tk.LogWarning, "failed to create VxlanDev: [ %v ] with the error: %s", VxlanDev, err)
			ret = -1
		}
		time.Sleep(1 * time.Second)
		VxlanDevNonPointer, err := netlink.LinkByName(VxlanBridgeName)
		if err != nil {
			tk.LogIt(tk.LogWarning, "[NLP] Vxlan Interface create fail: %s\n", err.Error())
			return -1
		}
		netlink.LinkSetUp(VxlanDevNonPointer)

	} else {
		tk.LogIt(tk.LogWarning, "[NLP] Vxlan Bridge Already exists\n")
		return 409
	}

	return ret
}

func DelVxLANNoHook(vxlanid int) int {
	var ret int
	VxlanName := fmt.Sprintf("vxlan%d", vxlanid)
	vxlanLink, err := netlink.LinkByName(VxlanName)
	if err != nil {
		ret = -1
		tk.LogIt(tk.LogWarning, "[NLP] Vxlan Bridge get Fail:%s\n", err.Error())
	}
	err = netlink.LinkSetDown(vxlanLink)
	if err != nil {
		ret = -1
		tk.LogIt(tk.LogWarning, "[NLP] Vxlan Bridge Link Down Fail:%s\n", err.Error())
	}
	err = netlink.LinkDel(vxlanLink)
	if err != nil {
		ret = -1
		tk.LogIt(tk.LogWarning, "[NLP] Vxlan Bridge delete Fail:%s\n", err.Error())
	}

	return ret
}

func GetVxLANPeerNoHook() (map[int][]string, error) {
	ret := map[int][]string{}
	links, err := netlink.LinkList()
	if err != nil {
		tk.LogIt(tk.LogError, "[NLP] Error in getting device info(%v)\n", err)
		return nil, err
	}

	for _, link := range links {
		if link.Type() == "vxlan" {
			neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_BRIDGE)
			if err != nil {
				tk.LogIt(tk.LogError, "[NLP] Error getting neighbors list %v for intf %s\n",
					err, link.Attrs().Name)
				return nil, err
			}
			for _, neigh := range neighs {
				if neigh.IP != nil {
					ret[link.Attrs().Index] = append(ret[link.Attrs().Index], neigh.IP.String())
				}
			}
		}
	}
	return ret, nil
}

func GetFDBNoHook() ([]map[string]string, error) {
	ret := []map[string]string{}
	links, err := netlink.LinkList()
	if err != nil {
		tk.LogIt(tk.LogError, "[NLP] Error in getting device info(%v)\n", err)
		return nil, err
	}

	for _, link := range links {
		if link.Attrs().MasterIndex > 0 {
			fdbs, err := netlink.NeighList(link.Attrs().Index, unix.AF_BRIDGE)
			if err != nil {
				tk.LogIt(tk.LogError, "[NLP] Error getting fdb list %v for intf %s\n",
					err, link.Attrs().Name)
				return nil, err
			}
			for _, fdb := range fdbs {
				tmpRet := map[string]string{}
				tmpRet["macAddress"] = fdb.HardwareAddr.String()
				tmpRet["dev"] = link.Attrs().Name
				ret = append(ret, tmpRet)
			}
		}
	}
	return ret, nil
}

func AddVxLANPeerNoHook(vxlanid int, PeerIP string) int {
	var ret int
	MacAddress, _ := net.ParseMAC("00:00:00:00:00:00")
	ifName := fmt.Sprintf("vxlan%d", vxlanid)
	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] VxLAN %s find Fail\n", ifName)
		return -1
	}
	peerIP := net.ParseIP(PeerIP)
	// Make Peer
	Peer := netlink.Neigh{
		IP:           peerIP,
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}
	err = netlink.NeighAppend(&Peer)
	if err != nil {
		fmt.Printf("err.Error(): %v\n", err.Error())
		tk.LogIt(tk.LogWarning, "[NLP] VxLAN Peer added Fail\n")
		return -1
	}
	return ret
}

func DelVxLANPeerNoHook(vxlanid int, PeerIP string) int {
	var ret int
	MacAddress, _ := net.ParseMAC("00:00:00:00:00:00")
	ifName := fmt.Sprintf("vxlan%d", vxlanid)
	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] VxLAN %s find Fail\n", ifName)
		return -1
	}
	peerIP := net.ParseIP(PeerIP)
	// Make Peer
	Peer := netlink.Neigh{
		IP:           peerIP,
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}

	err = netlink.NeighDel(&Peer)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] VxLAN Peer delete Fail\n")
		return -1
	}
	return ret
}

func AddAddrNoHook(address, ifName string) int {
	var ret int
	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	Address, err := netlink.ParseAddr(address)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] IPv4 Address %s Parse Fail\n", address)
		return -1
	}
	err = netlink.AddrAdd(IfName, Address)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] IPv4 Address %v Port %v added Fail\n", address, ifName)
		return -1
	}
	return ret
}

func DelAddrNoHook(address, ifName string) int {
	var ret int
	IfName, err := netlink.LinkByName(ifName)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	Address, err := netlink.ParseAddr(address)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] IPv4 Address %s Parse Fail\n", address)
		return -1
	}
	err = netlink.AddrDel(IfName, Address)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[NLP] IPv4 Address %v Port %v delete Fail\n", address, ifName)
		return -1
	}
	return ret
}

func AddRouteNoHook(DestinationIPNet, gateway string) int {
	var ret int
	var route netlink.Route
	_, Ipnet, err := net.ParseCIDR(DestinationIPNet)
	if err != nil {
		return -1
	}
	Gw := net.ParseIP(gateway)
	route.Dst = Ipnet
	route.Gw = Gw
	err = netlink.RouteAdd(&route)
	if err != nil {
		return -1
	}
	return ret
}

func DelRouteNoHook(DestinationIPNet string) int {
	var ret int
	var route netlink.Route
	_, Ipnet, err := net.ParseCIDR(DestinationIPNet)
	if err != nil {
		return -1
	}
	route.Dst = Ipnet
	err = netlink.RouteDel(&route)
	if err != nil {
		return -1
	}
	return ret
}
