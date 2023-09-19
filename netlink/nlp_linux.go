package netlink

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	nlf "github.com/flomesh-io/flb/pkg/netlink"
	nlp "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	IfOperUnknown uint8 = iota
	IfOperNotPresent
	IfOperDown
	IfOperLowerLayerDown
	IfOperTesting
	IfOperDormant
	IfOperUp
)

type AddrUpdateCh struct {
	FromAddrUpdateCh   chan nlp.AddrUpdate
	FromAddrUpdateDone chan struct{}
}
type LinkUpdateCh struct {
	FromLinkUpdateCh   chan nlp.LinkUpdate
	FromLinkUpdateDone chan struct{}
}
type NeighUpdateCh struct {
	FromNeighUpdateCh   chan nlp.NeighUpdate
	FromNeighUpdateDone chan struct{}
}
type RouteUpdateCh struct {
	FromRouteUpdateCh   chan nlp.RouteUpdate
	FromRouteUpdateDone chan struct{}
}

const (
	IfTypeReal uint8 = iota
	IfTypeSubIntf
	IfTypeBond
	IfTypeBridge
	IfTypeVxlan
)

type Intf struct {
	dev            string
	itype          int
	state          bool
	configApplied  bool
	needRouteApply bool
}

type NlH struct {
	AddrUpdateCh
	LinkUpdateCh
	NeighUpdateCh
	RouteUpdateCh
	IMap map[string]Intf
}

func applyAllConfig(name string) bool {
	command := "fsmxlbc apply --per-intf " + name + " -c /etc/fsmxlb/ipconfig/"
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
		return false
	}
	fmt.Printf("%v\n", string(output))
	return true
}

func applyLoadBalancerConfig() bool {
	var resp struct {
		Attr []nlf.LbRuleMod `json:"lbAttr"`
	}
	byteBuf, err := ioutil.ReadFile("/etc/fsmxlb/lbconfig.txt")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	// Unmashal to Json
	if err := json.Unmarshal(byteBuf, &resp); err != nil {
		fmt.Printf("Error: Failed to unmarshal File: (%s)\n", err.Error())
		return false
	}
	for _, lb := range resp.Attr {
		hooks.NetLbRuleAdd(&lb)
	}
	return true
}

func applySessionConfig() bool {
	var resp struct {
		Attr []nlf.SessionMod `json:"sessionAttr"`
	}
	byteBuf, err := ioutil.ReadFile("/etc/fsmxlb/sessionconfig.txt")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	// Unmashal to Json
	if err := json.Unmarshal(byteBuf, &resp); err != nil {
		fmt.Printf("Error: Failed to unmarshal File: (%s)\n", err.Error())
		return false
	}
	for _, session := range resp.Attr {
		hooks.NetSessionAdd(&session)
	}
	return true
}

func applyUlClConfig() bool {
	var resp struct {
		Attr []nlf.SessionUlClMod `json:"ulclAttr"`
	}
	byteBuf, err := ioutil.ReadFile("/etc/fsmxlb/sessionulclconfig.txt")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	// Unmashal to Json
	if err := json.Unmarshal(byteBuf, &resp); err != nil {
		fmt.Printf("Error: Failed to unmarshal File: (%s)\n", err.Error())
		return false
	}
	for _, ulcl := range resp.Attr {
		hooks.NetSessionUlClAdd(&ulcl)
	}
	return true
}

func applyFWConfig() bool {
	var resp struct {
		Attr []nlf.FwRuleMod `json:"fwAttr"`
	}
	byteBuf, err := ioutil.ReadFile("/etc/fsmxlb/FWconfig.txt")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	// Unmashal to Json
	if err := json.Unmarshal(byteBuf, &resp); err != nil {
		fmt.Printf("Error: Failed to unmarshal File: (%s)\n", err.Error())
		return false
	}
	for _, fw := range resp.Attr {
		hooks.NetFwRuleAdd(&fw)
	}
	return true
}

func applyEPConfig() bool {
	var resp struct {
		Attr []nlf.EndPointMod `json:"Attr"`
	}
	byteBuf, err := ioutil.ReadFile("/etc/fsmxlb/EPconfig.txt")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	// Unmashal to Json
	if err := json.Unmarshal(byteBuf, &resp); err != nil {
		fmt.Printf("Error: Failed to unmarshal File: (%s)\n", err.Error())
		return false
	}
	for _, ep := range resp.Attr {
		hooks.NetEpHostAdd(&ep)
	}
	return true
}

func applyRoutes(name string) {
	fmt.Printf("[NLP] Applying Route Config for %s \n", name)
	command := "fsmxlbc apply --per-intf " + name + " -r -c /etc/fsmxlb/ipconfig/"
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%v\n", string(output))
}

func applyConfigMap(name string, state bool, add bool) {
	var configApplied bool
	var needRouteApply bool
	if _, err := os.Stat("/etc/fsmxlb/ipconfig/"); errors.Is(err, os.ErrNotExist) {
		return
	}
	if add {
		if _, ok := nNl.IMap[name]; ok {
			configApplied = nNl.IMap[name].configApplied
			if !nNl.IMap[name].configApplied {
				fmt.Printf("[NLP] Applying Config for %s \n", name)
				if applyAllConfig(name) == true {
					configApplied = true
					fmt.Printf("[NLP] Applied Config for %s \n", name)
				} else {
					configApplied = false
					fmt.Printf("[NLP] Applied Config for %s - FAILED\n", name)
				}
				nNl.IMap[name] = Intf{dev: name, state: state, configApplied: configApplied, needRouteApply: false}
			} else if nNl.IMap[name].state != state {
				needRouteApply = nNl.IMap[name].needRouteApply
				if state && nNl.IMap[name].needRouteApply {
					applyRoutes(name)
					needRouteApply = false
				} else if !state {
					needRouteApply = true
					fmt.Printf("[NLP] Route Config for %s will be tried\n", name)
				}
				nNl.IMap[name] = Intf{dev: name, state: state, configApplied: configApplied, needRouteApply: needRouteApply}
			}
			fmt.Printf("[NLP] ConfigMap for %s : %v \n", name, nNl.IMap[name])
		} else {
			fmt.Printf("[NLP] Applying Config for %s \n", name)
			if applyAllConfig(name) == true {
				configApplied = true
				fmt.Printf("[NLP] Applied Config for %s \n", name)
			} else {
				configApplied = false
				fmt.Printf("[NLP] Applied Config for %s - FAILED\n", name)
			}
			nNl.IMap[name] = Intf{dev: name, state: state, configApplied: configApplied}
		}
	} else {
		if _, ok := nNl.IMap[name]; ok {
			delete(nNl.IMap, name)
		}
	}
}

func AddFDBNoHook(macAddress, ifName string) int {
	var ret int
	MacAddress, err := net.ParseMAC(macAddress)
	if err != nil {
		fmt.Printf("[NLP] MacAddress Parse %s Fail\n", macAddress)
		return -1
	}
	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}

	// Make Neigh
	neigh := nlp.Neigh{
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}
	err = nlp.NeighAppend(&neigh)
	if err != nil {
		fmt.Printf("err.Error(): %v\n", err.Error())
		fmt.Printf("[NLP] FDB added Fail\n")
		return -1
	}
	return ret
}

func DelFDBNoHook(macAddress, ifName string) int {
	var ret int
	MacAddress, err := net.ParseMAC(macAddress)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}

	// Make Neigh
	neigh := nlp.Neigh{
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}
	err = nlp.NeighDel(&neigh)
	if err != nil {
		fmt.Printf("[NLP] FDB delete Fail\n")
		return -1
	}
	return ret
}

func AddNeighNoHook(address, ifName, macAddress string) int {
	var ret int
	Address := net.ParseIP(address)

	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	MacAddress, err := net.ParseMAC(macAddress)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	// Make Neigh
	neigh := nlp.Neigh{
		IP:           Address,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
	}

	err = nlp.NeighAdd(&neigh)
	if err != nil {
		fmt.Printf("[NLP] Neighbor added Fail\n")
		return -1
	}
	return ret
}

func DelNeighNoHook(address, ifName string) int {
	var ret int
	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	Address := net.ParseIP(address)

	// Make Neigh
	neigh := nlp.Neigh{
		IP:        Address,
		LinkIndex: IfName.Attrs().Index,
	}
	err = nlp.NeighDel(&neigh)
	if err != nil {
		fmt.Printf("[NLP] Neighbor delete Fail\n")
		return -1
	}
	return ret
}

func AddVLANNoHook(vlanid int) int {
	var ret int
	// Check Vlan interface has been added.
	// Vlan Name : vlan$vlanid (vlan10, vlan100...)
	VlanName := fmt.Sprintf("vlan%d", vlanid)
	_, err := nlp.LinkByName(VlanName)
	if err != nil {
		newBr := &nlp.Bridge{
			LinkAttrs: nlp.LinkAttrs{
				Name: VlanName,
				MTU:  9000, // Static value for VxLAN
			},
		}
		if err := nlp.LinkAdd(newBr); err != nil {
			fmt.Printf("[NLP] Vlan Bridge added Fail\n")
			ret = -1
		}
		nlp.LinkSetUp(newBr)
	}
	return ret
}

func DelVLANNoHook(vlanid int) int {
	var ret int
	VlanName := fmt.Sprintf("vlan%d", vlanid)
	vlanLink, err := nlp.LinkByName(VlanName)
	if err != nil {
		ret = -1
		fmt.Printf("[NLP] Vlan Bridge get Fail\n", err.Error())
	}
	err = nlp.LinkSetDown(vlanLink)
	if err != nil {
		ret = -1
		fmt.Printf("[NLP] Vlan Bridge Link Down Fail\n", err.Error())
	}
	err = nlp.LinkDel(vlanLink)
	if err != nil {
		ret = -1
		fmt.Printf("[NLP] Vlan Bridge delete Fail\n", err.Error())
	}

	return ret
}

func AddVLANMemberNoHook(vlanid int, intfName string, tagged bool) int {
	var ret int
	var VlanDevName string
	// Check Vlan interface has been added.
	VlanBridgeName := fmt.Sprintf("vlan%d", vlanid)
	VlanLink, err := nlp.LinkByName(VlanBridgeName)
	if err != nil {
		fmt.Printf("[NLP] Vlan Bridge added Fail\n")
		return 404
	}
	ParentInterface, err := nlp.LinkByName(intfName)
	if err != nil {
		fmt.Printf("[NLP] Parent interface finding Fail\n")
		return 404
	}
	if tagged {
		VlanDevName = fmt.Sprintf("%s.%d", intfName, vlanid)
		VlanDev := &nlp.Vlan{
			LinkAttrs: nlp.LinkAttrs{
				Name:        VlanDevName,
				ParentIndex: ParentInterface.Attrs().Index,
			},
			VlanId: vlanid,
		}
		if err := nlp.LinkAdd(VlanDev); err != nil {
			fmt.Printf("failed to create VlanDev: [ %v ] with the error: %s", VlanDev, err)
			ret = -1
		}
	} else {
		VlanDevName = intfName
	}

	VlanDevNonPointer, _ := nlp.LinkByName(VlanDevName)
	nlp.LinkSetUp(VlanDevNonPointer)
	err = nlp.LinkSetMaster(VlanDevNonPointer, VlanLink)
	if err != nil {
		fmt.Printf("failed to master: [ %v ] with the error: %s", VlanDevNonPointer, err)
		ret = -1
	}

	return ret
}

func DelVLANMemberNoHook(vlanid int, intfName string, tagged bool) int {
	var ret int
	var VlanDevName string
	VlanName := fmt.Sprintf("vlan%d", vlanid)
	_, err := nlp.LinkByName(VlanName)
	if err != nil {
		fmt.Printf("[NLP] Vlan Bridge finding Fail\n")
		return 404
	}
	_, err = nlp.LinkByName(intfName)
	if err != nil {
		fmt.Printf("[NLP] Parent interface finding Fail\n")
		return 404
	}
	if tagged {
		VlanDevName = fmt.Sprintf("%s.%d", intfName, vlanid)
	} else {
		VlanDevName = intfName
	}
	VlanDevNonPointer, err := nlp.LinkByName(VlanDevName)
	if err != nil {
		fmt.Printf("[NLP] Vlan interface finding Fail\n")
		return 404
	}
	err = nlp.LinkSetNoMaster(VlanDevNonPointer)
	if err != nil {
		fmt.Printf("[NLP] No master fail \n")
	}
	if tagged {
		nlp.LinkDel(VlanDevNonPointer)
	}
	return ret
}

func AddVxLANBridgeNoHook(vxlanid int, epIntfName string) int {
	var ret int
	// Check Vlan interface has been added.
	VxlanBridgeName := fmt.Sprintf("vxlan%d", vxlanid)
	_, err := nlp.LinkByName(VxlanBridgeName)
	if err != nil {

		EndpointInterface, err := nlp.LinkByName(epIntfName)
		if err != nil {
			fmt.Printf("[NLP] Endpoint interface finding Fail\n")
			return 404
		}
		LocalIPs, err := nlp.AddrList(EndpointInterface, nlp.FAMILY_V4)
		if err != nil || len(LocalIPs) == 0 {
			fmt.Printf("[NLP] Endpoint interface dosen't have Local IP address\n")
			return 403
		}
		VxlanDev := &nlp.Vxlan{
			LinkAttrs: nlp.LinkAttrs{
				Name: VxlanBridgeName,
				MTU:  9000, // Static Value for Vxlan in fsmxlb
			},
			SrcAddr:      LocalIPs[0].IP,
			VtepDevIndex: EndpointInterface.Attrs().Index,
			VxlanId:      vxlanid,
			Port:         4789, // VxLAN default port
		}
		if err := nlp.LinkAdd(VxlanDev); err != nil {
			fmt.Printf("failed to create VxlanDev: [ %v ] with the error: %s", VxlanDev, err)
			ret = -1
		}
		time.Sleep(1 * time.Second)
		VxlanDevNonPointer, err := nlp.LinkByName(VxlanBridgeName)
		if err != nil {
			fmt.Printf("[NLP] Vxlan Interface create fail\n", err.Error())
			return -1
		}
		nlp.LinkSetUp(VxlanDevNonPointer)

	} else {
		fmt.Printf("[NLP] Vxlan Bridge Already exists\n")
		return 409
	}

	return ret
}

func DelVxLANNoHook(vxlanid int) int {
	var ret int
	VxlanName := fmt.Sprintf("vxlan%d", vxlanid)
	vxlanLink, err := nlp.LinkByName(VxlanName)
	if err != nil {
		ret = -1
		fmt.Printf("[NLP] Vxlan Bridge get Fail\n", err.Error())
	}
	err = nlp.LinkSetDown(vxlanLink)
	if err != nil {
		ret = -1
		fmt.Printf("[NLP] Vxlan Bridge Link Down Fail\n", err.Error())
	}
	err = nlp.LinkDel(vxlanLink)
	if err != nil {
		ret = -1
		fmt.Printf("[NLP] Vxlan Bridge delete Fail\n", err.Error())
	}

	return ret
}

func GetVxLANPeerNoHook() (map[int][]string, error) {
	ret := map[int][]string{}
	links, err := nlp.LinkList()
	if err != nil {
		fmt.Printf("[NLP] Error in getting device info(%v)\n", err)
		return nil, err
	}

	for _, link := range links {
		if link.Type() == "vxlan" {
			neighs, err := nlp.NeighList(link.Attrs().Index, unix.AF_BRIDGE)
			if err != nil {
				fmt.Printf("[NLP] Error getting neighbors list %v for intf %s\n",
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
	links, err := nlp.LinkList()
	if err != nil {
		fmt.Printf("[NLP] Error in getting device info(%v)\n", err)
		return nil, err
	}

	for _, link := range links {
		if link.Attrs().MasterIndex > 0 {
			fdbs, err := nlp.NeighList(link.Attrs().Index, unix.AF_BRIDGE)
			if err != nil {
				fmt.Printf("[NLP] Error getting fdb list %v for intf %s\n",
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
	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] VxLAN %s find Fail\n", ifName)
		return -1
	}
	peerIP := net.ParseIP(PeerIP)
	// Make Peer
	Peer := nlp.Neigh{
		IP:           peerIP,
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}
	err = nlp.NeighAppend(&Peer)
	if err != nil {
		fmt.Printf("err.Error(): %v\n", err.Error())
		fmt.Printf("[NLP] VxLAN Peer added Fail\n")
		return -1
	}
	return ret
}

func DelVxLANPeerNoHook(vxlanid int, PeerIP string) int {
	var ret int
	MacAddress, _ := net.ParseMAC("00:00:00:00:00:00")
	ifName := fmt.Sprintf("vxlan%d", vxlanid)
	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] VxLAN %s find Fail\n", ifName)
		return -1
	}
	peerIP := net.ParseIP(PeerIP)
	// Make Peer
	Peer := nlp.Neigh{
		IP:           peerIP,
		Family:       syscall.AF_BRIDGE,
		HardwareAddr: MacAddress,
		LinkIndex:    IfName.Attrs().Index,
		State:        unix.NUD_PERMANENT,
		Flags:        unix.NTF_SELF,
	}

	err = nlp.NeighDel(&Peer)
	if err != nil {
		fmt.Printf("[NLP] VxLAN Peer delete Fail\n")
		return -1
	}
	return ret
}

func ModLink(link nlp.Link, add bool) int {
	var ifMac [6]byte
	var ret int
	var err error
	var mod string
	var vid int
	var brLink nlp.Link
	re := regexp.MustCompile("[0-9]+")

	attrs := link.Attrs()
	name := attrs.Name
	idx := attrs.Index

	if len(attrs.HardwareAddr) > 0 {
		copy(ifMac[:], attrs.HardwareAddr[:6])
	}

	mtu := attrs.MTU
	linkState := attrs.Flags&net.FlagUp == 1
	state := uint8(attrs.OperState) != nlp.OperDown
	if add {
		mod = "ADD"
	} else {
		mod = "DELETE"
	}
	fmt.Printf("[NLP] %s Device %v mac(%v) attrs(%v) info recvd\n", mod, name, ifMac, attrs)

	if _, ok := link.(*nlp.Bridge); ok {

		vid, _ = strconv.Atoi(strings.Join(re.FindAllString(name, -1), " "))
		// Dirty hack to support docker0 bridge
		if vid == 0 && name == "docker0" {
			vid = 4090
		}
		if add {
			ret, err = hooks.NetVlanAdd(&nlf.VlanMod{Vid: vid, Dev: name, LinkIndex: idx,
				MacAddr: ifMac, Link: linkState, State: state, Mtu: mtu, TunID: 0})
		} else {
			ret, err = hooks.NetVlanDel(&nlf.VlanMod{Vid: vid})
		}

		if err != nil {
			fmt.Printf("[NLP] Bridge %v, %d, %v, %v, %v %s failed\n", name, vid, ifMac, state, mtu, mod)
			fmt.Println(err)
		} else {
			fmt.Printf("[NLP] Bridge %v, %d, %v, %v, %v %s [OK]\n", name, vid, ifMac, state, mtu, mod)
		}

		if (add && (err != nil)) || !add {
			applyConfigMap(name, state, add)
		}
	}

	/* Get bridge detail */
	if attrs.MasterIndex > 0 {
		brLink, err = nlp.LinkByIndex(attrs.MasterIndex)
		if err != nil {
			fmt.Println(err)
			return -1
		}
		vid, _ = strconv.Atoi(strings.Join(re.FindAllString(brLink.Attrs().Name, -1), " "))
		// Dirty hack to support docker bridge
		if vid == 0 && brLink.Attrs().Name == "docker0" {
			vid = 4090
		}
	}

	master := ""

	if attrs.MasterIndex > 0 {
		/* Tagged Vlan port */
		if strings.Contains(name, ".") {
			/* Currently, Sub-interfaces can only be part of bridges */
			pname := strings.Split(name, ".")
			if add {
				ret, err = hooks.NetVlanPortAdd(&nlf.VlanPortMod{Vid: vid, Dev: pname[0], Tagged: true})
			} else {
				ret, err = hooks.NetVlanPortDel(&nlf.VlanPortMod{Vid: vid, Dev: pname[0], Tagged: true})
			}
			if err != nil {
				fmt.Printf("[NLP] TVlan Port %v, v(%v), %v, %v, %v %s failed\n", name, vid, ifMac, state, mtu, mod)
				fmt.Println(err)
			} else {
				fmt.Printf("[NLP] TVlan Port %v, v(%v), %v, %v, %v %s OK\n", name, vid, ifMac, state, mtu, mod)
			}
			applyConfigMap(name, state, add)
			return ret
		} else {
			mif, err := nlp.LinkByIndex(attrs.MasterIndex)
			if err != nil {
				fmt.Println(err)
				return -1
			} else {
				if _, ok := mif.(*nlp.Bond); ok {
					master = mif.Attrs().Name
				}
			}
		}
	}

	/* Physical port/ Bond/ VxLAN */

	real := ""
	pType := nlf.PortReal
	tunId := 0
	tunSrc := net.IPv4zero
	tunDst := net.IPv4zero

	if strings.Contains(name, "ipsec") || strings.Contains(name, "vti") {
		pType = nlf.PortVti
	} else if strings.Contains(name, "wg") {
		pType = nlf.PortWg
	}

	if vxlan, ok := link.(*nlp.Vxlan); ok {
		pType = nlf.PortVxlanBr
		tunId = vxlan.VxlanId
		uif, err := nlp.LinkByIndex(vxlan.VtepDevIndex)
		if err != nil {
			fmt.Println(err)
			return -1
		}
		real = uif.Attrs().Name
		fmt.Printf("[NLP] Port %v, uif %v %s\n", name, real, mod)
	} else if _, ok := link.(*nlp.Bond); ok {
		pType = nlf.PortBond
		fmt.Printf("[NLP] Bond %v, %s\n", name, mod)
	} else if iptun, ok := link.(*nlp.Iptun); ok {
		pType = nlf.PortIPTun
		if iptun.Remote == nil || iptun.Local == nil {
			return -1
		}

		if iptun.Remote.IsUnspecified() || iptun.Local.IsUnspecified() {
			return -1
		}
		tunId = 1 // Just needed internally
		tunDst = iptun.Remote
		tunSrc = iptun.Local
		fmt.Printf("[NLP] IPTun %v (%s:%s), %s\n", name, tunSrc.String(), tunDst.String(), mod)
	} else if master != "" {
		pType = nlf.PortBondSif
	}

	if add {
		ret, err = hooks.NetPortAdd(&nlf.PortMod{Dev: name, LinkIndex: idx, Ptype: pType, MacAddr: ifMac,
			Link: linkState, State: state, Mtu: mtu, Master: master, Real: real,
			TunID: tunId, TunDst: tunDst, TunSrc: tunSrc})
		if err != nil {
			fmt.Printf("[NLP] Port %v, %v, %v, %v add failed\n", name, ifMac, state, mtu)
			fmt.Println(err)
		} else {
			fmt.Printf("[NLP] Port %v, %v, %v, %v add [OK]\n", name, ifMac, state, mtu)
		}
		applyConfigMap(name, state, add)
	} else if attrs.MasterIndex == 0 {
		ret, err = hooks.NetPortDel(&nlf.PortMod{Dev: name, Ptype: pType})
		if err != nil {
			fmt.Printf("[NLP] Port %v, %v, %v, %v delete failed\n", name, ifMac, state, mtu)
			fmt.Println(err)
		} else {
			fmt.Printf("[NLP] Port %v, %v, %v, %v delete [OK]\n", name, ifMac, state, mtu)
		}

		applyConfigMap(name, state, add)
		return ret
	}

	/* Untagged vlan ports */
	if attrs.MasterIndex > 0 && master == "" {
		if add {
			ret, err = hooks.NetVlanPortAdd(&nlf.VlanPortMod{Vid: vid, Dev: name, Tagged: false})
		} else {
			ret, err = hooks.NetVlanPortDel(&nlf.VlanPortMod{Vid: vid, Dev: name, Tagged: false})
		}
		if err != nil {
			fmt.Printf("[NLP] Vlan(%v) Port %v, %v, %v, %v %s failed\n", vid, name, ifMac, state, mtu, mod)
			fmt.Println(err)
		} else {
			fmt.Printf("[NLP] Vlan(%v) Port %v, %v, %v, %v %s [OK]\n", vid, name, ifMac, state, mtu, mod)
		}
		if (add && (err != nil)) || !add {
			applyConfigMap(name, state, add)
		}
	}
	return ret
}

func AddAddr(addr nlp.Addr, link nlp.Link) int {
	var ret int

	attrs := link.Attrs()
	name := attrs.Name
	ipStr := (addr.IPNet).String()

	ret, err := hooks.NetAddrAdd(&nlf.IpAddrMod{Dev: name, IP: ipStr})
	if err != nil {
		fmt.Printf("[NLP] IPv4 Address %v Port %v failed %v\n", ipStr, name, err)
		ret = -1
	} else {
		fmt.Printf("[NLP] IPv4 Address %v Port %v added\n", ipStr, name)
	}
	return ret
}

func AddAddrNoHook(address, ifName string) int {
	var ret int
	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	Address, err := nlp.ParseAddr(address)
	if err != nil {
		fmt.Printf("[NLP] IPv4 Address %s Parse Fail\n", address)
		return -1
	}
	err = nlp.AddrAdd(IfName, Address)
	if err != nil {
		fmt.Printf("[NLP] IPv4 Address %v Port %v added Fail\n", address, ifName)
		return -1
	}
	return ret
}

func DelAddrNoHook(address, ifName string) int {
	var ret int
	IfName, err := nlp.LinkByName(ifName)
	if err != nil {
		fmt.Printf("[NLP] Port %s find Fail\n", ifName)
		return -1
	}
	Address, err := nlp.ParseAddr(address)
	if err != nil {
		fmt.Printf("[NLP] IPv4 Address %s Parse Fail\n", address)
		return -1
	}
	err = nlp.AddrDel(IfName, Address)
	if err != nil {
		fmt.Printf("[NLP] IPv4 Address %v Port %v delete Fail\n", address, ifName)
		return -1
	}
	return ret
}

func AddNeigh(neigh nlp.Neigh, link nlp.Link) int {
	var ret int
	var brId int
	var mac [6]byte
	var brMac [6]byte
	var err error
	var dst net.IP
	var ftype int

	re := regexp.MustCompile("[0-9]+")
	attrs := link.Attrs()
	name := attrs.Name

	if len(neigh.HardwareAddr) == 0 {
		return -1
	}
	copy(mac[:], neigh.HardwareAddr[:6])

	if neigh.Family == unix.AF_INET ||
		neigh.Family == unix.AF_INET6 {
		ret, err = hooks.NetNeighAdd(&nlf.NeighMod{IP: neigh.IP, LinkIndex: neigh.LinkIndex,
			State:        neigh.State,
			HardwareAddr: neigh.HardwareAddr})
		if err != nil {
			fmt.Printf("[NLP] NH %v mac %v dev %v add failed %v\n", neigh.IP.String(), mac,
				name, err)

		} /*else {
			fmt.Printf("[NLP] NH %v mac %v dev %v added\n", neigh.IP.String(), mac, name)
		} */
	} else if neigh.Family == unix.AF_BRIDGE {

		if len(neigh.HardwareAddr) == 0 {
			return -1
		}
		copy(mac[:], neigh.HardwareAddr[:6])

		if neigh.Vlan == 1 {
			/*FDB comes with vlan 1 also */
			return 0
		}

		if mac[0]&0x01 == 1 || mac[0] == 0 {
			/* Multicast MAC or ZERO address --- IGNORED */
			return 0
		}

		if neigh.MasterIndex > 0 {
			brLink, err := nlp.LinkByIndex(neigh.MasterIndex)
			if err != nil {
				fmt.Println(err)
				return -1
			}

			copy(brMac[:], brLink.Attrs().HardwareAddr[:6])
			if mac == brMac {
				/*Same as bridge mac --- IGNORED */
				return 0
			}
			brId, _ = strconv.Atoi(strings.Join(re.FindAllString(brLink.Attrs().Name, -1), " "))
		}

		if vxlan, ok := link.(*nlp.Vxlan); ok {
			/* Interested in only VxLAN FDB */
			if len(neigh.IP) > 0 && (neigh.MasterIndex == 0) {
				dst = neigh.IP
				brId = vxlan.VxlanId
				ftype = nlf.FdbTun
			} else {
				fmt.Printf("[NLP] L2fdb %v brId %v dst %v dev %v IGNORED\n", mac[:], brId, dst, name)
				return 0
			}
		} else {
			dst = net.ParseIP("0.0.0.0")
			ftype = nlf.FdbVlan
		}

		ret, err = hooks.NetFdbAdd(&nlf.FdbMod{MacAddr: mac, BridgeID: brId, Dev: name, Dst: dst,
			Type: ftype})
		if err != nil {
			fmt.Printf("[NLP] L2fdb %v brId %v dst %v dev %v add failed\n", mac[:], brId, dst, name)
		} else {
			fmt.Printf("[NLP] L2fdb %v brId %v dst %v dev %v added\n", mac[:], brId, dst, name)
		}
	}

	return ret

}

func DelNeigh(neigh nlp.Neigh, link nlp.Link) int {
	var ret int
	var mac [6]byte
	var brMac [6]byte
	var brId int
	var err error
	var dst net.IP

	re := regexp.MustCompile("[0-9]+")
	attrs := link.Attrs()
	name := attrs.Name

	if neigh.Family == unix.AF_INET ||
		neigh.Family == unix.AF_INET6 {

		ret, err = hooks.NetNeighDel(&nlf.NeighMod{IP: neigh.IP})
		if err != nil {
			fmt.Printf("[NLP] NH  %v %v del failed\n", neigh.IP.String(), name)
			ret = -1
		} else {
			fmt.Printf("[NLP] NH %v %v deleted\n", neigh.IP.String(), name)
		}

	} else {

		if neigh.Vlan == 1 {
			/*FDB comes with vlan 1 also */
			return 0
		}
		if len(neigh.HardwareAddr) == 0 {
			return -1
		}

		copy(mac[:], neigh.HardwareAddr[:6])
		if mac[0]&0x01 == 1 || mac[0] == 0 {
			/* Multicast MAC or ZERO address --- IGNORED */
			return 0
		}

		if neigh.MasterIndex > 0 {
			brLink, err := nlp.LinkByIndex(neigh.MasterIndex)
			if err != nil {
				fmt.Println(err)
				return -1
			}

			if len(brLink.Attrs().HardwareAddr) != 6 {
				brMac = [6]byte{0, 0, 0, 0, 0, 0}
			} else {
				copy(brMac[:], brLink.Attrs().HardwareAddr[:6])
			}

			if mac == brMac {
				/*Same as bridge mac --- IGNORED */
				return 0
			}
			brId, _ = strconv.Atoi(strings.Join(re.FindAllString(brLink.Attrs().Name, -1), " "))
		}

		if vxlan, ok := link.(*nlp.Vxlan); ok {
			/* Interested in only VxLAN FDB */
			if len(neigh.IP) > 0 && (neigh.MasterIndex == 0) {
				dst = neigh.IP
				brId = vxlan.VxlanId
			} else {
				return 0
			}
		} else {
			dst = net.ParseIP("0.0.0.0")
		}

		ret, err = hooks.NetFdbDel(&nlf.FdbMod{MacAddr: mac, BridgeID: brId})
		if err != nil {
			fmt.Printf("[NLP] L2fdb %v brId %v dst %s dev %v delete failed %v\n", mac[:], brId, dst, name, err)
			ret = -1
		} else {
			fmt.Printf("[NLP] L2fdb %v brId %v dst %s dev %v deleted\n", mac[:], brId, dst, name)
		}
	}
	return ret
}

func AddRoute(route nlp.Route) int {
	var ipNet net.IPNet
	if route.Dst == nil {
		r := net.IPv4(0, 0, 0, 0)
		m := net.CIDRMask(0, 32)
		r = r.Mask(m)
		ipNet = net.IPNet{IP: r, Mask: m}
	} else {
		ipNet = *route.Dst
	}
	ret, err := hooks.NetRouteAdd(&nlf.RouteMod{Protocol: int(route.Protocol), Flags: route.Flags,
		Gw: route.Gw, LinkIndex: route.LinkIndex, Dst: ipNet})
	if err != nil {
		if route.Gw != nil {
			fmt.Printf("[NLP] RT  %s via %s add failed-%s\n", ipNet.String(),
				route.Gw.String(), err)
		} else {
			fmt.Printf("[NLP] RT  %s add failed-%s\n", ipNet.String(), err)
		}
	} else {
		if route.Gw != nil {
			fmt.Printf("[NLP] RT  %s via %s added\n", ipNet.String(),
				route.Gw.String())
		} else {
			fmt.Printf("[NLP] RT  %s added\n", ipNet.String())
		}
	}

	return ret
}

func AddRouteNoHook(DestinationIPNet, gateway string) int {
	var ret int
	var route nlp.Route
	_, Ipnet, err := net.ParseCIDR(DestinationIPNet)
	if err != nil {
		return -1
	}
	Gw := net.ParseIP(gateway)
	route.Dst = Ipnet
	route.Gw = Gw
	err = nlp.RouteAdd(&route)
	if err != nil {
		return -1
	}
	return ret
}

func DelRouteNoHook(DestinationIPNet string) int {
	var ret int
	var route nlp.Route
	_, Ipnet, err := net.ParseCIDR(DestinationIPNet)
	if err != nil {
		return -1
	}
	route.Dst = Ipnet
	err = nlp.RouteDel(&route)
	if err != nil {
		return -1
	}
	return ret
}

func DelRoute(route nlp.Route) int {
	var ret int
	var ipNet net.IPNet
	if route.Dst == nil {
		r := net.IPv4(0, 0, 0, 0)
		m := net.CIDRMask(0, 32)
		r = r.Mask(m)
		ipNet = net.IPNet{IP: r, Mask: m}
	} else {
		ipNet = *route.Dst
	}
	ret, err := hooks.NetRouteDel(&nlf.RouteMod{Dst: ipNet})
	if err != nil {
		if route.Gw != nil {
			fmt.Printf("[NLP] RT  %s via %s delete failed-%s\n", ipNet.String(),
				route.Gw.String(), err)
		} else {
			fmt.Printf("[NLP] RT  %s delete failed-%s\n", ipNet.String(), err)
		}
	} else {
		if route.Gw != nil {
			fmt.Printf("[NLP] RT  %s via %s deleted\n", ipNet.String(),
				route.Gw.String())
		} else {
			fmt.Printf("[NLP] RT  %s deleted\n", ipNet.String())
		}
	}
	return ret
}

func LinkUpdateWorkSingle(m nlp.LinkUpdate) int {
	var ret int
	ret = ModLink(m.Link, m.Header.Type == syscall.RTM_NEWLINK)
	return ret
}

func AddrUpdateWorkSingle(m nlp.AddrUpdate) int {
	var ret int
	link, err := nlp.LinkByIndex(m.LinkIndex)
	if err != nil {
		fmt.Println(err)
		return -1
	}

	attrs := link.Attrs()
	name := attrs.Name
	if m.NewAddr {
		_, err := hooks.NetAddrAdd(&nlf.IpAddrMod{Dev: name, IP: m.LinkAddress.String()})
		if err != nil {
			fmt.Printf("[NLP] Address %v Port %v add failed\n", m.LinkAddress.String(), name)
			fmt.Println(err)
		} else {
			fmt.Printf("[NLP] Address %v Port %v added\n", m.LinkAddress.String(), name)
		}

	} else {
		_, err := hooks.NetAddrDel(&nlf.IpAddrMod{Dev: name, IP: m.LinkAddress.String()})
		if err != nil {
			fmt.Printf("[NLP] Address %v Port %v delete failed\n", m.LinkAddress.String(), name)
			fmt.Println(err)
		} else {
			fmt.Printf("[NLP] Address %v Port %v deleted\n", m.LinkAddress.String(), name)
		}
	}

	return ret
}

func NeighUpdateWorkSingle(m nlp.NeighUpdate) int {
	var ret int

	link, err := nlp.LinkByIndex(m.LinkIndex)
	if err != nil {
		fmt.Println(err)
		return -1
	}

	add := m.Type == syscall.RTM_NEWNEIGH

	if add {
		ret = AddNeigh(m.Neigh, link)
	} else {
		ret = DelNeigh(m.Neigh, link)
	}

	return ret
}

func RouteUpdateWorkSingle(m nlp.RouteUpdate) int {
	var ret int

	if m.Type == syscall.RTM_NEWROUTE {
		ret = AddRoute(m.Route)
	} else {
		ret = DelRoute(m.Route)
	}

	return ret
}

func LinkUpdateWorker(ch chan nlp.LinkUpdate, f chan struct{}) {

	for n := 0; n < nlf.LinkUpdateWorkQLen; n++ {
		select {
		case m := <-ch:
			LinkUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func AddrUpdateWorker(ch chan nlp.AddrUpdate, f chan struct{}) {

	for n := 0; n < nlf.AddrUpdateWorkqLen; n++ {
		select {
		case m := <-ch:
			AddrUpdateWorkSingle(m)
		default:
			continue
		}
	}

}

func NeighUpdateWorker(ch chan nlp.NeighUpdate, f chan struct{}) {

	for n := 0; n < nlf.NeighUpdateWorkQLen; n++ {
		select {
		case m := <-ch:
			NeighUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func RouteUpdateWorker(ch chan nlp.RouteUpdate, f chan struct{}) {

	for n := 0; n < nlf.RouteUpdateWorkQLen; n++ {
		select {
		case m := <-ch:
			RouteUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func NLWorker(nNl *NlH) {
	for { /* Single thread for reading all NL msgs in below order */
		LinkUpdateWorker(nNl.FromLinkUpdateCh, nNl.FromLinkUpdateDone)
		AddrUpdateWorker(nNl.FromAddrUpdateCh, nNl.FromAddrUpdateDone)
		NeighUpdateWorker(nNl.FromNeighUpdateCh, nNl.FromNeighUpdateDone)
		RouteUpdateWorker(nNl.FromRouteUpdateCh, nNl.FromRouteUpdateDone)
		time.Sleep(1000 * time.Millisecond)
	}
}

func GetBridges() {
	links, err := nlp.LinkList()
	if err != nil {
		return
	}
	for _, link := range links {
		switch link.(type) {
		case *nlp.Bridge:
			{
				ModLink(link, true)
			}
		}
	}
}

func NlpGet(ch chan bool) int {
	var ret int
	fmt.Printf("[NLP] Getting device info\n")

	GetBridges()

	links, err := nlp.LinkList()
	if err != nil {
		fmt.Printf("[NLP] Error in getting device info(%v)\n", err)
		ret = -1
	}

	for _, link := range links {
		ret = ModLink(link, true)

		if ret == -1 {
			continue
		}

		/* Get FDBs */
		_, ok := link.(*nlp.Vxlan)
		if link.Attrs().MasterIndex > 0 || ok {
			neighs, err := nlp.NeighList(link.Attrs().Index, unix.AF_BRIDGE)
			if err != nil {
				fmt.Printf("[NLP] Error getting neighbors list %v for intf %s\n",
					err, link.Attrs().Name)
			}

			if len(neighs) == 0 {
				fmt.Printf("[NLP] No FDBs found for intf %s\n", link.Attrs().Name)
			} else {
				for _, neigh := range neighs {
					AddNeigh(neigh, link)
				}
			}
		}

		addrs, err := nlp.AddrList(link, nlp.FAMILY_ALL)
		if err != nil {
			fmt.Printf("[NLP] Error getting address list %v for intf %s\n",
				err, link.Attrs().Name)
		}

		if len(addrs) == 0 {
			fmt.Printf("[NLP] No addresses found for intf %s\n", link.Attrs().Name)
		} else {
			for _, addr := range addrs {
				AddAddr(addr, link)
			}
		}

		neighs, err := nlp.NeighList(link.Attrs().Index, nlp.FAMILY_ALL)
		if err != nil {
			fmt.Printf("[NLP] Error getting neighbors list %v for intf %s\n",
				err, link.Attrs().Name)
		}

		if len(neighs) == 0 {
			fmt.Printf("[NLP] No neighbors found for intf %s\n", link.Attrs().Name)
		} else {
			for _, neigh := range neighs {
				AddNeigh(neigh, link)
			}
		}

		/* Get Routes */
		routes, err := nlp.RouteList(link, nlp.FAMILY_ALL)
		if err != nil {
			fmt.Printf("[NLP] Error getting route list %v\n", err)
		}

		if len(routes) == 0 {
			fmt.Printf("[NLP] No STATIC routes found for intf %s\n", link.Attrs().Name)
		} else {
			for _, route := range routes {
				AddRoute(route)
			}
		}
	}
	fmt.Printf("[NLP] nlp get done\n")
	ch <- true
	return ret
}

var nNl *NlH

func LbSessionGet(done bool) int {

	if done {

		if _, err := os.Stat("/etc/fsmxlb/EPconfig.txt"); errors.Is(err, os.ErrNotExist) {
			if err != nil {
				fmt.Printf("[NLP] No EndPoint config file : %s \n", err.Error())
			}
		} else {
			applyEPConfig()
		}
		fmt.Printf("[NLP] EndPoint done\n")

		if _, err := os.Stat("/etc/fsmxlb/lbconfig.txt"); errors.Is(err, os.ErrNotExist) {
			if err != nil {
				fmt.Printf("[NLP] No load balancer config file : %s \n", err.Error())
			}
		} else {
			applyLoadBalancerConfig()
		}

		fmt.Printf("[NLP] LoadBalancer done\n")
		if _, err := os.Stat("/etc/fsmxlb/sessionconfig.txt"); errors.Is(err, os.ErrNotExist) {
			if err != nil {
				fmt.Printf("[NLP] No Session config file : %s \n", err.Error())
			}
		} else {
			applySessionConfig()
		}

		fmt.Printf("[NLP] Session done\n")
		if _, err := os.Stat("/etc/fsmxlb/sessionulclconfig.txt"); errors.Is(err, os.ErrNotExist) {
			if err != nil {
				fmt.Printf("[NLP] No UlCl config file : %s \n", err.Error())
			}
		} else {
			applyUlClConfig()
		}

		fmt.Printf("[NLP] Session UlCl done\n")
		if _, err := os.Stat("/etc/fsmxlb/FWconfig.txt"); errors.Is(err, os.ErrNotExist) {
			if err != nil {
				fmt.Printf("[NLP] No Firewall config file : %s \n", err.Error())
			}
		} else {
			applyFWConfig()
		}
		fmt.Printf("[NLP] Firewall done\n")

		fmt.Printf("[NLP] LbSessionGet done\n")
	}

	return 0
}

func NlpInit() *NlH {

	nNl = new(NlH)

	nNl.FromAddrUpdateCh = make(chan nlp.AddrUpdate, nlf.AddrUpdateWorkqLen)
	nNl.FromLinkUpdateCh = make(chan nlp.LinkUpdate, nlf.LinkUpdateWorkQLen)
	nNl.FromNeighUpdateCh = make(chan nlp.NeighUpdate, nlf.NeighUpdateWorkQLen)
	nNl.FromRouteUpdateCh = make(chan nlp.RouteUpdate, nlf.RouteUpdateWorkQLen)
	nNl.FromAddrUpdateDone = make(chan struct{})
	nNl.FromLinkUpdateDone = make(chan struct{})
	nNl.FromNeighUpdateDone = make(chan struct{})
	nNl.FromRouteUpdateDone = make(chan struct{})
	nNl.IMap = make(map[string]Intf)

	checkInit := make(chan bool)
	go NlpGet(checkInit)
	done := <-checkInit

	err := nlp.LinkSubscribe(nNl.FromLinkUpdateCh, nNl.FromAddrUpdateDone)
	if err != nil {
		fmt.Printf("%v", err)
	} else {
		fmt.Printf("[NLP] Link msgs subscribed\n")
	}
	err = nlp.AddrSubscribe(nNl.FromAddrUpdateCh, nNl.FromAddrUpdateDone)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("[NLP] Addr msgs subscribed\n")
	}
	err = nlp.NeighSubscribe(nNl.FromNeighUpdateCh, nNl.FromAddrUpdateDone)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("[NLP] Neigh msgs subscribed\n")
	}
	err = nlp.RouteSubscribe(nNl.FromRouteUpdateCh, nNl.FromAddrUpdateDone)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("[NLP] Route msgs subscribed\n")
	}

	go NLWorker(nNl)
	fmt.Printf("[NLP] NLP Subscription done\n")

	go LbSessionGet(done)

	return nNl
}
