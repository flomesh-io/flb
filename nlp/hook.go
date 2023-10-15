package nlp

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	nl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/flb/pkg/cmn"
	"github.com/flomesh-io/flb/pkg/tk"
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
	FromAUCh   chan nl.AddrUpdate
	FromAUDone chan struct{}
}
type LinkUpdateCh struct {
	FromLUCh   chan nl.LinkUpdate
	FromLUDone chan struct{}
}
type NeighUpdateCh struct {
	FromNUCh   chan nl.NeighUpdate
	FromNUDone chan struct{}
}
type RouteUpdateCh struct {
	FromRUCh   chan nl.RouteUpdate
	FromRUDone chan struct{}
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
	state          bool
	configApplied  bool
	needRouteApply bool
}

type NlH struct {
	AddrUpdateCh
	LinkUpdateCh
	NeighUpdateCh
	RouteUpdateCh
	IMap      map[string]Intf
	BlackList string
	BLRgx     *regexp.Regexp
}

var hooks cmn.NlpHookInterface

func NlpRegister(hook cmn.NlpHookInterface) {
	hooks = hook
}

func ModLink(link nl.Link, add bool) int {
	var ifMac [6]byte
	var ret int
	var err error
	var mod string
	var vid int
	var brLink nl.Link
	re := regexp.MustCompile("[0-9]+")

	attrs := link.Attrs()
	name := attrs.Name
	idx := attrs.Index

	if len(attrs.HardwareAddr) > 0 {
		copy(ifMac[:], attrs.HardwareAddr[:6])
	}

	mtu := attrs.MTU
	linkState := attrs.Flags&net.FlagUp == 1
	state := uint8(attrs.OperState) != nl.OperDown
	if add {
		mod = "ADD"
	} else {
		mod = "DELETE"
	}
	tk.LogIt(tk.LogDebug, "[NLP] %s Device %v mac(%v) attrs(%v) info recvd\n", mod, name, ifMac, attrs)

	if _, ok := link.(*nl.Bridge); ok {

		vid, _ = strconv.Atoi(strings.Join(re.FindAllString(name, -1), " "))
		// Dirty hack to support docker0 bridge
		if vid == 0 && name == "docker0" {
			vid = 4090
		}
		if add {
			ret, err = hooks.NetVlanAdd(&cmn.VlanMod{Vid: vid, Dev: name, LinkIndex: idx,
				MacAddr: ifMac, Link: linkState, State: state, Mtu: mtu, TunID: 0})
		} else {
			ret, err = hooks.NetVlanDel(&cmn.VlanMod{Vid: vid})
		}

		if err != nil {
			tk.LogIt(tk.LogInfo, "[NLP] Bridge %v, %d, %v, %v, %v %s failed\n", name, vid, ifMac, state, mtu, mod)
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Bridge %v, %d, %v, %v, %v %s [OK]\n", name, vid, ifMac, state, mtu, mod)
		}
	}

	/* Get bridge detail */
	if attrs.MasterIndex > 0 {
		brLink, err = nl.LinkByIndex(attrs.MasterIndex)
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
				ret, err = hooks.NetVlanPortAdd(&cmn.VlanPortMod{Vid: vid, Dev: pname[0], Tagged: true})
			} else {
				ret, err = hooks.NetVlanPortDel(&cmn.VlanPortMod{Vid: vid, Dev: pname[0], Tagged: true})
			}
			if err != nil {
				tk.LogIt(tk.LogError, "[NLP] TVlan Port %v, v(%v), %v, %v, %v %s failed\n", name, vid, ifMac, state, mtu, mod)
				fmt.Println(err)
			} else {
				tk.LogIt(tk.LogInfo, "[NLP] TVlan Port %v, v(%v), %v, %v, %v %s OK\n", name, vid, ifMac, state, mtu, mod)
			}
			return ret
		} else {
			mif, err := nl.LinkByIndex(attrs.MasterIndex)
			if err != nil {
				fmt.Println(err)
				return -1
			} else {
				if _, ok := mif.(*nl.Bond); ok {
					master = mif.Attrs().Name
				}
			}
		}
	}

	/* Physical port/ Bond/ VxLAN */

	real := ""
	pType := cmn.PortReal
	tunId := 0
	tunSrc := net.IPv4zero
	tunDst := net.IPv4zero

	if strings.Contains(name, "ipsec") || strings.Contains(name, "vti") {
		pType = cmn.PortVti
	} else if strings.Contains(name, "wg") {
		pType = cmn.PortWg
	}

	if vxlan, ok := link.(*nl.Vxlan); ok {
		pType = cmn.PortVxlanBr
		tunId = vxlan.VxlanId
		uif, err := nl.LinkByIndex(vxlan.VtepDevIndex)
		if err != nil {
			fmt.Println(err)
			return -1
		}
		real = uif.Attrs().Name
		tk.LogIt(tk.LogInfo, "[NLP] Port %v, uif %v %s\n", name, real, mod)
	} else if _, ok := link.(*nl.Bond); ok {
		pType = cmn.PortBond
		tk.LogIt(tk.LogInfo, "[NLP] Bond %v, %s\n", name, mod)
	} else if iptun, ok := link.(*nl.Iptun); ok {
		pType = cmn.PortIPTun
		if iptun.Remote == nil || iptun.Local == nil {
			return -1
		}

		if iptun.Remote.IsUnspecified() || iptun.Local.IsUnspecified() {
			return -1
		}
		tunId = 1 // Just needed internally
		tunDst = iptun.Remote
		tunSrc = iptun.Local
		tk.LogIt(tk.LogInfo, "[NLP] IPTun %v (%s:%s), %s\n", name, tunSrc.String(), tunDst.String(), mod)
	} else if master != "" {
		pType = cmn.PortBondSif
	}

	if add {
		ret, err = hooks.NetPortAdd(&cmn.PortMod{Dev: name, LinkIndex: idx, Ptype: pType, MacAddr: ifMac,
			Link: linkState, State: state, Mtu: mtu, Master: master, Real: real,
			TunID: tunId, TunDst: tunDst, TunSrc: tunSrc})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Port %v, %v, %v, %v add failed\n", name, ifMac, state, mtu)
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Port %v, %v, %v, %v add [OK]\n", name, ifMac, state, mtu)
		}
	} else if attrs.MasterIndex == 0 {
		ret, err = hooks.NetPortDel(&cmn.PortMod{Dev: name, Ptype: pType})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Port %v, %v, %v, %v delete failed\n", name, ifMac, state, mtu)
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Port %v, %v, %v, %v delete [OK]\n", name, ifMac, state, mtu)
		}
		return ret
	}

	/* Untagged vlan ports */
	if attrs.MasterIndex > 0 && master == "" {
		if add {
			ret, err = hooks.NetVlanPortAdd(&cmn.VlanPortMod{Vid: vid, Dev: name, Tagged: false})
		} else {
			ret, err = hooks.NetVlanPortDel(&cmn.VlanPortMod{Vid: vid, Dev: name, Tagged: false})
		}
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Vlan(%v) Port %v, %v, %v, %v %s failed\n", vid, name, ifMac, state, mtu, mod)
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Vlan(%v) Port %v, %v, %v, %v %s [OK]\n", vid, name, ifMac, state, mtu, mod)
		}
	}
	return ret
}

func AddAddr(addr nl.Addr, link nl.Link) int {
	var ret int

	attrs := link.Attrs()
	name := attrs.Name
	ipStr := (addr.IPNet).String()

	ret, err := hooks.NetAddrAdd(&cmn.IPAddrMod{Dev: name, IP: ipStr})
	if err != nil {
		tk.LogIt(tk.LogError, "[NLP] IPv4 Address %v Port %v failed %v\n", ipStr, name, err)
		ret = -1
	} else {
		tk.LogIt(tk.LogInfo, "[NLP] IPv4 Address %v Port %v added\n", ipStr, name)
	}
	return ret
}

func AddNeigh(neigh nl.Neigh, link nl.Link) int {
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
		ret, err = hooks.NetNeighAdd(&cmn.NeighMod{IP: neigh.IP, LinkIndex: neigh.LinkIndex,
			State:        neigh.State,
			HardwareAddr: neigh.HardwareAddr})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] NH %v mac %v dev %v add failed %v\n", neigh.IP.String(), mac,
				name, err)

		} /*else {
			tk.LogIt(tk.LogInfo, "[NLP] NH %v mac %v dev %v added\n", neigh.IP.String(), mac, name)
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
			brLink, err := nl.LinkByIndex(neigh.MasterIndex)
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

		if vxlan, ok := link.(*nl.Vxlan); ok {
			/* Interested in only VxLAN FDB */
			if len(neigh.IP) > 0 && (neigh.MasterIndex == 0) {
				dst = neigh.IP
				brId = vxlan.VxlanId
				ftype = cmn.FdbTun
			} else {
				tk.LogIt(tk.LogError, "[NLP] L2fdb %v brId %v dst %v dev %v IGNORED\n", mac[:], brId, dst, name)
				return 0
			}
		} else {
			dst = net.ParseIP("0.0.0.0")
			ftype = cmn.FdbVlan
		}

		ret, err = hooks.NetFdbAdd(&cmn.FdbMod{MacAddr: mac, BridgeID: brId, Dev: name, Dst: dst,
			Type: ftype})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] L2fdb %v brId %v dst %v dev %v add failed\n", mac[:], brId, dst, name)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] L2fdb %v brId %v dst %v dev %v added\n", mac[:], brId, dst, name)
		}
	}

	return ret

}

func DelNeigh(neigh nl.Neigh, link nl.Link) int {
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

		ret, err = hooks.NetNeighDel(&cmn.NeighMod{IP: neigh.IP})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] NH  %v %v del failed\n", neigh.IP.String(), name)
			ret = -1
		} else {
			tk.LogIt(tk.LogError, "[NLP] NH %v %v deleted\n", neigh.IP.String(), name)
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
			brLink, err := nl.LinkByIndex(neigh.MasterIndex)
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

		if vxlan, ok := link.(*nl.Vxlan); ok {
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

		ret, err = hooks.NetFdbDel(&cmn.FdbMod{MacAddr: mac, BridgeID: brId})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] L2fdb %v brId %v dst %s dev %v delete failed %v\n", mac[:], brId, dst, name, err)
			ret = -1
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] L2fdb %v brId %v dst %s dev %v deleted\n", mac[:], brId, dst, name)
		}
	}
	return ret
}

func AddRoute(route nl.Route) int {
	var ipNet net.IPNet
	if route.Dst == nil {
		r := net.IPv4(0, 0, 0, 0)
		m := net.CIDRMask(0, 32)
		r = r.Mask(m)
		ipNet = net.IPNet{IP: r, Mask: m}
	} else {
		ipNet = *route.Dst
	}

	ret, err := hooks.NetRouteAdd(&cmn.RouteMod{Protocol: int(route.Protocol), Flags: route.Flags,
		Gw: route.Gw, LinkIndex: route.LinkIndex, Dst: ipNet})
	if err != nil {
		if route.Gw != nil {
			tk.LogIt(tk.LogError, "[NLP] RT  %s via %s proto %d add failed-%s\n", ipNet.String(),
				route.Gw.String(), route.Protocol, err)
		} else {
			tk.LogIt(tk.LogError, "[NLP] RT  %s add failed-%s\n", ipNet.String(), err)
		}
	} else {
		if route.Gw != nil {
			tk.LogIt(tk.LogError, "[NLP] RT  %s via %s added\n", ipNet.String(),
				route.Gw.String())
		} else {
			tk.LogIt(tk.LogError, "[NLP] RT  %s added\n", ipNet.String())
		}
	}

	return ret
}

func DelRoute(route nl.Route) int {
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
	ret, err := hooks.NetRouteDel(&cmn.RouteMod{Dst: ipNet})
	if err != nil {
		if route.Gw != nil {
			tk.LogIt(tk.LogError, "[NLP] RT  %s via %s delete failed-%s\n", ipNet.String(),
				route.Gw.String(), err)
		} else {
			tk.LogIt(tk.LogError, "[NLP] RT  %s delete failed-%s\n", ipNet.String(), err)
		}
	} else {
		if route.Gw != nil {
			tk.LogIt(tk.LogError, "[NLP] RT  %s via %s deleted\n", ipNet.String(),
				route.Gw.String())
		} else {
			tk.LogIt(tk.LogError, "[NLP] RT  %s deleted\n", ipNet.String())
		}
	}
	return ret
}

func LUWorkSingle(m nl.LinkUpdate) int {
	var ret int

	filter := nNl.BLRgx.MatchString(m.Link.Attrs().Name)
	if filter {
		return -1
	}

	ret = ModLink(m.Link, m.Header.Type == syscall.RTM_NEWLINK)
	return ret
}

func AUWorkSingle(m nl.AddrUpdate) int {
	var ret int
	link, err := nl.LinkByIndex(m.LinkIndex)
	if err != nil {
		fmt.Println(err)
		return -1
	}

	filter := nNl.BLRgx.MatchString(link.Attrs().Name)
	if filter {
		return -1
	}

	attrs := link.Attrs()
	name := attrs.Name
	if m.NewAddr {
		_, err := hooks.NetAddrAdd(&cmn.IPAddrMod{Dev: name, IP: m.LinkAddress.String()})
		if err != nil {
			tk.LogIt(tk.LogInfo, "[NLP] Address %v Port %v add failed\n", m.LinkAddress.String(), name)
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Address %v Port %v added\n", m.LinkAddress.String(), name)
		}

	} else {
		_, err := hooks.NetAddrDel(&cmn.IPAddrMod{Dev: name, IP: m.LinkAddress.String()})
		if err != nil {
			tk.LogIt(tk.LogInfo, "[NLP] Address %v Port %v delete failed\n", m.LinkAddress.String(), name)
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Address %v Port %v deleted\n", m.LinkAddress.String(), name)
		}
	}

	return ret
}

func NUWorkSingle(m nl.NeighUpdate) int {
	var ret int

	link, err := nl.LinkByIndex(m.LinkIndex)
	if err != nil {
		fmt.Println(err)
		return -1
	}

	filter := nNl.BLRgx.MatchString(link.Attrs().Name)
	if filter {
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

func RUWorkSingle(m nl.RouteUpdate) int {
	var ret int

	link, err := nl.LinkByIndex(m.LinkIndex)
	if err != nil {
		fmt.Println(err)
		return -1
	}

	filter := nNl.BLRgx.MatchString(link.Attrs().Name)
	if filter {
		return -1
	}

	if m.Type == syscall.RTM_NEWROUTE {
		ret = AddRoute(m.Route)
	} else {
		ret = DelRoute(m.Route)
	}

	return ret
}

func LUWorker(ch chan nl.LinkUpdate, f chan struct{}) {

	for n := 0; n < cmn.LuWorkQLen; n++ {
		select {
		case m := <-ch:
			LUWorkSingle(m)
		default:
			continue
		}
	}
}

func AUWorker(ch chan nl.AddrUpdate, f chan struct{}) {

	for n := 0; n < cmn.AuWorkqLen; n++ {
		select {
		case m := <-ch:
			AUWorkSingle(m)
		default:
			continue
		}
	}

}

func NUWorker(ch chan nl.NeighUpdate, f chan struct{}) {

	for n := 0; n < cmn.NuWorkQLen; n++ {
		select {
		case m := <-ch:
			NUWorkSingle(m)
		default:
			continue
		}
	}
}

func RUWorker(ch chan nl.RouteUpdate, f chan struct{}) {

	for n := 0; n < cmn.RuWorkQLen; n++ {
		select {
		case m := <-ch:
			RUWorkSingle(m)
		default:
			continue
		}
	}
}

func NLWorker(nNl *NlH) {
	for { /* Single thread for reading all NL msgs in below order */
		LUWorker(nNl.FromLUCh, nNl.FromLUDone)
		AUWorker(nNl.FromAUCh, nNl.FromAUDone)
		NUWorker(nNl.FromNUCh, nNl.FromNUDone)
		RUWorker(nNl.FromRUCh, nNl.FromRUDone)
		time.Sleep(1000 * time.Millisecond)
	}
}

func GetBridges() {
	links, err := nl.LinkList()
	if err != nil {
		return
	}
	for _, link := range links {
		filter := nNl.BLRgx.MatchString(link.Attrs().Name)
		if filter {
			continue
		}
		switch link.(type) {
		case *nl.Bridge:
			{
				ModLink(link, true)
			}
		}
	}
}

func NlpGet(ch chan bool) int {
	var ret int
	tk.LogIt(tk.LogInfo, "[NLP] Getting device info\n")

	GetBridges()

	links, err := nl.LinkList()
	if err != nil {
		tk.LogIt(tk.LogError, "[NLP] Error in getting device info(%v)\n", err)
		ret = -1
	}

	for _, link := range links {

		filter := nNl.BLRgx.MatchString(link.Attrs().Name)
		if filter {
			continue
		}

		ret = ModLink(link, true)
		if ret == -1 {
			continue
		}

		/* Get FDBs */
		_, ok := link.(*nl.Vxlan)
		if link.Attrs().MasterIndex > 0 || ok {
			neighs, err := nl.NeighList(link.Attrs().Index, unix.AF_BRIDGE)
			if err != nil {
				tk.LogIt(tk.LogError, "[NLP] Error getting neighbors list %v for intf %s\n",
					err, link.Attrs().Name)
			}

			if len(neighs) == 0 {
				tk.LogIt(tk.LogDebug, "[NLP] No FDBs found for intf %s\n", link.Attrs().Name)
			} else {
				for _, neigh := range neighs {
					AddNeigh(neigh, link)
				}
			}
		}

		addrs, err := nl.AddrList(link, nl.FAMILY_ALL)
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Error getting address list %v for intf %s\n",
				err, link.Attrs().Name)
		}

		if len(addrs) == 0 {
			tk.LogIt(tk.LogDebug, "[NLP] No addresses found for intf %s\n", link.Attrs().Name)
		} else {
			for _, addr := range addrs {
				AddAddr(addr, link)
			}
		}

		neighs, err := nl.NeighList(link.Attrs().Index, nl.FAMILY_ALL)
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Error getting neighbors list %v for intf %s\n",
				err, link.Attrs().Name)
		}

		if len(neighs) == 0 {
			tk.LogIt(tk.LogDebug, "[NLP] No neighbors found for intf %s\n", link.Attrs().Name)
		} else {
			for _, neigh := range neighs {
				AddNeigh(neigh, link)
			}
		}

		/* Get Routes */
		routes, err := nl.RouteList(link, nl.FAMILY_ALL)
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Error getting route list %v\n", err)
		}

		if len(routes) == 0 {
			tk.LogIt(tk.LogDebug, "[NLP] No STATIC routes found for intf %s\n", link.Attrs().Name)
		} else {
			for _, route := range routes {
				AddRoute(route)
			}
		}
	}
	tk.LogIt(tk.LogInfo, "[NLP] nl get done\n")
	ch <- true
	return ret
}

var nNl *NlH

func NlpInit(blackList string) *NlH {

	nNl = new(NlH)

	nNl.BlackList = blackList
	nNl.BLRgx = regexp.MustCompile(blackList)

	nNl.FromAUCh = make(chan nl.AddrUpdate, cmn.AuWorkqLen)
	nNl.FromLUCh = make(chan nl.LinkUpdate, cmn.LuWorkQLen)
	nNl.FromNUCh = make(chan nl.NeighUpdate, cmn.NuWorkQLen)
	nNl.FromRUCh = make(chan nl.RouteUpdate, cmn.RuWorkQLen)
	nNl.FromAUDone = make(chan struct{})
	nNl.FromLUDone = make(chan struct{})
	nNl.FromNUDone = make(chan struct{})
	nNl.FromRUCh = make(chan nl.RouteUpdate, cmn.RuWorkQLen)
	nNl.IMap = make(map[string]Intf)

	checkInit := make(chan bool)
	go NlpGet(checkInit)
	<-checkInit

	err := nl.LinkSubscribe(nNl.FromLUCh, nNl.FromLUDone)
	if err != nil {
		tk.LogIt(tk.LogError, "%v", err)
	} else {
		tk.LogIt(tk.LogInfo, "[NLP] Link msgs subscribed\n")
	}
	err = nl.AddrSubscribe(nNl.FromAUCh, nNl.FromAUDone)
	if err != nil {
		fmt.Println(err)
	} else {
		tk.LogIt(tk.LogInfo, "[NLP] Addr msgs subscribed\n")
	}
	err = nl.NeighSubscribe(nNl.FromNUCh, nNl.FromNUDone)
	if err != nil {
		fmt.Println(err)
	} else {
		tk.LogIt(tk.LogInfo, "[NLP] Neigh msgs subscribed\n")
	}
	err = nl.RouteSubscribe(nNl.FromRUCh, nNl.FromRUDone)
	if err != nil {
		fmt.Println(err)
	} else {
		tk.LogIt(tk.LogInfo, "[NLP] Route msgs subscribed\n")
	}

	go NLWorker(nNl)
	tk.LogIt(tk.LogInfo, "[NLP] NLP Subscription done\n")

	return nNl
}
