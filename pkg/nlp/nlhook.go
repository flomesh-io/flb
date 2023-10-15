package nlp

/*
#include <stdbool.h>
#include <net_api.h>
#include <nlp.h>

extern int net_port_add(struct net_api_port_q *port);
extern int net_port_del(struct net_api_port_q *port);

extern int net_vlan_add(struct net_api_vlan_q *vlan);
extern int net_vlan_del(struct net_api_vlan_q *vlan);

extern int net_vlan_port_add(struct net_api_vlan_port_q *vlan_port);
extern int net_vlan_port_del(struct net_api_vlan_port_q *vlan_port);

extern int net_neigh_add(struct net_api_neigh_q *neigh);
extern int net_neigh_del(struct net_api_neigh_q *neigh);

extern int net_fdb_add(struct net_api_fdb_q *fdb);
extern int net_fdb_del(struct net_api_fdb_q *fdb);

extern int net_addr_add(struct net_api_addr_q *addr);
extern int net_addr_del(struct net_api_addr_q *addr);

extern int net_route_add(struct net_api_route_q *route);
extern int net_route_del(struct net_api_route_q *route);

extern void apply_config_map(char *name, bool state, bool add);


#cgo CFLAGS: -g -Og -W -Wextra -Wno-unused-parameter -I/usr/include/libnl3 -I../../netlink/headers
#cgo LDFLAGS: -L../../netlink -lnl-route-3 -lnl-3 -lev -lnlp
*/
import "C"
import (
	"fmt"
	"net"
	"time"

	"github.com/flomesh-io/flb/pkg/cmn"
	"github.com/flomesh-io/flb/pkg/tk"
)

var (
	debug_c_log = false

	portUpdateCh     = make(chan *portUpdate, cmn.LuWorkQLen)
	vlanUpdateCh     = make(chan *vlanUpdate, cmn.LuWorkQLen)
	vlanPortUpdateCh = make(chan *vlanPortUpdate, cmn.LuWorkQLen)
	addrUpdateCh     = make(chan *addrUpdate, cmn.AuWorkQLen)
	neighUpdateCh    = make(chan *neighUpdate, cmn.NuWorkQLen)
	fdbUpdateCh      = make(chan *fdbUpdate, cmn.RuWorkQLen)
	routeUpdateCh    = make(chan *routeUpdate, cmn.RuWorkQLen)
)

type portUpdate struct {
	delete bool
	msg    C.struct_net_api_port_q
}

type vlanUpdate struct {
	delete bool
	msg    C.struct_net_api_vlan_q
}

type vlanPortUpdate struct {
	delete bool
	msg    C.struct_net_api_vlan_port_q
}

type addrUpdate struct {
	delete bool
	msg    C.struct_net_api_addr_q
}

type neighUpdate struct {
	delete bool
	msg    C.struct_net_api_neigh_q
}

type fdbUpdate struct {
	delete bool
	msg    C.struct_net_api_fdb_q
}

type routeUpdate struct {
	delete bool
	msg    C.struct_net_api_route_q
}

//export net_port_add
func net_port_add(port *C.struct_net_api_port_q) C.int {
	printf("net_port_add ")
	printf("Dev: %-8s ", c16str(port.dev))
	printf("LinkIndex: %-4d ", port.link_index)
	printf("Ptype: %d ", port.link_type)
	printf("MacAddr: [%3d,%3d,%3d,%3d,%3d,%3d] ", port.mac_addr[0],
		port.mac_addr[1], port.mac_addr[2], port.mac_addr[3],
		port.mac_addr[4], port.mac_addr[5])
	printf("Link: %5t ", port.link)
	printf("State: %5t ", port.state)
	printf("Mtu: %-5d ", port.mtu)
	printf("Master: %-12s ", port.master)
	printf("Real: %-12s ", c16str(port.real))
	printf("TunID: %-4d ", port.tun_id)
	printf("TunSrc: %-20s ", c16str(port.tun_src))
	printf("TunDst: %-20s ", c16str(port.tun_dst))
	printf("\n")

	portUpdateCh <- &portUpdate{
		delete: false,
		msg:    *port,
	}

	return C.int(0)
}

//export net_port_del
func net_port_del(port *C.struct_net_api_port_q) C.int {
	printf("net_port_del ")
	printf("Dev: %-16s ", c16str(port.dev))
	printf("\n")

	portUpdateCh <- &portUpdate{
		delete: true,
		msg:    *port,
	}

	return C.int(0)
}

//export net_vlan_add
func net_vlan_add(vlan *C.struct_net_api_vlan_q) C.int {
	printf("net_vlan_add ")
	printf("Dev: %-8s ", c16str(vlan.dev))
	printf("LinkIndex: %-4d ", vlan.link_index)
	printf("VID: %-3d ", vlan.vid)
	printf("MacAddr: [%3d,%3d,%3d,%3d,%3d,%3d] ", vlan.mac_addr[0],
		vlan.mac_addr[1], vlan.mac_addr[2], vlan.mac_addr[3],
		vlan.mac_addr[4], vlan.mac_addr[5])
	printf("Link: %5t ", vlan.link)
	printf("State: %5t ", vlan.state)
	printf("Mtu: %-5d ", vlan.mtu)
	printf("TunID: %-4d ", vlan.tun_id)
	printf("\n")

	vlanUpdateCh <- &vlanUpdate{
		delete: false,
		msg:    *vlan,
	}

	return C.int(0)
}

//export net_vlan_del
func net_vlan_del(vlan *C.struct_net_api_vlan_q) C.int {
	printf("net_vlan_del ")
	printf("VID: %-3d ", vlan.vid)
	printf("\n")

	vlanUpdateCh <- &vlanUpdate{
		delete: true,
		msg:    *vlan,
	}

	return C.int(0)
}

//export net_vlan_port_add
func net_vlan_port_add(vlan_port *C.struct_net_api_vlan_port_q) C.int {
	printf("net_vlan_port_add ")
	printf("Dev: %-8s ", c16str(vlan_port.dev))
	printf("Tagged: %5t ", vlan_port.tagged)
	printf("VID: %-3d ", vlan_port.vid)
	printf("\n")

	vlanPortUpdateCh <- &vlanPortUpdate{
		delete: false,
		msg:    *vlan_port,
	}

	return C.int(0)
}

//export net_vlan_port_del
func net_vlan_port_del(vlan_port *C.struct_net_api_vlan_port_q) C.int {
	printf("net_vlan_port_del ")
	printf("Dev: %-8s ", c16str(vlan_port.dev))
	printf("Tagged: %5t ", vlan_port.tagged)
	printf("VID: %-3d ", vlan_port.vid)
	printf("\n")

	vlanPortUpdateCh <- &vlanPortUpdate{
		delete: true,
		msg:    *vlan_port,
	}

	return C.int(0)
}

//export net_neigh_add
func net_neigh_add(neigh *C.struct_net_api_neigh_q) C.int {
	printf("net_neigh_add ")
	printf("IP: %-33s ", c46str(neigh.ip))
	printf("LinkIndex: %-4d ", neigh.link_index)
	printf("State: %2d ", neigh.state)
	printf("HardwareAddr: [%3d,%3d,%3d,%3d,%3d,%3d] ", neigh.hwaddr[0],
		neigh.hwaddr[1], neigh.hwaddr[2], neigh.hwaddr[3],
		neigh.hwaddr[4], neigh.hwaddr[5])
	printf("\n")

	neighUpdateCh <- &neighUpdate{
		delete: false,
		msg:    *neigh,
	}

	return C.int(0)
}

//export net_neigh_del
func net_neigh_del(neigh *C.struct_net_api_neigh_q) C.int {
	printf("net_neigh_del ")
	printf("IP: %-33s ", c46str(neigh.ip))
	printf("\n")

	neighUpdateCh <- &neighUpdate{
		delete: true,
		msg:    *neigh,
	}

	return C.int(0)
}

//export net_fdb_add
func net_fdb_add(fdb *C.struct_net_api_fdb_q) C.int {
	printf("net_fdb_add ")
	printf("MacAddr: [%3d,%3d,%3d,%3d,%3d,%3d] ", fdb.mac_addr[0],
		fdb.mac_addr[1], fdb.mac_addr[2], fdb.mac_addr[3],
		fdb.mac_addr[4], fdb.mac_addr[5])
	printf("BridgeID: %d ", fdb.bridge_id)
	printf("Dev: %-8s ", c16str(fdb.dev))
	printf("Dst: %-33s ", c46str(fdb.dst))
	printf("Type: %d ", fdb.fdb_type)
	printf("\n")

	fdbUpdateCh <- &fdbUpdate{
		delete: false,
		msg:    *fdb,
	}

	return C.int(0)
}

//export net_fdb_del
func net_fdb_del(fdb *C.struct_net_api_fdb_q) C.int {
	printf("net_fdb_del ")
	printf("MacAddr: [%3d,%3d,%3d,%3d,%3d,%3d] ", fdb.mac_addr[0],
		fdb.mac_addr[1], fdb.mac_addr[2], fdb.mac_addr[3],
		fdb.mac_addr[4], fdb.mac_addr[5])
	printf("BridgeID: %d ", fdb.bridge_id)
	printf("\n")

	fdbUpdateCh <- &fdbUpdate{
		delete: true,
		msg:    *fdb,
	}

	return C.int(0)
}

//export net_addr_add
func net_addr_add(addr *C.struct_net_api_addr_q) C.int {
	printf("net_addr_add ")
	printf("Dev: %-8s ", c16str(addr.dev))
	printf("IP: %-33s", c50str(addr.ip))
	printf("\n")

	addrUpdateCh <- &addrUpdate{
		delete: false,
		msg:    *addr,
	}

	return C.int(0)
}

//export net_addr_del
func net_addr_del(addr *C.struct_net_api_addr_q) C.int {
	printf("net_addr_del ")
	printf("Dev: %-8s ", c16str(addr.dev))
	printf("IP: %-33s", c50str(addr.ip))

	addrUpdateCh <- &addrUpdate{
		delete: true,
		msg:    *addr,
	}

	return C.int(0)
}

//export net_route_add
func net_route_add(route *C.struct_net_api_route_q) C.int {
	printf("net_route_add ")
	printf("Protocol: %2d ", route.protocol)
	printf("Flags: %2d ", route.flags)
	printf("Link Index: %2d ", route.link_index)
	printf("Dst: %-33s ", c50str(route.dst))
	printf("Gw: %-33s ", c46str(route.gw))
	printf("\n")

	routeUpdateCh <- &routeUpdate{
		delete: false,
		msg:    *route,
	}

	return C.int(0)
}

//export net_route_del
func net_route_del(route *C.struct_net_api_route_q) C.int {
	printf("net_route_del ")
	printf("Dst: %-33s ", c50str(route.dst))
	printf("\n")

	routeUpdateCh <- &routeUpdate{
		delete: true,
		msg:    *route,
	}

	return C.int(0)
}

//export apply_config_map
func apply_config_map(name *C.char, state, add C.bool) {
}

func c6mac(chs [6]C.uchar) [6]byte {
	var bytes [6]byte
	for i := 0; i < 6; i++ {
		bytes[i] = byte(chs[i])
	}
	return bytes
}

func c6bytes(chs [6]C.uchar) []byte {
	var bytes [6]byte
	for i := 0; i < 6; i++ {
		bytes[i] = byte(chs[i])
	}
	return bytes[:]
}

func c16str(chs [16]C.uchar) string {
	bytes := make([]byte, 0)
	for _, c := range chs {
		if c != 0 {
			bytes = append(bytes, byte(c))
		}
	}
	return string(bytes)
}

func c46str(chs [46]C.uchar) string {
	bytes := make([]byte, 0)
	for _, c := range chs {
		if c != 0 {
			bytes = append(bytes, byte(c))
		}
	}
	return string(bytes)
}

func c50str(chs [50]C.uchar) string {
	bytes := make([]byte, 0)
	for _, c := range chs {
		if c != 0 {
			bytes = append(bytes, byte(c))
		}
	}
	return string(bytes)
}

func printf(format string, args ...any) (n int, err error) {
	if debug_c_log {
		return fmt.Printf(format, args...)
	}
	return 0, nil
}

func portUpdateWorker(ch chan *portUpdate) {
	for n := 0; n < cmn.LuWorkQLen; n++ {
		select {
		case m := <-ch:
			portUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func portUpdateWorkSingle(m *portUpdate) {
	if !m.delete {
		name := c16str(m.msg.dev)
		idx := int(m.msg.link_index)
		pType := int(m.msg.link_type)
		ifMac := c6mac(m.msg.mac_addr)
		linkState := bool(m.msg.link)
		state := bool(m.msg.state)
		mtu := int(m.msg.mtu)
		master := c16str(m.msg.master)
		realv := c16str(m.msg.real)
		tunId := int(m.msg.tun_id)
		tunDst := net.ParseIP(c16str(m.msg.tun_dst))
		tunSrc := net.ParseIP(c16str(m.msg.tun_src))
		_, err := hooks.NetPortAdd(&cmn.PortMod{Dev: name, LinkIndex: idx, Ptype: pType, MacAddr: ifMac,
			Link: linkState, State: state, Mtu: mtu, Master: master, Real: realv,
			TunID: tunId, TunDst: tunDst, TunSrc: tunSrc})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Port %v, %v, %v, %v add failed, err: %s\n", name, ifMac, state, mtu, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Port %v, %v, %v, %v add [OK]\n", name, ifMac, state, mtu)
		}
	} else {
		name := c16str(m.msg.dev)
		pType := int(m.msg.link_type)
		ifMac := c6mac(m.msg.mac_addr)
		state := bool(m.msg.state)
		mtu := int(m.msg.mtu)
		_, err := hooks.NetPortDel(&cmn.PortMod{Dev: name, Ptype: pType})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] Port %v, %v, %v, %v delete failed, err: %s\n", name, ifMac, state, mtu, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Port %v, %v, %v, %v delete [OK]\n", name, ifMac, state, mtu)
		}
	}
}

func vlanUpdateWorker(ch chan *vlanUpdate) {
	for n := 0; n < cmn.LuWorkQLen; n++ {
		select {
		case m := <-ch:
			vlanUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func vlanUpdateWorkSingle(m *vlanUpdate) {
	if !m.delete {
		vid := int(m.msg.vid)
		name := c16str(m.msg.dev)
		idx := int(m.msg.link_index)
		ifMac := c6mac(m.msg.mac_addr)
		linkState := bool(m.msg.link)
		state := bool(m.msg.state)
		mtu := int(m.msg.mtu)
		_, err := hooks.NetVlanAdd(&cmn.VlanMod{Vid: vid, Dev: name, LinkIndex: idx,
			MacAddr: ifMac, Link: linkState, State: state, Mtu: mtu, TunID: 0})
		if err != nil {
			tk.LogIt(tk.LogInfo, "[NLP] Bridge %v, %d, %v, %v, %v ADD failed, error: %s\n", name, vid, ifMac, state, mtu, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Bridge %v, %d, %v, %v, %v ADD [OK]\n", name, vid, ifMac, state, mtu)
		}
	} else {
		vid := int(m.msg.vid)
		name := c16str(m.msg.dev)
		ifMac := c6mac(m.msg.mac_addr)
		state := bool(m.msg.state)
		mtu := int(m.msg.mtu)
		_, err := hooks.NetVlanDel(&cmn.VlanMod{Vid: vid})
		if err != nil {
			tk.LogIt(tk.LogInfo, "[NLP] Bridge %v, %d, %v, %v, %v DELETE failed, error: %s\n", name, vid, ifMac, state, mtu, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] Bridge %v, %d, %v, %v, %v DELETE [OK]\n", name, vid, ifMac, state, mtu)
		}
	}
}

func vlanPortUpdateWorker(ch chan *vlanPortUpdate) {
	for n := 0; n < cmn.LuWorkQLen; n++ {
		select {
		case m := <-ch:
			vlanPortUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func vlanPortUpdateWorkSingle(m *vlanPortUpdate) {
	if !m.delete {
		vid := int(m.msg.vid)
		name := c16str(m.msg.dev)
		tagged := bool(m.msg.tagged)
		_, err := hooks.NetVlanPortAdd(&cmn.VlanPortMod{Vid: vid, Dev: name, Tagged: tagged})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] TVlan Port %v, v(%v) ADD failed, error: %s\n", name, vid, err.Error())
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] TVlan Port %v, v(%v) ADD OK\n", name, vid)
		}
	} else {
		vid := int(m.msg.vid)
		name := c16str(m.msg.dev)
		tagged := bool(m.msg.tagged)
		_, err := hooks.NetVlanPortDel(&cmn.VlanPortMod{Vid: vid, Dev: name, Tagged: tagged})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] TVlan Port %v, v(%v) DELETE failed, error: %s\n", name, vid, err.Error())
			fmt.Println(err)
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] TVlan Port %v, v(%v) DELETE OK\n", name, vid)
		}
	}
}

func addrUpdateWorker(ch chan *addrUpdate) {
	for n := 0; n < cmn.AuWorkQLen; n++ {
		select {
		case m := <-ch:
			addrUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func addrUpdateWorkSingle(m *addrUpdate) {
	if !m.delete {
		name := c16str(m.msg.dev)
		ipStr := c50str(m.msg.ip)
		_, err := hooks.NetAddrAdd(&cmn.IPAddrMod{Dev: name, IP: ipStr})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] IPv4 Address %v Port %v add failed, error: %s\n", ipStr, name, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] IPv4 Address %v Port %v added\n", ipStr, name)
		}
	} else {
		name := c16str(m.msg.dev)
		ipStr := c50str(m.msg.ip)
		_, err := hooks.NetAddrDel(&cmn.IPAddrMod{Dev: name, IP: ipStr})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] IPv4 Address %v Port %v delete failed, error: %s\n", ipStr, name, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] IPv4 Address %v Port %v deleted\n", ipStr, name)
		}
	}
}

func neighUpdateWorker(ch chan *neighUpdate) {
	for n := 0; n < cmn.NuWorkQLen; n++ {
		select {
		case m := <-ch:
			neighUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func neighUpdateWorkSingle(m *neighUpdate) {
	if !m.delete {
		ip := net.ParseIP(c46str(m.msg.ip))
		linkIndex := int(m.msg.link_index)
		state := int(m.msg.state)
		hwaddr := net.HardwareAddr(c6bytes(m.msg.hwaddr))
		name := c16str(m.msg.dev)

		_, err := hooks.NetNeighAdd(&cmn.NeighMod{
			IP:           ip,
			LinkIndex:    linkIndex,
			State:        state,
			HardwareAddr: hwaddr})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] NH %v mac %v dev %v add failed, error: %s\n", ip.String(), hwaddr,
				name, err.Error())

		} else {
			tk.LogIt(tk.LogInfo, "[NLP] NH %v mac %v dev %v added\n", ip.String(), hwaddr, name)
		}
	} else {
		ip := net.ParseIP(c46str(m.msg.ip))
		name := c16str(m.msg.dev)

		_, err := hooks.NetNeighDel(&cmn.NeighMod{IP: ip})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] NH  %v %v del failed, error: %s\n", ip.String(), name, err.Error())

		} else {
			tk.LogIt(tk.LogError, "[NLP] NH %v %v deleted\n", ip.String(), name)
		}
	}
}

func fdbUpdateWorker(ch chan *fdbUpdate) {
	for n := 0; n < cmn.RuWorkQLen; n++ {
		select {
		case m := <-ch:
			fdbUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func fdbUpdateWorkSingle(m *fdbUpdate) {
	if !m.delete {
		mac := c6mac(m.msg.mac_addr)
		brId := int(m.msg.bridge_id)
		name := c16str(m.msg.dev)
		dst := net.ParseIP(c46str(m.msg.dst))
		ftype := int(m.msg.fdb_type)

		_, err := hooks.NetFdbAdd(&cmn.FdbMod{
			MacAddr:  mac,
			BridgeID: brId,
			Dev:      name,
			Dst:      dst,
			Type:     ftype})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] L2fdb %v brId %v dst %v dev %v add failed, error: %s\n", mac[:], brId, dst, name, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] L2fdb %v brId %v dst %v dev %v added\n", mac[:], brId, dst, name)
		}
	} else {
		mac := c6mac(m.msg.mac_addr)
		brId := int(m.msg.bridge_id)
		name := c16str(m.msg.dev)
		dst := net.ParseIP(c46str(m.msg.dst))

		_, err := hooks.NetFdbDel(&cmn.FdbMod{
			MacAddr:  mac,
			BridgeID: brId})
		if err != nil {
			tk.LogIt(tk.LogError, "[NLP] L2fdb %v brId %v dst %s dev %v delete failed, error: %s\n", mac[:], brId, dst, name, err.Error())
		} else {
			tk.LogIt(tk.LogInfo, "[NLP] L2fdb %v brId %v dst %s dev %v deleted\n", mac[:], brId, dst, name)
		}
	}
}

func routeUpdateWorker(ch chan *routeUpdate) {
	for n := 0; n < cmn.RuWorkQLen; n++ {
		select {
		case m := <-ch:
			routeUpdateWorkSingle(m)
		default:
			continue
		}
	}
}

func routeUpdateWorkSingle(m *routeUpdate) {
	if !m.delete {
		protocol := int(m.msg.protocol)
		flags := int(m.msg.flags)
		linkIndex := int(m.msg.link_index)
		_, ipNet, err := net.ParseCIDR(c50str(m.msg.dst))
		if err != nil {
			fmt.Printf("net.ParseCIDR[%s] error:%s\n", c50str(m.msg.dst), err.Error())
		}
		gw := net.ParseIP(c46str(m.msg.gw))

		_, err = hooks.NetRouteAdd(&cmn.RouteMod{
			Protocol:  protocol,
			Flags:     flags,
			Gw:        gw,
			LinkIndex: linkIndex,
			Dst:       *ipNet})
		if err != nil {
			if gw != nil {
				tk.LogIt(tk.LogError, "[NLP] RT  %s via %s proto %d add failed, error: %s\n", ipNet.String(),
					gw.String(), protocol, err.Error())
			} else {
				tk.LogIt(tk.LogError, "[NLP] RT  %s add failed, error: %s\n", ipNet.String(), err.Error())
			}
		} else {
			if gw != nil {
				tk.LogIt(tk.LogError, "[NLP] RT  %s via %s added\n", ipNet.String(),
					gw.String())
			} else {
				tk.LogIt(tk.LogError, "[NLP] RT  %s added\n", ipNet.String())
			}
		}
	} else {
		_, ipNet, _ := net.ParseCIDR(c50str(m.msg.dst))
		gw := net.ParseIP(c46str(m.msg.gw))

		_, err := hooks.NetRouteDel(&cmn.RouteMod{Dst: *ipNet})
		if err != nil {
			if gw != nil {
				tk.LogIt(tk.LogError, "[NLP] RT  %s via %s delete failed, error: %s\n", ipNet.String(),
					gw.String(), err.Error())
			} else {
				tk.LogIt(tk.LogError, "[NLP] RT  %s delete failed, error: %s\n", ipNet.String(), err.Error())
			}
		} else {
			if gw != nil {
				tk.LogIt(tk.LogError, "[NLP] RT  %s via %s deleted\n", ipNet.String(),
					gw.String())
			} else {
				tk.LogIt(tk.LogError, "[NLP] RT  %s deleted\n", ipNet.String())
			}
		}
	}
}

func nlpWorker() {
	for { /* 务必以单线程按如下顺序执行 */
		portUpdateWorker(portUpdateCh)
		vlanUpdateWorker(vlanUpdateCh)
		vlanPortUpdateWorker(vlanPortUpdateCh)
		addrUpdateWorker(addrUpdateCh)
		neighUpdateWorker(neighUpdateCh)
		fdbUpdateWorker(fdbUpdateCh)
		routeUpdateWorker(routeUpdateCh)
		time.Sleep(500 * time.Millisecond)
	}
}

func nlpMonitor() {
	C.nl_bridge_list()
	C.nl_link_list()
	go func() {
		C.nl_link_subscribe()
	}()
	go func() {
		C.nl_addr_subscribe()
	}()
	go func() {
		C.nl_neigh_subscribe()
	}()
	go func() {
		C.nl_route_subscribe()
	}()
	go func() {
		nlpWorker()
	}()
}
