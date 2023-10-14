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
)

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
	return C.NL_OK
}

//export net_port_del
func net_port_del(port *C.struct_net_api_port_q) C.int {
	printf("net_port_del ")
	printf("Dev: %-16s ", c16str(port.dev))
	printf("\n")
	return C.NL_OK
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
	return C.NL_OK
}

//export net_vlan_del
func net_vlan_del(vlan *C.struct_net_api_vlan_q) C.int {
	printf("net_vlan_del ")
	printf("VID: %-3d ", vlan.vid)
	printf("\n")
	return C.NL_OK
}

//export net_vlan_port_add
func net_vlan_port_add(vlan_port *C.struct_net_api_vlan_port_q) C.int {
	printf("net_vlan_port_add ")
	printf("Dev: %-8s ", c16str(vlan_port.dev))
	printf("Tagged: %5t ", vlan_port.tagged)
	printf("VID: %-3d ", vlan_port.vid)
	printf("\n")
	return C.NL_OK
}

//export net_vlan_port_del
func net_vlan_port_del(vlan_port *C.struct_net_api_vlan_port_q) C.int {
	printf("net_vlan_port_del ")
	printf("Dev: %-8s ", c16str(vlan_port.dev))
	printf("Tagged: %5t ", vlan_port.tagged)
	printf("VID: %-3d ", vlan_port.vid)
	printf("\n")
	return C.NL_OK
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
	return C.NL_OK
}

//export net_neigh_del
func net_neigh_del(neigh *C.struct_net_api_neigh_q) C.int {
	printf("net_neigh_del ")
	printf("IP: %-33s ", c46str(neigh.ip))
	printf("\n")
	return C.NL_OK
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
	return C.NL_OK
}

//export net_fdb_del
func net_fdb_del(fdb *C.struct_net_api_fdb_q) C.int {
	printf("net_fdb_del ")
	printf("MacAddr: [%3d,%3d,%3d,%3d,%3d,%3d] ", fdb.mac_addr[0],
		fdb.mac_addr[1], fdb.mac_addr[2], fdb.mac_addr[3],
		fdb.mac_addr[4], fdb.mac_addr[5])
	printf("BridgeID: %d ", fdb.bridge_id)
	printf("\n")
	return C.NL_OK
}

//export net_addr_add
func net_addr_add(addr *C.struct_net_api_addr_q) C.int {
	printf("net_addr_add ")
	printf("Dev: %-8s ", c16str(addr.dev))
	printf("IP: %-33s", c50str(addr.ip))
	printf("\n")
	return C.NL_OK
}

//export net_addr_del
func net_addr_del(addr *C.struct_net_api_addr_q) C.int {
	printf("net_addr_del ")
	printf("Dev: %-8s ", c16str(addr.dev))
	printf("IP: %-33s", c50str(addr.ip))
	return C.NL_OK
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
	return C.NL_OK
}

//export net_route_del
func net_route_del(route *C.struct_net_api_route_q) C.int {
	printf("net_route_del ")
	printf("Dst: %-33s ", c50str(route.dst))
	printf("\n")
	return C.NL_OK
}

//export apply_config_map
func apply_config_map(name *C.char, state, add C.bool) {
	return
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
	return fmt.Printf(format, args...)
}

func netlinkMonitor() {
	C.nl_bridge_list()
	C.nl_link_list()
	go func() {
		C.nl_link_subscribe()
	}()
	go func() {
		C.nl_neigh_subscribe()
	}()
	go func() {
		C.nl_route_subscribe()
	}()
	go func() {
		C.nl_link_subscribe()
	}()
}
