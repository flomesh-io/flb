#ifndef __FLB_NET_API_H__
#define __FLB_NET_API_H__

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <net/if.h>
#include <stdbool.h>

struct net_api_port_q {
  __u8 dev[IF_NAMESIZE];
  __u32 link_index;
  __u32 link_type;
  __u8 mac_addr[ETH_ALEN];
  bool link;  // link - lowerlayer state
  bool state; // state - administrative state
  __u32 mtu;
  __u8 master[IF_NAMESIZE];
  __u8 real[IF_NAMESIZE];
  __u32 tun_id;
  __u8 tun_src[INET_ADDRSTRLEN];
  __u8 tun_dst[INET_ADDRSTRLEN];
};

struct net_api_vlan_q {
  __u32 vid;
  __u8 dev[IF_NAMESIZE];
  __u32 link_index;
  __u8 mac_addr[ETH_ALEN];
  bool link;
  bool state;
  __u32 mtu;
  __u32 tun_id;
};

struct net_api_vlan_port_q {
  __u32 vid;
  __u8 dev[IF_NAMESIZE];
  bool tagged;
};

struct net_api_neigh_q {
  __u8 ip[INET6_ADDRSTRLEN];
  __u32 link_index;
  __u32 state;
  __u8 hwaddr[ETH_ALEN];
};

struct net_api_fdb_q {
  __u8 mac_addr[ETH_ALEN];
  __u32 bridge_id;
  __u8 dst[INET6_ADDRSTRLEN];
  __u32 fdb_type;
  __u8 dev[IF_NAMESIZE];
};

struct net_api_addr_q {
  __u8 dev[IF_NAMESIZE];
  __u8 ip[INET6_ADDRSTRLEN + 4];
};

struct net_api_route_q {
  __u32 link_index;
  __u32 protocol;
  __u32 flags;
  __u8 gw[INET6_ADDRSTRLEN];
  __u8 dst[INET6_ADDRSTRLEN + 4];
};

int net_port_add(struct net_api_port_q *port);
int net_port_del(struct net_api_port_q *port);
int net_vlan_add(struct net_api_vlan_q *vlan);
int net_vlan_del(struct net_api_vlan_q *vlan);
int net_vlan_port_add(struct net_api_vlan_port_q *vlan_port);
int net_vlan_port_del(struct net_api_vlan_port_q *vlan_port);
int net_neigh_add(struct net_api_neigh_q *neigh);
int net_neigh_del(struct net_api_neigh_q *neigh);
int net_fdb_add(struct net_api_fdb_q *fdb);
int net_fdb_del(struct net_api_fdb_q *fdb);
int net_addr_add(struct net_api_addr_q *addr);
int net_addr_del(struct net_api_addr_q *addr);
int net_route_add(struct net_api_route_q *route);
int net_route_del(struct net_api_route_q *route);

void apply_config_map(char *name, bool state, bool add);

#endif /* __FLB_NET_API_H__ */