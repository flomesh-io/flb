#include <net_api.h>
#include <nlp.h>
#include <regex.h>
#include <unistd.h>

static inline void debug_link(nl_port_mod_t *port) {
  printf("Master: %2d Index: %2d MTU: %5d "
         "MAC: %02x:%02x:%02x:%02x:%02x:%02x "
         "State: %d IFNAME: %8s ",
         port->master_index, port->index, port->mtu, port->hwaddr[0],
         port->hwaddr[1], port->hwaddr[2], port->hwaddr[3], port->hwaddr[4],
         port->hwaddr[5], port->oper_state, port->name);
  if (port->type.vxlan) {
    printf("Type: vxlan vxlan_id: %3d vtep_dev_index: %d",
           port->u.vxlan.vxlan_id, port->u.vxlan.vtep_dev_index);
  } else if (port->type.bridge) {
    printf("Type: bridge");
  } else if (port->type.bond) {
    printf("Type: bond");
  } else if (port->type.ipip) {
    printf("Type: iptun");
  }
  printf("\n");
}

int nl_link_mod(nl_port_mod_t *port, bool add) {
  bool link_state = (port->flags & FLAG_UP) == 1;
  bool state = port->oper_state != OPER_DOWN;
  int vid = 0;
  int ret;
  if (port->type.bridge) {
    regex_t regex;
    const size_t nmatch = 1;
    regmatch_t pmatch[1];
    regcomp(&regex, "[0-9]+", REG_EXTENDED);
    int status = regexec(&regex, (char *)port->name, nmatch, pmatch, 0);
    if (status == 0) {
      char str_buf[IF_NAMESIZE];
      strncpy(str_buf, (char *)port->name + pmatch[0].rm_so,
              pmatch[0].rm_eo - pmatch[0].rm_so);
      vid = atoi(str_buf);
    }
    regfree(&regex);
    if (vid == 0 && strcmp((char *)port->name, "docker0") == 0) {
      // Dirty hack to support docker0 bridge
      vid = 4090;
    }

    struct net_api_vlan_q vlan_q;
    memset(&vlan_q, 0, sizeof(vlan_q));
    vlan_q.vid = vid;
    if (add) {
      vlan_q.link_index = port->index;
      vlan_q.link = link_state;
      vlan_q.state = state;
      vlan_q.mtu = port->mtu;
      vlan_q.tun_id = 0;
      memcpy(vlan_q.dev, port->name, IF_NAMESIZE);
      memcpy(vlan_q.mac_addr, port->hwaddr, 6);
      ret = net_vlan_add(&vlan_q);
    } else {
      ret = net_vlan_del(&vlan_q);
    }

    if ((add && ret != 0) || !add) {
      apply_config_map((char *)port->name, state, add);
    }
  }

  char master[IF_NAMESIZE];
  memset(master, 0, IF_NAMESIZE);
  if (port->master_index > 0) {
    char if_name_buf[IF_NAMESIZE];
    regex_t regex;
    const size_t nmatch = 1;
    regmatch_t pmatch[1];
    regcomp(&regex, "[0-9]+", REG_EXTENDED);
    if_indextoname(port->master_index, if_name_buf);
    int status = regexec(&regex, (char *)if_name_buf, nmatch, pmatch, 0);
    if (status == 0) {
      char str_buf[IF_NAMESIZE];
      strncpy(str_buf, (char *)if_name_buf + pmatch[0].rm_so,
              pmatch[0].rm_eo - pmatch[0].rm_so);
      vid = atoi(str_buf);
    }
    regfree(&regex);
    if (vid == 0 && strcmp((char *)if_name_buf, "docker0") == 0) {
      // Dirty hack to support docker0 bridge
      vid = 4090;
    }

    /* Tagged Vlan port */
    char *p_pos = strchr((char *)port->name, '.');
    if ((void *)p_pos > (void *)port->name) {
      struct net_api_vlan_port_q vlan_port_q;
      memset(&vlan_port_q, 0, sizeof(vlan_port_q));
      vlan_port_q.vid = vid;
      vlan_port_q.tagged = true;

      strncpy((char *)vlan_port_q.dev, (char *)port->name,
              (void *)p_pos - (void *)port->name - 1);
      if (add) {
        net_vlan_port_add(&vlan_port_q);
      } else {
        net_vlan_port_del(&vlan_port_q);
      }
      apply_config_map((char *)port->name, state, add);
      return ret;
    } else {
      nl_port_mod_t mif;
      memset(&mif, 0, sizeof(nl_port_mod_t));
      ret = nl_link_get(port->master_index, &mif);
      if (ret < 0) {
        return ret;
      }
      if (mif.type.bond) {
        memcpy(master, mif.name, IF_NAMESIZE);
      }
    }
  }

  /* Physical port/ Bond/ VxLAN */
  char real[IF_NAMESIZE];
  int p_type = PORT_REAL;
  int tun_id = 0;
  int tun_src = 0;
  int tun_dst = 0;
  memset(real, 0, IF_NAMESIZE);
  if (strstr((char *)port->name, "ipsec") != NULL ||
      strstr((char *)port->name, "vti") != NULL) {
    p_type = PORT_VTI;
  } else if (strstr((char *)port->name, "wg") != NULL) {
    p_type = PORT_WG;
  }

  if (port->type.vxlan) {
    p_type = PORT_VXLAN_BR;
    tun_id = port->u.vxlan.vxlan_id;
    if_indextoname(port->u.vxlan.vtep_dev_index, real);
  } else if (port->type.bond) {
    p_type = PORT_BOND;
  } else if (port->type.ipip) {
    p_type = PORT_IPTUN;
    if (port->u.iptun.local == 0 || port->u.iptun.remote == 0) {
      return ret;
    }
    tun_id = 1;
    tun_src = port->u.iptun.local;
    tun_dst = port->u.iptun.remote;
  } else if (strlen(master) > 0) {
    p_type = PORT_BOND_SLAVE_IF;
  }

  struct net_api_port_q port_q;
  memset(&port_q, 0, sizeof(port_q));
  port_q.link_type = p_type;
  memcpy(port_q.dev, port->name, IF_NAMESIZE);
  if (add) {
    port_q.link_index = port->index;
    port_q.link = link_state;
    port_q.state = state;
    port_q.mtu = port->mtu;
    port_q.tun_id = tun_id;
    memcpy(port_q.mac_addr, port->hwaddr, ETH_ALEN);

    struct in_addr *tun_src_in = (struct in_addr *)&tun_src;
    inet_ntop(AF_INET, tun_src_in, (char *)port_q.tun_src, INET_ADDRSTRLEN);

    struct in_addr *tun_dst_in = (struct in_addr *)&tun_dst;
    inet_ntop(AF_INET, tun_dst_in, (char *)port_q.tun_dst, INET_ADDRSTRLEN);

    if (strlen(master) > 0) {
      memcpy(port_q.master, master, IF_NAMESIZE);
    }
    if (strlen(real) > 0) {
      memcpy(port_q.real, real, IF_NAMESIZE);
    }
    ret = net_port_add(&port_q);
    apply_config_map((char *)port->name, state, add);
  } else if (port->master_index == 0) {
    ret = net_port_del(&port_q);
    apply_config_map((char *)port->name, state, add);
    return ret;
  }

  /* Untagged vlan ports */
  if (port->master_index > 0 && strlen(master) > 0) {
    struct net_api_vlan_port_q vlan_port_q;
    memset(&vlan_port_q, 0, sizeof(vlan_port_q));
    vlan_port_q.vid = vid;
    vlan_port_q.tagged = false;
    memcpy(vlan_port_q.dev, port->name, IF_NAMESIZE);
    if (add) {
      ret = net_vlan_port_add(&vlan_port_q);
    } else {
      ret = net_vlan_port_del(&vlan_port_q);
    }
    if ((add && ret < 0) || !add) {
      apply_config_map((char *)port->name, state, add);
    }
  }

  return ret;
}

int nl_link_list_res(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
    return NL_SKIP;
  }

  struct ifinfomsg *ifi_msg = NLMSG_DATA(nlh);
  struct nl_multi_arg *args = (struct nl_multi_arg *)arg;
  bool only_bridges = *(bool *)args->arg1;
  bool only_links = *(bool *)args->arg2;
  bool add = nlh->nlmsg_type == RTM_NEWLINK;

  struct rtattr *attrs[IFLA_MAX + 1];
  int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi_msg));
  parse_rtattr(attrs, IFLA_MAX, IFLA_RTA(ifi_msg), remaining);

  nl_port_mod_t port;
  memset(&port, 0, sizeof(port));
  port.index = ifi_msg->ifi_index;
  port.flags = ifi_msg->ifi_flags;

  struct rtattr *info = attrs[IFLA_LINKINFO];
  if (info) {
    struct rtattr *info_attrs[IFLA_INFO_MAX + 1];
    parse_rtattr(info_attrs, IFLA_INFO_MAX, RTA_DATA(info), RTA_PAYLOAD(info));
    char *kind = (char *)RTA_DATA(info_attrs[IFLA_INFO_KIND]);
    if (only_bridges && strcmp(kind, "bridge") != 0) {
      return NL_SKIP;
    }
    if (strcmp(kind, "bridge") == 0) {
      port.type.bridge = 1;
    } else if (strcmp(kind, "bond") == 0) {
      port.type.bond = 1;
    } else if (strcmp(kind, "vxlan") == 0) {
      struct rtattr *info_data = info_attrs[IFLA_INFO_DATA];
      struct rtattr *vxlan_attrs[IFLA_VXLAN_MAX + 1];
      parse_rtattr(vxlan_attrs, IFLA_VXLAN_MAX, RTA_DATA(info_data),
                   RTA_PAYLOAD(info_data));
      if (vxlan_attrs[IFLA_VXLAN_ID]) {
        port.u.vxlan.vxlan_id = *(__u32 *)RTA_DATA(vxlan_attrs[IFLA_VXLAN_ID]);
      }
      if (vxlan_attrs[IFLA_VXLAN_LINK]) {
        port.u.vxlan.vtep_dev_index =
            *(__u32 *)RTA_DATA(vxlan_attrs[IFLA_VXLAN_LINK]);
      }
      port.type.vxlan = 1;
    } else if (strcmp(kind, "ipip") == 0) {
      struct rtattr *info_data = info_attrs[IFLA_INFO_DATA];
      struct rtattr *iptun_attrs[IFLA_IPTUN_MAX + 1];
      parse_rtattr(iptun_attrs, IFLA_IPTUN_MAX, RTA_DATA(info_data),
                   RTA_PAYLOAD(info_data));
      if (iptun_attrs[IFLA_IPTUN_LOCAL]) {
        port.u.iptun.local = *(__u32 *)RTA_DATA(iptun_attrs[IFLA_IPTUN_LOCAL]);
      }
      if (iptun_attrs[IFLA_IPTUN_REMOTE]) {
        port.u.iptun.remote =
            *(__u32 *)RTA_DATA(iptun_attrs[IFLA_IPTUN_REMOTE]);
      }
      port.type.ipip = 1;
    }
  } else if (only_bridges) {
    return NL_SKIP;
  }

  if (attrs[IFLA_IFNAME]) {
    __u8 *ifname = (__u8 *)RTA_DATA(attrs[IFLA_IFNAME]);
    memcpy(port.name, ifname, attrs[IFLA_IFNAME]->rta_len - 4);
  }

  if (attrs[IFLA_MASTER]) {
    port.master_index = *(__u32 *)RTA_DATA(attrs[IFLA_MASTER]);
  }

  if (add) {
    if (attrs[IFLA_MTU]) {
      port.mtu = *(__u32 *)RTA_DATA(attrs[IFLA_MTU]);
    }
    if (attrs[IFLA_OPERSTATE]) {
      port.oper_state = *(__u8 *)RTA_DATA(attrs[IFLA_OPERSTATE]);
    }
    if (attrs[IFLA_ADDRESS]) {
      __u8 *hwaddr = (__u8 *)RTA_DATA(attrs[IFLA_ADDRESS]);
      memcpy(port.hwaddr, hwaddr, attrs[IFLA_ADDRESS]->rta_len - 4);
    }
  }

  int ret = nl_link_mod(&port, add);
  if (ret < 0) {
    return NL_SKIP;
  }

  if (only_links) {
    return NL_OK;
  }

  /* Get FDBs */
  if (port.master_index > 0 || port.type.vxlan) {
    nl_neigh_list(&port, AF_BRIDGE);
  }

  nl_addr_list(&port, FAMILY_ALL);
  nl_neigh_list(&port, FAMILY_ALL);
  nl_route_list(&port, FAMILY_ALL);
  // debug_link(&port);

  return NL_OK;
}

static inline int _internal_nl_link_list(bool only_bridges) {
  struct nl_sock *socket = nl_socket_alloc();
  nl_connect(socket, NETLINK_ROUTE);

  struct nl_msg *msg = nlmsg_alloc();

  struct {
    struct ifinfomsg ifh;
    struct {
      __u16 rta_len;
      __u16 rta_type;
      __u32 rta_val;
    } rtattr;
  } * nl_req;

  struct nlmsghdr *nlh = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETLINK,
                                   sizeof(*nl_req), NLM_F_REQUEST | NLM_F_DUMP);

  nl_req = nlmsg_data(nlh);
  memset(nl_req, 0, sizeof(*nl_req));
  nl_req->ifh.ifi_family = AF_UNSPEC;
  nl_req->rtattr.rta_type = IFLA_EXT_MASK;
  nl_req->rtattr.rta_len = 8;
  nl_req->rtattr.rta_val = RTEXT_FILTER_VF;

  int ret = nl_send_auto_complete(socket, msg);
  if (ret < 0) {
    nlmsg_free(msg);
    nl_socket_free(socket);
    return ret;
  }

  bool only_links = false;
  struct nl_multi_arg args = {
      .arg1 = &only_bridges,
      .arg2 = &only_links,
  };
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_link_list_res,
                      &args);
  nl_recvmsgs_default(socket);

  nlmsg_free(msg);
  nl_socket_free(socket);

  return 0;
}

int nl_bridge_list() { return _internal_nl_link_list(true); }

int nl_link_list() { return _internal_nl_link_list(false); }

int nl_link_get_res(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  struct ifinfomsg *link_msg = NLMSG_DATA(nlh);
  struct rtattr *attrs[IFLA_MAX + 1];
  int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*link_msg));
  parse_rtattr(attrs, IFLA_MAX, IFLA_RTA(link_msg), remaining);

  nl_port_mod_t *port = *((nl_port_mod_t **)arg);
  port->index = link_msg->ifi_index;
  port->flags = link_msg->ifi_flags;

  if (attrs[IFLA_MASTER]) {
    port->master_index = *(__u32 *)RTA_DATA(attrs[IFLA_MASTER]);
  }

  if (attrs[IFLA_IFNAME]) {
    __u8 *ifname = (__u8 *)RTA_DATA(attrs[IFLA_IFNAME]);
    memcpy(port->name, ifname, attrs[IFLA_IFNAME]->rta_len - 4);
  }

  if (attrs[IFLA_MTU]) {
    port->mtu = *(__u32 *)RTA_DATA(attrs[IFLA_MTU]);
  }

  if (attrs[IFLA_OPERSTATE]) {
    port->oper_state = *(__u8 *)RTA_DATA(attrs[IFLA_OPERSTATE]);
  }

  if (attrs[IFLA_ADDRESS]) {
    __u8 *hwaddr = (__u8 *)RTA_DATA(attrs[IFLA_ADDRESS]);
    memcpy(port->hwaddr, hwaddr, attrs[IFLA_ADDRESS]->rta_len - 4);
  }

  struct rtattr *info = attrs[IFLA_LINKINFO];
  if (info) {
    struct rtattr *info_attrs[IFLA_INFO_MAX + 1];
    parse_rtattr(info_attrs, IFLA_INFO_MAX, RTA_DATA(info), RTA_PAYLOAD(info));
    char *kind = (char *)RTA_DATA(info_attrs[IFLA_INFO_KIND]);
    if (strcmp(kind, "bridge") == 0) {
      port->type.bridge = 1;
    } else if (strcmp(kind, "bond") == 0) {
      port->type.bond = 1;
    } else if (strcmp(kind, "vxlan") == 0) {
      struct rtattr *info_data = info_attrs[IFLA_INFO_DATA];
      struct rtattr *vxlan_attrs[IFLA_VXLAN_MAX + 1];
      parse_rtattr(vxlan_attrs, IFLA_VXLAN_MAX, RTA_DATA(info_data),
                   RTA_PAYLOAD(info_data));
      if (vxlan_attrs[IFLA_VXLAN_ID]) {
        port->u.vxlan.vxlan_id = *(__u32 *)RTA_DATA(vxlan_attrs[IFLA_VXLAN_ID]);
      }
      if (vxlan_attrs[IFLA_VXLAN_LINK]) {
        port->u.vxlan.vtep_dev_index =
            *(__u32 *)RTA_DATA(vxlan_attrs[IFLA_VXLAN_LINK]);
      }
      port->type.vxlan = 1;
    } else if (strcmp(kind, "ipip") == 0) {
      struct rtattr *info_data = info_attrs[IFLA_INFO_DATA];
      struct rtattr *iptun_attrs[IFLA_IPTUN_MAX + 1];
      parse_rtattr(iptun_attrs, IFLA_IPTUN_MAX, RTA_DATA(info_data),
                   RTA_PAYLOAD(info_data));
      if (iptun_attrs[IFLA_IPTUN_LOCAL]) {
        port->u.iptun.local = *(__u32 *)RTA_DATA(iptun_attrs[IFLA_IPTUN_LOCAL]);
      }
      if (iptun_attrs[IFLA_IPTUN_REMOTE]) {
        port->u.iptun.remote =
            *(__u32 *)RTA_DATA(iptun_attrs[IFLA_IPTUN_REMOTE]);
      }
      port->type.ipip = 1;
    }
  }

  return NL_OK;
}

int nl_link_get(int ifi_index, nl_port_mod_t *port) {
  struct nl_sock *socket = nl_socket_alloc();
  nl_connect(socket, NETLINK_ROUTE);

  struct nl_msg *msg = nlmsg_alloc();

  struct {
    struct ifinfomsg ifh;
    struct {
      __u16 rta_len;
      __u16 rta_type;
      __u32 rta_val;
    } rtattr;
  } * nl_req;

  struct nlmsghdr *nlh = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETLINK,
                                   sizeof(*nl_req), NLM_F_REQUEST | NLM_F_ACK);

  nl_req = nlmsg_data(nlh);
  memset(nl_req, 0, sizeof(*nl_req));
  nl_req->ifh.ifi_family = AF_UNSPEC;
  nl_req->ifh.ifi_index = ifi_index;
  nl_req->rtattr.rta_type = IFLA_EXT_MASK;
  nl_req->rtattr.rta_len = 8;
  nl_req->rtattr.rta_val = RTEXT_FILTER_VF;

  int ret = nl_send_auto_complete(socket, msg);
  if (ret < 0) {
    nlmsg_free(msg);
    nl_socket_free(socket);
    return ret;
  }

  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_link_get_res,
                      (void *)(&port));
  nl_recvmsgs_default(socket);

  nlmsg_free(msg);
  nl_socket_free(socket);

  return ret;
}

int nl_link_subscribe() {
  bool only_bridges = false;
  bool only_links = true;
  struct nl_multi_arg args = {
      .arg1 = &only_bridges,
      .arg2 = &only_links,
  };
  struct nl_sock *socket = nl_socket_alloc();
  nl_socket_disable_seq_check(socket);
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_link_list_res,
                      &args);
  nl_connect(socket, NETLINK_ROUTE);
  nl_socket_add_memberships(socket, RTNLGRP_LINK);
  while (1) {
    nl_recvmsgs_default(socket);
  }
  nl_socket_free(socket);
  return 0;
}
