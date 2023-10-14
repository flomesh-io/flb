#include <net_api.h>
#include <nlp.h>
#include <regex.h>
#include <unistd.h>

#ifndef NDM_RTA
#define NDM_RTA(r)                                                             \
  ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#ifndef NDM_PAYLOAD
#define NDM_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

static inline void debug_neigh(nl_neigh_mod_t *neigh) {
  printf("Neigh Master: %2d ", neigh->master_index);
  printf("Index: %2d ", neigh->link_index);

  printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x ", neigh->hwaddr[0],
         neigh->hwaddr[1], neigh->hwaddr[2], neigh->hwaddr[3], neigh->hwaddr[4],
         neigh->hwaddr[5]);
  printf("State: %d ", neigh->state);

  if (neigh->ip.f.v4) {
    struct in_addr *in = (struct in_addr *)neigh->ip.v4.bytes;
    printf("IP: %s ", inet_ntoa(*in));
  } else if (neigh->ip.f.v6) {
    struct in6_addr *in = (struct in6_addr *)neigh->ip.v6.bytes;
    char a_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, a_str, INET6_ADDRSTRLEN);
    printf("IP: %s ", a_str);
  }

  printf("\n");
}

int nl_neigh_mod(nl_neigh_mod_t *neigh, struct nl_port_mod *port, bool add) {
  if (add) {
    if (is_zero_mac(neigh->hwaddr)) {
      return NL_SKIP;
    }
  }

  if (neigh->family == AF_INET || neigh->family == AF_INET6) {
    struct net_api_neigh_q neigh_q;
    memset(&neigh_q, 0, sizeof(neigh_q));
    if (neigh->ip.f.v4) {
      struct in_addr *in = (struct in_addr *)neigh->ip.v4.bytes;
      inet_ntop(AF_INET, in, (char *)neigh_q.ip, INET_ADDRSTRLEN);
    } else if (neigh->ip.f.v6) {
      struct in6_addr *in = (struct in6_addr *)neigh->ip.v6.bytes;
      inet_ntop(AF_INET6, in, (char *)neigh_q.ip, INET6_ADDRSTRLEN);
    }
    if (add) {
      neigh_q.link_index = neigh->link_index;
      neigh_q.state = neigh->state;
      memcpy(neigh_q.hwaddr, neigh->hwaddr, ETH_ALEN);
      return net_neigh_add(&neigh_q);
    } else {
      return net_neigh_del(&neigh_q);
    }
  } else if (neigh->family == AF_BRIDGE) {
    if (neigh->vlan == 1) {
      /*FDB comes with vlan 1 also */
      return NL_SKIP;
    }
    if (!add) {
      if (is_zero_mac(neigh->hwaddr)) {
        return NL_SKIP;
      }
    }
    if ((neigh->hwaddr[0] & 0x01) == 1 || neigh->hwaddr[0] == 0) {
      /* Multicast MAC or ZERO address --- IGNORED */
      return NL_SKIP;
    }

    int brId = 0;
    int ftype;
    __u8 dst[INET6_ADDRSTRLEN];

    memset(dst, 0, INET_ADDRSTRLEN);

    if (neigh->master_index > 0) {
      nl_port_mod_t brLink;
      if (nl_link_get(neigh->master_index, &brLink) < 0) {
        return -1;
      }
      if (memcmp(brLink.hwaddr, neigh->hwaddr, 6) == 0) {
        /*Same as bridge mac --- IGNORED */
        return 0;
      }

      regex_t regex;
      const size_t nmatch = 1;
      regmatch_t pmatch[1];
      regcomp(&regex, "[0-9]+", REG_EXTENDED);
      int status = regexec(&regex, (char *)brLink.name, nmatch, pmatch, 0);
      if (status == 0) {
        char str_buf[IF_NAMESIZE];
        strncpy(str_buf, (char *)brLink.name + pmatch[0].rm_so,
                pmatch[0].rm_eo - pmatch[0].rm_so);
        brId = atoi(str_buf);
      }
      regfree(&regex);
    }

    if (port == NULL) {
      nl_port_mod_t l_port;
      memset(&l_port, 0, sizeof(l_port));
      if (nl_link_get(neigh->link_index, &l_port) < 0) {
        return NL_SKIP;
      }
      port = &l_port;
    }
    if (port->type.vxlan) {
      /* Interested in only VxLAN FDB */
      if ((neigh->ip.f.v4 || neigh->ip.f.v6) && neigh->master_index == 0) {
        if (neigh->ip.f.v4) {
          struct in_addr *in = (struct in_addr *)neigh->ip.v4.bytes;
          inet_ntop(AF_INET, in, (char *)dst, INET_ADDRSTRLEN);
        } else if (neigh->ip.f.v6) {
          struct in6_addr *in = (struct in6_addr *)neigh->ip.v6.bytes;
          inet_ntop(AF_INET6, in, (char *)dst, INET6_ADDRSTRLEN);
        }
        brId = port->u.vxlan.vxlan_id;
        ftype = FDB_TUN;
      } else {
        return 0;
      }
    } else {
      memset(dst, 0, INET_ADDRSTRLEN);
      ftype = FDB_VLAN;
    }

    struct net_api_fdb_q fdb_q;
    memset(&fdb_q, 0, sizeof(fdb_q));
    fdb_q.bridge_id = brId;
    memcpy(fdb_q.mac_addr, neigh->hwaddr, ETH_ALEN);
    if (add) {
      fdb_q.fdb_type = ftype;
      memcpy(fdb_q.dev, port->name, IF_NAMESIZE);
      memcpy(fdb_q.dst, dst, INET6_ADDRSTRLEN);
      return net_fdb_add(&fdb_q);
    } else {
      return net_fdb_del(&fdb_q);
    }
  }
  return 0;
}

int nl_neigh_list_res(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
    return NL_SKIP;
  }

  struct ndmsg *neigh_msg = NLMSG_DATA(nlh);
  struct nl_port_mod *port = NULL;
  if (arg != NULL) {
    struct nl_multi_arg *args = (struct nl_multi_arg *)arg;
    port = (struct nl_port_mod *)args->arg1;
    struct ndmsg *nl_req = (struct ndmsg *)args->arg2;

    if (nl_req->ndm_ifindex != 0 &&
        nl_req->ndm_ifindex != neigh_msg->ndm_ifindex) {
      return NL_SKIP;
    }

    if (nl_req->ndm_family != 0 &&
        nl_req->ndm_family != neigh_msg->ndm_family) {
      return NL_SKIP;
    }

    if (nl_req->ndm_state != 0 && nl_req->ndm_state != neigh_msg->ndm_state) {
      return NL_SKIP;
    }

    if (nl_req->ndm_type != 0 && nl_req->ndm_type != neigh_msg->ndm_type) {
      return NL_SKIP;
    }

    if (nl_req->ndm_flags != 0 && nl_req->ndm_flags != neigh_msg->ndm_flags) {
      return NL_SKIP;
    }
  }

  bool add = nlh->nlmsg_type == RTM_NEWNEIGH;

  struct rtattr *attrs[NDA_MAX + 1];
  int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*neigh_msg));
  parse_rtattr(attrs, NDA_MAX, NDM_RTA(neigh_msg), remaining);

  nl_neigh_mod_t neigh;
  memset(&neigh, 0, sizeof(neigh));
  neigh.link_index = neigh_msg->ndm_ifindex;
  neigh.family = neigh_msg->ndm_family;
  neigh.state = neigh_msg->ndm_state;
  neigh.type = neigh_msg->ndm_type;
  neigh.flags = neigh_msg->ndm_flags;

  if (attrs[NDA_MASTER]) {
    neigh.master_index = *(__u32 *)RTA_DATA(attrs[NDA_MASTER]);
  }

  if (attrs[NDA_VNI]) {
    neigh.vni = *(__u32 *)RTA_DATA(attrs[NDA_VNI]);
  }

  if (attrs[NDA_VLAN]) {
    neigh.vlan = *(__u32 *)RTA_DATA(attrs[NDA_VLAN]);
  }

  if (attrs[NDA_DST]) {
    struct rtattr *dst_addr = attrs[NDA_DST];
    __u8 *rta_val = (__u8 *)RTA_DATA(dst_addr);
    if (dst_addr->rta_len == 8) {
      neigh.ip.f.v4 = 1;
      memcpy(neigh.ip.v4.bytes, rta_val, 4);
    } else if (dst_addr->rta_len == 20) {
      neigh.ip.f.v6 = 1;
      memcpy(neigh.ip.v6.bytes, rta_val, 16);
    }
  }

  if (attrs[NDA_LLADDR]) {
    struct rtattr *ll_addr = attrs[NDA_LLADDR];
    __u8 *rta_val = (__u8 *)RTA_DATA(ll_addr);
    if (ll_addr->rta_len == 8) {
      neigh.ll_ip_addr.f.v4 = 1;
      memcpy(neigh.ll_ip_addr.v4.bytes, rta_val, 4);
    } else if (ll_addr->rta_len == 20) {
      // Can be IPv6 or FireWire HWAddr
      neigh.ll_ip_addr.f.v6 = 1;
      memcpy(neigh.ll_ip_addr.v6.bytes, rta_val, 16);
    } else {
      memcpy(neigh.hwaddr, rta_val, ETH_ALEN);
    }
  }

  // debug_neigh(&neigh);
  return nl_neigh_mod(&neigh, port, add);
}

int nl_neigh_list(nl_port_mod_t *port, __u8 family) {
  struct nl_sock *socket = nl_socket_alloc();
  nl_connect(socket, NETLINK_ROUTE);

  struct nl_msg *msg = nlmsg_alloc();

  struct ndmsg *nl_req;

  struct nlmsghdr *nlh = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETNEIGH,
                                   sizeof(*nl_req), NLM_F_REQUEST | NLM_F_DUMP);

  nl_req = nlmsg_data(nlh);
  memset(nl_req, 0, sizeof(*nl_req));
  nl_req->ndm_family = family;
  nl_req->ndm_ifindex = port->index;

  int ret = nl_send_auto_complete(socket, msg);
  if (ret < 0) {
    nlmsg_free(msg);
    nl_socket_free(socket);
    return ret;
  }

  struct nl_multi_arg args = {
      .arg1 = port,
      .arg2 = nl_req,
  };
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_neigh_list_res,
                      &args);
  nl_recvmsgs_default(socket);

  nlmsg_free(msg);
  nl_socket_free(socket);

  return 0;
}

int nl_neigh_subscribe() {
  struct nl_sock *socket = nl_socket_alloc();
  nl_socket_disable_seq_check(socket);
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_neigh_list_res,
                      NULL);
  nl_connect(socket, NETLINK_ROUTE);
  nl_socket_add_memberships(socket, RTNLGRP_NEIGH);
  while (1) {
    nl_recvmsgs_default(socket);
  }
  nl_socket_free(socket);
  return 0;
}