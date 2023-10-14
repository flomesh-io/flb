#include <net_api.h>
#include <nlp.h>
#include <regex.h>
#include <unistd.h>

static inline void debug_addr(nl_addr_mod_t *addr) {
  printf("Addr Link Index: %2d ", addr->link_index);

  if (addr->peer.ip.f.v4) {
    struct in_addr *in = (struct in_addr *)addr->peer.ip.v4.bytes;
    printf("peer: %s/%d ", inet_ntoa(*in), addr->peer.mask);
  } else if (addr->peer.ip.f.v6) {
    struct in6_addr *in = (struct in6_addr *)addr->peer.ip.v6.bytes;
    char a_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, a_str, INET6_ADDRSTRLEN);
    printf("peer: %s/%d ", a_str, addr->peer.mask);
  }

  if (addr->ipnet.ip.f.v4) {
    struct in_addr *in = (struct in_addr *)addr->ipnet.ip.v4.bytes;
    printf("ipnet: %s/%d ", inet_ntoa(*in), addr->ipnet.mask);
  } else if (addr->ipnet.ip.f.v6) {
    struct in6_addr *in = (struct in6_addr *)addr->ipnet.ip.v6.bytes;
    char a_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, a_str, INET6_ADDRSTRLEN);
    printf("ipnet: %s/%d ", a_str, addr->ipnet.mask);
  }

  if (addr->broadcast.f.v4) {
    struct in_addr *in = (struct in_addr *)addr->broadcast.v4.bytes;
    printf("broadcast: %s ", inet_ntoa(*in));
  } else if (addr->broadcast.f.v6) {
    struct in6_addr *in = (struct in6_addr *)addr->broadcast.v6.bytes;
    char a_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, a_str, INET6_ADDRSTRLEN);
    printf("broadcast: %s ", a_str);
  }

  printf("scope: %d ", addr->scope);

  printf("\n");
}

int nl_addr_mod(nl_addr_mod_t *addr, struct nl_port_mod *port, bool add) {
  if (port == NULL) {
    nl_port_mod_t l_port;
    memset(&l_port, 0, sizeof(l_port));
    if (nl_link_get(addr->link_index, &l_port) < 0) {
      return NL_SKIP;
    }
    port = &l_port;
  }

  struct net_api_addr_q addr_q;
  memset(&addr_q, 0, sizeof(addr_q));

  if (addr->ipnet.ip.f.v4) {
    struct in_addr *in = (struct in_addr *)addr->ipnet.ip.v4.bytes;
    inet_ntop(AF_INET, in, (char *)(addr_q.ip), INET_ADDRSTRLEN);
    sprintf((char *)((void *)addr_q.ip + strlen((char *)addr_q.ip)), "/%d",
            addr->ipnet.mask);
  } else if (addr->ipnet.ip.f.v6) {
    struct in6_addr *in = (struct in6_addr *)addr->ipnet.ip.v6.bytes;
    inet_ntop(AF_INET6, in, (char *)addr_q.ip, INET6_ADDRSTRLEN);
    sprintf((char *)((void *)addr_q.ip + strlen((char *)addr_q.ip)), "/%d",
            addr->ipnet.mask);
  } else {
    return NL_SKIP;
  }

  memcpy(addr_q.dev, port->name, IF_NAMESIZE);

  if (add) {
    return net_addr_add(&addr_q);
  } else {
    return net_addr_del(&addr_q);
  }
}

int nl_addr_list_res(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
    return NL_SKIP;
  }
  if (nlh->nlmsg_type != RTM_NEWADDR && nlh->nlmsg_type != RTM_DELADDR) {
    return NL_SKIP;
  }

  struct ifaddrmsg *ifa_msg = NLMSG_DATA(nlh);
  struct nl_port_mod *port = NULL;
  if (arg != NULL) {
    struct nl_multi_arg *args = (struct nl_multi_arg *)arg;
    port = (struct nl_port_mod *)args->arg1;
    struct ifaddrmsg *nl_req = (struct ifaddrmsg *)args->arg2;

    if (nl_req->ifa_index != 0 && nl_req->ifa_index != ifa_msg->ifa_index) {
      return NL_SKIP;
    }

    if (nl_req->ifa_family != 0 && nl_req->ifa_family != ifa_msg->ifa_family) {
      return NL_SKIP;
    }
  }

  bool add = nlh->nlmsg_type == RTM_NEWADDR;

  struct rtattr *attrs[IFA_MAX + 1];
  int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa_msg));
  parse_rtattr(attrs, IFA_MAX, IFA_RTA(ifa_msg), remaining);

  __u8 family = ifa_msg->ifa_family;
  nl_addr_mod_t addr;
  memset(&addr, 0, sizeof(addr));
  addr.link_index = ifa_msg->ifa_index;

  nl_ipnet_t local, dst;
  bool has_local = false;
  memset(&local, 0, sizeof(local));
  memset(&dst, 0, sizeof(dst));
  if (attrs[IFA_ADDRESS]) {
    struct rtattr *ifa_addr = attrs[IFA_ADDRESS];
    __u8 *rta_val = (__u8 *)RTA_DATA(ifa_addr);
    if (ifa_addr->rta_len == 8) {
      dst.ip.f.v4 = 1;
      memcpy(dst.ip.v4.bytes, rta_val, 4);
      dst.mask = ifa_msg->ifa_prefixlen;
    } else if (ifa_addr->rta_len == 20) {
      dst.ip.f.v6 = 1;
      memcpy(dst.ip.v6.bytes, rta_val, 16);
      dst.mask = ifa_msg->ifa_prefixlen;
    }
  }
  if (attrs[IFA_LOCAL]) {
    struct rtattr *ifa_addr = attrs[IFA_LOCAL];
    __u8 *rta_val = (__u8 *)RTA_DATA(ifa_addr);
    if (ifa_addr->rta_len == 8) {
      local.ip.f.v4 = 1;
      memcpy(local.ip.v4.bytes, rta_val, 4);
      local.mask = 32;
      has_local = true;
    } else if (ifa_addr->rta_len == 20) {
      local.ip.f.v6 = 1;
      memcpy(local.ip.v6.bytes, rta_val, 16);
      local.mask = 128;
      has_local = true;
    }
  }
  if (attrs[IFA_BROADCAST]) {
    struct rtattr *ifa_addr = attrs[IFA_BROADCAST];
    __u8 *rta_val = (__u8 *)RTA_DATA(ifa_addr);
    if (ifa_addr->rta_len == 8) {
      addr.broadcast.f.v4 = 1;
      memcpy(addr.broadcast.v4.bytes, rta_val, 4);
    } else if (ifa_addr->rta_len == 20) {
      addr.broadcast.f.v6 = 1;
      memcpy(addr.broadcast.v6.bytes, rta_val, 16);
    }
  }

  if (has_local) {
    if (family == FAMILY_V4 &&
        memcmp(&local.ip, &dst.ip, sizeof(nl_ip_t)) == 0) {
      memcpy(&addr.ipnet, &dst, sizeof(nl_ipnet_t));
    } else {
      memcpy(&addr.ipnet, &local, sizeof(nl_ipnet_t));
      memcpy(&addr.peer, &dst, sizeof(nl_ipnet_t));
    }
  } else {
    memcpy(&addr.ipnet, &dst, sizeof(nl_ipnet_t));
  }

  addr.scope = ifa_msg->ifa_scope;

  // debug_addr(&addr);
  return nl_addr_mod(&addr, port, add);
}

int nl_addr_list(nl_port_mod_t *port, __u8 family) {
  struct nl_sock *socket = nl_socket_alloc();
  nl_connect(socket, NETLINK_ROUTE);

  struct nl_msg *msg = nlmsg_alloc();

  struct ifaddrmsg *nl_req;

  struct nlmsghdr *nlh = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETADDR,
                                   sizeof(*nl_req), NLM_F_REQUEST | NLM_F_DUMP);

  nl_req = nlmsg_data(nlh);
  memset(nl_req, 0, sizeof(*nl_req));
  nl_req->ifa_family = family;
  nl_req->ifa_index = port->index;

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
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_addr_list_res,
                      &args);
  nl_recvmsgs_default(socket);

  nlmsg_free(msg);
  nl_socket_free(socket);

  return 0;
}

int nl_addr_subscribe() {
  struct nl_sock *socket = nl_socket_alloc();
  nl_socket_disable_seq_check(socket);
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_addr_list_res,
                      NULL);
  nl_connect(socket, NETLINK_ROUTE);
  nl_socket_add_memberships(socket, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR);
  while (1) {
    nl_recvmsgs_default(socket);
  }
  nl_socket_free(socket);
  return 0;
}