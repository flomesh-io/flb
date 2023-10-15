#include <linux/rtnetlink.h>
#include <net_api.h>
#include <nlp.h>
#include <regex.h>
#include <unistd.h>

static inline void debug_route(nl_route_mod_t *route) {
  printf("Addr Protocol: %d ", route->protocol);
  printf("Flags: %d ", route->flags);
  printf("Link Index: %2d ", route->link_index);

  if (route->dst.ip.f.v4) {
    struct in_addr *in = (struct in_addr *)route->dst.ip.v4.bytes;
    printf("Dst: %s/%d ", inet_ntoa(*in), route->dst.mask);
  } else if (route->dst.ip.f.v6) {
    struct in6_addr *in = (struct in6_addr *)route->dst.ip.v6.bytes;
    char a_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, a_str, INET6_ADDRSTRLEN);
    printf("Dst: %s/%d ", a_str, route->dst.mask);
  }

  if (route->gw.f.v4) {
    struct in_addr *in = (struct in_addr *)route->gw.v4.bytes;
    printf("Gw: %s ", inet_ntoa(*in));
  } else if (route->gw.f.v6) {
    struct in6_addr *in = (struct in6_addr *)route->gw.v6.bytes;
    char a_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, a_str, INET6_ADDRSTRLEN);
    printf("Gw: %s ", a_str);
  }

  printf("\n");
}

int nl_route_mod(nl_route_mod_t *route, bool add) {
  struct net_api_route_q route_q;
  memset(&route_q, 0, sizeof(route_q));

  if (route->dst.ip.f.v4) {
    struct in_addr *in = (struct in_addr *)route->dst.ip.v4.bytes;
    char a_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, in, a_str, INET_ADDRSTRLEN);
    sprintf((char *)route_q.dst, "%s/%d", a_str, route->dst.mask);
  } else if (route->dst.ip.f.v6) {
    struct in6_addr *in = (struct in6_addr *)route->dst.ip.v6.bytes;
    char a_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, a_str, INET6_ADDRSTRLEN);
    sprintf((char *)route_q.dst, "%s/%d", a_str, route->dst.mask);
  } else {
    sprintf((char *)route_q.dst, "0.0.0.0/0");
  }

  if (add) {
    route_q.link_index = route->link_index;
    route_q.protocol = route->protocol;
    route_q.flags = route->flags;
    if (route->gw.f.v4) {
      struct in_addr *in = (struct in_addr *)route->gw.v4.bytes;
      inet_ntop(AF_INET, in, (char *)route_q.gw, INET_ADDRSTRLEN);
    } else if (route->gw.f.v6) {
      struct in6_addr *in = (struct in6_addr *)route->gw.v6.bytes;
      inet_ntop(AF_INET6, in, (char *)route_q.gw, INET6_ADDRSTRLEN);
    }
    return net_route_add(&route_q);
  } else {
    return net_route_del(&route_q);
  }
}

int nl_route_list_res(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
    return NL_SKIP;
  }

  bool add = nlh->nlmsg_type == RTM_NEWROUTE;
  struct rtmsg *rt_msg = NLMSG_DATA(nlh);
  if (add && arg != NULL) {
    if ((rt_msg->rtm_flags & RTM_F_CLONED) != 0) {
      return NL_SKIP;
    }
    if (rt_msg->rtm_table != RT_TABLE_MAIN) {
      return NL_SKIP;
    }
  }

  struct rtattr *attrs[RTA_MAX + 1];
  int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*rt_msg));
  parse_rtattr(attrs, RTA_MAX, RTM_RTA(rt_msg), remaining);

  __u32 rt_link_index = 0;
  if (add) {
    if (attrs[RTA_OIF]) {
      rt_link_index = *(__u32 *)RTA_DATA(attrs[RTA_OIF]);
      struct nl_port_mod *port = NULL;
      if (arg != NULL) {
        struct nl_multi_arg *args = (struct nl_multi_arg *)arg;
        port = (struct nl_port_mod *)args->arg1;
      } else {
        nl_port_mod_t l_port;
        memset(&l_port, 0, sizeof(l_port));
        if (nl_link_get_by_index(rt_link_index, &l_port) < 0) {
          return NL_SKIP;
        }
        port = &l_port;
      }
      if (rt_link_index != port->index) {
        return NL_SKIP;
      }
    }
  }

  nl_route_mod_t route;
  memset(&route, 0, sizeof(route));
  if (add) {
    route.link_index = rt_link_index;
    route.protocol = rt_msg->rtm_protocol;
    route.flags = rt_msg->rtm_flags;
    if (attrs[RTA_GATEWAY]) {
      struct rtattr *gw_addr = attrs[RTA_GATEWAY];
      __u8 *rta_val = (__u8 *)RTA_DATA(gw_addr);
      if (gw_addr->rta_len == 8) {
        route.gw.f.v4 = 1;
        memcpy(route.gw.v4.bytes, rta_val, 4);
      } else if (gw_addr->rta_len == 20) {
        route.gw.f.v6 = 1;
        memcpy(route.gw.v6.bytes, rta_val, 16);
      }
    }
  }

  if (attrs[RTA_DST]) {
    struct rtattr *rta_addr = attrs[RTA_DST];
    __u8 *rta_val = (__u8 *)RTA_DATA(rta_addr);
    if (rta_addr->rta_len == 8) {
      route.dst.ip.f.v4 = 1;
      route.dst.mask = rt_msg->rtm_dst_len;
      memcpy(route.dst.ip.v4.bytes, rta_val, 4);
    } else if (rta_addr->rta_len == 20) {
      route.dst.ip.f.v6 = 1;
      route.dst.mask = rt_msg->rtm_dst_len;
      memcpy(route.dst.ip.v6.bytes, rta_val, 16);
    }
  }

  // debug_route(&route);
  return nl_route_mod(&route, add);
}

int nl_route_list(nl_port_mod_t *port, __u8 family) {
  struct nl_sock *socket = nl_socket_alloc();
  nl_connect(socket, NETLINK_ROUTE);

  struct nl_msg *msg = nlmsg_alloc();

  struct rtmsg *nl_req;

  struct nlmsghdr *nlh = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETROUTE,
                                   sizeof(*nl_req), NLM_F_REQUEST | NLM_F_DUMP);

  nl_req = nlmsg_data(nlh);
  memset(nl_req, 0, sizeof(*nl_req));
  nl_req->rtm_family = family;

  int ret = nl_send_auto_complete(socket, msg);
  if (ret < 0) {
    nlmsg_free(msg);
    nl_socket_free(socket);
    return ret;
  }

  struct nl_multi_arg args = {
      .arg1 = port,
  };
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_route_list_res,
                      &args);
  nl_recvmsgs_default(socket);

  nlmsg_free(msg);
  nl_socket_free(socket);

  return 0;
}

int nl_route_subscribe() {
  struct nl_sock *socket = nl_socket_alloc();
  nl_socket_disable_seq_check(socket);
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_route_list_res,
                      NULL);
  nl_connect(socket, NETLINK_ROUTE);
  nl_socket_add_memberships(socket, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE);
  while (1) {
    nl_recvmsgs_default(socket);
  }
  nl_socket_free(socket);
  return 0;
}