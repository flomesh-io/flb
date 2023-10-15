#include <linux/rtnetlink.h>
#include <nlp.h>
#include <unistd.h>

enum {
  TCA_BPF_UNSPEC,
  TCA_BPF_ACT,
  TCA_BPF_POLICE,
  TCA_BPF_CLASSID,
  TCA_BPF_OPS_LEN,
  TCA_BPF_OPS,
  TCA_BPF_FD,
  TCA_BPF_NAME,
  TCA_BPF_FLAGS,
  TCA_BPF_FLAGS_GEN,
  TCA_BPF_TAG,
  TCA_BPF_ID,
  __TCA_BPF_MAX,
};

#define TCA_BPF_MAX (__TCA_BPF_MAX - 1)

int nl_filter_list_res(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
    return NL_SKIP;
  }
  if (nlh->nlmsg_type != RTM_NEWTFILTER) {
    return NL_SKIP;
  }

  bool *loaded = (bool *)arg;

  struct tcmsg *tc_msg = NLMSG_DATA(nlh);
  struct rtattr *attrs[TCA_MAX + 1];
  int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*tc_msg));
  parse_rtattr(attrs, TCA_MAX, TCA_RTA(tc_msg), remaining);

  nl_filter_mod_t filter;
  memset(&filter, 0, sizeof(filter));
  filter.index = tc_msg->tcm_ifindex;
  filter.handle = tc_msg->tcm_handle;
  filter.parent = tc_msg->tcm_parent;
  filter.priority = (__u16)((tc_msg->tcm_handle & 0xFFFF0000) >> 16);
  filter.Protocol = (__u16)(tc_msg->tcm_handle & 0x0000FFFFF);
  filter.Protocol = (filter.Protocol & 0xff00) >> 8 | (filter.Protocol & 0xff)
                                                          << 8;
  if (attrs[TCA_KIND]) {
    char *kind = (char *)RTA_DATA(attrs[TCA_KIND]);
    if (strcmp(kind, "u32") == 0) {
      filter.type.u32 = 1;
    } else if (strcmp(kind, "fw") == 0) {
      filter.type.fw = 1;
    } else if (strcmp(kind, "bpf") == 0) {
      struct rtattr *opt_data = attrs[TCA_OPTIONS];
      if (opt_data) {
        struct rtattr *bpf_attrs[TCA_BPF_MAX + 1];
        parse_rtattr(bpf_attrs, TCA_BPF_MAX, RTA_DATA(opt_data),
                     RTA_PAYLOAD(opt_data));
        if (bpf_attrs[TCA_BPF_FD]) {
          filter.u.bpf.fd = *(__u32 *)RTA_DATA(bpf_attrs[TCA_BPF_FD]);
        }
        if (bpf_attrs[TCA_BPF_NAME]) {
          struct rtattr *bpf_name = bpf_attrs[TCA_BPF_NAME];
          __u8 *rta_val = (__u8 *)RTA_DATA(bpf_name);
          memcpy(filter.u.bpf.name, rta_val, bpf_name->rta_len - 4);
        }
        if (bpf_attrs[TCA_BPF_CLASSID]) {
          filter.u.bpf.class_id =
              *(__u32 *)RTA_DATA(bpf_attrs[TCA_BPF_CLASSID]);
        }
        if (bpf_attrs[TCA_BPF_ID]) {
          filter.u.bpf.id = *(__u32 *)RTA_DATA(bpf_attrs[TCA_BPF_ID]);
        }
        if (bpf_attrs[TCA_BPF_FLAGS]) {
          __u32 flags = *(__u32 *)RTA_DATA(bpf_attrs[TCA_BPF_FLAGS]);
#define TCA_BPF_FLAG_ACT_DIRECT (1 << 0)
          if ((flags & TCA_BPF_FLAG_ACT_DIRECT) != 0) {
            filter.u.bpf.direct_action = true;
          }
        }
        if (bpf_attrs[TCA_BPF_TAG]) {
          struct rtattr *bpf_tag = bpf_attrs[TCA_BPF_TAG];
          __u8 *rta_val = (__u8 *)RTA_DATA(bpf_tag);
          int j = 0;
          char hextable[16] = "0123456789abcdef";
          for (int n = 0; n < bpf_tag->rta_len - 4; n++) {
            filter.u.bpf.tag[j] = hextable[rta_val[n] >> 4];
            filter.u.bpf.tag[j + 1] = hextable[rta_val[n] & 0x0f];
            j += 2;
          }
        }
      }
      filter.type.bpf = 1;
    } else if (strcmp(kind, "matchall") == 0) {
      filter.type.matchall = 1;
    } else {
      filter.type.generic_filter = 1;
    }
  }
  if (filter.type.bpf) {
    if (strstr((char *)filter.u.bpf.name, "tc_packet_hook0") != NULL) {
      *loaded = true;
    }
  }

  return NL_OK;
}

#define HANDLE_MIN_INGRESS 0xFFFFFFF2

bool _internal_nl_has_loaded_tc_prog(nl_port_mod_t *port) {
  struct nl_sock *socket = nl_socket_alloc();
  nl_connect(socket, NETLINK_ROUTE);

  struct nl_msg *msg = nlmsg_alloc();

  struct tcmsg *nl_req;

  struct nlmsghdr *nlh =
      nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETTFILTER, sizeof(*nl_req),
                NLM_F_REQUEST | NLM_F_DUMP);

  nl_req = nlmsg_data(nlh);
  memset(nl_req, 0, sizeof(*nl_req));
  nl_req->tcm_family = FAMILY_ALL;
  nl_req->tcm_ifindex = port->index;
  nl_req->tcm_parent = HANDLE_MIN_INGRESS;

  int ret = nl_send_auto_complete(socket, msg);
  if (ret < 0) {
    nlmsg_free(msg);
    nl_socket_free(socket);
    return false;
  }

  bool loaded = false;
  nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, nl_filter_list_res,
                      &loaded);
  nl_recvmsgs_default(socket);

  nlmsg_free(msg);
  nl_socket_free(socket);

  return loaded;
}

bool nl_has_loaded_tc_prog(const char *ifi_name) {
  nl_port_mod_t port;
  int ret = nl_link_get_by_name(ifi_name, &port);
  if (ret < 0) {
    return false;
  }
  return _internal_nl_has_loaded_tc_prog(&port);
}