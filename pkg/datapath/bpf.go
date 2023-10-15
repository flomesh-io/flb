package datapath

/*
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <linux/types.h>

struct bpf_spin_lock {
	__u32	val;
};

struct bpf_lpm_trie_key {
	__u32	prefixlen;
	__u8	data[0];
};

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "../../ebpf/common/common_sum.h"
#include "../../ebpf/common/common_frame.h"
#include "../../ebpf/common/pdi.h"
#include "../../ebpf/common/flb_dp_mdi.h"
#include "../../ebpf/common/flb_dpapi.h"

//-------------------------------- 数据包 辅助函数 实现 开始---------------------------------------
#include "../../ebpf/common/common_sum.c"
#include "../../ebpf/common/common_frame.c"
//-------------------------------- 数据包 辅助函数 实现 结束---------------------------------------
//-------------------------------- FW 辅助函数 实现 开始------------------------------------------
#include "../../ebpf/common/common_pdi.c"
static void flb_dp_pdik2_ufw4(struct pdi_rule *new, struct pdi_key *k)
{
  memset(k, 0, sizeof(struct pdi_key));

  PDI_MATCH_COPY(&k->dest, &new->key.dest);
  PDI_MATCH_COPY(&k->source, &new->key.source);
  PDI_RMATCH_COPY(&k->sport, &new->key.sport);
  PDI_RMATCH_COPY(&k->dport, &new->key.dport);
  PDI_MATCH_COPY(&k->inport, &new->key.inport);
  PDI_MATCH_COPY(&k->protocol, &new->key.protocol);
  PDI_MATCH_COPY(&k->zone, &new->key.zone);
}

static void flb_dp_ufw42_pdik(struct pdi_rule *new, struct pdi_key *k)
{
  PDI_MATCH_COPY(&new->key.dest, &k->dest);
  PDI_MATCH_COPY(&new->key.source, &k->source);
  PDI_RMATCH_COPY(&new->key.sport, &k->sport);
  PDI_RMATCH_COPY(&new->key.dport, &k->dport);
  PDI_MATCH_COPY(&new->key.inport, &k->inport);
  PDI_MATCH_COPY(&new->key.protocol, &k->protocol);
  PDI_MATCH_COPY(&new->key.zone, &k->zone);
}

static void flb_dp_pdiop2_ufw4(struct pdi_rule *new, struct dp_fwv4_ent *e)
{
  memset(&e->fwa, 0, sizeof(e->fwa));
  e->fwa.ca.cidx = new->data.rid;
  e->fwa.ca.mark = new->data.opts.mark;
  e->fwa.ca.record = new->data.opts.record;

  switch (new->data.op) {
  case PDI_SET_DROP:
    e->fwa.ca.act_type = DP_SET_DROP;
    break;
  case PDI_SET_TRAP:
    e->fwa.ca.act_type = DP_SET_TOCP;
    break;
  case PDI_SET_RDR:
    e->fwa.ca.act_type = DP_SET_RDR_PORT;
    e->fwa.port_act.oport = new->data.opts.port;
    break;
  case PDI_SET_FWD:
    e->fwa.ca.act_type = DP_SET_NOP;
    break;
  default:
    break;
  }
}

static void flb_dp_ufw42_pdiop(struct pdi_rule *new, struct dp_fwv4_ent *e)
{
  new->data.rid = e->fwa.ca.cidx;
  new->data.pref = e->fwa.ca.oaux; // Overloaded field
  new->data.opts.mark = e->fwa.ca.mark;
  new->data.opts.record = e->fwa.ca.record;

  switch (e->fwa.ca.act_type) {
  case DP_SET_DROP:
    new->data.op = PDI_SET_DROP;
    break;
  case DP_SET_TOCP:
    new->data.op = PDI_SET_TRAP;
    break;
  case DP_SET_RDR_PORT:
    new->data.op = PDI_SET_RDR;
    new->data.opts.port = e->fwa.port_act.oport;
    break;
  case DP_SET_NOP:
    new->data.op = PDI_SET_FWD;
  default:
    break;
  }
}
//-------------------------------- FW 辅助函数 实现 结束------------------------------------------
//--------------------------------最小化 BPF LIB 实现 开始----------------------------------------
#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# elif defined(__arc__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

// typedef __signed__ char __s8;
// typedef unsigned char __u8;

// typedef __signed__ short __s16;
// typedef unsigned short __u16;

// typedef __signed__ int __s32;
// typedef unsigned int __u32;

// #define __aligned_u64 __u64 __attribute__((aligned(8)))

// #ifdef __GNUC__
// __extension__ typedef __signed__ long long __s64;
// __extension__ typedef unsigned long long __u64;
// #else
// typedef __signed__ long long __s64;
// typedef unsigned long long __u64;
// #endif

// flags for BPF_MAP_UPDATE_ELEM command
#define BPF_ANY		  0 // create new element or update existing
#define BPF_NOEXIST	1 // create new element if it didn't exist
#define BPF_EXIST	  2 // update existing element
#define BPF_F_LOCK	4 // spin_lock-ed map_lookup/map_update

enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
};

union bpf_attr {
	struct {
		__u32		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		__u64		flags;
	};
	struct {
		union {
			__u32		start_id;
			__u32		prog_id;
			__u32		map_id;
			__u32		btf_id;
		};
		__u32		next_id;
		__u32		open_flags;
	};
	struct {
		__aligned_u64	pathname;
		__u32		bpf_fd;
		__u32		file_flags;
	};
	struct {
		__u32		__pad[28];
	};
} __attribute__((aligned(8)));

static inline int nr_bpf() {
	return __NR_bpf;
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static inline int bpf_map_update_elem(int fd, const void *key, const void *value,
			__u64 flags)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_delete_elem(int fd, const void *key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return sys_bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static inline int bpf_map_get_fd_by_id(__u32 id)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_id = id;

	return sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}

static inline int parse_cpu_mask_str(const char *s, bool **mask, int *mask_sz)
{
	int err = 0, n, len, start, end = -1;
	bool *tmp;

	*mask = NULL;
	*mask_sz = 0;

	while (*s) {
		if (*s == ',' || *s == '\n') {
			s++;
			continue;
		}
		n = sscanf(s, "%d%n-%d%n", &start, &len, &end, &len);
		if (n <= 0 || n > 2) {
			err = -EINVAL;
			goto cleanup;
		} else if (n == 1) {
			end = start;
		}
		if (start < 0 || start > end) {
			err = -EINVAL;
			goto cleanup;
		}
		tmp = realloc(*mask, end + 1);
		if (!tmp) {
			err = -ENOMEM;
			goto cleanup;
		}
		*mask = tmp;
		memset(tmp + *mask_sz, 0, start - *mask_sz);
		memset(tmp + start, 1, end - start + 1);
		*mask_sz = end + 1;
		s += len;
	}
	if (!*mask_sz) {
		return -EINVAL;
	}
	return 0;
cleanup:
	free(*mask);
	*mask = NULL;
	return err;
}

static inline int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz)
{
	int fd, err = 0, len;
	char buf[128];

  #define O_RDONLY 00
	fd = open(fcpu, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		return err;
	}
	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len <= 0) {
		err = len ? -errno : -EINVAL;
		return err;
	}
	if (len >= sizeof(buf)) {
		return -E2BIG;
	}
	buf[len] = '\0';

	return parse_cpu_mask_str(buf, mask, mask_sz);
}

#define READ_ONCE(x)		  (*(volatile typeof(x) *)&x)
#define WRITE_ONCE(x, v)	(*(volatile typeof(x) *)&x) = (v)

static inline int bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	static int cpus;
	int err, n, i, tmp_cpus;
	bool *mask;

	tmp_cpus = READ_ONCE(cpus);
	if (tmp_cpus > 0)
		return tmp_cpus;

	err = parse_cpu_mask_file(fcpu, &mask, &n);
	if (err)
		return err;

	tmp_cpus = 0;
	for (i = 0; i < n; i++) {
		if (mask[i])
			tmp_cpus++;
	}
	free(mask);

	WRITE_ONCE(cpus, tmp_cpus);
	return tmp_cpus;
}

static inline int bpf_num_online_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/online";
	static int cpus;
	int err, n, i, tmp_cpus;
	bool *mask;

	tmp_cpus = READ_ONCE(cpus);
	if (tmp_cpus > 0)
		return tmp_cpus;

	err = parse_cpu_mask_file(fcpu, &mask, &n);
	if (err)
		return err;

	tmp_cpus = 0;
	for (i = 0; i < n; i++) {
		if (mask[i])
			tmp_cpus++;
	}
	free(mask);

	WRITE_ONCE(cpus, tmp_cpus);
	return tmp_cpus;
}
//--------------------------------最小化 BPF LIB 实现 结束----------------------------------------
//--------------------------------系统时间 辅助函数 实现 开始--------------------------------------
unsigned long long get_os_usecs(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((unsigned long long)ts.tv_sec * 1000000UL) + ts.tv_nsec/1000;
}

unsigned long long get_os_nsecs(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
//--------------------------------系统时间 辅助函数 实现 结束--------------------------------------
//--------------------------------Tap Tun 辅助函数 实现 开始--------------------------------------
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

static int set_dev_up(const char *ifname, bool up)
{
  struct ifreq ifr;
  int fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ifr.ifr_ifindex = if_nametoindex(ifname);

  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }
  if (up && !(ifr.ifr_flags & IFF_UP)) {
    ifr.ifr_flags |= IFF_UP;
  } else if (!up && ifr.ifr_flags & IFF_UP) {
    ifr.ifr_flags &= ~IFF_UP;
  } else {
    close(fd);
    return 0;
  }

  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

static int set_up_tap_dev(const char *ifname) {
  int fd;
  int ret;
  struct ifreq ifr;
  char *dev = "/dev/net/tun";

  if ((fd = open(dev, O_RDWR)) < 0 ) {
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

  if ((ret = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    close(fd);
    return ret;
  }

  if ((ret = ioctl(fd, TUNSETPERSIST, 1)) < 0) {
    close(fd);
    return ret;
  }

  set_dev_up(ifname, 1);

  return 0;
}
//--------------------------------Tap Tun 辅助函数 实现 结束--------------------------------------
#ifndef XDP_LL_SEC_DEFAULT
#define XDP_LL_SEC_DEFAULT       "xdp_packet_hook"
#endif

#ifndef TC_LL_SEC_DEFAULT
#define TC_LL_SEC_DEFAULT        "tc_packet_hook0"
#endif

struct ebpfcfg {
  int nodenum;
};

typedef struct ct_arg_struct
{
  uint64_t curr_ns;
  uint32_t rid;
  uint32_t aid[32];
  int n_aids;
  int n_aged;
} ct_arg_struct_t;

typedef struct flb_dp_map {
  int map_fd;
  char *map_name;
  uint32_t max_entries;
  int has_pb;
  int pb_xtid;
  struct dp_pbc_stats *pbs;
  int has_pol;
  struct dp_pol_stats *pls;
  pthread_rwlock_t stat_lock;
} flb_dp_map_t;

typedef struct flb_dp_struct
{
  pthread_rwlock_t lock;
  pthread_rwlock_t mplock;
  const char *ll_dp_fname;
  const char *ll_tc_fname;
  const char *ll_dp_dfl_sec;
  const char *ll_dp_pdir;
  int nodenum;
  flb_dp_map_t maps[LL_DP_MAX_MAP];
  struct pdi_map *ufw4;
  struct pdi_map *ufw6;
} flb_dp_struct_t;

flb_dp_struct_t *xh;
static uint64_t lost;

#define XH_LOCK()    pthread_rwlock_wrlock(&xh->lock)
#define XH_RD_LOCK() pthread_rwlock_rdlock(&xh->lock)
#define XH_UNLOCK()  pthread_rwlock_unlock(&xh->lock)

#define XH_MPLOCK()  pthread_rwlock_wrlock(&xh->mplock)
#define XH_MPUNLOCK() pthread_rwlock_unlock(&xh->mplock)

static int flb_objmap2fd(const char *mapname)
{
  struct bpf_map *map;
  char path[512];
  union bpf_attr attr;
  snprintf(path, 512, "%s/%s", xh->ll_dp_pdir, mapname);
  memset(&attr, 0, sizeof(attr));
  attr.pathname = (__u64) (unsigned long)&path[0];
  return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static void flb_clear_stats_pcpu_arr(int mfd, __u32 idx)
{
  unsigned int nr_cpus = bpf_num_possible_cpus();
  struct dp_pb_stats values[nr_cpus];

  memset(values, 0, sizeof(values));
  if (bpf_map_update_elem(mfd, &idx, values, 0) != 0) {
    printf("bpf_map_lookup_elem failed idx:0x%X\n", idx);
    return;
  }
}

static void flb_clear_map_stats_internal(int tid, __u32 idx, bool wipe)
{
  int e = 0;
  flb_dp_map_t *t;

  if (tid < 0 || tid >= LL_DP_MAX_MAP)
    return;

  t = &xh->maps[tid];
  if (t->has_pb) {
    if (t->pb_xtid > 0) {
      if (t->pb_xtid >= LL_DP_MAX_MAP)
        return;
      t = &xh->maps[t->pb_xtid];
      if (!t->has_pb || t->pb_xtid > 0) {
        return;
      }
    }
    if (!wipe) {
      flb_clear_stats_pcpu_arr(t->map_fd, idx);
    } else {
      for (e = 0; e < t->max_entries; e++) {
        flb_clear_stats_pcpu_arr(t->map_fd, e);
      }
    }
  }
}

static int ll_map_elem_cmp_cidx(int tid, void *k, void *ita)
{
  dp_map_ita_t *it = ita;
  uint32_t cidx;

  if (!it|| !it->uarg || !it->val) return 0;

  cidx = *(uint32_t *)it->uarg;

  if (tid == LL_DP_CT_MAP ||
      tid == LL_DP_TMAC_MAP ||
      tid == LL_DP_FCV4_MAP ||
      tid == LL_DP_RTV4_MAP) {
    struct dp_cmn_act *ca = it->val;
    if (ca->cidx == cidx) return 1;
  }

  return 0;
}

static void flb_del_map_elem_with_cidx(int tbl, uint32_t cidx)
{
  dp_map_ita_t it;
  uint8_t skey[1024];
  uint8_t sval[1024];

  memset(&it, 0, sizeof(it));
  memset(&skey, 0, sizeof(skey));
  memset(&sval, 0, sizeof(sval));

  it.next_key = &skey;
  it.val = &sval;
  it.uarg = &cidx;

  flb_map_loop_and_delete(tbl, ll_map_elem_cmp_cidx, &it);
}

static int ll_ct_map_ent_rm_related(int tid, void *k, void *ita)
{
  int i = 0;
  struct dp_ct_key *key = k;
  dp_map_ita_t *it = ita;
  struct dp_ct_tact *adat;
  ct_arg_struct_t *as;
  char dstr[INET6_ADDRSTRLEN];
  char sstr[INET6_ADDRSTRLEN];

  if (!it|| !it->uarg || !it->val) return 0;

  as = it->uarg;
  adat = it->val;

  if (adat->ctd.rid != as->rid) {
    return 0;
  }

  for (i = 0; i < as->n_aids; i++) {
    if (adat->ctd.aid == as->aid[i]) {
      if (!key->v6) {
        inet_ntop(AF_INET, &key->saddr[0], sstr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &key->daddr[0], dstr, INET_ADDRSTRLEN);
      } else {
        inet_ntop(AF_INET6, &key->saddr[0], sstr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &key->daddr[0], dstr, INET6_ADDRSTRLEN);
      }

      if (!key->v6) {
        flb_del_map_elem_with_cidx(LL_DP_FCV4_MAP, adat->ca.cidx);
      }
      flb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);

      return 1;
    }
  }

  return 0;
}

static void ll_map_ct_rm_related(uint32_t rid, uint32_t *aids, int naid)
{
  dp_map_ita_t it;
  int i = 0;
  struct dp_ct_key next_key;
  struct dp_ct_tact *adat;
  ct_arg_struct_t *as;
  uint64_t ns = get_os_nsecs();

  adat = calloc(1, sizeof(*adat));
  if (!adat) return;

  as = calloc(1, sizeof(*as));
  if (!as) {
    free(adat);
    return;
  }

  as->curr_ns = ns;

  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.val = adat;
  it.uarg = as;

  as->rid = rid;
  for (i = 0; i < naid; i++) {
    as->aid[i] = aids[i];
  }
  as->n_aids = naid;

  flb_map_loop_and_delete(LL_DP_CT_MAP, ll_ct_map_ent_rm_related, &it);
  if (adat) free(adat);
  if (as) free(as);
}

static int flb_add_map_elem_nat_post_proc(void *k, void *v)
{
  struct dp_nat_tacts *na = v;
  struct mf_xfrm_inf *ep_arm;
  uint32_t inact_aids[FLB_MAX_NXFRMS];
  int i = 0;
  int j = 0;

  memset(inact_aids, 0, sizeof(inact_aids));

  for (i = 0; i < na->nxfrm && i < FLB_MAX_NXFRMS; i++) {
    ep_arm = &na->nxfrms[i];

    if (ep_arm->inactive) {
      inact_aids[j++] = i;
    }
  }

  if (j > 0) {
    ll_map_ct_rm_related(na->ca.cidx, inact_aids, j);
  }

  return 0;
}

static int flb_del_map_elem_nat_post_proc(void *k, void *v)
{
  struct dp_nat_tacts *na = v;
  struct mf_xfrm_inf *ep_arm;
  uint32_t inact_aids[FLB_MAX_NXFRMS];
  int i = 0;
  int j = 0;

  memset(inact_aids, 0, sizeof(inact_aids));

  for (i = 0; i < na->nxfrm && i < FLB_MAX_NXFRMS; i++) {
    ep_arm = &na->nxfrms[i];

    if (ep_arm->inactive == 0) {
      inact_aids[j++] = i;
    }
  }

  if (j > 0) {
    ll_map_ct_rm_related(na->ca.cidx, inact_aids, j);
  }

  return 0;

}

int flb_add_mf_map_elem__(int tbl, void *k, void *v)
{
  int ret = 0;
  int n = 0;
  int nr = 0;
  struct dp_fwv4_ent p = { 0 };

  if (tbl == LL_DP_FW4_MAP) {
    struct dp_fwv4_ent *e = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));

    if (!new) return -1;

    flb_dp_ufw42_pdik(new, &e->k);
    flb_dp_ufw42_pdiop(new, e) ;

    ret = pdi_rule_insert(xh->ufw4, new, &nr);
    if (ret != 0) {
      free(new);
      return -1;
    }

    PDI_MAP_LOCK(xh->ufw4);
    FOR_EACH_PDI_ENT(xh->ufw4, new) {
      if (n == 0 || n >= nr) {
        memset(&p, 0, sizeof(p));
        flb_dp_pdik2_ufw4(new, &p.k);
        flb_dp_pdiop2_ufw4(new, &p);
        if (n == 0) {
          PDI_VAL_INIT(&p.k.nr, xh->ufw4->nr);
        }
        ret = bpf_map_update_elem(flb_map2fd(tbl), &n, &p, 0);
        if (ret != 0) {
          ret = -EFAULT;
        }
      }
      n++;
    }
    PDI_MAP_ULOCK(xh->ufw4);
  }
  return ret;
}

int flb_del_mf_map_elem__(int tbl, void *k)
{
  int ret = 0;
  int n = 0;
  int nr = 0;
  struct dp_fwv4_ent p = { 0 };

  if (tbl == LL_DP_FW4_MAP) {
    struct dp_fwv4_ent *e = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));

    if (!new) return -1;

    flb_dp_ufw42_pdik(new, &e->k);
    flb_dp_ufw42_pdiop(new, e) ;

    ret = pdi_rule_delete(xh->ufw4, &new->key, new->data.pref, &nr);
    if (ret != 0) {
      free(new);
      return -1;
    }

    free(new);

    PDI_MAP_LOCK(xh->ufw4);
    FOR_EACH_PDI_ENT(xh->ufw4, new) {
      if (n == 0 || n >= nr) {
        memset(&p, 0, sizeof(p));
        flb_dp_pdik2_ufw4(new, &p.k);
        flb_dp_pdiop2_ufw4(new, &p);
        if (n == 0) {
          PDI_VAL_INIT(&p.k.nr, xh->ufw4->nr);
        }
        ret = bpf_map_update_elem(flb_map2fd(tbl), &n, &p, 0);
        if (ret != 0) {
          ret = -EFAULT;
        }
      }
      n++;
    }
    PDI_MAP_ULOCK(xh->ufw4);

    while (n < FLB_FW4_MAP_ENTRIES) {
      memset(&p, 0, sizeof(p));
      bpf_map_update_elem(flb_map2fd(tbl), &n, &p, 0);
      n++;
    }
  }
  return ret;
}

static int ll_fcmap_ent_has_aged(int tid, void *k, void *ita)
{
  dp_map_ita_t *it = ita;
  struct dp_fc_tacts *fc_val;
  uint64_t curr_ns;

  if (!it|| !it->uarg || !it->val) return 0;

  curr_ns = *(uint64_t *)it->uarg;
  fc_val = it->val;

  if (fc_val->its  &&
      curr_ns - fc_val->its > FC_V4_CPTO) {
    return 1;
  }

  return 0;
}

static void ll_age_fcmap(void)
{
  dp_map_ita_t it;
  struct dp_fcv4_key next_key;
  struct dp_fc_tacts *fc_val;
  uint64_t ns = get_os_nsecs();

  fc_val = calloc(1, sizeof(*fc_val));
  if (!fc_val) return;

  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.val = fc_val;
  it.uarg = &ns;

  XH_LOCK();
  flb_map_loop_and_delete(LL_DP_FCV4_MAP, ll_fcmap_ent_has_aged, &it);
  XH_UNLOCK();
  if (fc_val) free(fc_val);
}

static void ll_send_ctep_reset(struct dp_ct_key *ep, struct dp_ct_tact *adat)
{
  struct mkr_args r;
  ct_tcp_pinf_t *ts = &adat->ctd.pi.t;

  if (ep->l4proto != IPPROTO_TCP) {
    return;
  }

  if (ts->state != CT_TCP_EST) {
    return;
  }

  memset(&r, 0, sizeof(r));

  if (ep->v6 == 0) {
    r.sip[0] = ntohl(ep->daddr[0]);
    r.dip[0] = ntohl(ep->saddr[0]);
  } else {
    memcpy(r.sip, ep->daddr, 16);
    memcpy(r.dip, ep->saddr, 16);
    r.v6 = 1;
  }
  r.sport = ntohs(ep->dport);
  r.dport = ntohs(ep->sport);
  r.protocol = ep->l4proto;
  r.t.seq = ntohl(adat->ctd.pi.t.tcp_cts[CT_DIR_IN].pack);
  r.t.rst = 1;

  create_xmit_raw_tcp(&r);
}

static int ctm_proto_xfk_init(struct dp_ct_key *key,
                   struct dp_ct_tact *adat,
                   struct dp_ct_key *xkey,
                   struct dp_ct_key *okey)
{
  nxfrm_inf_t *xi;

  DP_XADDR_CP(xkey->daddr, key->saddr);
  DP_XADDR_CP(xkey->saddr, key->daddr);
  xkey->sport = key->dport;
  xkey->dport = key->sport;
  xkey->l4proto = key->l4proto;
  xkey->zone = key->zone;
  xkey->v6 = key->v6;

  xi = &adat->ctd.xi;

  if (xi->dsr || adat->ctd.pi.frag) {
    return 0;
  }

  // Apply NAT xfrm if needed
  if (xi->nat_flags & FLB_NAT_DST) {
    xkey->v6 = xi->nv6;
    DP_XADDR_CP(xkey->saddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->daddr, xi->nat_rip);
    }
    if (key->l4proto != IPPROTO_ICMP) {
        if (xi->nat_xport)
          xkey->sport = xi->nat_xport;
    }
  }
  if (xi->nat_flags & FLB_NAT_SRC) {
    xkey->v6 = xi->nv6;
    DP_XADDR_CP(xkey->daddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->saddr, xi->nat_rip);
    }
    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
    }
  }
  if (xi->nat_flags & FLB_NAT_HDST) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->sport = xi->nat_xport;
    }
  }
  if (xi->nat_flags & FLB_NAT_HSRC) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
    }
  }

  return 0;
}

static void ll_get_stats_pcpu_arr(int mfd, __u32 idx,
                      struct dp_pbc_stats *s,
                      dp_ts_cb_t cb)
{
  // For percpu maps, userspace gets a value per possible CPU
  unsigned int nr_cpus = bpf_num_possible_cpus();
  struct dp_pb_stats values[nr_cpus];
  __u64 sum_bytes = 0;
  __u64 sum_pkts = 0;
  __u64 opc = 0;
  int i;

  if ((bpf_map_lookup_elem(mfd, &idx, values)) != 0) {
    return;
  }

  opc = s->st.packets;

  // Sum values from each CPU
  for (i = 0; i < nr_cpus; i++) {
    sum_pkts  += values[i].packets;
    sum_bytes += values[i].bytes;
  }

  s->st.packets = sum_pkts;
  s->st.bytes   = sum_bytes;

  if (s->st.packets || s->st.bytes) {
    if (s->st.packets > opc) {
      s->used = 1;
    }
    if (cb) {
      cb(idx, s->st.bytes, s->st.packets);
    }
  }
}

static int flb_fetch_map_stats_used(int tbl, uint32_t e, int clr, int *used)
{
  flb_dp_map_t *t;

  if (tbl < 0 || tbl >= LL_DP_MAX_MAP)
    return -1;

  t = &xh->maps[tbl];
  if (t->has_pb && t->pb_xtid > 0) {
    if (t->pb_xtid < 0 || t->pb_xtid >= LL_DP_MAX_MAP)
      return -1;

    t = &xh->maps[t->pb_xtid];
  }

  pthread_rwlock_wrlock(&t->stat_lock);

  if (used) {
    *used = t->pbs[e].used;
  }

  if (clr) {
    t->pbs[e].used = 0;
  }

  pthread_rwlock_unlock(&t->stat_lock);

  return 0;
}

static int ll_ct_map_ent_has_aged(int tid, void *k, void *ita)
{
  dp_map_ita_t *it = ita;
  struct dp_ct_key *key = k;
  struct dp_ct_key xkey;
  struct dp_ct_key okey;
  struct dp_ct_dat *dat;
  struct dp_ct_tact *adat;
  struct dp_ct_tact axdat;
  ct_arg_struct_t *as;
  uint64_t curr_ns;
  uint64_t latest_ns;
  int used1 = 0;
  int used2 = 0;
  bool est = false;
  bool has_nat = false;
  uint64_t to = CT_V4_CPTO;
  char dstr[INET6_ADDRSTRLEN];
  char sstr[INET6_ADDRSTRLEN];
  uint64_t bytes, pkts;
  flb_dp_map_t *t;

  if (!it|| !it->uarg || !it->val) return 0;

  as = it->uarg;
  curr_ns = as->curr_ns;
  adat = it->val;
  dat = &adat->ctd;

  if (key->v6 == 0) {
    inet_ntop(AF_INET, key->saddr, sstr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, key->daddr, dstr, INET_ADDRSTRLEN);
  } else {
    inet_ntop(AF_INET6, key->saddr, sstr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, key->daddr, dstr, INET6_ADDRSTRLEN);
  }

  if (adat->ctd.xi.nat_flags) {
    has_nat = true;
  }

  ctm_proto_xfk_init(key, adat, &xkey, &okey);

  t = &xh->maps[LL_DP_CT_MAP];

  if (adat->ctd.pi.frag) {
    memset(&axdat, 0, sizeof(axdat));
  } else if (bpf_map_lookup_elem(t->map_fd, &xkey, &axdat) != 0) {
    if (key->v6 == 0) {
      inet_ntop(AF_INET, xkey.saddr, sstr, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, xkey.daddr, dstr, INET_ADDRSTRLEN);
    } else {
      inet_ntop(AF_INET6, xkey.saddr, sstr, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, xkey.daddr, dstr, INET6_ADDRSTRLEN);
    }

    if (curr_ns - adat->lts < CT_MISMATCH_FN_CPTO) {
      return 0;
    }

    flb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);
    return 1;
  }

  if (adat->lts > axdat.lts) {
    latest_ns = adat->lts;
  } else {
    latest_ns = axdat.lts;
  }

  if (!adat->ctd.pi.frag && dat->dir == CT_DIR_OUT) {
    return 0;
  }

  flb_fetch_map_stats_cached(LL_DP_CT_STATS_MAP, adat->ca.cidx, 1, &bytes, &pkts);
  flb_fetch_map_stats_cached(LL_DP_CT_STATS_MAP, adat->ca.cidx+1, 1, &bytes, &pkts);

  if (key->l4proto == IPPROTO_TCP) {
    ct_tcp_pinf_t *ts = &dat->pi.t;

    if (ts->state & CT_TCP_FIN_MASK ||
        ts->state & CT_TCP_ERR ||
        ts->state & CT_TCP_SYNC_MASK ||
        ts->state == CT_TCP_CLOSED) {
      to = CT_TCP_FN_CPTO;
    } else if (ts->state == CT_TCP_EST) {
      est = true;
    }
  } else if (key->l4proto == IPPROTO_UDP) {
    ct_udp_pinf_t *us = &dat->pi.u;

    if (adat->ctd.pi.frag) {
      to = CT_UDP_FN_CPTO;
    } else if (us->state & (CT_UDP_UEST|CT_UDP_EST)) {
      to = CT_UDP_EST_CPTO;
      est = true;
    } else {
      to = CT_UDP_FN_CPTO;
    }
  } else if (key->l4proto == IPPROTO_ICMP ||
             key->l4proto == IPPROTO_ICMPV6) {
    ct_icmp_pinf_t *is = &dat->pi.i;
    if (is->state == CT_ICMP_REPS) {
      est = true;
      to = CT_ICMP_EST_CPTO;
    } else {
      to = CT_ICMP_FN_CPTO;
    }
  } else if (key->l4proto == IPPROTO_SCTP) {
    ct_sctp_pinf_t *ss = &dat->pi.s;

    if (ss->state & CT_SCTP_FIN_MASK ||
        ss->state & CT_SCTP_ERR ||
        (ss->state & CT_SCTP_INIT_MASK && ss->state != CT_SCTP_EST) ||
        ss->state == CT_SCTP_CLOSED) {
      to = CT_SCTP_FN_CPTO;
    } else if (ss->state == CT_SCTP_EST) {
      est = true;
    }
  }

  if (curr_ns < latest_ns) return 0;

  if (est && adat->ito != 0) {
    to = adat->ito;
  }

  // CT is allocated both for current and reverse direction
  flb_fetch_map_stats_used(LL_DP_CT_STATS_MAP, adat->ca.cidx, 1, &used1);
  flb_fetch_map_stats_used(LL_DP_CT_STATS_MAP, adat->ca.cidx+1, 1, &used2);

  if (curr_ns - latest_ns > to && !used1 && !used2) {
    ll_send_ctep_reset(key, adat);
    flb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);

    if (!adat->ctd.pi.frag) {
      ll_send_ctep_reset(&xkey, &axdat);
      //flb_maptrace_uhook(LL_DP_CT_MAP, 0, &xkey, sizeof(xkey), NULL, 0);
      bpf_map_delete_elem(t->map_fd, &xkey);
      flb_clear_map_stats(LL_DP_CT_STATS_MAP, axdat.ca.cidx);
    }
    return 1;
  }

  return 0;
}

static void ll_age_ctmap(void)
{
  dp_map_ita_t it;
  struct dp_ct_key next_key;
  struct dp_ct_tact *adat;
  ct_arg_struct_t *as;
  uint64_t ns = get_os_nsecs();

  adat = calloc(1, sizeof(*adat));
  if (!adat) return;

  as = calloc(1, sizeof(*as));
  if (!as) {
    free(adat);
    return;
  }

  as->curr_ns = ns;

  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.key_sz = sizeof(next_key);
  it.val = adat;
  it.uarg = as;

  XH_LOCK();
  if (lost > 0) {
    printf("PerfBuf Lost count %lu", lost);
    lost = 0;
  }

  flb_map_loop_and_delete(LL_DP_CT_MAP, ll_ct_map_ent_has_aged, &it);
  XH_UNLOCK();
  if (adat) free(adat);
  if (as) free(as);
}

static void flb_fetch_map_stats_raw(int tid, dp_ts_cb_t cb, dp_tiv_cb_t vcb)
{
  int e = 0;
  flb_dp_map_t *t;

  if (tid < 0 || tid >= LL_DP_MAX_MAP)
    return;

  t = &xh->maps[tid];

  if (t->pb_xtid) return;

  if (t->has_pb) {

    pthread_rwlock_wrlock(&t->stat_lock);
    // FIXME : Handle non-pcpu
    for (e = 0; e < t->max_entries; e++) {
      if (vcb && vcb(tid, e) == 0) {
        continue;
      }

      ll_get_stats_pcpu_arr(t->map_fd, e, &t->pbs[e], cb);
    }
    pthread_rwlock_unlock(&t->stat_lock);
  }
}

static void flb_sys_exec(char *str)
{
  (void)(system(str)+1);
}

#include <sys/resource.h>
static void flb_set_rlims(void)
{
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    printf("Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

//-------------------------------- dpapi 函数 实现 开始------------------------------------------
int flb_map2fd(int t)
{
  return xh->maps[t].map_fd;
}

void flb_clear_map_stats(int tid, __u32 idx)
{
  return flb_clear_map_stats_internal(tid, idx, false);
}

int flb_add_map_elem(int tbl, void *k, void *v)
{
  int ret = -EINVAL;
  if (tbl < 0 || tbl >= LL_DP_MAX_MAP) {
    return ret;
  }

  XH_LOCK();

  // Any table which has stats pb needs to get stats cleared before use
  if (tbl == LL_DP_NAT_MAP ||
      tbl == LL_DP_TMAC_MAP ||
      tbl == LL_DP_FW4_MAP  ||
      tbl == LL_DP_RTV4_MAP) {
    __u32 cidx = 0;

    if (tbl == LL_DP_FW4_MAP) {
      struct dp_fwv4_ent *e = k;
      cidx = e->fwa.ca.cidx;
    } else {
      struct dp_cmn_act *ca = v;
      cidx = ca->cidx;
    }

    flb_clear_map_stats(tbl, cidx);
  }

  if (tbl == LL_DP_FW4_MAP) {
    ret = flb_add_mf_map_elem__(tbl, k, v);
  } else {
    ret = bpf_map_update_elem(flb_map2fd(tbl), k, v, 0);
  }
  if (ret != 0) {
    ret = -EFAULT;
  } else {
    // Need some post-processing for certain maps
    if (tbl == LL_DP_NAT_MAP) {
      flb_add_map_elem_nat_post_proc(k, v);
    }
  }
  XH_UNLOCK();

  return ret;
}

int flb_del_map_elem(int tbl, void *k)
{
  int ret = -EINVAL;
  struct dp_nat_tacts t = { 0 };

  if (tbl < 0 || tbl >= LL_DP_MAX_MAP) {
    return ret;
  }

  XH_LOCK();

  // Need some pre-processing for certain maps
  if (tbl == LL_DP_NAT_MAP) {
    ret = bpf_map_lookup_elem(flb_map2fd(tbl), k, &t);
    if (ret != 0) {
      XH_UNLOCK();
      return -EINVAL;
    }
  }

  if (tbl == LL_DP_FW4_MAP) {
    ret = flb_del_mf_map_elem__(tbl, k);
  } else {
    ret = bpf_map_delete_elem(flb_map2fd(tbl), k);
  }
  if (ret != 0) {
    ret = -EFAULT;
  }

  // Need some post-processing for certain maps
  if (tbl == LL_DP_NAT_MAP) {
    flb_del_map_elem_nat_post_proc(k, &t);
  }

  XH_UNLOCK();

  return ret;
}

void flb_map_loop_and_delete(int tid, dp_map_walker_t cb, dp_map_ita_t *it)
{
  void *key = NULL;
  flb_dp_map_t *t;
  int n = 0;

  if (!cb) return;

  if (tid < 0 || tid >= LL_DP_MAX_MAP)
    return;

  t = &xh->maps[tid];

  while (bpf_map_get_next_key(t->map_fd, key, it->next_key) == 0) {
    if (n >= t->max_entries) break;

    if (bpf_map_lookup_elem(t->map_fd, it->next_key, it->val) != 0) {
      goto next;
    }

    if (cb(tid, it->next_key, it)) {
      //flb_maptrace_uhook(tid, 0, it->next_key, it->key_sz, NULL, 0);
      bpf_map_delete_elem(t->map_fd, it->next_key);
    }

next:
    key = it->next_key;
    n++;
  }

  return;
}

void flb_age_map_entries(int tbl)
{
  XH_MPLOCK();
  switch (tbl) {
  case LL_DP_FCV4_MAP:
    ll_age_fcmap();
    break;
  case LL_DP_CT_MAP:
    ll_age_ctmap();
    break;
  default:
    break;
  }
  XH_MPUNLOCK();

  return;
}

int flb_fetch_map_stats_cached(int tbl, uint32_t e, int raw,
                           void *bytes, void *packets)
{
  flb_dp_map_t *t;

  if (tbl < 0 || tbl >= LL_DP_MAX_MAP)
    return -1;

  t = &xh->maps[tbl];
  if (t->has_pb && t->pb_xtid > 0) {
    if (t->pb_xtid < 0 || t->pb_xtid >= LL_DP_MAX_MAP)
      return -1;

    t = &xh->maps[t->pb_xtid];
  }

  // FIXME : Handle non-pcpu

  pthread_rwlock_wrlock(&t->stat_lock);
  if (raw) {
    ll_get_stats_pcpu_arr(t->map_fd, e, &t->pbs[e], NULL);
  }
  if (e < t->max_entries) {
    *(uint64_t *)bytes = t->pbs[e].st.bytes;
    *(uint64_t *)packets = t->pbs[e].st.packets;
  }
  pthread_rwlock_unlock(&t->stat_lock);

  return 0;
}

void flb_collect_map_stats(int tid)
{
  return flb_fetch_map_stats_raw(tid, NULL, NULL);
}

int flb_fetch_pol_map_stats(int tid, uint32_t e, void *ppass, void *pdrop)
{
  flb_dp_map_t *t;
  struct dp_pol_tact pa;

  if (tid < 0 || tid >= LL_DP_MAX_MAP)
    return -1;

  t = &xh->maps[tid];

  if (t->has_pol) {
    pthread_rwlock_wrlock(&t->stat_lock);

    if ((bpf_map_lookup_elem(t->map_fd, &e, &pa)) != 0) {
      pthread_rwlock_unlock(&t->stat_lock);
      return -1;
    }

    *(uint64_t *)ppass = pa.pol.ps.pass_packets;
    *(uint64_t *)pdrop = pa.pol.ps.drop_packets;

    pthread_rwlock_unlock(&t->stat_lock);

    return 0;
  }

  return -1;
}

void flb_xh_lock(void)
{
  XH_MPLOCK();
}

void flb_xh_unlock(void)
{
  XH_MPUNLOCK();
}

//-------------------------------- dpapi 函数 实现 结束------------------------------------------

static void flb_setup_crc32c_map(int mapfd)
{
  int i;
  uint32_t crc;

  // Generate crc32c table
  for (i = 0; i < 256; i++) {
    crc = i;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    bpf_map_update_elem(mapfd, &i, &crc, BPF_ANY);
  }
}

static void flb_setup_ctctr_map(int mapfd)
{
  uint32_t k = 0;
  struct dp_ct_ctrtact ctr;

  memset(&ctr, 0, sizeof(ctr));
  ctr.start = (FLB_CT_MAP_ENTRIES/FLB_MAX_LB_NODES) * xh->nodenum;
  ctr.counter = ctr.start;
  ctr.entries = ctr.start + (FLB_CT_MAP_ENTRIES/FLB_MAX_LB_NODES);
  bpf_map_update_elem(mapfd, &k, &ctr, BPF_ANY);
}

static void flb_setup_cpu_map(int mapfd)
{
  uint32_t qsz = 2048;
  unsigned int live_cpus = bpf_num_possible_cpus();
  int ret, i;

  for (i = 0; i < live_cpus; i++) {
    ret = bpf_map_update_elem(mapfd, &i, &qsz, BPF_ANY);
    if (ret < 0) {
      printf("Failed to update cpu-map %d ent", i);
    }
  }
}

static void flb_setup_lcpu_map(int mapfd)
{
  unsigned int live_cpus = bpf_num_online_cpus();
  int ret, i;
  i = 0;
  ret = bpf_map_update_elem(mapfd, &i, &live_cpus, BPF_ANY);
  if (ret < 0) {
    printf("Failed to update live cpu-map %d ent", i);
  }
}

static void flb_xh_init(flb_dp_struct_t *xh)
{
  xh->ll_dp_fname = FLB_FP_IMG_DEFAULT;
  xh->ll_tc_fname = FLB_FP_IMG_BPF;
  xh->ll_dp_dfl_sec = XDP_LL_SEC_DEFAULT;
  xh->ll_dp_pdir  = FLB_DB_MAP_PDIR;

  xh->maps[LL_DP_INTF_MAP].map_name = "intf_map";
  xh->maps[LL_DP_INTF_MAP].has_pb   = 0;
  xh->maps[LL_DP_INTF_MAP].max_entries   = FLB_INTF_MAP_ENTRIES;

  xh->maps[LL_DP_INTF_STATS_MAP].map_name = "intf_stats_map";
  xh->maps[LL_DP_INTF_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_INTF_STATS_MAP].max_entries = FLB_INTERFACES;
  xh->maps[LL_DP_INTF_STATS_MAP].pbs = calloc(FLB_INTERFACES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_BD_STATS_MAP].map_name = "bd_stats_map";
  xh->maps[LL_DP_BD_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_BD_STATS_MAP].max_entries = FLB_INTF_MAP_ENTRIES;
  xh->maps[LL_DP_BD_STATS_MAP].pbs = calloc(FLB_INTF_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_SMAC_MAP].map_name = "smac_map";
  xh->maps[LL_DP_SMAC_MAP].has_pb   = 0;
  xh->maps[LL_DP_SMAC_MAP].max_entries   = FLB_SMAC_MAP_ENTRIES;

  xh->maps[LL_DP_TMAC_MAP].map_name = "tmac_map";
  xh->maps[LL_DP_TMAC_MAP].has_pb   = 1;
  xh->maps[LL_DP_TMAC_MAP].pb_xtid  = LL_DP_TMAC_STATS_MAP;
  xh->maps[LL_DP_TMAC_MAP].max_entries   = FLB_TMAC_MAP_ENTRIES;

  xh->maps[LL_DP_TMAC_STATS_MAP].map_name = "tmac_stats_map";
  xh->maps[LL_DP_TMAC_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_TMAC_STATS_MAP].max_entries = FLB_TMAC_MAP_ENTRIES;
  xh->maps[LL_DP_TMAC_STATS_MAP].pbs = calloc(FLB_TMAC_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_CT_MAP].map_name = "ct_map";
  xh->maps[LL_DP_CT_MAP].has_pb   = 0;
  xh->maps[LL_DP_CT_MAP].max_entries = FLB_CT_MAP_ENTRIES;

  xh->maps[LL_DP_CT_STATS_MAP].map_name = "ct_stats_map";
  xh->maps[LL_DP_CT_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_CT_STATS_MAP].max_entries = FLB_CT_MAP_ENTRIES;
  xh->maps[LL_DP_CT_STATS_MAP].pbs = calloc(FLB_CT_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_RTV4_MAP].map_name = "rt_v4_map";
  xh->maps[LL_DP_RTV4_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV4_MAP].pb_xtid  = LL_DP_RTV4_STATS_MAP;
  xh->maps[LL_DP_RTV4_MAP].max_entries = FLB_RTV4_MAP_ENTRIES;

  xh->maps[LL_DP_RTV4_STATS_MAP].map_name = "rt_v4_stats_map";
  xh->maps[LL_DP_RTV4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV4_STATS_MAP].max_entries   = FLB_RTV4_MAP_ENTRIES;
  xh->maps[LL_DP_RTV4_STATS_MAP].pbs = calloc(FLB_RTV4_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_RTV6_MAP].map_name = "rt_v6_map";
  xh->maps[LL_DP_RTV6_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV6_MAP].pb_xtid  = LL_DP_RTV6_STATS_MAP;
  xh->maps[LL_DP_RTV6_MAP].max_entries = FLB_RTV6_MAP_ENTRIES;

  xh->maps[LL_DP_RTV6_STATS_MAP].map_name = "rt_v6_stats_map";
  xh->maps[LL_DP_RTV6_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV6_STATS_MAP].max_entries   = FLB_RTV6_MAP_ENTRIES;
  xh->maps[LL_DP_RTV6_STATS_MAP].pbs = calloc(FLB_RTV6_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_NH_MAP].map_name = "nh_map";
  xh->maps[LL_DP_NH_MAP].has_pb   = 0;
  xh->maps[LL_DP_NH_MAP].max_entries   = FLB_NH_MAP_ENTRIES;

  xh->maps[LL_DP_DMAC_MAP].map_name = "dmac_map";
  xh->maps[LL_DP_DMAC_MAP].has_pb   = 0;
  xh->maps[LL_DP_DMAC_MAP].max_entries   = FLB_DMAC_MAP_ENTRIES;

  xh->maps[LL_DP_TX_INTF_MAP].map_name = "tx_intf_map";
  xh->maps[LL_DP_TX_INTF_MAP].has_pb   = 0;
  xh->maps[LL_DP_TX_INTF_MAP].max_entries   = FLB_INTF_MAP_ENTRIES;

  xh->maps[LL_DP_MIRROR_MAP].map_name = "mirr_map";
  xh->maps[LL_DP_MIRROR_MAP].has_pb   = 0;
  xh->maps[LL_DP_MIRROR_MAP].max_entries  = FLB_MIRR_MAP_ENTRIES;

  xh->maps[LL_DP_TX_INTF_STATS_MAP].map_name = "tx_intf_stats_map";
  xh->maps[LL_DP_TX_INTF_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_TX_INTF_STATS_MAP].max_entries = FLB_INTERFACES;
  xh->maps[LL_DP_TX_INTF_STATS_MAP].pbs = calloc(FLB_INTERFACES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_TX_BD_STATS_MAP].map_name = "tx_bd_stats_map";
  xh->maps[LL_DP_TX_BD_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_TX_BD_STATS_MAP].max_entries = FLB_INTF_MAP_ENTRIES;
  xh->maps[LL_DP_TX_BD_STATS_MAP].pbs = calloc(FLB_INTF_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_FCV4_MAP].map_name = "fc_v4_map";
  xh->maps[LL_DP_FCV4_MAP].has_pb   = 0;
  xh->maps[LL_DP_FCV4_MAP].max_entries = FLB_FCV4_MAP_ENTRIES;

  xh->maps[LL_DP_FCV4_STATS_MAP].map_name = "fc_v4_stats_map";
  xh->maps[LL_DP_FCV4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_FCV4_STATS_MAP].max_entries = FLB_FCV4_MAP_ENTRIES;
  xh->maps[LL_DP_FCV4_STATS_MAP].pbs = calloc(FLB_FCV4_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_PGM_MAP].map_name = "pgm_tbl";
  xh->maps[LL_DP_PGM_MAP].has_pb   = 0;
  xh->maps[LL_DP_PGM_MAP].max_entries = FLB_PGM_MAP_ENTRIES;

  xh->maps[LL_DP_POL_MAP].map_name = "polx_map";
  xh->maps[LL_DP_POL_MAP].has_pb   = 0;
  xh->maps[LL_DP_POL_MAP].has_pol  = 1;
  xh->maps[LL_DP_POL_MAP].max_entries = FLB_POL_MAP_ENTRIES;

  xh->maps[LL_DP_NAT_MAP].map_name = "nat_map";
  xh->maps[LL_DP_NAT_MAP].has_pb   = 1;
  xh->maps[LL_DP_NAT_MAP].pb_xtid  = LL_DP_NAT_STATS_MAP;
  xh->maps[LL_DP_NAT_MAP].max_entries = FLB_NATV4_MAP_ENTRIES;

  xh->maps[LL_DP_NAT_STATS_MAP].map_name = "nat_stats_map";
  xh->maps[LL_DP_NAT_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_NAT_STATS_MAP].max_entries = FLB_NATV4_STAT_MAP_ENTRIES;
  xh->maps[LL_DP_NAT_STATS_MAP].pbs = calloc(FLB_NATV4_STAT_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_PKT_PERF_RING].map_name = "pkt_ring";
  xh->maps[LL_DP_PKT_PERF_RING].has_pb   = 0;
  xh->maps[LL_DP_PKT_PERF_RING].max_entries = 128;

  xh->maps[LL_DP_SESS4_MAP].map_name = "sess_v4_map";
  xh->maps[LL_DP_SESS4_MAP].has_pb   = 1;
  xh->maps[LL_DP_SESS4_MAP].pb_xtid  = LL_DP_SESS4_STATS_MAP;
  xh->maps[LL_DP_SESS4_MAP].max_entries  = FLB_SESS_MAP_ENTRIES;

  xh->maps[LL_DP_SESS4_STATS_MAP].map_name = "sess_v4_stats_map";
  xh->maps[LL_DP_SESS4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_SESS4_STATS_MAP].max_entries = FLB_SESS_MAP_ENTRIES;
  xh->maps[LL_DP_SESS4_STATS_MAP].pbs = calloc(FLB_SESS_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_FW4_MAP].map_name = "fw_v4_map";
  xh->maps[LL_DP_FW4_MAP].has_pb   = 1;
  xh->maps[LL_DP_FW4_MAP].pb_xtid  = LL_DP_FW4_STATS_MAP;
  xh->maps[LL_DP_FW4_MAP].max_entries = FLB_FW4_MAP_ENTRIES;

  xh->maps[LL_DP_FW4_STATS_MAP].map_name = "fw_v4_stats_map";
  xh->maps[LL_DP_FW4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_FW4_STATS_MAP].max_entries = FLB_FW4_MAP_ENTRIES;
  xh->maps[LL_DP_FW4_STATS_MAP].pbs = calloc(FLB_FW4_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_CRC32C_MAP].map_name = "crc32c_map";
  xh->maps[LL_DP_CRC32C_MAP].has_pb   = 0;
  xh->maps[LL_DP_CRC32C_MAP].max_entries = FLB_CRC32C_ENTRIES;

  xh->maps[LL_DP_CTCTR_MAP].map_name = "ct_ctr";
  xh->maps[LL_DP_CTCTR_MAP].has_pb   = 0;
  xh->maps[LL_DP_CTCTR_MAP].max_entries = 1;

  xh->maps[LL_DP_CPU_MAP].map_name = "cpu_map";
  xh->maps[LL_DP_CPU_MAP].has_pb   = 0;
  xh->maps[LL_DP_CPU_MAP].max_entries = bpf_num_possible_cpus();

  xh->maps[LL_DP_LCPU_MAP].map_name = "live_cpu_map";
  xh->maps[LL_DP_LCPU_MAP].has_pb   = 0;
  xh->maps[LL_DP_LCPU_MAP].max_entries = bpf_num_online_cpus();

  xh->maps[LL_DP_XFIS_MAP].map_name = "xfis";
  xh->maps[LL_DP_XFIS_MAP].has_pb   = 0;
  xh->maps[LL_DP_XFIS_MAP].max_entries = 1;

  xh->maps[LL_DP_PKTS_MAP].map_name = "pkts";
  xh->maps[LL_DP_PKTS_MAP].has_pb   = 0;
  xh->maps[LL_DP_PKTS_MAP].max_entries = 1;

  xh->maps[LL_DP_FCAS_MAP].map_name = "fcas";
  xh->maps[LL_DP_FCAS_MAP].has_pb   = 0;
  xh->maps[LL_DP_FCAS_MAP].max_entries = 1;

  xh->maps[LL_DP_XFCK_MAP].map_name = "xfck";
  xh->maps[LL_DP_XFCK_MAP].has_pb   = 0;
  xh->maps[LL_DP_XFCK_MAP].max_entries = 1;

  xh->maps[LL_DP_XCTK_MAP].map_name = "xctk";
  xh->maps[LL_DP_XCTK_MAP].has_pb   = 0;
  xh->maps[LL_DP_XCTK_MAP].max_entries = 2;

  xh->maps[LL_DP_GPARSER_MAP].map_name = "gparser";
  xh->maps[LL_DP_GPARSER_MAP].has_pb   = 0;
  xh->maps[LL_DP_GPARSER_MAP].max_entries = 1;

  for(int i = 0; i < LL_DP_MAX_MAP; i++) {
	  xh->maps[i].map_fd = flb_objmap2fd(xh->maps[i].map_name);
    if (xh->maps[i].map_fd < 0) {
      printf("BPF: map2fd failed %s\n", xh->maps[i].map_name);
    }
  }

  xh->ufw4 = pdi_map_alloc("ufw4", NULL, NULL);
  xh->ufw6 = pdi_map_alloc("ufw6", NULL, NULL);

  flb_setup_crc32c_map(flb_map2fd(LL_DP_CRC32C_MAP));
  flb_setup_ctctr_map(flb_map2fd(LL_DP_CTCTR_MAP));
  flb_setup_cpu_map(flb_map2fd(LL_DP_CPU_MAP));
  flb_setup_lcpu_map(flb_map2fd(LL_DP_LCPU_MAP));

  return;
}

int flb_init(struct ebpfcfg *cfg)
{
  flb_set_rlims();

  xh = calloc(1, sizeof(*xh));

  if (cfg) {
    xh->nodenum = cfg->nodenum;
  }

  flb_xh_init(xh);
  return 0;
}

#cgo CFLAGS:  -I./../../ebpf/headers -I./../../ebpf/common
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"

	"github.com/flomesh-io/flb/pkg/nlp"
)

// error codes
const (
	EbpfErrBase = iota - 50000
	EbpfErrPortPropAdd
	EbpfErrPortPropDel
	EbpfErrEbpfLoad
	EbpfErrEbpfUnload
	EbpfErrL2AddrAdd
	EbpfErrL2AddrDel
	EbpfErrTmacAdd
	EbpfErrTmacDel
	EbpfErrNhAdd
	EbpfErrNhDel
	EbpfErrRt4Add
	EbpfErrRt4Del
	EbpfErrNat4Add
	EbpfErrNat4Del
	EbpfErrSess4Add
	EbpfErrSess4Del
	EbpfErrPolAdd
	EbpfErrPolDel
	EbpfErrMirrAdd
	EbpfErrMirrDel
	EbpfErrFwAdd
	EbpfErrFwDel
	EbpfErrCtAdd
	EbpfErrCtDel
	EbpfErrWqUnk
)

const (
	FLB_MGMT_CHANNEL = C.FLB_MGMT_CHANNEL
)

// ebpf table related defines in go
type (
	dp_cmn_act           C.struct_dp_cmn_act
	dp_intf_key          C.struct_intf_key
	dp_intf_tact         C.struct_dp_intf_tact
	dp_intf_tact_set_ifi C.struct_dp_intf_tact_set_ifi
	dp_smac_key          C.struct_dp_smac_key
	dp_dmac_key          C.struct_dp_dmac_key
	dp_dmac_tact         C.struct_dp_dmac_tact
	dp_l2vlan_act        C.struct_dp_l2vlan_act
	dp_tmac_key          C.struct_dp_tmac_key
	dp_tmac_tact         C.struct_dp_tmac_tact
	dp_nh_key            C.struct_dp_nh_key
	dp_nh_tact           C.struct_dp_nh_tact
	dp_rt_l2nh_act       C.struct_dp_rt_l2nh_act
	dp_rt_tunnh_act      C.struct_dp_rt_tunnh_act
	dp_rtv4_key          C.struct_dp_rtv4_key
	dp_rtv6_key          C.struct_dp_rtv6_key
	dp_rt_tact           C.struct_dp_rt_tact
	dp_rt_nh_act         C.struct_dp_rt_nh_act
	dp_rt_l3nh_act       C.struct_dp_rt_nh_act
	dp_nat_key           C.struct_dp_nat_key
	dp_nat_tacts         C.struct_dp_nat_tacts
	dp_mf_xfrm_inf       C.struct_mf_xfrm_inf
	dp_sess4_key         C.struct_dp_sess4_key
	dp_sess_tact         C.struct_dp_sess_tact
	dp_pol_tact          C.struct_dp_pol_tact
	dp_policer_act       C.struct_dp_policer_act
	dp_mirr_tact         C.struct_dp_mirr_tact
	dp_fwv4_ent          C.struct_dp_fwv4_ent
	dp_rdr_act           C.struct_dp_rdr_act
	dp_ct_ctrtact        C.struct_dp_ct_ctrtact
	dp_map_notif         C.struct_ll_dp_map_notif
)

const (
	sizeof_struct_dp_cmn_act           = C.sizeof_struct_dp_cmn_act
	sizeof_struct_intf_key             = C.sizeof_struct_intf_key
	sizeof_struct_dp_intf_tact         = C.sizeof_struct_dp_intf_tact
	sizeof_struct_dp_intf_tact_set_ifi = C.sizeof_struct_dp_intf_tact_set_ifi
	sizeof_struct_dp_smac_key          = C.sizeof_struct_dp_smac_key
	sizeof_struct_dp_dmac_key          = C.sizeof_struct_dp_dmac_key
	sizeof_struct_dp_dmac_tact         = C.sizeof_struct_dp_dmac_tact
	sizeof_struct_dp_l2vlan_act        = C.sizeof_struct_dp_l2vlan_act
	sizeof_struct_dp_tmac_key          = C.sizeof_struct_dp_tmac_key
	sizeof_struct_dp_tmac_tact         = C.sizeof_struct_dp_tmac_tact
	sizeof_struct_dp_nh_key            = C.sizeof_struct_dp_nh_key
	sizeof_struct_dp_nh_tact           = C.sizeof_struct_dp_nh_tact
	sizeof_struct_dp_rt_l2nh_act       = C.sizeof_struct_dp_rt_l2nh_act
	sizeof_struct_dp_rt_tunnh_act      = C.sizeof_struct_dp_rt_tunnh_act
	sizeof_struct_dp_rtv4_key          = C.sizeof_struct_dp_rtv4_key
	sizeof_struct_dp_rtv6_key          = C.sizeof_struct_dp_rtv6_key
	sizeof_struct_dp_rt_tact           = C.sizeof_struct_dp_rt_tact
	sizeof_struct_dp_rt_nh_act         = C.sizeof_struct_dp_rt_nh_act
	sizeof_struct_dp_rt_l3nh_act       = C.sizeof_struct_dp_rt_nh_act
	sizeof_struct_dp_nat_key           = C.sizeof_struct_dp_nat_key
	sizeof_struct_dp_nat_tacts         = C.sizeof_struct_dp_nat_tacts
	sizeof_struct_mf_xfrm_inf          = C.sizeof_struct_mf_xfrm_inf
	sizeof_struct_dp_sess4_key         = C.sizeof_struct_dp_sess4_key
	sizeof_struct_dp_sess_tact         = C.sizeof_struct_dp_sess_tact
	sizeof_struct_dp_pol_tact          = C.sizeof_struct_dp_pol_tact
	sizeof_struct_dp_policer_act       = C.sizeof_struct_dp_policer_act
	sizeof_struct_dp_mirr_tact         = C.sizeof_struct_dp_mirr_tact
	sizeof_struct_dp_fwv4_ent          = C.sizeof_struct_dp_fwv4_ent
	sizeof_struct_dp_rdr_act           = C.sizeof_struct_dp_rdr_act
	sizeof_struct_dp_ct_ctrtact        = C.sizeof_struct_dp_ct_ctrtact
	sizeof_struct_ll_dp_map_notif      = C.sizeof_struct_ll_dp_map_notif
	sizeof_struct_bpf_lpm_trie_key     = 0x4
	sizeof_struct_bpf_spin_lock        = 0x4
)

const (
	LL_DP_INTF_MAP          = C.LL_DP_INTF_MAP
	LL_DP_INTF_STATS_MAP    = C.LL_DP_INTF_STATS_MAP
	LL_DP_BD_STATS_MAP      = C.LL_DP_BD_STATS_MAP
	LL_DP_SMAC_MAP          = C.LL_DP_SMAC_MAP
	LL_DP_TMAC_MAP          = C.LL_DP_TMAC_MAP
	LL_DP_CT_MAP            = C.LL_DP_CT_MAP
	LL_DP_RTV4_MAP          = C.LL_DP_RTV4_MAP
	LL_DP_RTV6_MAP          = C.LL_DP_RTV6_MAP
	LL_DP_NH_MAP            = C.LL_DP_NH_MAP
	LL_DP_DMAC_MAP          = C.LL_DP_DMAC_MAP
	LL_DP_TX_INTF_MAP       = C.LL_DP_TX_INTF_MAP
	LL_DP_MIRROR_MAP        = C.LL_DP_MIRROR_MAP
	LL_DP_TX_INTF_STATS_MAP = C.LL_DP_TX_INTF_STATS_MAP
	LL_DP_TX_BD_STATS_MAP   = C.LL_DP_TX_BD_STATS_MAP
	LL_DP_PKT_PERF_RING     = C.LL_DP_PKT_PERF_RING
	LL_DP_RTV4_STATS_MAP    = C.LL_DP_RTV4_STATS_MAP
	LL_DP_RTV6_STATS_MAP    = C.LL_DP_RTV6_STATS_MAP
	LL_DP_CT_STATS_MAP      = C.LL_DP_CT_STATS_MAP
	LL_DP_TMAC_STATS_MAP    = C.LL_DP_TMAC_STATS_MAP
	LL_DP_FCV4_MAP          = C.LL_DP_FCV4_MAP
	LL_DP_FCV4_STATS_MAP    = C.LL_DP_FCV4_STATS_MAP
	LL_DP_PGM_MAP           = C.LL_DP_PGM_MAP
	LL_DP_POL_MAP           = C.LL_DP_POL_MAP
	LL_DP_NAT_MAP           = C.LL_DP_NAT_MAP
	LL_DP_NAT_STATS_MAP     = C.LL_DP_NAT_STATS_MAP
	LL_DP_SESS4_MAP         = C.LL_DP_SESS4_MAP
	LL_DP_SESS4_STATS_MAP   = C.LL_DP_SESS4_STATS_MAP
	LL_DP_FW4_MAP           = C.LL_DP_FW4_MAP
	LL_DP_FW4_STATS_MAP     = C.LL_DP_FW4_STATS_MAP
	LL_DP_CRC32C_MAP        = C.LL_DP_CRC32C_MAP
	LL_DP_CTCTR_MAP         = C.LL_DP_CTCTR_MAP
	LL_DP_CPU_MAP           = C.LL_DP_CPU_MAP
	LL_DP_LCPU_MAP          = C.LL_DP_LCPU_MAP
	LL_DP_XFIS_MAP          = C.LL_DP_XFIS_MAP
	LL_DP_PKTS_MAP          = C.LL_DP_PKTS_MAP
	LL_DP_FCAS_MAP          = C.LL_DP_FCAS_MAP
	LL_DP_XFCK_MAP          = C.LL_DP_XFCK_MAP
	LL_DP_XCTK_MAP          = C.LL_DP_XCTK_MAP
	LL_DP_GPARSER_MAP       = C.LL_DP_GPARSER_MAP
	LL_DP_MAX_MAP           = C.LL_DP_MAX_MAP
)

const (
	DP_SET_DROP         = C.DP_SET_DROP
	DP_SET_SNAT         = C.DP_SET_SNAT
	DP_SET_DNAT         = C.DP_SET_DNAT
	DP_SET_NEIGH_L2     = C.DP_SET_NEIGH_L2
	DP_SET_ADD_L2VLAN   = C.DP_SET_ADD_L2VLAN
	DP_SET_RM_L2VLAN    = C.DP_SET_RM_L2VLAN
	DP_SET_TOCP         = C.DP_SET_TOCP
	DP_SET_RM_VXLAN     = C.DP_SET_RM_VXLAN
	DP_SET_NEIGH_VXLAN  = C.DP_SET_NEIGH_VXLAN
	DP_SET_RT_TUN_NH    = C.DP_SET_RT_TUN_NH
	DP_SET_L3RT_TUN_NH  = C.DP_SET_L3RT_TUN_NH
	DP_SET_IFI          = C.DP_SET_IFI
	DP_SET_NOP          = C.DP_SET_NOP
	DP_SET_L3_EN        = C.DP_SET_L3_EN
	DP_SET_RT_NHNUM     = C.DP_SET_RT_NHNUM
	DP_SET_SESS_FWD_ACT = C.DP_SET_SESS_FWD_ACT
	DP_SET_RDR_PORT     = C.DP_SET_RDR_PORT
	DP_SET_POLICER      = C.DP_SET_POLICER
	DP_SET_DO_POLICER   = C.DP_SET_DO_POLICER
	DP_SET_FCACT        = C.DP_SET_FCACT
	DP_SET_DO_CT        = C.DP_SET_DO_CT
	DP_SET_RM_GTP       = C.DP_SET_RM_GTP
	DP_SET_ADD_GTP      = C.DP_SET_ADD_GTP
	DP_SET_NEIGH_IPIP   = C.DP_SET_NEIGH_IPIP
	DP_SET_RM_IPIP      = C.DP_SET_RM_IPIP
)

const (
	NAT_LB_SEL_RR   = C.NAT_LB_SEL_RR
	NAT_LB_SEL_HASH = C.NAT_LB_SEL_HASH
	NAT_LB_SEL_PRIO = C.NAT_LB_SEL_PRIO
)

const (
	FLB_MAX_LB_NODES           = C.FLB_MAX_LB_NODES
	FLB_MIRR_MAP_ENTRIES       = C.FLB_MIRR_MAP_ENTRIES
	FLB_NH_MAP_ENTRIES         = C.FLB_NH_MAP_ENTRIES
	FLB_RTV4_MAP_ENTRIES       = C.FLB_RTV4_MAP_ENTRIES
	FLB_RTV4_PREF_LEN          = C.FLB_RTV4_PREF_LEN
	FLB_CT_MAP_ENTRIES         = C.FLB_CT_MAP_ENTRIES
	FLB_ACLV6_MAP_ENTRIES      = C.FLB_ACLV6_MAP_ENTRIES
	FLB_RTV6_MAP_ENTRIES       = C.FLB_RTV6_MAP_ENTRIES
	FLB_TMAC_MAP_ENTRIES       = C.FLB_TMAC_MAP_ENTRIES
	FLB_DMAC_MAP_ENTRIES       = C.FLB_DMAC_MAP_ENTRIES
	FLB_NATV4_MAP_ENTRIES      = C.FLB_NATV4_MAP_ENTRIES
	FLB_NATV4_STAT_MAP_ENTRIES = C.FLB_NATV4_STAT_MAP_ENTRIES
	FLB_SMAC_MAP_ENTRIES       = C.FLB_SMAC_MAP_ENTRIES
	FLB_FW4_MAP_ENTRIES        = C.FLB_FW4_MAP_ENTRIES
	FLB_INTERFACES             = C.FLB_INTERFACES
	FLB_PORT_NO                = C.FLB_PORT_NO
	FLB_PORT_PIDX_START        = C.FLB_PORT_PIDX_START
	FLB_INTF_MAP_ENTRIES       = C.FLB_INTF_MAP_ENTRIES
	FLB_FCV4_MAP_ENTRIES       = C.FLB_FCV4_MAP_ENTRIES
	FLB_PGM_MAP_ENTRIES        = C.FLB_PGM_MAP_ENTRIES
	FLB_FCV4_MAP_ACTS          = C.FLB_FCV4_MAP_ACTS
	FLB_POL_MAP_ENTRIES        = C.FLB_POL_MAP_ENTRIES
	FLB_SESS_MAP_ENTRIES       = C.FLB_SESS_MAP_ENTRIES
	FLB_PSECS                  = C.FLB_PSECS
	FLB_MAX_NXFRMS             = C.FLB_MAX_NXFRMS
	FLB_CRC32C_ENTRIES         = C.FLB_CRC32C_ENTRIES
	FLB_MAX_MHOSTS             = C.FLB_MAX_MHOSTS
	FLB_MAX_MPHOSTS            = C.FLB_MAX_MPHOSTS
)

const (
	FLB_DP_PORT_UPP = 0x1
)

const (
	FLB_TUN_VXLAN = 1
	FLB_TUN_GTP   = 2
	FLB_TUN_STT   = 3
	FLB_TUN_GRE   = 4
	FLB_TUN_IPIP  = 5
)

const (
	FLB_PIPE_COL_NONE   = 0
	FLB_PIPE_COL_GREEN  = 1
	FLB_PIPE_COL_YELLOW = 2
	FLB_PIPE_COL_RED    = 3
)

func bpf_map_update_elem(fd int, key, value unsafe.Pointer, flags uint64) int {
	return int(C.bpf_map_update_elem(C.int(fd), key, value, C.ulonglong(flags)))
}

func bpf_map_lookup_elem(fd int, key, value unsafe.Pointer) int {
	return int(C.bpf_map_lookup_elem(C.int(fd), key, value))
}

func bpf_map_delete_elem(fd int, key unsafe.Pointer) int {
	return int(C.bpf_map_delete_elem(C.int(fd), key))
}

func bpf_map_lookup_and_delete_elem(fd int, key, value unsafe.Pointer) int {
	return int(C.bpf_map_lookup_and_delete_elem(C.int(fd), key, value))
}

func bpf_map_get_next_key(fd int, key, nextkey unsafe.Pointer) int {
	return int(C.bpf_map_get_next_key(C.int(fd), key, nextkey))
}

func bpf_map_get_fd_by_id(id uint32) int {
	return int(C.bpf_map_get_fd_by_id(C.__u32(id)))
}

func get_os_usecs() C.ulonglong {
	return C.get_os_usecs()
}

func get_os_nsecs() C.ulonglong {
	return C.get_os_nsecs()
}

func getPtrOffset(ptr unsafe.Pointer, size uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(ptr) + size)
}

func Exec(cmd string) {
	cmdStr := C.CString(cmd)
	C.flb_sys_exec(cmdStr)
	C.free(unsafe.Pointer(cmdStr))
}

func LinkTapDev(ifName string) int {
	ifStr := C.CString(ifName)
	ret := C.set_up_tap_dev(ifStr)
	C.free(unsafe.Pointer(ifStr))
	return int(ret)
}

func UnlinkTapDev(intfName string) {
	Exec(fmt.Sprintf(`ip link delete %s`, intfName))
}

// LoadXdpProg - load xdp program
func LoadXdpProg() int {
	Exec(fmt.Sprintf(`bpftool prog loadall %s %s/flb_xdp_main type xdp`, C.FLB_FP_IMG_DEFAULT, C.FLB_DB_MAP_PDIR))
	return 0
}

func UnloadXdpProg() {
	os.RemoveAll(fmt.Sprintf(`%s/flb_xdp_main`, C.FLB_DB_MAP_PDIR))
}

// AttachXdpProg - attach eBPF program to an interface
func AttachXdpProg(intfName string) int {
	Exec(fmt.Sprintf(`bpftool net attach xdpgeneric name xdp_packet_func dev %s`, intfName))
	return 0
}

// DetachXdpProg - detach eBPF program to an interface
func DetachXdpProg(intfName string) int {
	Exec(fmt.Sprintf(`bpftool net detach xdpgeneric dev %s`, intfName))
	return 0
}

// AttachTcProg - attach eBPF program to an interface
func AttachTcProg(intfName string) int {
	if !hasLoadedTcProg(intfName) {
		Exec(fmt.Sprintf(`ftc qdisc add dev %s clsact`, intfName))
		Exec(fmt.Sprintf(`ftc filter add dev %s ingress bpf da obj %s sec tc_packet_hook0`, intfName, C.FLB_FP_IMG_BPF))
	}
	return 0
}

// DetachTcProg - detach eBPF program from an interface
func DetachTcProg(intfName string) int {
	if hasLoadedTcProg(intfName) {
		Exec(fmt.Sprintf(`ftc filter del dev %s ingress`, intfName))
		Exec(fmt.Sprintf(`ftc qdisc del dev %s clsact`, intfName))
	}
	return 0
}

func hasLoadedTcProg(intfName string) bool {
	return nlp.HasLoadedTcProg(intfName)
}

func RemoveEBpfMaps() {
	mapPinFiles := make([]string, 0)
	for i := 0; i < C.LL_DP_MAX_MAP; i++ {
		mapPinFiles = append(mapPinFiles, fmt.Sprintf(`%s/%s`, C.GoString(C.xh.ll_dp_pdir), C.GoString(C.xh.maps[i].map_name)))
		mapPinFiles = append(mapPinFiles, fmt.Sprintf(`%s/tc/globals/%s`, C.GoString(C.xh.ll_dp_pdir), C.GoString(C.xh.maps[i].map_name)))
	}
	for _, pinFile := range mapPinFiles {
		os.Remove(pinFile)
	}
}

func flb_add_map_elem(tbl int, k, v unsafe.Pointer) int {
	return int(C.flb_add_map_elem(C.int(tbl), k, v))
}

func flb_del_map_elem(tbl int, k unsafe.Pointer) int {
	return int(C.flb_del_map_elem(C.int(tbl), k))
}

func flb_clear_map_stats(tid int, idx uint32) {
	C.flb_clear_map_stats(C.int(tid), C.uint(idx))
}

func flb_fetch_map_stats_cached(tbl int, e uint32, raw int, bytes, packets unsafe.Pointer) int {
	return int(C.flb_fetch_map_stats_cached(C.int(tbl), C.uint(e), C.int(raw), bytes, packets))
}

func flb_fetch_pol_map_stats(tid int, e uint32, ppass, pdrop unsafe.Pointer) int {
	return int(C.flb_fetch_pol_map_stats(C.int(tid), C.uint(e), ppass, pdrop))
}

// flb_xh_lock - routine to take underlying DP lock
func flb_xh_lock() {
	C.flb_xh_lock()
}

// flb_xh_unlock - routine to release underlying DP lock
func flb_xh_unlock() {
	C.flb_xh_unlock()
}

func FLBInit() {
	C.flb_init(nil)
}
