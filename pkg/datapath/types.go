package datapath

/*
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/types.h>

#include "../../ebpf/headers/linux/bpf.h"
#include "../../ebpf/common/pdi.h"
#include "../../ebpf/common/flb_dpapi.h"
#include "../../ebpf/common/common_pdi.c"

#cgo CFLAGS:  -I./../../ebpf/headers/linux -I./../../ebpf/common
*/
import "C"
import "unsafe"

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

// ebpf table related defines in go
type (
	dp_cmn_act          C.struct_dp_cmn_act
	dp_intf_key         C.struct_intf_key
	dp_intf_tact        C.struct_dp_intf_tact
	dp_intf_tact_set_if C.struct_dp_intf_tact_set_ifi
	dp_smac_key         C.struct_dp_smac_key
	dp_dmac_key         C.struct_dp_dmac_key
	dp_dmac_tact        C.struct_dp_dmac_tact
	dp_l2vlan_act       C.struct_dp_l2vlan_act
	dp_tmac_key         C.struct_dp_tmac_key
	dp_tmac_tact        C.struct_dp_tmac_tact
	dp_nh_key           C.struct_dp_nh_key
	dp_nh_tact          C.struct_dp_nh_tact
	dp_rt_l2nh_act      C.struct_dp_rt_l2nh_act
	dp_rt_tunnh_act     C.struct_dp_rt_tunnh_act
	dp_rtv4_key         C.struct_dp_rtv4_key
	dp_rtv6_key         C.struct_dp_rtv6_key
	dp_rt_tact          C.struct_dp_rt_tact
	dp_rt_nh_act        C.struct_dp_rt_nh_act
	dp_rt_l3nh_act      C.struct_dp_rt_nh_act
	dp_nat_key          C.struct_dp_nat_key
	dp_nat_tacts        C.struct_dp_nat_tacts
	dp_mf_xfrm_inf      C.struct_mf_xfrm_inf
	dp_sess4_key        C.struct_dp_sess4_key
	dp_sess_tact        C.struct_dp_sess_tact
	dp_pol_tact         C.struct_dp_pol_tact
	dp_policer_act      C.struct_dp_policer_act
	dp_mirr_tact        C.struct_dp_mirr_tact
	dp_fwv4_ent         C.struct_dp_fwv4_ent
	dp_rdr_act          C.struct_dp_rdr_act
	dp_map_notif        C.struct_ll_dp_map_notif
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
	sizeof_struct_ll_dp_map_notif      = C.sizeof_struct_ll_dp_map_notif
)

const (
	LL_DP_INTF_MAP         = C.LL_DP_INTF_MAP
	LL_DP_INTF_STATS_MAP   = C.LL_DP_INTF_STATS_MAP
	LL_DP_BD_STATS_MAP     = C.LL_DP_BD_STATS_MAP
	LL_DP_SMAC_MAP         = C.LL_DP_SMAC_MAP
	LL_DP_TMAC_MAP         = C.LL_DP_TMAC_MAP
	LL_DP_CT_MAP           = C.LL_DP_CT_MAP
	LL_DP_RTV4_MAP         = C.LL_DP_RTV4_MAP
	LL_DP_RTV6_MAP         = C.LL_DP_RTV6_MAP
	LL_DP_NH_MAP           = C.LL_DP_NH_MAP
	LL_DP_DMAC_MAP         = C.LL_DP_DMAC_MAP
	LL_DP_TX_INTF_MAP      = C.LL_DP_TX_INTF_MAP
	LL_DP_MIRROR_MAP       = C.LL_DP_MIRROR_MAP
	LL_DP_TX_INTF_STATS_MA = C.LL_DP_TX_INTF_STATS_MAP
	LL_DP_TX_BD_STATS_MAP  = C.LL_DP_TX_BD_STATS_MAP
	LL_DP_PKT_PERF_RING    = C.LL_DP_PKT_PERF_RING
	LL_DP_RTV4_STATS_MAP   = C.LL_DP_RTV4_STATS_MAP
	LL_DP_RTV6_STATS_MAP   = C.LL_DP_RTV6_STATS_MAP
	LL_DP_CT_STATS_MAP     = C.LL_DP_CT_STATS_MAP
	LL_DP_TMAC_STATS_MAP   = C.LL_DP_TMAC_STATS_MAP
	LL_DP_FCV4_MAP         = C.LL_DP_FCV4_MAP
	LL_DP_FCV4_STATS_MAP   = C.LL_DP_FCV4_STATS_MAP
	LL_DP_PGM_MAP          = C.LL_DP_PGM_MAP
	LL_DP_POL_MAP          = C.LL_DP_POL_MAP
	LL_DP_NAT_MAP          = C.LL_DP_NAT_MAP
	LL_DP_NAT_STATS_MAP    = C.LL_DP_NAT_STATS_MAP
	LL_DP_SESS4_MAP        = C.LL_DP_SESS4_MAP
	LL_DP_SESS4_STATS_MAP  = C.LL_DP_SESS4_STATS_MAP
	LL_DP_FW4_MAP          = C.LL_DP_FW4_MAP
	LL_DP_FW4_STATS_MAP    = C.LL_DP_FW4_STATS_MAP
	LL_DP_CRC32C_MAP       = C.LL_DP_CRC32C_MAP
	LL_DP_CTCTR_MAP        = C.LL_DP_CTCTR_MAP
	LL_DP_CPU_MAP          = C.LL_DP_CPU_MAP
	LL_DP_LCPU_MAP         = C.LL_DP_LCPU_MAP
	LL_DP_XFIS_MAP         = C.LL_DP_XFIS_MAP
	LL_DP_PKTS_MAP         = C.LL_DP_PKTS_MAP
	LL_DP_FCAS_MAP         = C.LL_DP_FCAS_MAP
	LL_DP_XFCK_MAP         = C.LL_DP_XFCK_MAP
	LL_DP_XCTK_MAP         = C.LL_DP_XCTK_MAP
	LL_DP_GPARSER_MAP      = C.LL_DP_GPARSER_MAP
	LL_DP_MAX_MAP          = C.LL_DP_MAX_MAP
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

func getPtrOffset(ptr unsafe.Pointer, size uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(ptr) + size)
}
