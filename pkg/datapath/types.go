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

#include <bpf.h>
#include <pdi.h>
#include <flb_dpapi.h>
#include <common_pdi.c>

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

func getPtrOffset(ptr unsafe.Pointer, size uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(ptr) + size)
}
