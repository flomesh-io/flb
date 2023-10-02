package consts

// error codes
const (
	LL_DP_INTF_MAP = iota
	LL_DP_INTF_STATS_MAP
	LL_DP_BD_STATS_MAP
	LL_DP_SMAC_MAP
	LL_DP_TMAC_MAP
	LL_DP_CT_MAP
	LL_DP_RTV4_MAP
	LL_DP_RTV6_MAP
	LL_DP_NH_MAP
	LL_DP_DMAC_MAP
	LL_DP_TX_INTF_MAP
	LL_DP_MIRROR_MAP
	LL_DP_TX_INTF_STATS_MAP
	LL_DP_TX_BD_STATS_MAP
	LL_DP_PKT_PERF_RING
	LL_DP_RTV4_STATS_MAP
	LL_DP_RTV6_STATS_MAP
	LL_DP_CT_STATS_MAP
	LL_DP_TMAC_STATS_MAP
	LL_DP_FCV4_MAP
	LL_DP_FCV4_STATS_MAP
	LL_DP_PGM_MAP
	LL_DP_POL_MAP
	LL_DP_NAT_MAP
	LL_DP_NAT_STATS_MAP
	LL_DP_SESS4_MAP
	LL_DP_SESS4_STATS_MAP
	LL_DP_FW4_MAP
	LL_DP_FW4_STATS_MAP
	LL_DP_CRC32C_MAP
	LL_DP_CTCTR_MAP
	LL_DP_CPU_MAP
	LL_DP_LCPU_MAP
	LL_DP_MAX_MAP
)

const (
	DP_INTF_MAP       = "intf_map"
	DP_TX_INTF_MAP    = "tx_intf_map"
	DP_NAT_MAP        = "nat_map"
	DP_RTV4_MAP       = "rt_v4_map"
	DP_RTV4_STATS_MAP = "rt_v4_stats_map"
	DP_RTV6_MAP       = "rt_v6_map"
	DP_RTV6_STATS_MAP = "rt_v6_stats_map"
	DP_SMAC_MAP       = "smac_map"
	DP_SMAC_STATS_MAP = "smac_stats_map"
	DP_DMAC_MAP       = "dmac_map"
	DP_DMAC_STATS_MAP = "dmac_stats_map"
	DP_TMAC_MAP       = "tmac_map"
	DP_TMAC_STATS_MAP = "tmac_stats_map"
	DP_NH_MAP         = "nh_map"
	DP_MIRROR_MAP     = "mirr_map"
	DP_POL_MAP        = "polx_map"

	DP_CRC32C_MAP   = "crc32c_map"
	DP_CTCTR_MAP    = "ct_ctr"
	DP_CPU_MAP      = "cpu_map"
	DP_LIVE_CPU_MAP = "live_cpu_map"
)

const (
	DP_SET_NOP         = 0xc
	DP_SET_SNAT        = 0x1
	DP_SET_DNAT        = 0x2
	DP_SET_ADD_L2VLAN  = 0x4
	DP_SET_RM_L2VLAN   = 0x5
	DP_SET_TOCP        = 0x6
	DP_SET_RM_VXLAN    = 0x7
	DP_SET_RT_TUN_NH   = 0x9
	DP_SET_IFI         = 0xb
	DP_SET_L3_EN       = 0xd
	DP_SET_RT_NHNUM    = 0xe
	DP_SET_NEIGH_IPIP  = 0x17
	DP_SET_NEIGH_L2    = 0x3
	DP_SET_NEIGH_VXLAN = 0x8
	DP_SET_DO_POLICER  = 0x12

	NAT_LB_SEL_RR   = 0x0
	NAT_LB_SEL_HASH = 0x1
	NAT_LB_SEL_PRIO = 0x2

	FLB_DP_PORT_UPP = 0x1
	FLB_INTERFACES  = 0x200

	FLB_TUN_GRE   = 0x4
	FLB_TUN_GTP   = 0x2
	FLB_TUN_STT   = 0x3
	FLB_TUN_VXLAN = 0x1

	FLB_PIPE_COL_YELLOW = 0x2
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
