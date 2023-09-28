package config

import "github.com/flomesh-io/flb/pkg/consts"

const (
	FLB_MAX_MHOSTS  = 3
	FLB_MAX_MPHOSTS = 7
	FLB_MAX_NXFRMS  = 16
)

const (
	BPF_FS_BASE  = "/sys/fs/bpf"
	FLB_BASE     = "/opt/flb"
	FLB_TAP_NAME = `flb0`
)

var (
	NodeNo = uint32(0)

	FLB_MAX_LB_NODES           = 2
	FLB_MIRR_MAP_ENTRIES       = 32
	FLB_NH_MAP_ENTRIES         = 4 * 1024
	FLB_RTV4_MAP_ENTRIES       = 32 * 1024
	FLB_RTV4_PREF_LEN          = 48
	FLB_CT_MAP_ENTRIES         = 256 * 1024 * FLB_MAX_LB_NODES
	FLB_ACLV6_MAP_ENTRIES      = 4 * 1024
	FLB_RTV6_MAP_ENTRIES       = 2 * 1024
	FLB_TMAC_MAP_ENTRIES       = 2 * 1024
	FLB_DMAC_MAP_ENTRIES       = 8 * 1024
	FLB_NATV4_MAP_ENTRIES      = 4 * 1024
	FLB_NATV4_STAT_MAP_ENTRIES = 4 * 16 * 1024 /* 16 end-points */
	FLB_SMAC_MAP_ENTRIES       = FLB_DMAC_MAP_ENTRIES
	FLB_FW4_MAP_ENTRIES        = 8 * 1024
	FLB_INTERFACES             = 512
	FLB_PORT_NO                = FLB_INTERFACES - 1
	FLB_PORT_PIDX_START        = FLB_PORT_NO - 128
	FLB_INTF_MAP_ENTRIES       = 6 * 1024
	FLB_FCV4_MAP_ENTRIES       = FLB_CT_MAP_ENTRIES
	FLB_PGM_MAP_ENTRIES        = 8
	FLB_FCV4_MAP_ACTS          = consts.DP_SET_TOCP
	FLB_POL_MAP_ENTRIES        = 8 * 1024
	FLB_SESS_MAP_ENTRIES       = 20 * 1024
	FLB_PSECS                  = 8
	FLB_CRC32C_ENTRIES         = 256
)
