package bpf

import "C"

const (
	FLB_FP_IMG_DEFAULT = `/opt/flb/flb_xdp_main.o`
	FLB_FP_IMG_BPF     = `/opt/flb/flb_ebpf_main.o`
	FLB_DB_MAP_PDIR    = `/sys/fs/bpf`
)
