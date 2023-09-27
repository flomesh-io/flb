/*
 * flb_ebpf_main.c: FLB TC eBPF Main processing
 * Copyright (C) 2022,  Flomesh <www.flomesh.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "flb_kern_entry.c"

char _license[] SEC("license") = "Dual BSD/GPL";
