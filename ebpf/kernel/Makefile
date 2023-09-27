# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_DEPS := flb_kern_devif.c      \
            flb_kern_l2fwd.c      \
            flb_kern_l3fwd.c      \
            flb_kern_sessfwd.c    \
            flb_kern_natlbfwd.c   \
            flb_kern_policer.c    \
            flb_kern_fcfwd.c      \
            flb_kern_entry.c      \
            flb_kern_ct.c

XDP_TARGETS  := flb_xdp_main
TC_TARGETS   := flb_ebpf_main
TC_ETARGETS  := flb_ebpf_emain
MON_TARGETS  := flb_kern_mon

LLC ?= llc
CLANG ?= clang
CC := gcc

COMMON_DIR = ../common

LDFLAGS +=  -lz 

include $(COMMON_DIR)/common.mk
