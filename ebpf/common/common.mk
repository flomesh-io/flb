# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS
# as a space-separated list
#
LLC = llc
CLANG := $(shell if [ -f /usr/bin/clang-13 ];then echo clang-13; else echo clang-10; fi;)
CC ?= gcc
BPFTOOL ?= bpftool

XDP_C = ${XDP_TARGETS:=.c}
TC_C = ${TC_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
TC_OBJ = ${TC_C:.c=.o}

UNAME := $(shell uname -m)
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
ifeq ($(UNAME), aarch64)
ARCH=arm64
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
  | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
  Q =
  msg =
else
  Q = @
  msg = @printf '  %-8s %s%s\n'         \
          "$(1)"            \
          "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
          "$(if $(3), $(3))";
  MAKEFLAGS += --no-print-directory
endif


# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ../common/

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS_ALL ?= -DHAVE_DP_FC=1 -DHAVE_DP_EXTCT=1 -DHAVE_DP_SCTP_SUM=1 -DHAVE_DP_CT_SYNC=1 -DMAX_REAL_CPUS=40 -DHAVE_DP_RSS=1
ifeq ($(CLANG), clang-13)
CFLAGS_ALL += -DHAVE_CLANG13
endif

BPF_CFLAGS ?= -I../headers/ -I/usr/include/$(shell uname -m)-linux-gnu $(CFLAGS_ALL)

all: llvm-check $(XDP_OBJ) $(TC_OBJ)

.PHONY: clean $(CLANG) $(LLC) vmlinux

clean:
	rm -f $(XDP_OBJ)
	rm -f $@
	rm -f *.ll
	rm -f *~

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	#$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	sudo mv $@ /opt/flb/ 

## Remove debug in production
## -DLL_XDP_DEBUG=1

$(TC_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-DLL_TC_EBPF=1 \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	sudo mv $@ /opt/flb/ 
	@#sudo pahole -J /opt/flb/$@

install:
	@sudo cp -f /opt/flb/flb_*.o ${dpinstalldir}/
