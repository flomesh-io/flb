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

var (
	a C.struct_pdi_key
)
