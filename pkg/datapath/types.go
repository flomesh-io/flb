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
#include "../../ebpf/common/pdi.h"
#include "../../ebpf/common/flb_dpapi.h"
*/
import "C"

var (
	a C.struct_pdi_key
)
