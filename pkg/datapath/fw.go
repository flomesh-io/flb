package datapath

/*
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <linux/types.h>
#include "../../ebpf/common/common_pdi.h"
*/
import "C"

var (
	a C.struct_pdi_key
)
