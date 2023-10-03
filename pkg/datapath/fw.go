package datapath

/*
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "../../ebpf/common/common_pdi.h"
*/
import "C"

var (
	a C.struct_pdi_key
)
