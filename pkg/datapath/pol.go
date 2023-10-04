package datapath

/*
#include <string.h>
#include <time.h>

unsigned long long get_os_usecs(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((unsigned long long)ts.tv_sec * 1000000UL) + ts.tv_nsec/1000;
}

unsigned long long get_os_nsecs(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"
import (
	"unsafe"

	. "github.com/flomesh-io/flb/pkg/wq"
)

// DpPolMod - routine to work on a ebpf policer change request
func DpPolMod(w *PolDpWorkQ) int {
	key := C.uint(w.Mark)

	if w.Work == DpCreate {
		dat := new(dp_pol_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_pol_tact)
		dat.ca.act_type = DP_SET_DO_POLICER
		// For finding pa, we need to account for padding of 4
		pa := (*dp_policer_act)(getPtrOffset(unsafe.Pointer(dat),
			sizeof_struct_dp_cmn_act+sizeof_struct_bpf_spin_lock+4))

		if !w.Srt {
			pa.trtcm = 1
		} else {
			pa.trtcm = 0
		}

		if !w.Color {
			pa.color_aware = 0
		} else {
			pa.color_aware = 1
		}

		pa.toksc_pus = C.ulonglong(w.Cir / (8000000))
		pa.tokse_pus = C.ulonglong(w.Pir / (8000000))
		pa.cbs = C.uint(w.Cbs)
		pa.ebs = C.uint(w.Ebs)
		pa.tok_c = pa.cbs
		pa.tok_e = pa.ebs
		pa.lastc_uts = C.get_os_usecs()
		pa.laste_uts = pa.toksc_pus
		pa.drop_prio = FLB_PIPE_COL_YELLOW

		sErr := llb_add_map_elem(LL_DP_POL_MAP,
			unsafe.Pointer(&key),
			unsafe.Pointer(dat))

		if sErr != nil {
			*w.Status = 1
			return EbpfErrPolAdd
		}

		*w.Status = 0

	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(dp_pol_tact)
		C.memset(unsafe.Pointer(dat), 0, sizeof_struct_dp_pol_tact)
		llb_add_map_elem(LL_DP_POL_MAP, unsafe.Pointer(&key), unsafe.Pointer(dat))
		// This operation is unnecessary
		llb_del_map_elem(LL_DP_POL_MAP, unsafe.Pointer(&key))
		return 0
	}
	return 0
}
