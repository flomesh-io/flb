package main

/*

#include <sys/resource.h>

static int flb_set_rlims(void)
{
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    return -1;
  }

  return 0;
}

*/
import "C"

func setResourceLimit() bool {
	ret := C.flb_set_rlims()
	return ret == 0
}
