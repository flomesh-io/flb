package bpf

/*
#include <sys/time.h>

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

func GetOsUSecs() uint64 {
	usecs := C.get_os_usecs()
	return uint64(usecs)
}

func GetOsNSecs() uint64 {
	nsecs := C.get_os_nsecs()
	return uint64(nsecs)
}
