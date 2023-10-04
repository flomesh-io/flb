package bpf

/*
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

func GetOsUSecs() C.ulonglong {
	return C.get_os_usecs()
}

func GetOsNSecs() C.ulonglong {
	return C.get_os_nsecs()
}
