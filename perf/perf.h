#ifndef PERF_H
# define PERF_H

# include <sys/time.h>
# include "../include/conf.h"

static inline unsigned long long
dt(struct timeval *t1, struct timeval *t2)
{
	unsigned long long dt;

	dt = (unsigned long long)(t2->tv_sec) * 1000000ULL + t2->tv_usec;
	dt -= (unsigned long long)(t1->tv_sec) * 1000000ULL + t1->tv_usec;
	return dt;
}

static inline unsigned long long
kbytes(unsigned long long bytes)
{
	return bytes / 1000;
}

static inline long double
sec(unsigned long long usec)
{
	return (long double)usec / 1000000;
}

static inline long double
kbytes_per_sec(unsigned long long bytes, unsigned long long usec)
{
	return (long double)(bytes * 1000) / usec;
}

static inline long double
cycles_per_byte(unsigned long long bytes, unsigned long long usec)
{
	return (long double)MHZ * usec / bytes;
}

#endif
