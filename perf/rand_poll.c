#include <openssl/rand.h>
#include <stdio.h>
#include "perf.h"

#define	IMAX		300000ULL

int main(void)
{
	struct timeval t1, t2;
	unsigned long long d, i;

	gettimeofday(&t1, NULL);
	for (i = 0; i < IMAX; i++)
		RAND_poll();
	gettimeofday(&t2, NULL);

	d = dt(&t1, &t2);

	printf("RAND_poll(): ");
	printf("%llu times in %.02Lf sec [%.02Lf times/sec]\n", IMAX, sec(d),
	       (long double)IMAX / sec(d));
	return 0;
}
