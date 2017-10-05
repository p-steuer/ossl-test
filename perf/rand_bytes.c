#include <openssl/rand.h>
#include <stdio.h>
#include "perf.h"

#define BYTES		(20345 * 49152ULL)	/* n * lcm(buflen_list) */

#define BUFLENMAX	65536ULL
#define BUFLENLAST	0ULL
unsigned long long
buflen_list[] =		{16, 24, 32, 128, 256, 512, 16384, BUFLENLAST};

int main(void)
{
	unsigned char buf[BUFLENMAX];
	struct timeval t1, t2;
	unsigned long long d, *buflen, i, imax;

	for (buflen = buflen_list; *buflen != BUFLENLAST; buflen++) {
		imax = BYTES / *buflen;

		gettimeofday(&t1, NULL);
		for (i = 0; i < imax; i++)
			RAND_bytes(buf, *buflen);
		gettimeofday(&t2, NULL);

		d = dt(&t1, &t2);

		printf("RAND_bytes(buf, %llu): ", *buflen);
		printf("%llu Kbytes in %.02Lf sec [%.02Lf Kbytes/sec,"
		       " %.02Lf cycles/byte]\n",
		       kbytes(*buflen * imax), sec(d),
		       kbytes_per_sec(*buflen * imax, d),
		       cycles_per_byte(*buflen * imax, d));
	}
	return 0;
}
