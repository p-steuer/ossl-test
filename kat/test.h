/* Author: Patrick Steuer <psteuer@mail.de> */

#ifndef TEST_H
#define TEST_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_DEV	"/dev/urandom"

static inline void
test_passed(void)
{
	exit(0);
}

#define test_failed(...) __test_failed__(__LINE__, __VA_ARGS__)
static inline void
__test_failed__(int line, const char *format, ...)
{
	va_list argptr;

	printf("line %d", line);

	if ((format != NULL) && (strlen(format) > 0)) {
		printf(": ");
		va_start(argptr, format);
		vprintf(format, argptr);
		va_end(argptr);
	}

	printf(".\n");

	exit(1);
}

static inline void
test_memset_rnd(void *out, size_t len)
{
	FILE *dev;

	if ((dev = fopen(TEST_DEV, "r")) == NULL)
		test_failed("Can't open %s", TEST_DEV);
	if((fread(out, len, 1, dev)) != 1) {
		fclose(dev);
		test_failed("Can't read %s", TEST_DEV);
	}
	fclose(dev);
}

#endif
