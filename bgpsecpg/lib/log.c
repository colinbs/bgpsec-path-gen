/*
 * Here are the logging and debugging functions.
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

void bgpsecpg_dbg(const char *frmt, ...)
{
	va_list argptr;
	struct timeval tv;
	struct timezone tz;

	va_start(argptr, frmt);

	bool fail = true;

	if (gettimeofday(&tv, &tz) == 0) {
		struct tm tm;

		if (localtime_r(&tv.tv_sec, &tm)) {
			fprintf(stderr,
				"(%04d/%02d/%02d %02d:%02d:%02d:%06ld): ",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
			fail = false;
		}
	}

	if (fail)
		fprintf(stderr, "(%jd): ", (intmax_t)time(0));

	vfprintf(stderr, frmt, argptr);
	fprintf(stderr, "\n");
	va_end(argptr);
}
