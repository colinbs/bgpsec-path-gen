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
#include <string.h>

#include "log.h"
#include "generators.h"

#define MAX_BGPSEC_SEG_STR_LEN 1024
#define MAX_BYTE_SEQ_STR_LEN 256
#define MAX_BGPSEC_BIN_PATH_STR_LEN 4096

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

int byte_sequence_to_str(
		char *buffer,
		uint8_t *bytes,
		unsigned int bytes_len,
		unsigned int tabstops)
{
	unsigned int bytes_printed = 1;

	for (unsigned int j = 0; j < tabstops; j++)
		buffer += sprintf(buffer, "\t");

	for (unsigned int i = 0; i < bytes_len; i++, bytes_printed++) {
		buffer += sprintf(buffer, "%02X ", bytes[i]);

		/* Only print 16 bytes in a single line. */
		if (bytes_printed % 16 == 0) {
			buffer += sprintf(buffer, "\n");
			for (unsigned int j = 0; j < tabstops; j++)
				buffer += sprintf(buffer, "\t");
		}
	}

	/* TODO: that's ugly.
	 * If there was no new line printed at the end of the for loop,
	 * print an extra new line.
	 */
	if (bytes_len % 16 != 0)
		buffer += sprintf(buffer, "\n");
	sprintf(buffer, "\n");
	return RTR_BGPSEC_SUCCESS;
}

/* cppcheck-suppress unusedFunction */
int bgpsec_segment_to_str(
		char *buffer,
		struct rtr_signature_seg *sig_seg,
		struct rtr_secure_path_seg *sec_path)
{
	char byte_buffer[MAX_BYTE_SEQ_STR_LEN] = {'\0'};

	buffer += sprintf(buffer, "++++++++++++++++++++++++++++++++++++++++\n");
	buffer += sprintf(buffer, "Signature Segment:\n");
	buffer += sprintf(buffer, "\tSKI:\n");

	byte_sequence_to_str(byte_buffer, sig_seg->ski, SKI_SIZE, 2);
	buffer += sprintf(buffer, "%s\n", byte_buffer);

	buffer += sprintf(buffer, "\tLength: %d\n", sig_seg->sig_len);
	buffer += sprintf(buffer, "\tSignature:\n");

	memset(byte_buffer, 0, sizeof(byte_buffer));
	byte_sequence_to_str(byte_buffer, sig_seg->signature, sig_seg->sig_len,
			     2);
	buffer += sprintf(buffer, "%s\n", byte_buffer);

	buffer += sprintf(buffer, "----------------------------------------\n");
	buffer += sprintf(buffer, "Secure_Path Segment:\n"
			"\tpCount: %d\n"
			"\tFlags: %d\n"
			"\tAS number: %d\n",
			sec_path->pcount,
			sec_path->flags,
			sec_path->asn);
	buffer += sprintf(buffer, "++++++++++++++++++++++++++++++++++++++++\n");
	buffer += sprintf(buffer, "\n");
	*buffer = '\0';

	return RTR_BGPSEC_SUCCESS;
}

void print_bgpsec_path(struct rtr_bgpsec *bgpsec) {
    struct rtr_secure_path_seg *tmp_sec = bgpsec->path;
    struct rtr_signature_seg *tmp_sig = bgpsec->sigs;
    char buffer[MAX_BGPSEC_SEG_STR_LEN];

    for (int i = 0; i < bgpsec->path_len; i++) {
        memset(buffer, 0, MAX_BGPSEC_SEG_STR_LEN);
        bgpsec_segment_to_str(buffer, tmp_sig, tmp_sec);
        printf("%s\n", buffer);
        tmp_sig = tmp_sig->next;
        tmp_sec = tmp_sec->next;
    }
}

void write_output(char *outdir, struct bgpsec_upd *upd) {
    FILE *output_f = NULL;
    int bytes_written;

    if (!upd)
        return;

    output_f = fopen(outdir, "wb");
    if (!output_f)
        return;

    bytes_written = fwrite(upd->upd, sizeof(uint8_t), upd->len, output_f);
    fclose(output_f);

    if (bytes_written == upd->len) {
        printf("File successfully written\n");
    } else {
        printf("Error writing file\n");
    }
}

void parse_binary_path(char *readfile) {
    FILE *f = NULL;
    uint8_t fbuffer[MAX_BGPSEC_BIN_PATH_STR_LEN];
    int bytes_read;

    memset(fbuffer, 0, MAX_BGPSEC_BIN_PATH_STR_LEN);

    if (!readfile)
        return;

    f = fopen(readfile, "rb");
    if (!f)
        return;

    bytes_read = fread(fbuffer, sizeof(uint8_t), MAX_BGPSEC_BIN_PATH_STR_LEN, f);
    if (bytes_read == 0) {
        printf("Error reading file\n");
    }

    char pbuffer[(MAX_BGPSEC_BIN_PATH_STR_LEN * 3) + 1];
    memset(pbuffer, 0, sizeof(pbuffer));
    byte_sequence_to_str(pbuffer, fbuffer, bytes_read, 2);
    printf("%s", pbuffer);

    fclose(f);
}
