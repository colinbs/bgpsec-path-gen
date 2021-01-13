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
#include "pdus.h"

#define BGPSECPG_PREFIX_STR "BGPSEC Path Gen:"

#define MAX_BGPSEC_SEG_STR_LEN 1024
#define MAX_BYTE_SEQ_STR_LEN 256
#define MAX_BGPSEC_BIN_PATH_STR_LEN (4096 * 4)

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
				"(%04d/%02d/%02d %02d:%02d:%02d:%06ld): %s ",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec,
                BGPSECPG_PREFIX_STR);
			fail = false;
		}
	}

	if (fail)
		fprintf(stderr, "(%jd): %s", (intmax_t)time(0),
                BGPSECPG_PREFIX_STR);

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

        /* Add additional space after 8 bytes */
        if (bytes_printed % 8 == 0) {
			buffer += sprintf(buffer, " ");
        }

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

void write_output(char *outdir, struct bgpsec_upd *upd, int append) {
    FILE *output_f = NULL;
    int bytes_written;
    char *options = NULL;

    if (!upd)
        return;

    if (append == 1) {
        options = "ab";
    } else {
        options = "wb";
    }

    output_f = fopen(outdir, options);
    if (!output_f) {
        bgpsecpg_dbg("Error opening file");
        return;
    }

    bytes_written = fwrite(upd->upd, sizeof(uint8_t), upd->len, output_f);
    fclose(output_f);

    if (bytes_written == upd->len) {
        bgpsecpg_dbg("File successfully written");
    } else {
        bgpsecpg_dbg("Error writing file");
    }
}

void parse_bgpsec_update(char *readfile, int print_binary) {
    FILE *f = NULL;
    uint8_t fbuffer[MAX_BGPSEC_BIN_PATH_STR_LEN];
    int bytes_read;
    long end;

    memset(fbuffer, 0, MAX_BGPSEC_BIN_PATH_STR_LEN);

    if (!readfile)
        return;

    f = fopen(readfile, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    end = ftell(f);
    rewind(f);

    if (print_binary) {
        while (end > 0) {
            uint16_t upd_len = get_next_len(f);
            char *pbuffer = malloc(MAX_BGPSEC_BIN_PATH_STR_LEN);
            if (!pbuffer)
                return;

            fread(fbuffer, sizeof(uint8_t), upd_len, f);
            byte_sequence_to_str(pbuffer, fbuffer, upd_len, 0);

            end -= upd_len;

            printf("%s", pbuffer);
            free(pbuffer);
            pbuffer = NULL;
        }
    } else {
        while (end > 0) {
            //TODO: print human readable format.
            char *pbuffer;
            char *start;
            uint8_t c;
            uint16_t w;
            uint32_t l;
            char b[128];
            uint8_t cidr = 0;
            int cidr_b = 0;
            int block_len = 0;
            uint16_t upd_len = get_next_len(f);
            int i = 0;

            memset(b, 0, sizeof(b));
            pbuffer = malloc(MAX_BGPSEC_BIN_PATH_STR_LEN);
            if (!pbuffer)
                return;

            fread(fbuffer, sizeof(uint8_t), upd_len, f);

            start = pbuffer;
            i += BGPSEC_UPD_HEADER_SIZE; // Skip the header fields
            i += 4; // Skip Flags and Type Code of MP_REACH_NLRI
            
            w = ((uint16_t)fbuffer[i] << 8) | fbuffer[i+1];
            pbuffer += sprintf(pbuffer, "\nAFI: %d\n", w);
            i += 2;

            c = fbuffer[i];
            pbuffer += sprintf(pbuffer, "SAFI: %d\n", c);
            i += 1;

            c = fbuffer[i];
            i += c + 2; // Skip the Nexthop and SNPA

            cidr = fbuffer[i];
            cidr_b = (cidr + 7) / 8;
            i += 1;
            pbuffer += sprintf(pbuffer, "NLRI: ");
            for (int ii = 0; ii < cidr_b; ii++) {
                pbuffer += sprintf(pbuffer, "%d", fbuffer[i]);
                i += 1;
                if (ii < (cidr_b - 1))
                    pbuffer += sprintf(pbuffer, ".");
            }
            pbuffer += sprintf(pbuffer, "/%d\n\n", cidr);
            
            i += 2; // Skip to ORIGIN Length
            c = fbuffer[i];
            i += c + 1; // Skip the Origin

            i += 2; // Skip to MULTI_EXIT_DISC Length
            c = fbuffer[i];
            i += c + 1; // Skip the MULTI_EXIT_DISC

            /* BGPsec PATH */
            pbuffer += sprintf(pbuffer, "BGPSec_PATH:\n\n");
            i += 4; // Skip to Secure Path Length
            w = (((uint16_t)fbuffer[i] << 8) | fbuffer[i+1]) - 2;
            w = w / 6;
            i += 2;
            for (int ii = 0; ii < w; ii++) {
                int w1 = 0;
                int w2 = 0;

                pbuffer += sprintf(pbuffer, "\tSecure Path Segment:\n");
                c = fbuffer[i];
                pbuffer += sprintf(pbuffer, "\t\tpCount: %d\n", c);
                i += 1;

                c = fbuffer[i];
                pbuffer += sprintf(pbuffer, "\t\tFlags: %d\n", c);
                i += 1;

                w1 = ((uint16_t)fbuffer[i] << 8) | fbuffer[i+1];
                w2 = ((uint16_t)fbuffer[i+2] << 8) | fbuffer[i+3];
                l = ((uint32_t)w1 << 16) | w2;
                pbuffer += sprintf(pbuffer, "\t\tAS Number: %d\n\n", l);
                i += 4;
            }

            block_len =  (((uint16_t)fbuffer[i] << 8) | fbuffer[i+1]) - 2;
            i += 2;

            pbuffer += sprintf(pbuffer, "\tSignature Block:\n");

            c = fbuffer[i];
            pbuffer += sprintf(pbuffer, "\t\tAlgorithm Suite ID: %d\n\n", c);
            i += 1;

            for (int ii = (block_len - 1); ii > 0;) {
                pbuffer += sprintf(pbuffer, "\t\tSignature Segment:\n\n");
                pbuffer += sprintf(pbuffer, "\t\t\tSubject Key Identifier:\n");
                memset(b, 0, sizeof(b));
                byte_sequence_to_str(b, (uint8_t *)&fbuffer[i], SKI_SIZE, 4);
                pbuffer += sprintf(pbuffer, "%s", b);
                i += SKI_SIZE;
                ii -= SKI_SIZE;

                w = (((uint16_t)fbuffer[i] << 8) | fbuffer[i+1]);
                pbuffer += sprintf(pbuffer, "\t\t\tSignature Length: %d\n\n", w);
                i += 2;
                ii -= 2;

                pbuffer += sprintf(pbuffer, "\t\t\tSignature:\n");
                memset(b, 0, sizeof(b));
                byte_sequence_to_str(b, (uint8_t *)&fbuffer[i], w, 4);
                pbuffer += sprintf(pbuffer, "%s", b);
                i += w;
                ii -= w;
            }

            end -= i;

            printf("%s\n", start);
            free(start);
            start = NULL;
        }
    }

    fclose(f);
}

uint16_t get_next_len(FILE *f) {
    uint16_t len = 0;
    int curr = 0;
    uint8_t buffer[2];
    
    curr = ftell(f);
    fseek(f, 16, SEEK_CUR);

    fread(buffer, sizeof(uint8_t), 2, f);

    len = ((uint16_t)buffer[0] << 8) | buffer[1];
    fseek(f, curr, SEEK_SET);

    return len;
}
