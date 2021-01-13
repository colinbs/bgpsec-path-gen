/*
 * Here are the logging and debugging functions.
 */

#ifndef LOG_H
#define LOG_H

#include <stdint.h>
#include <stdio.h>

#include "generators.h"
#include "rtrlib/rtrlib.h"

void bgpsecpg_dbg(const char *frmt, ...) __attribute__((format(printf, 1, 2)));

int byte_sequence_to_str(
        char *buffer,
        uint8_t *bytes,
		unsigned int bytes_len,
		unsigned int tabstops);

int bgpsec_segment_to_str(
		char *buffer,
		struct rtr_signature_seg *sig_seg,
		struct rtr_secure_path_seg *sec_path);

void print_bgpsec_path(struct rtr_bgpsec *bgpsec);

void write_output(char *outdir, struct bgpsec_upd *upd, int append);

void parse_bgpsec_update(char *readfile, int print_binary);

uint16_t get_next_len(FILE *f);

#define BGPSECPG_DBG(fmt, ...) bgpsecpg_dbg("BGPSECPG: " fmt, ## __VA_ARGS__)
#define BGPSECPG_DBG1(a) bgpsecpg_dbg("BGPSECPG: " a)

#endif
