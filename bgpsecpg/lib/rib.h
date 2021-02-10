#ifndef RIB_H
#define RIB_H

#include <stdint.h>
#include <stdio.h>

#include "rtrlib/rtrlib.h"

#define MAX_AS_LEN 11
#define MAX_LINE_LEN 1024
#define MAX_ASN_COUNT 40

struct rib_entry {
    uint32_t as_path[MAX_ASN_COUNT];
    int as_path_len;
    struct rtr_bgpsec_nlri *nlri;
};

struct rib_entry *get_next_rib_entry(FILE *ribfile);

struct rib_entry *convert_as_path(char *as_path_str);

void clear_line(FILE *ribfile);

uint8_t get_pcount(struct rib_entry *re, int idx);
#endif
