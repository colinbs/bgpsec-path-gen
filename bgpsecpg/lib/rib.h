#ifndef RIB_H
#define RIB_H

#include <stdint.h>
#include <stdio.h>

#include "rtrlib/rtrlib.h"

#define MAX_AS_LEN 11
#define MAX_LINE_LEN 256
#define MAX_ASN_COUNT 20

struct rib_entry {
    char as_path[MAX_ASN_COUNT][MAX_AS_LEN];
    int as_path_len;
    struct rtr_bgpsec_nlri *nlri;
};

struct rib_entry *get_next_rib_entry(FILE *ribfile);

struct rib_entry *convert_as_path(char *as_path_str);

#endif
