#ifndef KEYHANDLER_H
#define KEYHANDLER_H

#include "bgpsec_structs.h"

struct key {
    const unsigned char ski[SKI_SIZE];
    uint8_t *privkey;
    int privkey_len;
};

struct key *load_key(char *filepath);

void key_free(struct key *k);

#endif
