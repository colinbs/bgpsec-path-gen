#ifndef KEYHANDLER_H
#define KEYHANDLER_H

#include "bgpsec_structs.h"

#define MAX_KEYS 500000

struct key {
    unsigned char ski[SKI_SIZE];
    uint8_t *data;
    int privkey_len;
};

struct key_vault {
    struct key *keys[MAX_KEYS];
    int index;
    int amount;
};

struct key_vault *load_key_dir(char *filepath);

struct key *load_key(char *filepath, char *filename);

void add_key_to_vault(struct key_vault *vault, struct key *k);

void vault_free(struct key_vault *vault);

void key_free(struct key *k);

int chartob16(unsigned char hex_char);

int ski_char_to_hex(uint8_t *buffer, char *ski);

#endif
