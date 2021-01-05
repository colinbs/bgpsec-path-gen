#ifndef BGPSEC_STRUCTS_H
#define BGPSEC_STRUCTS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SKI_SIZE 20
#define SECURE_PATH_SEG_SIZE (sizeof(struct secure_path_seg))

struct private_key {
    uint8_t ski[SKI_SIZE];
    uint8_t *key;
};

struct secure_path {
    uint8_t path_len;
    struct secure_path_seg *path;
};

struct signature_block {
    uint16_t block_size;
    uint16_t sigs_len;
    uint8_t algo;
    struct signature_seg *sigs;
};

struct secure_path_seg {
    struct secure_path_seg *next;
    uint8_t pcount;
    uint8_t flags;
    uint32_t as;
};

struct signature_seg {
    struct signature_seg *next;
    uint8_t ski[SKI_SIZE];
    uint16_t sig_len;
    uint8_t *signature;
};

struct bgpsec_nlri {
    uint16_t nlri_len;
    uint8_t pfx_len;
    uint8_t *pfx;
};

struct bgpsec_data {
    uint8_t algo;
    uint16_t afi;
    uint8_t safi;
};

struct secure_path_seg *new_sps(uint8_t pcount,
                                uint8_t flags,
                                uint32_t as);

struct signature_seg *new_ss(uint8_t ski[],
                             uint8_t sig_len,
                             uint8_t *signature);

void free_secure_path(struct secure_path_seg *path);

void free_signatures(struct signature_seg *sigs);

void prepend_sps(struct secure_path_seg *sps, struct secure_path *path);

void prepend_ss(struct signature_seg *ss, struct signature_block *block);

#endif
