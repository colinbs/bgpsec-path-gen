#include "bgpsec_structs.h"

struct secure_path_seg *new_sps(uint8_t pcount,
                                uint8_t flags,
                                uint32_t as)
{
    struct secure_path_seg *new_sps = malloc(SECURE_PATH_SEG_SIZE);

    if (!new_sps)
        return NULL;

    new_sps->next = NULL;
    new_sps->pcount = pcount;
    new_sps->flags = flags;
    new_sps->as = as;
    return new_sps;
}

struct signature_seg *new_ss(uint8_t ski[],
                             uint8_t sig_len,
                             uint8_t *signature)
{
    struct signature_seg *new_ss = malloc(sizeof(struct signature_seg));

    if (!new_ss)
        return NULL;

    new_ss->signature = malloc(sig_len);
    if (!new_ss->signature)
        return NULL;

    new_ss->next = NULL;
    memcpy(new_ss->ski, ski, SKI_SIZE);
    memcpy(new_ss->signature, signature, sig_len);
    new_ss->sig_len;
    return new_ss;
}

void free_secure_path(struct secure_path_seg *path)
{
    struct secure_path_seg *next = NULL;

    if (!path)
        return;

    do {
        next = path->next;
        free(path);
        path = next;
    } while (next);

    path = next = NULL;
}

void free_signatures(struct signature_seg *sigs)
{
    struct signature_seg *next = NULL;

    if (!sigs)
        return;

    do {
        next = sigs->next;
        free(sigs->signature);
        free(sigs);
        sigs = next;
    } while (next);

    sigs = next = NULL;
}

void prepend_sps(struct secure_path_seg *sps, struct secure_path *path)
{
    if (!sps || !path)
        return;

    if (!path->path) {
        path->path = sps;
        path->path_len += 1;
        return;
    }

    sps->next = path->path;
    path->path = sps;
    path->path_len += 1;
}

void prepend_ss(struct signature_seg *ss, struct signature_block *block)
{
    if (!ss || !block)
        return;

    if (!block->sigs) {
        block->sigs = ss;
        block->sigs_len += 1;
        return;
    }

    ss->next = block->sigs;
    block->sigs = ss;
    block->sigs_len += 1;
}
