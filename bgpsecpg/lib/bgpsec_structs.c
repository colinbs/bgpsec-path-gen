#include <stdio.h>

#include "rtrlib/rtrlib.h"

#include "bgpsec_structs.h"
#include "log.h"

static int pos = 0;

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
    new_ss->sig_len = sig_len;

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

int get_upd_len(struct rtr_bgpsec *bgpsec) {
    int total_len = 0;
    struct rtr_signature_seg *sig = bgpsec->sigs;

    total_len += 4; // Flags (1), Type Code (1), Length (2)
    total_len += 2; // Secure Path Length Field (2)
    total_len += bgpsec->path_len * 6; // Path Count * Path Size (6)
    total_len += 2; // Signature Block Length Field (2)
    total_len += 1; // Algorithm ID (1)
    while (sig) {
        total_len += SKI_SIZE; // SKI Size (20)
        total_len += 2; // Signature Length Field (2)
        total_len += sig->sig_len; // Signature Length (Var)
        sig = sig->next;
    }

    return total_len;
}

struct rtr_bgpsec_nlri *convert_prefix(char *nlri_str) {
    struct rtr_bgpsec_nlri *nlri = NULL;
    struct lrtr_ip_addr tmpaddr;
    char *len_str = NULL;
    char *tok = "/";
    char *ip_str = NULL;
    int nlri_len = get_nlri_len(nlri_str);

    nlri = rtr_mgr_bgpsec_nlri_new(nlri_len);
    if (!nlri)
        return NULL;

    /* Call twice to get the string after the slash */
    strtok(nlri_str, tok);
    len_str = strtok(NULL, tok);
    nlri->nlri_len = atoi(len_str);

    nlri->afi = 1;
    tmpaddr.ver = LRTR_IPV4;
    if (strstr(nlri_str, ":") != NULL) {
        tmpaddr.ver = LRTR_IPV6;
        nlri->afi = 2;
    }

    /*ip_str = strtok(nlri_str, tok);*/
	lrtr_ip_str_to_addr(nlri_str, &tmpaddr);

    *nlri->nlri = tmpaddr.u.addr4.addr;
    if (tmpaddr.ver == LRTR_IPV6) {
        *nlri->nlri = tmpaddr.u.addr6.addr;
    }

    return nlri;
}

int get_nlri_len(char* nlri_str) {
    // Basically, just count '.'s
    int count = 0;
    for (int i = 0; nlri_str[i]; i++) {
        if (nlri_str[i]== '.') count++;
    }
    return count;
}
