#include <arpa/inet.h>
#include <stdio.h>

#include "generators.h"
#include "pdus.h"
#include "keyhandler.h"
#include "bgpsec_structs.h"

char *generate_bytes(int amount, int mode)
{
    char *bytes = malloc(amount);

    if (!bytes)
        return NULL;

    for (int i = 0; i < amount; i++) {
        if (mode == MODE_DEC)
            bytes[i] = bytes[i] + i;
        else if (mode == MODE_HEX)
            bytes[i] = (bytes[i] + i) % 16;
    }

    return bytes;
}

struct rtr_bgpsec *generate_bgpsec_data(uint32_t origin_as,
                                        uint32_t target_as,
                                        struct rtr_bgpsec_nlri *nlri) {
    struct rtr_bgpsec *data = NULL;

    data = rtr_mgr_bgpsec_new(1, 1, 1, origin_as, target_as, *nlri);
    if (!data)
        return NULL;

    return data;
}

/*uint8_t *generate_bgpsec_attr(struct rtr_secure_path_seg *sec_path,*/
                              /*uint8_t *nlri) {*/
    /*return NULL;*/
/*}*/

struct rtr_signature_seg *generate_signature(
                            struct rtr_bgpsec *data,
                            struct key *priv_key) {
    struct rtr_signature_seg *new_sig = NULL;
    rtr_mgr_bgpsec_generate_signature(data, priv_key->data, &new_sig);

    return new_sig;
}

struct bgpsec_upd *generate_bgpsec_upd(struct rtr_bgpsec *bgpsec) {
    struct bgpsec_upd *new_upd = malloc(sizeof(struct bgpsec_upd));
    uint8_t *upd = NULL;
    uint16_t total_len = 0;
    uint8_t *total_len_p = NULL;
    struct rtr_secure_path_seg *sec = bgpsec->path;
    struct rtr_signature_seg *sig = bgpsec->sigs;
    uint16_t sig_block_len = 0;
    uint8_t *sig_block_len_p = NULL;
    uint8_t *start = NULL;
    uint16_t tmp16 = 0;

    if (!new_upd)
        return NULL;

    new_upd->len = get_upd_len(bgpsec);

    upd = malloc(BGPSEC_UPD_SIZE + new_upd->len);
    if (!upd) {
        free(new_upd);
        return NULL;
    }
    start = upd;

    memcpy(upd, bgpsec_upd_header, BGPSEC_UPD_HEADER_SIZE);
    upd += BGPSEC_UPD_HEADER_SIZE;

    *upd = 0x90; // Flags
    upd += 1;
    *upd = 0x21; // Type Code
    upd += 1;

    total_len_p = upd; // Save position for later
    upd += 2;

    tmp16 = ntohs(bgpsec->path_len * 6);
    memcpy(upd, &tmp16, 2); // Secure Path Length
    upd += 2;

    while (sec) {
        uint32_t asn = ntohl(sec->asn);
        *upd = sec->pcount;
        upd += 1;
        *upd = sec->flags;
        upd += 1;
        memcpy(upd, &asn, 4);
        upd += 4;
        sec = sec->next;
    }

    sig_block_len_p = upd; // Save position for later
    
    *upd = bgpsec->alg;
    upd += 1;
    sig_block_len += 1;

    while (sig) {
        int sig_len = ntohs(sig->sig_len);
        memcpy(upd, sig->ski, SKI_SIZE);
        upd += SKI_SIZE;
        memcpy(upd, &sig_len, 2);
        upd += 2;
        memcpy(upd, sig->signature, sig->sig_len);
        upd += sig->sig_len;
        sig_block_len += 20 + 2 + sig->sig_len;
        sig = sig->next;
    }

    upd = sig_block_len_p;
    tmp16 = ntohs(sig_block_len);
    memcpy(upd, &tmp16, 2);

    total_len += 51 + 6 + (bgpsec->path_len * 6);
    total_len += sig_block_len;

    upd = total_len_p;
    tmp16 = ntohs(total_len);
    memcpy(upd, &tmp16, 2);

    new_upd->upd = start;
    new_upd->len = total_len;
    return new_upd;
}
