#include <arpa/inet.h>
#include <stdio.h>

#include "generators.h"
#include "pdus.h"
#include "keyhandler.h"
#include "bgpsec_structs.h"
#include "log.h"

#define MP_BUFFER_SIZE 64

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
    uint16_t total_attr_len = 0;
    uint8_t *total_attr_len_p = NULL;
    uint16_t path_attr_len = 0;
    struct rtr_secure_path_seg *sec = bgpsec->path;
    struct rtr_signature_seg *sig = bgpsec->sigs;
    uint16_t sig_block_len = 0;
    uint8_t *sig_block_len_p = NULL;
    uint8_t *start = NULL;
    uint16_t tmp16 = 0;
    uint8_t *mp_buffer;
    uint16_t mp_i = 0;
    uint16_t upd_len = 0;
    uint8_t nexthop[4] = { 0xAC, 0x12, 0x00, 0x02 };

    if (!new_upd)
        return NULL;

    new_upd->len = get_upd_len(bgpsec);

    upd = malloc(BGPSEC_UPD_SIZE + new_upd->len);
    if (!upd) {
        free(new_upd);
        return NULL;
    }
    start = upd;

    /* Build MP_REACH_NLRI attribute */
    mp_buffer = malloc(MP_BUFFER_SIZE);
    if (!mp_buffer)
        return NULL;
    mp_i = generate_mp_attr(mp_buffer, nexthop, bgpsec);

    memcpy(upd, bgpsec_upd_header, BGPSEC_UPD_HEADER_SIZE);
    upd += BGPSEC_UPD_HEADER_SIZE;
    memcpy(upd, mp_buffer, mp_i);
    upd += mp_i;
    memcpy(upd, bgpsec_upd_header_rest, BGPSEC_UPD_HEADER_REST_SIZE);
    upd += BGPSEC_UPD_HEADER_REST_SIZE;

    /* Build BGPsec PATH attribute */
    *upd = 0x90; // Flags
    upd += 1;
    *upd = 0x21; // Type Code
    upd += 1;

    total_attr_len_p = upd; // Save position for later
    upd += 2;

    tmp16 = ntohs((bgpsec->path_len * 6) + 2);
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
    upd += 2;
    sig_block_len += 2;
    
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
        sig_block_len += SKI_SIZE + 2 + sig->sig_len;
        sig = sig->next;
    }

    upd = sig_block_len_p;
    tmp16 = ntohs(sig_block_len);
    memcpy(upd, &tmp16, 2);

    total_attr_len += 6 + (bgpsec->path_len * 6);
    total_attr_len += sig_block_len;

    upd = total_attr_len_p;
    tmp16 = ntohs(total_attr_len - 4); // Subtract Flags, Type Code and Length Fields
    memcpy(upd, &tmp16, 2);

    upd_len = ntohs(BGPSEC_UPD_HEADER_SIZE +
                    mp_i +
                    BGPSEC_UPD_HEADER_REST_SIZE +
                    total_attr_len);
    memcpy(&start[16], &upd_len, 2);

    path_attr_len = ntohs(htons(upd_len) - BGPSEC_UPD_HEADER_SIZE);
    memcpy(&start[21], &path_attr_len, 2);

    new_upd->upd = start;
    new_upd->len = ntohs(upd_len);

    free(mp_buffer);

    return new_upd;
}

uint16_t generate_mp_attr(uint8_t *buffer,
                          uint8_t *nexthop,
                          struct rtr_bgpsec *bgpsec) {
    uint16_t mp_i = 0;
    uint16_t tmp = 0;
    uint8_t nlri_byte_len = (bgpsec->nlri.prefix_len + 7) / 8;

    buffer[mp_i++] = 0x90; // Flags
    buffer[mp_i++] = 0x0E; // Type Code
    buffer[mp_i++] = 0x00; // Length (temp)
    buffer[mp_i++] = 0x00; // Length (temp)
    tmp = ntohs(bgpsec->nlri.prefix.ver + 1);
    memcpy(&buffer[mp_i], &tmp, 2); // AFI
    mp_i += 2;
    buffer[mp_i++] = 0x01; // SAFI
    if (bgpsec->nlri.prefix.ver == LRTR_IPV4) {
        buffer[mp_i++] = 0x04; // Nexthop Length
        memcpy(&buffer[mp_i], nexthop, 4); // IPv4 Nexthop
        mp_i += 4;
    } else {
        buffer[mp_i++] = 0x20; // Nexthop Length
        memcpy(&buffer[mp_i], nexthop, 32); // IPv6 Nexthop
        mp_i += 32;
    }
    buffer[mp_i++] = 0x00; // SNPA
    buffer[mp_i++] = bgpsec->nlri.prefix_len; // NLRI Length
    if (bgpsec->nlri.prefix.ver == LRTR_IPV4) {
        // IPv4 NLRI
        uint32_t addr = htonl(bgpsec->nlri.prefix.u.addr4.addr);
        memcpy(&buffer[mp_i], &addr, nlri_byte_len);
        mp_i += nlri_byte_len;
    } else {
        // IPv6 NLRI
        for (int i = (nlri_byte_len - 1); i >= 0; i--) {
            buffer[mp_i + i] = bgpsec->nlri.prefix.u.addr6.addr[i];
        }
        mp_i += nlri_byte_len;
    }
    tmp = ntohs(mp_i - 4); // Subtract Flags, Type Code and Length Fields
    memcpy(&buffer[2], &tmp, 2); // Total Length

    return mp_i;
}
