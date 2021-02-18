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

struct bgpsec_upd *generate_bgpsec_upd(struct rtr_bgpsec *bgpsec,
                                       struct rtr_bgpsec_nlri *nexthop) {
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
    uint16_t upd_len_n = 0;

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

    tmp16 = htons((bgpsec->path_len * 6) + 2);
    memcpy(upd, &tmp16, 2); // Secure Path Length
    upd += 2;

    while (sec) {
        uint32_t asn = htonl(sec->asn);
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
        uint16_t sig_len = htons(sig->sig_len);
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
    tmp16 = htons(sig_block_len);
    memcpy(upd, &tmp16, 2);

    total_attr_len += 6 + (bgpsec->path_len * 6);
    total_attr_len += sig_block_len;

    upd = total_attr_len_p;
    tmp16 = htons(total_attr_len - 4); // Subtract Flags, Type Code and Length Fields
    memcpy(upd, &tmp16, 2);

    upd_len = BGPSEC_UPD_HEADER_SIZE +
              mp_i +
              BGPSEC_UPD_HEADER_REST_SIZE +
              total_attr_len;
    upd_len_n = htons(upd_len);
    memcpy(&start[16], &upd_len_n, 2);

    path_attr_len = htons(upd_len - BGPSEC_UPD_HEADER_SIZE);
    memcpy(&start[21], &path_attr_len, 2);

    new_upd->upd = start;
    new_upd->len = upd_len;

    free(mp_buffer);

    return new_upd;
}

uint16_t generate_mp_attr(uint8_t *buffer,
                          struct rtr_bgpsec_nlri *nexthop,
                          struct rtr_bgpsec *bgpsec) {
    uint16_t mp_i = 0;
    uint16_t tmp = 0;
    uint8_t nlri_byte_len = (bgpsec->nlri.prefix_len + 7) / 8;
    uint8_t *start = buffer;

    buffer[mp_i++] = 0x90; // Flags
    buffer[mp_i++] = 0x0E; // Type Code
    buffer[mp_i++] = 0x00; // Length (temp)
    buffer[mp_i++] = 0x00; // Length (temp)
    tmp = htons(bgpsec->nlri.prefix.ver + 1);
    memcpy(&buffer[mp_i], &tmp, 2); // AFI
    mp_i += 2;
    buffer[mp_i++] = 0x01; // SAFI
    if (bgpsec->nlri.prefix.ver == LRTR_IPV4) {
        // IPv4 Nexthop
        buffer[mp_i++] = 0x04; // Nexthop Length
        uint32_t addr = htonl(nexthop->prefix.u.addr4.addr);
        memcpy(&buffer[mp_i], &addr, 4); // IPv4 Nexthop
        mp_i += 4;
    } else {
        // TODO: needs proper testing!
        // IPv6 Nexthop
        buffer[mp_i++] = 0x20; // Nexthop Length
        uint32_t addr[4] = {0};
        addr[0] = htonl(nexthop->prefix.u.addr6.addr[0]);
        addr[1] = htonl(nexthop->prefix.u.addr6.addr[1]);
        addr[2] = htonl(nexthop->prefix.u.addr6.addr[2]);
        addr[3] = htonl(nexthop->prefix.u.addr6.addr[3]);
		memcpy(&buffer[mp_i], addr, 32);
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
        // TODO: needs proper testing!
        // IPv6 NLRI
        uint32_t addr[4] = {0};
        addr[0] = htonl(bgpsec->nlri.prefix.u.addr6.addr[0]);
        addr[1] = htonl(bgpsec->nlri.prefix.u.addr6.addr[1]);
        addr[2] = htonl(bgpsec->nlri.prefix.u.addr6.addr[2]);
        addr[3] = htonl(bgpsec->nlri.prefix.u.addr6.addr[3]);
		memcpy(&buffer[mp_i], addr, nlri_byte_len);
        mp_i += nlri_byte_len;
    }
    tmp = htons(mp_i - 4); // Subtract Flags, Type Code and Length Fields
    memcpy(&buffer[2], &tmp, 2); // Total Length

    return mp_i;
}

int align_byte_sequence(const struct rtr_bgpsec *data)
{
	/* Variables used for network-to-host-order transformation. */
	uint32_t asn = 0;
	uint16_t afi = 0;
    uint8_t *buffer = malloc(4096);
    uint8_t *start = buffer;

	/* Temp secure path and signature segments to prevent any
	 * alteration of the original data.
	 */
	struct rtr_secure_path_seg *tmp_sec = NULL;
	struct rtr_signature_seg *tmp_sig = NULL;

    memset(buffer, 0, 4096);

	/* The data alignment begins here, starting with the target ASN. */
	asn = ntohl(data->target_as);
    memcpy(buffer, &asn, sizeof(asn));
    buffer += sizeof(asn);

	/* Depending on whether we are dealing with alignment for validation
	 * or signing, the first signature segment is skipped.
	 */
	/*if (type == VALIDATION)*/
		/*tmp_sig = data->sigs->next;*/
	/*else*/

	tmp_sec = data->path;

	while (tmp_sec) {
		if (tmp_sig) {
			uint16_t sig_len = ntohs(tmp_sig->sig_len);

			/* Write the signature segment data to stream. */
			memcpy(buffer, tmp_sig->ski, SKI_SIZE);
            buffer += SKI_SIZE;
			memcpy(buffer, &sig_len, sizeof(sig_len));
            buffer += 2;
			memcpy(buffer, tmp_sig->signature, tmp_sig->sig_len);
            buffer += tmp_sig->sig_len;

			tmp_sig = tmp_sig->next;
		}

		/* Write the secure path segment data to stream. */
		memcpy(buffer, (uint8_t *)&tmp_sec->pcount, 1);
        buffer++;
		memcpy(buffer, (uint8_t *)&tmp_sec->flags, 1);
        buffer++;

		asn = ntohl(tmp_sec->asn);
		memcpy(buffer, &asn, sizeof(asn));
        buffer += sizeof(asn);
		tmp_sec = tmp_sec->next;
	}

	/* Write the rest of the data to stream. */
	memcpy(buffer, (uint8_t *)&data->alg, 1);
    buffer++;

	afi = ntohs(data->afi);
	memcpy(buffer, &afi, sizeof(afi));
    buffer += sizeof(afi);

	memcpy(buffer, (uint8_t *)&data->safi, 1);
    buffer++;
	memcpy(buffer, (uint8_t *)&data->nlri.prefix_len, 1);
    buffer++;

	/* Make sure we write the right IP address type by checking the AFI. */
	switch (data->nlri.prefix.ver) {
	case LRTR_IPV4:
		memcpy(buffer, (uint8_t *)&data->nlri.prefix.u.addr4.addr,
			     (data->nlri.prefix_len + 7 ) / 8);
        buffer += (data->nlri.prefix_len + 7 ) / 8;

		break;
	case LRTR_IPV6:
		memcpy(buffer, (uint8_t *)&data->nlri.prefix.u.addr6.addr,
			     (data->nlri.prefix_len + 7 ) / 8);
        buffer += (data->nlri.prefix_len + 7 ) / 8;
		break;
	default:
		/* Should not come here. */
		return RTR_BGPSEC_UNSUPPORTED_AFI;
	}

	return RTR_BGPSEC_SUCCESS;
}
