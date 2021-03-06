#ifndef GENERATORS_H
#define GENERATORS_H

#include <stdlib.h>
#include <stdint.h>

#include "bgpsec_structs.h"
#include "rtrlib/rtrlib.h"
#include "keyhandler.h"

#define MODE_HEX 1
#define MODE_DEC 2

struct bgpsec_upd {
    uint16_t len;
    uint8_t *upd;
};

char *generate_bytes(int amount, int mode);

struct rtr_bgpsec *generate_bgpsec_data(uint32_t origin_as,
                                        uint32_t target_as,
                                        struct rtr_bgpsec_nlri *nlri);

//uint8_t *generate_bgpsec_attr(struct rtr_secure_path_seg *sec_path,
                              //uint8_t *nlri);

uint8_t *generate_new_upd();

struct bgpsec_upd *generate_bgpsec_upd(struct rtr_bgpsec *bgpsec,
                                       struct rtr_bgpsec_nlri *nexthop);

struct rtr_signature_seg *generate_signature(
                            struct rtr_bgpsec *data,
                            struct key *priv_key);

uint16_t generate_mp_attr(uint8_t *buffer,
                          struct rtr_bgpsec_nlri *nexthop,
                          struct rtr_bgpsec *bgpsec);

int align_byte_sequence(const struct rtr_bgpsec *data);
#endif
