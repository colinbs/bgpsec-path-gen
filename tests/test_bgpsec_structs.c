/*
 * Unittests that test struct initialization, appending segments
 * and freeing them.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "../bgpsecpg/lib/bgpsec_structs.h"

uint8_t ski[] = {
    0x01,0x02,0x03,0x04,0x05,
    0x06,0x07,0x08,0x09,0x0A,
    0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14
};

uint8_t signature[] = {
    0x01,0x02,0x03,0x04,0x05,
    0x06,0x07,0x08,0x09,0x0A,
    0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,
    0x01,0x02,0x03,0x04,0x05,
    0x06,0x07,0x08,0x09,0x0A,
    0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,
    0x01,0x02,0x03,0x04,0x05,
    0x06,0x07,0x08,0x09,0x0A,
    0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14
};

static void test_init_structs(void)
{
    struct secure_path_seg *sps = NULL;
    struct signature_seg *ss = NULL;

    sps = new_sps(1, 0, 65536);
    assert(sps);
    assert(sps->next == NULL);
    assert(sps->pcount == 1);
    assert(sps->flags == 0);
    assert(sps->as == 65536);

    ss = new_ss(ski, 71, signature);
    assert(ss);
    assert(ss->next == NULL);
    assert(ss->sig_len == 71);

    for (int i = 0; i < SKI_SIZE; i++)
        assert(ss->ski[i] == ski[i]);

    for (int i = 0; i < 71; i++)
        assert(ss->signature[i] == signature[i]);

    free(sps);
    free(ss->signature);
    free(ss);
}

static void test_prepend(void)
{
    struct secure_path *path = NULL;
    struct secure_path_seg *sps1 = NULL;
    struct secure_path_seg *sps2 = NULL;
    struct secure_path_seg *sps3 = NULL;

    struct signature_block *block = NULL;
    struct signature_seg *ss1 = NULL;
    struct signature_seg *ss2 = NULL;
    struct signature_seg *ss3 = NULL;

    path = malloc(sizeof(struct secure_path));
    path->path_len = 0;
    path->path = NULL;

    sps1 = new_sps(1, 0, 65536);
    sps2 = new_sps(1, 0, 65537);
    sps3 = new_sps(1, 0, 65538);

    prepend_sps(sps1, path);
    prepend_sps(sps2, path);
    prepend_sps(sps3, path);

    assert(path->path->as == 65538);
    assert(path->path->next->as == 65537);
    assert(path->path->next->next->as == 65536);

    block = malloc(sizeof(struct signature_block));
    block->block_size = 0;
    block->sigs_len = 0;
    block->algo = 1;
    block->sigs = NULL;

    ss1 = new_ss(ski, 70, signature);
    ss2 = new_ss(ski, 71, signature);
    ss3 = new_ss(ski, 72, signature);

    prepend_ss(ss1, block);
    prepend_ss(ss2, block);
    prepend_ss(ss3, block);

    assert(block->sigs->sig_len == 72);
    assert(block->sigs->next->sig_len == 71);
    assert(block->sigs->next->next->sig_len == 70);

    free_secure_path(path->path);
    free(path);
    free_signatures(block->sigs);
    free(block);
}

int main()
{
    test_init_structs();
    test_prepend();
    printf("All tests successful!\n");
    return EXIT_SUCCESS;
}
