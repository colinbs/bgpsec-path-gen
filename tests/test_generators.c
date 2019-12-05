/*
 * Unittests that test generator functions such as returning
 * "random" byte sequences.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "bgpsecpg/lib/bgpsec_structs.h"
#include "bgpsecpg/lib/generators.h"

static void test_generate_bytes(void)
{
    char *bytes;

    bytes = generate_bytes(SKI_SIZE, MODE_HEX);
    assert(bytes);
    free(bytes);

    bytes = NULL;

    bytes = generate_bytes(SKI_SIZE, MODE_DEC);
    assert(bytes);
    free(bytes);
}

int main()
{
    test_generate_bytes();
    printf("All tests successful!\n");
    return EXIT_SUCCESS;
}
