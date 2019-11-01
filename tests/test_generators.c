/*
 * Unittests that test generator functions such as returning
 * "random" byte sequences.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "../lib/bgpsec_structs.h"
#include "../lib/generators.h"

static void test_generate_bytes(void)
{
    char *bytes;

    bytes = generate_bytes(SKI_SIZE, MODE_HEX);
    assert(bytes);
}

int main()
{
    test_generate_bytes();
    printf("All tests successful!\n");
    return EXIT_SUCCESS;
}
