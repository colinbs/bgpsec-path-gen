#include "generators.h"

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
