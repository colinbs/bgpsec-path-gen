#include <stdio.h>
#include <string.h>

#include "keyhandler.h"

#define PRIV_KEY_BUFFER_SIZE 500

struct key *load_key(char *filepath) {
    struct key *k = malloc(sizeof(struct key));
    uint8_t tmp_buff[PRIV_KEY_BUFFER_SIZE];
    uint16_t length = 0;
    char file_ext[] = ".der";
    int s = strlen(filepath) + strlen(file_ext);
    char priv_filepath[s];
    FILE *keyfile = NULL;

    if (!k)
        return NULL;

    memset(priv_filepath, 0, s);
    strcat(strcat(priv_filepath, filepath), file_ext);

    /* Load private key */
    keyfile = fopen(priv_filepath, "r");

    if (!keyfile) {
        free(k);
        return NULL;
    }

    memset(tmp_buff, 0, PRIV_KEY_BUFFER_SIZE);
    length = fread(&tmp_buff, sizeof(uint8_t), PRIV_KEY_BUFFER_SIZE, keyfile);
    fclose(keyfile);

    if (length <= 0)
        return NULL;

    k->privkey = malloc(length);
    if (!(k->privkey))
        return NULL;

    memcpy(k->privkey, &tmp_buff, length);
    k->privkey_len = length;

    return k;
}

void key_free(struct key *k) {
    free(k->privkey);
    free(k);
}
