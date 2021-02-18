#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>

#include "keyhandler.h"
#include "log.h"

#define PRIV_KEY_BUFFER_SIZE 500
#define SKI_STR_SIZE 41
#define FILENAME_WITH_EXT_LEN 44
#define MAX_FULLPATH_LEN 256

const char *file_ext = ".der";

struct key_vault *load_key_dir(char *filepath) {
    DIR *d = NULL;
    struct dirent *d_ent = NULL;
    struct key_vault *vault = malloc(sizeof(struct key_vault));

    if (!vault)
        return NULL;
    vault->index = 0;
    vault->amount = 0;

    d = opendir(filepath);
    if (!d)
        return NULL;
    
    while ((d_ent = readdir(d)) != NULL) {
        if (d_ent->d_type == DT_REG) {
            if (strstr(d_ent->d_name, file_ext) != NULL
                && strlen(d_ent->d_name) == FILENAME_WITH_EXT_LEN) {
                char fullpath[MAX_FULLPATH_LEN];
                memset(fullpath, 0, MAX_FULLPATH_LEN);
                strcat(fullpath, filepath);
                if (fullpath[strlen(fullpath) - 1] != '/') {
                    strcat(fullpath, "/");
                }
                strcat(fullpath, d_ent->d_name);
                struct key *k = load_key(fullpath, d_ent->d_name);
                if (k)
                    add_key_to_vault(vault, k);
                if (vault->amount > MAX_KEYS) {
                    bgpsecpg_dbg("Reached the maximum amount of router keys.");
                    break;
                }
            }
        }
    }
    closedir(d);

    return vault;
}

struct key *load_key(char *filepath, char *filename) {
    struct key *k = malloc(sizeof(struct key));
    uint8_t tmp_buff[PRIV_KEY_BUFFER_SIZE];
    uint16_t length = 0;
    char priv_filepath[strlen(filepath)];
    FILE *keyfile = NULL;
    unsigned char ski_buffer[SKI_SIZE];

    if (!k)
        return NULL;

    memset(priv_filepath, 0, strlen(filepath));
    strcat(priv_filepath, filepath);

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

    k->data = malloc(length);
    if (!(k->data))
        return NULL;

    memcpy(k->data, &tmp_buff, length);
    k->privkey_len = length;
    ski_char_to_hex(ski_buffer, filename);
    memcpy(k->ski, ski_buffer, SKI_SIZE);

    return k;
}

void add_key_to_vault(struct key_vault *vault, struct key *k) {
    /*vault->keys[vault->index++] = malloc(sizeof(struct key));*/
    /*memcpy(vault->keys[vault->index], k, sizeof(struct key));*/
    vault->keys[vault->index++] = k;
    vault->amount++;
}

void vault_free(struct key_vault *vault) {
    while (vault->index > 0) {
        key_free(vault->keys[--vault->index]);
    }
    free(vault);
}

void key_free(struct key *k) {
    free(k->data);
    free(k);
}

int chartob16(unsigned char hex_char)
{
    if (hex_char > 47 && hex_char < 58)
        return hex_char - 48;

    if (hex_char > 64 && hex_char < 71)
        return hex_char - 55;

    if (hex_char > 96 && hex_char < 103)
        return hex_char - 87;

    return -1;
}

int ski_char_to_hex(uint8_t *buffer, char *ski)
{
    char ch1;
    char ch2;

    for (int i = 0, j = 0; i < (SKI_STR_SIZE - 1); i += 2, j++) {
        ch1 = chartob16(ski[i]);
        ch2 = chartob16(ski[i+1]);
        if (ch1 == -1 || ch2 == -1)
            return (i + 1);
        buffer[j] = (ch1 << 4) | ch2;
    }

    return 0;
}
