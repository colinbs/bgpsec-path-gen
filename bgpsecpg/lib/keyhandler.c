#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>

#include "keyhandler.h"

#define PRIV_KEY_BUFFER_SIZE 500

struct key_vault *load_key_dir(char *filepath) {
    DIR *d = NULL;
    struct dirent *d_ent = NULL;
    struct key_vault *vault = malloc(sizeof(struct key_vault));

    if (!vault)
        return NULL;
    vault->index = 0;

    d = opendir(filepath);
    if (!d)
        return NULL;
    
    while ((d_ent = readdir(d)) != NULL) {
        if (d_ent->d_type == DT_REG) {
            if (strstr(d_ent->d_name, ".der") != NULL) {
                char fullpath[256] = {'\0'};
                strcat(fullpath, filepath);
                strcat(fullpath, "/");
                strcat(fullpath, d_ent->d_name);
                printf("%s\n", fullpath);
                struct key *k = load_key(fullpath, d_ent->d_name);
                if (k)
                    add_key_to_vault(vault, k);
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
    memcpy(k->ski, filename, SKI_SIZE);

    return k;
}

void add_key_to_vault(struct key_vault *vault, struct key *k) {
    /*vault->keys[vault->index++] = malloc(sizeof(struct key));*/
    /*memcpy(vault->keys[vault->index], k, sizeof(struct key));*/
    vault->keys[vault->index++] = k;
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

void print_filename(char *filepath) {
    char *foo = basename(filepath);
    printf("%s\n", foo);
}
