#include <stdio.h>
#include <string.h>

#include "rib.h"
#include "bgpsec_structs.h"

struct rib_entry *get_next_rib_entry(FILE *ribfile) {
    struct rib_entry *re = NULL;
    struct rtr_bgpsec_nlri *nlri = NULL;
    char line[MAX_LINE_LEN];
    char *tok = "|";
    char *sub = NULL;
    int col_i = 0;
    char nlri_str[64] = {'\0'};
    char as_path_str[128] = {'\0'};
    int cont = 0;

    if (!ribfile)
        return NULL;

    do {
        cont = 0;
        col_i = 0;
        memset(line, 0, MAX_LINE_LEN);

        if (fgets(line, MAX_LINE_LEN, ribfile) == NULL)
            return NULL;

        if ((line[MAX_LINE_LEN-2] != '\n') &&
            (line[MAX_LINE_LEN-2] != '\0')) {
            clear_line(ribfile);
        }

        if (strchr(line, '{') != NULL)
            continue;

        sub = strtok(line, tok);
        while (sub) {
            // Position of the NLRI
            if (col_i == 2) {
                if (strcmp(sub, "W") == 0) {
                    cont = 1;
                    break;
                }
            }
            // Position of the NLRI
            if (col_i == 5) {
                memset(nlri_str, 0, 64);
                if (!sub) {
                    cont = 1;
                    break;
                }
                strcpy(nlri_str, sub);
            }
            // Position of the AS Path
            if (col_i == 6) {
                memset(as_path_str, 0, 128);
                if (!sub) {
                    cont = 1;
                    break;
                }
                strcpy(as_path_str, sub);
                break;
            }
            sub = strtok(NULL, tok);
            col_i++;
        }

        if (cont)
            continue;

        nlri = convert_prefix(nlri_str);
        re = convert_as_path(as_path_str);

        if (!re) {
            rtr_mgr_bgpsec_nlri_free(nlri);
            continue;
        }

        re->nlri = nlri;
    } while (re == NULL);

    return re;
}

struct rib_entry *convert_as_path(char *as_path_str) {
    struct rib_entry *re = NULL;
    char *sub = NULL;
    char *tok = " ";
    int i = 0;

    if (!as_path_str)
        return NULL;

    re = malloc(sizeof(struct rib_entry));
    if (!re)
        return NULL;

    memset(re->as_path, 0, sizeof(re->as_path));

    sub = strtok(as_path_str, tok);
    while (sub) {
        re->as_path[i] = atoi(sub);
        sub = strtok(NULL, tok);
        i++;
    }

    re->as_path_len = i;

    return re;
}

void clear_line(FILE *ribfile) {
    char rest[MAX_LINE_LEN];

    if (!ribfile)
        return;
    
    memset(rest, 0, MAX_LINE_LEN);
    fgets(rest, MAX_LINE_LEN, ribfile);
    while ((rest[MAX_LINE_LEN-2] != '\n') &&
           (rest[MAX_LINE_LEN-2] != '\0')) {
        memset(rest, 0, MAX_LINE_LEN);
        fgets(rest, MAX_LINE_LEN, ribfile);
    }
}

uint8_t get_pcount(struct rib_entry *re, int idx) {
    int pcount = 0;
    int asn = 0;
    int next_asn = 0;

    if (!re || re->as_path_len == 0)
        return 0;

    /* If at the last position, the pcount must be 1 */
    if (idx == 0)
        return 1;

    asn = next_asn = re->as_path[idx];

    while (asn == next_asn && idx > 0) {
        next_asn = re->as_path[--idx];
        pcount++;
    }

    return pcount;
}
