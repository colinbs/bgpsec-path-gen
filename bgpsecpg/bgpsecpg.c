/*
 * This is the BGPsec path generator. Its purpose is to generate BGPsec path
 * attributes for Update messages. The main issues with valid BGPsec path
 * attributes are the signature segments. To have a valid signature segment,
 * the path attributes must be hashed and then signed recursively. Doing
 * this by hand is tedious and error prone.
 * Generating long BGPsec path attributes that contain valid signatures is very
 * useful for testing purposes. Otherwise, to generate a BGPsec path of length
 * N, one would have to set up N BGPsec speaker that forward Update messages,
 * and then extract the information.
 * This tool shall help getting around this issue. It works as follows: the
 * user specifies the length of the path by giving a number N, or by passing
 * a config file that contains more specific information such as AS numbers,
 * SKIs and NLRI. In case a number was given, random AS numbers, SKIs and NLRI,
 * will be chosen.
 * The output of the program will be either a hex encoded BGPsec path or a
 * human readable output in wireshark-like format.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "bgpsecpg/lib/generators.h"
#include "bgpsecpg/lib/bgpsec_structs.h"
#include "bgpsecpg/lib/config_parser.h"
#include "bgpsecpg/lib/log.h"
#include "bgpsecpg/lib/keyhandler.h"

#include "rtrlib/rtrlib.h"

#define ASN_MAX_LEN     11
#define MAX_ASN_COUNT   1000

enum return_vals {
    SUCCESS,
    ERROR
};

struct master_conf {
    struct tr_socket *tr_tcp;
    struct tr_tcp_config *tcp_config;
    struct rtr_socket *rtr_tcp;
    struct rtr_mgr_group *group;
    struct rtr_mgr_config *config;
};

static struct option long_opts[] = {
    {"help", no_argument, 0, 'h'},
    {"config", required_argument, 0, 'c'},
    {"output", required_argument, 0, 'o'},
    {"format", required_argument, 0, 'f'},
    {"gen-config", no_argument, 0, 'g'},
    {"asns", required_argument, 0, 'a'},
    {"nlri", required_argument, 0, 'n'},
    {"keys", required_argument, 0, 'k'},
    /*{"host", required_argument, 0, '\0'},*/
    /*{"port", required_argument, 0, '\0'},*/
    {0, 0, 0, 0}
};

static void print_usage(void)
{
    printf("Usage: bgpsecpg [OPTION]...\n");
    printf("\n");
    printf("-h, --help\t\tShow this help\n");
    printf("-c, --config\t\tSpecify the config file\n");
    printf("-o, --output\t\tName of the output file\n");
    printf("-f, --format\t\tThe format in which the output file should be\n\
            \t\tdisplayed. Either WireShark-like (default) or JSON\n");
    printf("-g, --gen-config\tGenerate an example config file named\n\
            \t\tbgpsecpg.conf.example\n");
    printf("-a, --asns\t\tSpecify a comma-separated list of ASNs\n");
    printf("-n, --nlri\t\tSpecify the NLRI\n");
    printf("-k, --keys\t\tPath to the directory containing the public\n\
            \t\tand private router keys");
}

static int establish_rtr_connection(struct master_conf **cnf) {
    struct master_conf *conf = malloc(sizeof(struct master_conf));
    conf->tr_tcp = malloc(sizeof(struct tr_socket));
    char tcp_host[] = "0.0.0.0";
    char tcp_port[] = "8383";

    conf->tcp_config = malloc(sizeof(struct tr_tcp_config));
    conf->tcp_config->host = tcp_host;
    conf->tcp_config->port = tcp_port,
    conf->tcp_config->bindaddr = NULL;
    conf->tcp_config->data = NULL;
    conf->tcp_config->new_socket = NULL;
    conf->tcp_config->connect_timeout = 0;
    tr_tcp_init(conf->tcp_config, conf->tr_tcp);

    conf->rtr_tcp = malloc(sizeof(struct rtr_socket));
    conf->rtr_tcp->tr_socket = conf->tr_tcp;

    conf->group = malloc(sizeof(struct rtr_mgr_group));

    conf->group[0].sockets = malloc(sizeof(struct rtr_socket*));
    conf->group[0].sockets_len = 1;
    conf->group[0].sockets[0] = conf->rtr_tcp;
    conf->group[0].preference = 1;

    int ret = rtr_mgr_init(&(conf->config), conf->group, 1, 30, 600, 600, NULL, NULL, NULL, NULL);

    if (ret == RTR_ERROR) {
        free(conf->group->sockets);
        free(conf->group);
        free(conf->rtr_tcp);
        free(conf->tr_tcp);
        free(conf->tcp_config);
        return ERROR;
    }

    rtr_mgr_start(conf->config);

    while(!rtr_mgr_conf_in_sync(conf->config)) {
        sleep(1);
    }

    *cnf = conf;

    return SUCCESS;
}

int main(int argc, char *argv[])
{
    int opt;
    int option_index = 0;
    int rtval = 0;
    int i;
    const char *tok = {","};
    char asns[MAX_ASN_COUNT][ASN_MAX_LEN];
    int asn_count = 0;
    char *sub = NULL;
    char *keydir = NULL;
    struct master_conf *conf = NULL;
    struct rtr_bgpsec *bgpsec = NULL;
    struct bgpsec_upd *upd = NULL;
    struct rtr_signature_seg *new_sig = NULL;
    uint32_t nlri = 0xC0000200;
    struct key_vault *vault = NULL;
    /*char *host = "0.0.0.0";*/
    /*char *port = "8383";*/
    int exit_val = EXIT_SUCCESS;
    uint32_t origin_as = 0;

    do {
        opt = getopt_long(argc, argv, "hc:o:f:ga:n:k:", long_opts, &option_index);

        switch (opt) {
        case 'h':
            print_usage();
            exit(EXIT_FAILURE);
            break;
        case 'c':
            printf("reading config file: %s\n", optarg);
            rtval = open_conf((const char *)optarg);
            if (rtval == 0) {
                bgpsecpg_dbg("Successfully opened file %s", optarg);
            } else {
                bgpsecpg_dbg("Could not open file %s", optarg);
            }
            break;
        case 'a':
            printf("Passed ASNs: %s\n", optarg);
            i = 0;
            sub = strtok(optarg, tok);
            while (sub) {
                memcpy(asns[i++], sub, strlen(sub));
                sub = strtok(NULL, tok);
                asn_count++;
                origin_as = atoi(asns[i-1]);
            }
            break;
        case 'n':
            printf("Passed NLRI: %s\n", optarg);
            break;
        case 'k':
            printf("Key directory: %s\n", optarg);
            keydir = optarg;
        case -1:
            break;
        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    } while (opt != -1);

    /* establish the RTR connection */
    rtval = establish_rtr_connection(&conf);
    if (rtval == ERROR) {
        exit_val = EXIT_FAILURE;
        goto err;
    }

    vault = load_key_dir(keydir);
    if (!vault) {
        exit_val = EXIT_FAILURE;
        goto err;
    }

    bgpsec = generate_bgpsec_data(origin_as, nlri);
    if (!bgpsec) {
        exit_val = EXIT_FAILURE;
        goto err;
    }

    for (int i = 0; i < asn_count; i++) {
        struct rtr_secure_path_seg *new_path =
            rtr_mgr_bgpsec_new_secure_path_seg(1, 0, atoi(asns[i]));
        if (!new_path) {
            printf("error generating sec path seg\n");
            exit_val = EXIT_FAILURE;
            goto err;
        }
        rtr_mgr_bgpsec_append_sec_path_seg(bgpsec, new_path);

        struct key *k = vault->keys[i];
        new_sig = NULL;
        rtval = rtr_mgr_bgpsec_generate_signature(bgpsec, k->data, &new_sig);
        if (rtval != RTR_BGPSEC_SUCCESS) {
            printf("rtval: %d\n", rtval);
            exit_val = EXIT_FAILURE;
            goto err;
        }
        memcpy(new_sig->ski, vault->keys[i]->ski, SKI_SIZE);
        rtr_mgr_bgpsec_prepend_sig_seg(bgpsec, new_sig);
    }

    print_bgpsec_path(bgpsec);
    upd = generate_bgpsec_upd(bgpsec);

err:
    if (conf) {
        /* stop the RTR connection */
        rtr_mgr_stop(conf->config);

        /* free conf and sec_path */
        rtr_mgr_free(conf->config);
        free(conf->group->sockets);
        free(conf->group);
        free(conf->rtr_tcp);
        free(conf->tr_tcp);
        free(conf->tcp_config);
        free(conf);
    }
    if (bgpsec)
        rtr_mgr_bgpsec_free(bgpsec);
    if (vault)
        vault_free(vault);
    if (upd) {
        free(upd->upd);
        free(upd);
    }

    return exit_val;
}
