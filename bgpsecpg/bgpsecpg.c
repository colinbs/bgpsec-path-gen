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

#include "lib/generators.h"
#include "lib/bgpsec_structs.h"
#include "lib/config_parser.h"
#include "lib/log.h"
#include "lib/keyhandler.h"

#include "rtrlib/rtrlib.h"

#define ASN_MAX_LEN     11
#define MAX_ASN_COUNT   1000
#define DUMMY_TARGET_AS 65445

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
    /*{"config", required_argument, 0, 'c'},*/
    {"output", required_argument, 0, 'o'},
    /*{"gen-config", no_argument, 0, 'g'},*/
    {"asns", required_argument, 0, 'a'},
    {"nlri", required_argument, 0, 'n'},
    {"keys", required_argument, 0, 'k'},
    /*{"host", required_argument, 0, '\0'},*/
    /*{"port", required_argument, 0, '\0'},*/
    {"print", required_argument, 0, 'p'},
    {"print-binary", no_argument, 0, 'b'},
    {"target-as", required_argument, 0, 't'},
    {"append-output", no_argument, 0, 'd'},
    {0, 0, 0, 0}
};

static void print_usage(void)
{
    printf("Usage: bgpsecpg [OPTIONS]...\n");
    printf("\n");
    printf("-h, --help\t\tShow this help\n");
    /*printf("-c, --config\t\tSpecify the config file\n");*/
    printf("-o, --output\t\tName of the output file. If used with\n\
            \t\t--append-output, the output will be appended to the file\n");
    /*printf("-g, --gen-config\tGenerate an example config file named\n\*/
            /*\t\tbgpsecpg.conf.example\n");*/
    printf("-a, --asns\t\tSpecify a comma-separated list of ASNs\n");
    printf("-n, --nlri\t\tSpecify the NLRI\n");
    printf("-k, --keys\t\tPath to the directory containing the public\n\
            \t\tand private router keys\n");
    printf("-p, --print\t\tPrint a binary BGPsec_PATH in human readable\n\
            \t\tformat\n");
    printf("-b, --print-binary\tPrint a binary BGPsec_PATH in hexadecimal\n\
            \t\tformat\n");
    printf("-t, --target-as\t\tSpeficy the target AS for the last\n\
            \t\tgenerated signature\n");
    printf("--append-output\t\tAppend output to file specified with\n\
            \t\t-o/--output instead of overwriting it\n");

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
    char *outfile = NULL;
    char *readfile = NULL;
    struct master_conf *conf = NULL;
    struct rtr_bgpsec *bgpsec = NULL;
    struct bgpsec_upd *upd = NULL;
    struct rtr_signature_seg *new_sig = NULL;
    struct rtr_bgpsec_nlri *nlri = NULL;
    struct key_vault *vault = NULL;
    /*char *host = "0.0.0.0";*/
    /*char *port = "8383";*/
    int exit_val = EXIT_SUCCESS;
    uint32_t origin_as = 0;
    uint32_t target_as = 0;
    int print_binary = 0;
    int append_output = 0;

    do {
        opt = getopt_long(argc, argv, "ho:a:n:k:p:bt:d", long_opts, &option_index);

        switch (opt) {
        case 'h':
            print_usage();
            exit(EXIT_FAILURE);
            break;
        /*case 'c':*/
            /*printf("reading config file: %s\n", optarg);*/
            /*rtval = open_conf((const char *)optarg);*/
            /*if (rtval == 0) {*/
                /*bgpsecpg_dbg("Successfully opened file %s", optarg);*/
            /*} else {*/
                /*bgpsecpg_dbg("Could not open file %s", optarg);*/
            /*}*/
            /*break;*/
        case 'a':
            i = 0;
            sub = strtok(optarg, tok);
            while (sub) {
                memcpy(asns[i++], sub, strlen(sub));
                sub = strtok(NULL, tok);
                asn_count++;
            }
            origin_as = atoi(asns[i - 1]);
            break;
        case 'n':
            nlri = convert_prefix(optarg);
            break;
        case 'k':
            keydir = optarg;
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'p':
            readfile = optarg;
            break;
        case 'b':
            print_binary = 1;
            break;
        case 't':
            target_as = atoi(optarg);
            break;
        case 'd':
            append_output = 1;
            break;
        case -1:
            break;
        default:
            print_usage();
            exit(EXIT_SUCCESS);
        }
    } while (opt != -1);

    if (readfile) {
        parse_bgpsec_update(readfile, print_binary);
        exit(EXIT_SUCCESS);
    }

    if (!nlri || asn_count == 0) {
        print_usage();
        exit(EXIT_SUCCESS);
    }

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

    for (int j = 0; j < 100000; j++) {
        bgpsec = generate_bgpsec_data(origin_as, DUMMY_TARGET_AS, nlri);
        if (!bgpsec) {
            exit_val = EXIT_FAILURE;
            goto err;
        }

        for (int i = (asn_count - 1); i >= 0; i--) {
            struct rtr_secure_path_seg *new_path =
                rtr_mgr_bgpsec_new_secure_path_seg(1, 0, atoi(asns[i]));
            if (!new_path) {
                bgpsecpg_dbg("error generating sec path seg");
                exit_val = EXIT_FAILURE;
                goto err;
            }
            rtr_mgr_bgpsec_append_sec_path_seg(bgpsec, new_path);

            if (i > 0) {
                bgpsec->target_as = atoi(asns[i - 1]);
            } else {
                bgpsec->target_as = target_as;
            }

            struct key *k = vault->keys[rand() % vault->amount];
            new_sig = NULL;
            rtval = rtr_mgr_bgpsec_generate_signature(bgpsec, k->data, &new_sig);
            if (rtval != RTR_BGPSEC_SUCCESS) {
                exit_val = EXIT_FAILURE;
                goto err;
            }
            memcpy(new_sig->ski, vault->keys[i]->ski, SKI_SIZE);
            rtr_mgr_bgpsec_prepend_sig_seg(bgpsec, new_sig);
        }

        upd = generate_bgpsec_upd(bgpsec);

        if (outfile) {
            write_output(outfile, upd, append_output);
        }

        if (bgpsec) {
            rtr_mgr_bgpsec_free(bgpsec);
            bgpsec = NULL;
        }
        if (upd) {
            free(upd->upd);
            free(upd);
            upd = NULL;
        }
    }

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
    if (nlri) {
        rtr_mgr_bgpsec_nlri_free(nlri);
    }

    return exit_val;
}
