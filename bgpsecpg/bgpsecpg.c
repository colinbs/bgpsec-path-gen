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
#include <stdlib.h>
#include <getopt.h>

#include "bgpsecpg/lib/generators.h"
#include "bgpsecpg/lib/bgpsec_structs.h"

static struct option long_opts[] = {
    {"help", no_argument, 0, 'h'},
    {"config", required_argument, 0, 'c'},
    {"output", required_argument, 0, 'o'},
    {"format", required_argument, 0, 'f'},
    {"gen-config", no_argument, 0, 'g'},
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
}

int main(int argc, char *argv[])
{
    int opt;
    int option_index = 0;

    do {
        opt = getopt_long(argc, argv, "hc:o:f:g", long_opts, &option_index);

        switch (opt) {
        case 'h':
            print_usage();
            exit(EXIT_FAILURE);
            break;
        case 'c':
            printf("reading config file: %s\n", optarg);
            break;
        case -1:
            break;
        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    } while (opt != -1);

    char *foo = generate_bytes(10, MODE_HEX);
    /*struct secure_path_seg *foo = new_sps(0, 0, 1);*/
    /*free(foo);*/
    /*foo->pcount = 1;*/

    return EXIT_SUCCESS;
}
