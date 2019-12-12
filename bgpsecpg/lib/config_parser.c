/*
 * Config file handling and parsing. It basically does everything that is
 * related to the config file.
 */

#include <stdio.h>

int open_conf(const char *filepath)
{
    FILE *file;

    if ((file = fopen(filepath, "r"))) {
        fclose(file);
        return 0;
    } else {
        return 1;
    }
}
