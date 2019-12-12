/*
 * Here are the logging and debugging functions.
 */

void bgpsecpg_dbg(const char *frmt, ...) __attribute__((format(printf, 1, 2)));

#define BGPSECPG_DBG(fmt, ...) bgpsecpg_dbg("BGPSECPG: " fmt, ## __VA_ARGS__)
#define BGPSECPG_DBG1(a) bgpsecpg_dbg("BGPSECPG: " a)
