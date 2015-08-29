#ifndef _TUN_H
#define _TUN_H

#include <stdint.h>
#include "uv.h"

#define xTun_VERSION      "0.1.0"
#define xTun_VER          "xTun/" xTun_VERSION

#define PRIMITIVE_BYTES 24

int verbose;

struct tundev;

enum tun_mode {
    TUN_MODE_CLIENT = 1,
    TUN_MODE_SERVER = 2,
};

struct tundev * tun_alloc(char *iface);
void tun_free(struct tundev *tun);
void tun_config(struct tundev *tun, const char *ifconf, int mtu, int mode, struct sockaddr *addr);
int tun_start(uv_loop_t *loop, struct tundev *tun);
void tun_stop(struct tundev *tun);

#endif // for #ifndef _TUN_H
