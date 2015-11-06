#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <netinet/in.h>

#define xTun_VERSION      "0.2.1"
#define xTun_VER          "xTun/" xTun_VERSION

#define PRIMITIVE_BYTES 24

int verbose;

struct tundev;

enum tun_mode {
    TUN_MODE_CLIENT = 1,
    TUN_MODE_SERVER = 2,
};

#ifndef ANDROID
struct tundev * tun_alloc(char *iface);
#else
struct tundev * tun_alloc(int fd, int mtu, const char *server, const char *password);
#endif
void tun_free(struct tundev *tun);
void tun_config(struct tundev *tun, const char *ifconf, int mtu, int mode, struct sockaddr *addr);
int tun_start(struct tundev *tun);
void tun_stop(struct tundev *tun);

#endif // for #ifndef TUN_H
