#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <netinet/in.h>

#define xTun_VERSION      "0.4.0"
#define xTun_VER          "xTun/" xTun_VERSION

/* MTU of VPN tunnel device. Use the following formula to calculate:
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 8 (UDP) - 24 (xTun) */
#define MTU 1440

#define PRIMITIVE_BYTES 24


int verbose;

struct tundev;

enum tun_mode {
    TUN_MODE_CLIENT = 1,
    TUN_MODE_SERVER = 2,
};

#ifndef ANDROID
struct tundev * tun_alloc(char *iface, uint32_t queues);
void tun_config(struct tundev *tun, const char *ifconf, int mtu, int mode,
                struct sockaddr *addr);
#else
struct tundev * tun_alloc(void);
int tun_config(struct tundev *tun, int fd, int mtu, int globalProxy,
               int verbose, const char *server, const char *dns);
#endif
void tun_free(struct tundev *tun);
int tun_start(struct tundev *tun);
void tun_stop(struct tundev *tun);

#endif // for #ifndef TUN_H
