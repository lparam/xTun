#ifndef _XTUN_H
#define _XTUN_H

#include <stdint.h>

#define xTun_VERSION    "0.6.2"
#define xTun_VER        "xTun/" xTun_VERSION

struct tundev;

#ifdef ANDROID
struct tundev * tun_alloc(void);
int tun_config(struct tundev *tun, const char *ifconf, int fd, int mtu,
               int protocol, int global, int verbose, const char *dns);
int tun_run(struct tundev *tun, const char *server, int port);
#else
struct tundev * tun_alloc(char *iface, uint32_t queues);
void tun_config(struct tundev *tun, const char *ifconf, int mtu);
int tun_run(struct tundev *tun, struct sockaddr addr);
#endif
void tun_free(struct tundev *tun);
void tun_stop(struct tundev *tun);
int tun_keepalive(struct tundev *tun, int on, uint32_t interval);

#endif // for #ifndef _XTUN_H
