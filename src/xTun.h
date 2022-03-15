#ifndef _XTUN_H
#define _XTUN_H

#include <stdint.h>

#ifdef VERSION
#define xTun_VER        VERSION
#define xTun_BUILD_TIME BUILD_TIME
#else
#define xTun_VER        "undefined"
#define xTun_BUILD_TIME ""
#endif

struct tundev;

#ifdef ANDROID
struct tundev * tun_alloc(void);
int tun_config(struct tundev *tun, const char *ifconf, int fd, int mtu,
               int protocol, int global, int verbose, const char *dns);
int tun_run(struct tundev *tun, const char *server, int port);
#else
struct peer_addr;
struct tundev * tun_alloc(char *iface, uint32_t queues);
void tun_config(struct tundev *tun, const char *ifconf, int mtu);
int tun_run(struct tundev *tun, struct peer_addr addr);
#endif
void tun_free(struct tundev *tun);
void tun_stop(struct tundev *tun);

#endif // for #ifndef _XTUN_H
