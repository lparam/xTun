#include <netinet/ip.h>
#include <string.h>
#include "tun.h"
#include "util.h"

int
is_keepalive_packet(uint8_t *buf, ssize_t len) {
    if ((len == sizeof(struct iphdr) + 1) && *buf == 0) { // keepalive
        // strncmp((char *)buf, "keepalive", 9) == 0;
        return 1;
    }
    return 0;
}

void
construct_keepalive_packet(struct tundev *tun, uint8_t *buf) {
    // TODO: Set the first 9 bytes to "keepalive"
    // memcpy(buf, "keepalive", 9);
    struct iphdr *iphdr = (struct iphdr *)buf;
    iphdr->saddr = tun->addr;
    iphdr->daddr = tun->network;
}
