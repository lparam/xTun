#include <netinet/ip.h>
#include "tun.h"

int
check_incoming_packet(uint8_t *buf, ssize_t len) {
    if (sizeof(struct iphdr) + 1 <= len) {
        if ((len == sizeof(struct iphdr) + 1) && *buf == 0) { // keepalive
            return 1;
        }
        return -1;
    }
    return 0;
}

void
construct_keepalive_packet(struct tundev *tun, uint8_t *buf) {
    struct iphdr *iphdr = (struct iphdr *)buf;
    iphdr->saddr = tun->s_addr;
    iphdr->daddr = tun->network;
}
