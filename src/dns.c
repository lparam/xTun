#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <resolv.h>

#include "dns.h"
#include "logger.h"


struct domain_list {
    int elements;
    char **domains;
};

static struct domain_list black_list;

const char *
hostname_from_question(ns_msg msg) {
    static char hostname[256] = {0};
    ns_rr rr;
    int rrnum, rrmax;
    const char *result;
    int result_len;
    rrmax = ns_msg_count(msg, ns_s_qd);
    if (rrmax == 0)
        return NULL;
    for (rrnum = 0; rrnum < rrmax; rrnum++) {
        if (local_ns_parserr(&msg, ns_s_qd, rrnum, &rr)) {
            logger_log(LOG_ERR, "local_ns_parserr");
            return NULL;
        }
        result = ns_rr_name(rr);
        result_len = strlen(result) + 1;
        if (result_len > sizeof(hostname)) {
            logger_log(LOG_ERR, "hostname too long: %s", result);
        }
        memset(hostname, 0, sizeof(hostname));
        memcpy(hostname, result, result_len);
        return hostname;
    }
    return NULL;
}

static int
domain_match(const char *source, char *dest) {
    int slen = strlen(source);
    int dlen = strlen(dest);
    if (dest[0] == '.') {
        if ((slen < (dlen - 1)) || (slen == dlen)) {
            return 0;
        }
        if (slen == (dlen - 1)) {
            return !strcasecmp(source, dest + 1);
        }
        return !strcasecmp(source + (slen - dlen), dest);

    } else {
        if ((slen < dlen) || (slen > dlen)) {
            return 0;
        }
        return !strcasecmp(source, dest);
    }
}

int
dns_pasre_query(uint8_t *buf, int buflen) {
    ns_msg msg;

    if (local_ns_initparse(buf, buflen, &msg) < 0) {
        logger_log(LOG_ERR, "local_ns_initparse");
        return -1;

    } else {
        const char *host = hostname_from_question(msg);
        logger_log(LOG_DEBUG, "query %s", host);
    }

    return 0;
}


int
dns_filter_query(uint8_t *buf, int buflen) {
    ns_msg msg;

    if (local_ns_initparse(buf, buflen, &msg) < 0) {
        logger_log(LOG_ERR, "local_ns_initparse");
        return -1;

    } else {
        int i;
        const char *host = hostname_from_question(msg);
        for (i = 0; i < black_list.elements; i++) {
            int rc = domain_match(host, black_list.domains[i]);
            if (rc) {
                logger_log(LOG_INFO, "query %s", host);
                return 0;
            }
        }
        logger_log(LOG_DEBUG, "request %s ", host);
    }

    return 1;
}

static int
skip_line(char *line, int len) {
    int i;
    if (strlen(line) == 0) {
        return 1;
    }
    for (i = 0; i < len; i++) {
        if (line[i] == '#') {
            return 1;
        }
    }
    return 0;
}


int
dns_init(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        logger_log(LOG_ERR, "Invalid domain path");
        return -1;
    }

    black_list.elements = 0;

    char line[256] = {0};
    while (fgets(line, 256, f)) {
        // Trim the newline
        int len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        // Skip blank or comment line
        if (skip_line(line, 256)) continue;

        black_list.elements++;
    }

    if (0 != fseek(f, 0, SEEK_SET)) {
        logger_log(LOG_ERR, "fseek");
        return -1;
    }

    black_list.domains = calloc(black_list.elements, sizeof(char*));

    int i = 0;
    while (fgets(line, 256, f)) {
        // Trim the newline
        int len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        // Skip blank or comment line
        if (skip_line(line, 256)) continue;

        black_list.domains[i++] = strdup(line);
    }

    fclose(f);

    for (i = 0; i < black_list.elements; i++) {
        logger_log(LOG_DEBUG, "domain: %s", black_list.domains[i]);
    }

    logger_log(LOG_INFO, "DNS filter started.");

    return 0;
}

void
dns_destroy() {
    int i;
    for (i = 0; i < black_list.elements; i++) {
        free(black_list.domains[i]);
    }
    free(black_list.domains);
    black_list.elements = 0;

    logger_log(LOG_NOTICE, "DNS filter stoped.");
}