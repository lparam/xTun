#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "daemon.h"
#include "tun.h"
#include "xTun.h"


static int mtu = MTU;
static int port = 1082;
static int keepalive_interval = 0;
static int daemon_mode = 1;
static uint32_t parallel = 1;
static int log_level = LOG_INFO;
static char *iface = "";
static char *ifconf;
static char *addrbuf;
static char *pidfile = "/var/run/xTun.pid";
static char *password = NULL;
static char *xsignal;

int signal_process(char *signal, const char *pidfile);

enum {
    GETOPT_MTU = 128,
    GETOPT_MARK,
    GETOPT_MULTICAST,
    GETOPT_KEEPALIVE,
    GETOPT_PID,
    GETOPT_SIGNAL,
    GETOPT_LEVEL,
    GETOPT_DEBUG
};

static const char *_optString = "i:I:k:c:sb:tp:P:nVvh";
static const struct option _lopts[] = {
    { "",           required_argument,   NULL, 'i' },
    { "",           required_argument,   NULL, 'I' },
    { "",           required_argument,   NULL, 'k' },
    { "client",     required_argument,   NULL, 'c' },
    { "server",     no_argument,         NULL, 's' },
    { "port",       required_argument,   NULL, 'p' },
    { "bind",       required_argument,   NULL, 'b' },
    { "",           required_argument,   NULL, 'P' },
    { "tcp",        no_argument,         NULL, 't' },
    { "mtu",        required_argument,   NULL,  GETOPT_MTU },
    { "mark",       required_argument,   NULL,  GETOPT_MARK },
    { "multicast",  no_argument,         NULL,  GETOPT_MULTICAST },
    { "keepalive",  required_argument,   NULL,  GETOPT_KEEPALIVE },
    { "pid",        required_argument,   NULL,  GETOPT_PID },
    { "signal",     required_argument,   NULL,  GETOPT_SIGNAL },
    { "level",      required_argument,   NULL,  GETOPT_LEVEL },
    { "debug",      no_argument,         NULL,  GETOPT_DEBUG },
    { "",           no_argument,         NULL, 'n' },
    { "",           no_argument,         NULL, 'V' },
    { "version",    no_argument,         NULL, 'v' },
    { "help",       no_argument,         NULL, 'h' },
    { NULL,         no_argument,         NULL,  0  }
};


static void
print_usage(const char *prog) {
    printf("xTun Version: %s Maintained by lparam\n", xTun_VER);
    printf("Usage:\n  %s [options]\n", prog);
    printf("Options:\n");
    puts(""
         "  -I <ifconf>\t\t CIDR of interface (e.g. 10.3.0.1/16)\n"
         "  -k <password>\t\t shared password for data encryption\n"
         "  -c --client <host>\t run in client mode, connecting to <host>\n"
         "  -s --server\t\t run in server mode\n"
         "  [-p --port <port>]\t server port to listen on/connect to (default: 1082)\n"
         "  [-i <iface>]\t\t interface name (e.g. tun0)\n"
         "  [-b --bind <host>]\t bind to a specific interface (only available on server mode, default: 0.0.0.0)\n"
         "  [-P <parallel>]\t number of parallel tun queues (only available on server mode & UDP)\n"
         "  [-t --tcp]\t\t use TCP rather than UDP (only available on client mode)\n"
         "  [--pid <pid>]\t\t PID file of daemon (default: /var/run/xTun.pid)\n"
         "  [--mtu <mtu>]\t\t MTU size (default: 1426)\n"
         "  [--mark <mark>]\t netfilter mark (default: 0x3dd5)\n"
         "  [--multicast] \t enable multicast\n"
         "  [--keepalive <second>] keepalive delay (default: 0)\n"
         "  [--signal <signal>]\t send signal to xTun: quit, stop\n"
         "  [--level <level>] \t log level: debug, info, warn, error\n"
         "  [--debug] \t\t debug mode\n"
         "  [-n]\t\t\t non daemon mode\n"
         "  [-V] \t\t\t verbose mode\n"
         "  [-h, --help]\t\t this help\n"
         "  [-v, --version]\t show version\n"
         );

    exit(1);
}

static void
parse_opts(int argc, char *argv[]) {
    int opt = 0, longindex = 0;

    while ((opt = getopt_long(argc, argv, _optString, _lopts, &longindex)) != -1) {
        switch (opt) {
        case 'i':
            iface = optarg;
            break;
        case 'I':
            ifconf = optarg;
            break;
        case 'c':
            mode = xTUN_CLIENT;
            addrbuf = optarg;
            break;
        case 's':
            mode = xTUN_SERVER;
            break;
        case 'k':
            password = optarg;
            break;
        case 'b':
            addrbuf = optarg;
            break;
        case 'p':
            port = strtol(optarg, NULL, 10);
            break;
        case 'P':
            parallel = strtoul(optarg, NULL, 10);
            if(parallel == 0 ||  parallel > 256) {
                parallel = 1;
            }
            break;
        case 't':
            protocol = xTUN_TCP;
            break;
        case 'n':
            daemon_mode = 0;
            break;
        case GETOPT_LEVEL:
            if (strcmp(optarg, "debug") == 0) {
                log_level = LOG_DEBUG;

            } else if (strcmp(optarg, "info") == 0) {
                log_level = LOG_INFO;

            } else if (strcmp(optarg, "warn") == 0) {
                log_level = LOG_WARNING;

            } else if (strcmp(optarg, "error") == 0) {
                log_level = LOG_ERR;

            } else {
                fprintf(stderr, "invalid option: --level %s\n", optarg);
                print_usage(argv[0]);
            }
            break;
        case GETOPT_DEBUG:
            debug = 1;
            break;
        case 'V':
            verbose = 1;
            break;
        case 'v':
            printf("%s %s\n", xTun_VER, xTun_BUILD_TIME);
            exit(0);
            break;
        case 'h':
        case '?':
            print_usage(argv[0]);
            break;
        case GETOPT_MTU:
            mtu = strtol(optarg, NULL, 10);
            if(!mtu || mtu < 0 || mtu > 4096) {
                mtu = MTU;
            }
            break;
        case GETOPT_MARK:
            nf_mark = strtoul(optarg, NULL, 16);
            break;
        case GETOPT_MULTICAST:
            multicast = 1;
            break;
        case GETOPT_KEEPALIVE:
            keepalive_interval = strtol(optarg, NULL, 10);
            break;
        case GETOPT_PID:
            pidfile = optarg;
            break;
        case GETOPT_SIGNAL:
            if (strcmp(optarg, "stop") == 0 || strcmp(optarg, "quit") == 0) {
                xsignal = optarg;
                break;
            }
            fprintf(stderr, "invalid option: --signal %s\n", optarg);
            print_usage(argv[0]);
            break;
		case 0: /* long option without a short arg */
			break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
}

static int
init() {
    logger_init(daemon_mode, log_level);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    if (crypto_init(password)) {
        logger_stderr("Crypto init failed");
        exit(1);
    }

    return 0;
}

int
main(int argc, char *argv[]) {
    parse_opts(argc, argv);

    if (xsignal) {
        return signal_process(xsignal, pidfile);
    }

    if (!mode || !ifconf || !password) {
        print_usage(argv[0]);
        return 1;
    }

    if (addrbuf == NULL) {
        if (mode == xTUN_SERVER) {
            addrbuf = "0.0.0.0";
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    protocol = protocol ? protocol : xTUN_UDP;
    nf_mark = nf_mark ? nf_mark : SOCKET_MARK;

    if (daemon_mode) {
        if (daemonize()) {
            return 1;
        }
        if (already_running(pidfile)) {
            logger_stderr("xTun already running.");
            return 1;
        }
    }

    init();

    struct sockaddr addr;
    int rc = resolve_addr(addrbuf, port, &addr);
    if (rc) {
        return 1;
    }

	tundev_t *tun = tun_alloc(iface, parallel);
    if (!tun) {
        return 1;
    }

    tun_config(tun, ifconf, mtu);
    if (keepalive_interval) {
        tun_keepalive(tun, 1, keepalive_interval);
    }
    tun_run(tun, addr);

    tun_free(tun);
    if (daemon_mode) {
        delete_pidfile(pidfile);
    }

    return 0;
}
