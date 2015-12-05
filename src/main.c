#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "daemon.h"
#include "tun.h"


static int mtu = MTU;
static int daemon_mode = 1;
static int mode;
static uint32_t parallel = 1;
static char *iface;
static char *ifconf;
static char *server_addrbuf;
static char *bind_addrbuf = "0.0.0.0:1082";
static char *pidfile = "/var/run/xTun.pid";
static char *password = NULL;
static char *xsignal;

int signal_process(char *signal, const char *pidfile);

static const char *_optString = "i:I:m:k:s:l:p:P:nVvh";
static const struct option _lopts[] = {
    { "",        required_argument,   NULL, 'i' },
    { "",        required_argument,   NULL, 'I' },
    { "",        required_argument,   NULL, 'm' },
    { "",        required_argument,   NULL, 'k' },
    { "",        required_argument,   NULL, 's' },
    { "",        required_argument,   NULL, 'l' },
    { "",        required_argument,   NULL, 'p' },
    { "",        required_argument,   NULL, 'P' },
    { "mtu",     required_argument,   NULL,  0  },
    { "signal",  required_argument,   NULL,  0  },
    { "version", no_argument,         NULL, 'v' },
    { "",        no_argument,         NULL, 'n' },
    { "help",    no_argument,         NULL, 'h' },
    { "",        no_argument,         NULL, 'V' },
    { NULL,      no_argument,         NULL,  0  }
};


static void
print_usage(const char *prog) {
    printf("xTun Version: %s Maintained by lparam\n", xTun_VER);
    printf("Usage:\n  %s [options]\n", prog);
    printf("Options:\n");
    puts("  -i <iface>\t\t interface name (e.g. tun0)\n"
         "  -I <ifconf>\t\t IP address of interface (e.g. 10.3.0.1/16)\n"
         "  -m <mode>\t\t client, server\n"
         "  -k <encryption_key>\t shared password for data encryption\n"
         "  -s <server address>\t server address:port (only available in client mode)\n"
         "  [-l <bind address>]\t bind address:port (only available in server mode, default: 0.0.0.0:1082)\n"
         "  [-p <pid_file>]\t PID file of daemon (default: /var/run/xTun.pid)\n"
         "  [-P <parallel>]\t number of parallel instance to run\n"
         "  [--mtu <mtu>]\t\t MTU size (default: 1440)\n"
         "  [--signal <signal>]\t send signal to xTun: quit, stop\n"
         "  [-n]\t\t\t non daemon mode\n"
         "  [-h, --help]\t\t this help\n"
         "  [-v, --version]\t show version\n"
         "  [-V] \t\t\t verbose mode\n");

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
        case 'm':
            if (strcasecmp("client", optarg) == 0) {
                mode = TUN_MODE_CLIENT;
            }
            if (strcasecmp("server", optarg) == 0) {
                mode = TUN_MODE_SERVER;
            }
            break;
        case 'k':
            password = optarg;
            break;
        case 's':
            server_addrbuf = optarg;
            break;
        case 'l':
            bind_addrbuf = optarg;
            break;
        case 'p':
            pidfile = optarg;
            break;
        case 'P':
            parallel = strtoul(optarg, NULL, 10);
            if(parallel == 0 ||  parallel > 256) {
                parallel = 1;
            }
            break;
        case 'n':
            daemon_mode = 0;
            break;
        case 'V':
            verbose = 1;
            break;
        case 'v':
            printf("xTun version: %s \n", xTun_VER);
            exit(0);
            break;
        case 'h':
        case '?':
            print_usage(argv[0]);
            break;
		case 0: /* long option without a short arg */
            if (strcmp("signal", _lopts[longindex].name) == 0) {
                xsignal = optarg;
                if (strcmp(xsignal, "stop") == 0
                  || strcmp(xsignal, "quit") == 0) {
                    break;
                }
                fprintf(stderr, "invalid option: --signal %s\n", xsignal);
                print_usage(argv[0]);
            }
            if (strcmp("mtu", _lopts[longindex].name) == 0) {
                mtu = strtol(optarg, NULL, 10);
                if(!mtu || mtu < 0 || mtu > 4096) {
                    mtu = MTU;
                }
            }
			break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
}

static int
init() {
    logger_init(daemon_mode);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    if (crypto_init(password)) {
        logger_stderr("crypto init failed");
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

    if (!mode || !iface || !ifconf || !password) {
        print_usage(argv[0]);
        return 1;
    }

    if (mode == TUN_MODE_CLIENT) {
        if (!server_addrbuf) {
            print_usage(argv[0]);
            return 1;
        }
    }

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

    int rc;
    if (mode == TUN_MODE_CLIENT) {
        rc = resolve_addr(server_addrbuf, &addr);
        if (rc) {
            logger_stderr("invalid server address");
            return 1;
        }

    } else {
        rc = resolve_addr(bind_addrbuf, &addr);
        if (rc) {
            logger_stderr("invalid bind address");
            return 1;
        }
    }

	struct tundev *tun = tun_alloc(iface, parallel);
    if (!tun) {
        return 1;
    }

    tun_config(tun, ifconf, mtu, mode, &addr);
    tun_start(tun);

    tun_free(tun);
    if (daemon_mode) {
        delete_pidfile(pidfile);
    }
    logger_exit();

    return 0;
}
