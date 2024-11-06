#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#undef true
#undef false
#define true  1
#define false 0

#define ENV_CLUSTER_JOIN       "CLUSTER_JOIN_ADDR"
#define ENV_CLUSTER_JOIN_PORT  "CLUSTER_JOIN_PORT"
#define ENV_CLUSTER_ADVERTISE  "CLUSTER_ADVERTISED_ADDR"
#define ENV_CLUSTER_ADV_PORT   "CLUSTER_ADVERTISED_PORT"
#define ENV_CLUSTER_BIND       "CLUSTER_BIND_ADDR"

#define ENV_SCANNER_DOCKER_URL         "SCANNER_DOCKER_URL"
#define ENV_SCANNER_LICENSE            "SCANNER_LICENSE"
#define ENV_SCANNER_ON_DEMAND          "SCANNER_ON_DEMAND"
#define ENV_SCANNER_REGISTRY           "SCANNER_REGISTRY"
#define ENV_SCANNER_REPOSITORY         "SCANNER_REPOSITORY"
#define ENV_SCANNER_TAG                "SCANNER_TAG"
#define ENV_SCANNER_REG_USER           "SCANNER_REGISTRY_USERNAME"
#define ENV_SCANNER_REG_PASS           "SCANNER_REGISTRY_PASSWORD"
#define ENV_SCANNER_SCAN_LAYERS        "SCANNER_SCAN_LAYERS"
#define ENV_SCANNER_BASE_IMAGE         "SCANNER_BASE_IMAGE"
#define ENV_SCANNER_CTRL_USER          "SCANNER_CTRL_API_USERNAME"
#define ENV_SCANNER_CTRL_PASS          "SCANNER_CTRL_API_PASSWORD"
#define ENV_SCANNER_TLS_VERIFICATION   "SCANNER_STANDALONE_TLS_VERIFICATION"
#define ENV_SCANNER_DEBUG_MODE         "SCANNER_DEBUG_MODE"

#define ENV_SCANNER_CACHE_MAX   "MAX_CACHE_RECORD_MB"
#define ENV_CAP_CRITICAL        "CAP_CRITICAL"

enum {
    PROC_SCANNER = 0,
    PROC_MAX,
};

enum {
    MODE_SCANNER = 0,
};

#define PROC_ARGS_MAX 32

typedef struct proc_info_ {
    char name[32];
    char path[64];
    int active  : 1,
        running : 1;
    pid_t pid;
    int short_live_count;
    struct timeval start;
    int exit_status;
} proc_info_t;

static proc_info_t g_procs[PROC_MAX] = {
[PROC_SCANNER]  {"scanner", "/usr/local/bin/scanner", },
};

static int g_mode = MODE_SCANNER;
static int g_debug = 0;
static int g_node = 0;
static char *g_image = NULL;
static volatile sig_atomic_t g_exit_signal = 0;
static int g_exit_monitor_on_proc_exit = 0;

static void debug_ts(FILE *logfp)
{
    struct timeval now;
    struct tm *tm;

    gettimeofday(&now, NULL);
    tm = localtime(&now.tv_sec);

    fprintf(logfp, "%04d-%02d-%02dT%02d:%02d:%02d|MON|",
                   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                   tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static void debug(const char *fmt, ...)
{
    if (g_debug != 0) {
        static FILE *logfp = NULL;
        va_list args;

        logfp = stdout;

        debug_ts(logfp);
        va_start(args, fmt);
        vfprintf(logfp, fmt, args);
        va_end(args);
        fflush(logfp);
    }
}

static void print_log(const char *fmt, ...)
{
    static FILE *logfp = NULL;
    va_list args;

    logfp = stdout;

    debug_ts(logfp);
    va_start(args, fmt);
    vfprintf(logfp, fmt, args);
    va_end(args);
    fflush(logfp);
}

static int checkImplicitEnableFlag(char *enable)
{
    if (enable == NULL) return 0;
    if (enable[0] == '\0') return 1; // If the command line only has the option without value, consider it as enabled
    if (enable[0] == '1' || enable[0] == 'e' || // 'e' for enable
        enable[0] == 'y' || enable[0] == 'Y' || enable[0] == 't' || enable[0] == 'T') return 1;
    return 0;
}

static pid_t fork_exec(int i)
{
    pid_t pid;
    char *args[PROC_ARGS_MAX], *join, *adv, *url;
    char *join_port, *adv_port;
    char *license, *registry, *repository, *tag, *user, *pass, *base, *api_user, *api_pass, *enable;
    char *on_demand, *cache_record_max;
    int a;

    switch (i) {
    case PROC_SCANNER:
        args[0] = g_procs[i].path;
        a = 1;
        args[a ++] = "-d";
        args[a ++] = "/etc/neuvector/db/";

        if (g_debug == 1) {
            args[a ++] = "-x";
        }

        if (g_node) {
            // scan node
            args[a ++] = "--license";
            args[a ++] = "on_demand";

            g_exit_monitor_on_proc_exit = 1;

            args[a ++] = "--pid";
            args[a ++] = "1";

            if ((url = getenv(ENV_CAP_CRITICAL)) != NULL) {
                args[a ++] = "--cap_critical";
            }
        } else if (g_image != NULL) {
            // automatically set to standalone mode
            args[a ++] = "--license";
            args[a ++] = "on_demand";

            g_exit_monitor_on_proc_exit = 1;

            args[a ++] = "--image";
            args[a ++] = g_image;

            if ((url = getenv(ENV_SCANNER_DOCKER_URL)) != NULL) {
                args[a ++] = "-u";
                args[a ++] = url;
            }

            if ((url = getenv(ENV_CAP_CRITICAL)) != NULL) {
                args[a ++] = "--cap_critical";
            }
        } else {
            // options for non-standalone mode
            if ((url = getenv(ENV_SCANNER_DOCKER_URL)) != NULL) {
                args[a ++] = "-u";
                args[a ++] = url;
            }
            if ((join = getenv(ENV_CLUSTER_JOIN)) != NULL) {
                args[a ++] = "-j";
                args[a ++] = join;
            }
            if ((join_port = getenv(ENV_CLUSTER_JOIN_PORT)) != NULL) {
                args[a ++] = "--join_port";
                args[a ++] = join_port;
            }
            if ((adv = getenv(ENV_CLUSTER_ADVERTISE)) != NULL) {
                args[a ++] = "-a";
                args[a ++] = adv;
            }
            if ((adv_port = getenv(ENV_CLUSTER_ADV_PORT)) != NULL) {
                args[a ++] = "--adv_port";
                args[a ++] = adv_port;
            }
            if (((license = getenv(ENV_SCANNER_LICENSE)) != NULL) || (on_demand = getenv(ENV_SCANNER_ON_DEMAND)) != NULL) {
                args[a ++] = "--license";
                args[a ++] = "on_demand";

                g_exit_monitor_on_proc_exit = 1;
            }
            if ((registry = getenv(ENV_SCANNER_REGISTRY)) != NULL) {
                args[a ++] = "--registry";
                args[a ++] = registry;
            }
            if ((repository = getenv(ENV_SCANNER_REPOSITORY)) != NULL) {
                args[a ++] = "--repository";
                args[a ++] = repository;
            }
            if ((tag = getenv(ENV_SCANNER_TAG)) != NULL) {
                args[a ++] = "--tag";
                args[a ++] = tag;
            }
        }

        // The following options apply to both standalone or non-standalone mode
        if ((user = getenv(ENV_SCANNER_REG_USER)) != NULL) {
            args[a ++] = "--registry_username";
            args[a ++] = user;
        }
        if ((pass = getenv(ENV_SCANNER_REG_PASS)) != NULL) {
            args[a ++] = "--registry_password";
            args[a ++] = pass;
        }
        if ((base = getenv(ENV_SCANNER_BASE_IMAGE)) != NULL) {
            args[a ++] = "--base_image";
            args[a ++] = base;
        }
        if ((enable = getenv(ENV_SCANNER_SCAN_LAYERS)) != NULL) {
            if (checkImplicitEnableFlag(enable) == 1) {
                args[a ++] = "--scan_layers";
            }
        }
        if ((api_user = getenv(ENV_SCANNER_CTRL_USER)) != NULL) {
            args[a ++] = "--ctrl_username";
            args[a ++] = api_user;
        }
        if ((api_pass = getenv(ENV_SCANNER_CTRL_PASS)) != NULL) {
            args[a ++] = "--ctrl_password";
            args[a ++] = api_pass;
        }
        if ((cache_record_max = getenv(ENV_SCANNER_CACHE_MAX)) != NULL) {
               args[a ++] = "-maxrec";
               args[a ++] = cache_record_max;
        }
        if ((api_pass = getenv(ENV_SCANNER_TLS_VERIFICATION)) != NULL) {
            args[a ++] = "--enable-tls-verification";
        }
        args[a] = NULL;
        break;
    default:
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        return pid;
    }

    if (pid == 0) {
        // child : set the process group ID
        setpgrp();
        execv(args[0], args);
        exit(0);
    }
    return pid;
}

static void start_proc(int i)
{
    pid_t pid;

    if (g_procs[i].pid > 0) {
        return;
    }

    pid = fork_exec(i);
    if (pid > 0) {
        g_procs[i].pid = pid;
        g_procs[i].running = true;
        print_log("Start %s, pid=%d\n", g_procs[i].name, g_procs[i].pid);
        gettimeofday(&g_procs[i].start, NULL);
    }
}

static void stop_proc(int i, int sig, int wait)
{
    if (g_procs[i].pid > 0) {
        debug("Kill %s with signal %d, pid=%d\n", g_procs[i].name, sig, g_procs[i].pid);
        kill(g_procs[i].pid, sig);

        int pid, status;
        while (wait) {
            pid = waitpid(WAIT_ANY, &status, WNOHANG);
            if (pid == g_procs[i].pid) {
                g_procs[i].running = false;
                g_procs[i].pid = 0;
                debug("%s stopped.\n", g_procs[i].name);
                break;
            }
        }
    }
}

static void stop_related_proc(int cause)
{
}

static void exit_handler(int sig)
{
    g_exit_signal = 1;
}

static int exit_monitor(void)
{
    int ret = 0;

    g_procs[PROC_SCANNER].active = false;

    signal(SIGCHLD, SIG_DFL);

    switch (g_mode) {
    case MODE_SCANNER:
        stop_proc(PROC_SCANNER, SIGTERM, false);
        break;
    }

    debug("Clean up.\n");
    return ret;
}

static void proc_exit_handler(int signal)
{
    int i, status, exit_status;
    pid_t pid;

    /* Wait for a child process to exit */
    while (1) {
        // waitpid() can be called in signal handler
        pid = waitpid(WAIT_ANY, &status, WNOHANG);
        if (pid <= 0) {
            return;
        }

        if (WIFEXITED(status)) {
            exit_status = WEXITSTATUS(status);
        } else {
            exit_status = -1;
        }

        for (i = 0; i < PROC_MAX; i ++) {
            if (pid != g_procs[i].pid) {
                continue;
            }

            g_procs[i].exit_status = exit_status;
            g_procs[i].running = false;
        }
    }
}

static void help(const char *prog)
{
    printf("%s:\n", prog);
    printf("    d: enable debug\n");
    printf("    h: help\n");
    printf("    n: scan node in standalone mode\n");
    printf("    i: <image>, scan image in standalone mode\n");
}

int main (int argc, char **argv)
{
    int i, ret;
    struct timeval tmo;
    fd_set read_fds;

    int arg = 0;
    while (arg != -1) {
        arg = getopt(argc, argv, "hdni:");

        switch (arg) {
        case -1:
            break;
        case 'd':
            g_debug = 1;
            break;
        case 'n':
            g_node = 1;
            break;
        case 'i':
            g_image = optarg;
            break;
        case 'h':
        default:
            help(argv[0]);
            exit(0);
        }
    }
    if (getenv(ENV_SCANNER_DEBUG_MODE) != NULL) {
        g_debug = 1;
    }

    signal(SIGTERM, exit_handler);
    signal(SIGBUS, exit_handler);
    signal(SIGINT, exit_handler);
    signal(SIGQUIT, exit_handler);
    signal(SIGCHLD, proc_exit_handler);

    debug("%s starts, pid=%d\n", argv[0], getpid());

    ret = 0;
    switch (g_mode) {
    case MODE_SCANNER:
        g_procs[PROC_SCANNER].active = true;
        break;
    }

    while (1) {
        if (g_exit_signal == 1) {
            ret = exit_monitor();
            debug("monitor exit[%d]", ret);
            sleep(3);       // wait for consul exit
            exit(0);
        }

        // stop/start process
        for (i = 0; i < PROC_MAX; i ++) {
            if (g_procs[i].active && !g_procs[i].running) {
                if (g_procs[i].pid > 0) {
                    // Previous process exited.
                    debug("Process %s exit status %d, pid=%d\n",
                          g_procs[i].name, g_procs[i].exit_status, g_procs[i].pid);

                    g_procs[i].pid = 0;

                    if (g_exit_monitor_on_proc_exit == 1) {
                        debug("Process %s exit. Monitor Exit.\n",
                              g_procs[i].name);
                        exit_monitor();
                        exit(g_procs[i].exit_status & 0xff);
                    }

                    if (g_procs[i].exit_status == (-2 & 0xff)) {
                        debug("Process %s exit with non-recoverable return code. Monitor Exit!!\n",
                              g_procs[i].name);
                        exit_monitor();
                        exit(-2);
                    }

                    g_procs[i].exit_status = 0;

                    stop_related_proc(i);
                }

                start_proc(i);
            } else if (!g_procs[i].active && g_procs[i].pid > 0) {
                stop_proc(i, SIGTERM, true);
            }
        }

        tmo.tv_sec = 1;
        tmo.tv_usec = 0;

        FD_ZERO(&read_fds);
        ret = select(0, &read_fds, NULL, NULL, &tmo);
    }
    return 0;
}
