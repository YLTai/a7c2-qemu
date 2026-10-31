/* QEMU-only dependency probe, not a USB payload or a Sony service broker.
 * A fresh, single-threaded child loads the original DSO. No handler is called.
 * Parent exclusively reaps its child and enforces a wall deadline.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "jiritsu-fixture.h"

static int child(int lazy) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return 19;
    int own = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        const char *p = entry->d_name;
        unsigned fd = 0;
        while (*p >= '0' && *p <= '9') {
            unsigned digit = (unsigned)(*p - '0');
            if (fd > ((unsigned)INT_MAX - digit) / 10) break;
            fd = fd * 10 + digit; ++p;
        }
        if (*entry->d_name && !*p && fd != 1 && fd != (unsigned)own) close((int)fd);
    }
    closedir(directory);
    struct rlimit core = {0, 0}, files = {32, 32}, memory = {128UL<<20, 128UL<<20};
    if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_NOFILE, &files) ||
        setrlimit(RLIMIT_AS, &memory)) return 20;
    for (int cap = 0; cap <= 63; ++cap)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) && errno != EINVAL) return 21;
    if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 22;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    if (syscall(SYS_capset, &header, caps) || syscall(SYS_capget, &header, caps) ||
        caps[0].effective || caps[1].effective || caps[0].permitted || caps[1].permitted ||
        caps[0].inheritable || caps[1].inheritable) return 23;
    printf("JIRITSU_PROBE restricted=1 uid=%u\n", (unsigned)getuid());
    fflush(stdout);
    void *handle = dlopen("/usr/lib/libJiritsu.so", (lazy ? RTLD_LAZY : RTLD_NOW) | RTLD_LOCAL);
    if (!handle) {
        const char *error = dlerror();
        const char *prefix = "undefined symbol: ";
        const char *symbol = error ? strstr(error, prefix) : NULL;
        if (symbol) {
            char safe[160]; unsigned i = 0;
            symbol += strlen(prefix);
            while (i < sizeof(safe)-1 && ((symbol[i] >= 'a' && symbol[i] <= 'z') ||
                   (symbol[i] >= 'A' && symbol[i] <= 'Z') ||
                   (symbol[i] >= '0' && symbol[i] <= '9') || symbol[i] == '_')) {
                safe[i] = symbol[i]; ++i;
            }
            safe[i] = 0;
            printf("JIRITSU_PROBE missing_symbol=%s\n", safe);
        }
        printf("JIRITSU_PROBE loaded=0 category=%d\n", symbol ? 1 : 2);
        fflush(stdout); return 31;
    }
    if (lazy) {
        /* Fixed selector/base only. This original helper constructs a pathname;
         * no upload/read/delete handler, native payload or service init is called. */
        void (*filename)(unsigned, const char *, char *, unsigned) =
            dlsym(handle, "get_access_filename");
        char path[514] = {0};
        if (!filename) return 33;
        filename(2, "/tmp/jiritsu", path, sizeof(path));
        int matched = !strcmp(path, "/tmp/jiritsu/libJit.so");
        printf("JIRITSU_PROBE original_filename_helper=1 matched=%d\n", matched);
        fflush(stdout);
        if (!matched) return 34;
    }
    if (lazy == 2) { int rc = fixture_handler(handle); if (rc) return rc; }
    int set = dlsym(handle, "adj_cmd_set_file2") != NULL;
    int get = dlsym(handle, "adj_cmd_get_file2") != NULL;
    printf("JIRITSU_PROBE loaded=1 set_export=%d get_export=%d handlers_called=%d\n", set, get, lazy == 2);
    fflush(stdout);
    return dlclose(handle) ? 32 : 0;
}
static double now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return t.tv_sec + t.tv_nsec / 1e9;
}
static int one(int lazy) {
    printf("JIRITSU_PROBE binding=%s\n", lazy == 2 ? "handler" : lazy ? "lazy" : "now");
    fflush(stdout);
    double deadline = now();
    if (deadline < 0) return 40;
    deadline += 10;
    pid_t pid = fork();
    if (pid < 0) return 41;
    if (!pid) _exit(child(lazy));
    int status = 0;
    for (;;) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) break;
        if (got < 0 && errno != EINTR) return 42; /* No signal after ownership loss. */
        double current = now();
        if (current < 0 || current >= deadline) {
            kill(pid, SIGKILL);
            do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
            printf("JIRITSU_PROBE timed_out=1 reaped=%d\n", got == pid);
            fflush(stdout); return 43;
        }
        usleep(10000);
    }
    printf("JIRITSU_PROBE child_exit=%d signal=%d reaped=1 sony_usb=0\n",
           WIFEXITED(status) ? WEXITSTATUS(status) : -1,
           WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    fflush(stdout); return 0;
}
void _start(void) {
    int rc = one(0);
    if (!rc) rc = one(1);
    if (!rc) {
        rc = fixture_prepare();
        if (!rc) {
            rc = one(2);
            if (rc != 42) { int cleanup = fixture_cleanup(); if (!rc) rc = cleanup; }
        }
    }
    _exit(rc);
}
