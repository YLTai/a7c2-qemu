/* Synthetic loader, not Sony SET_FILE2 or its authentication/service loop. */
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void put(const char *path, const void *data, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, data, size) == (ssize_t)size);
    assert(close(fd) == 0);
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    const char *scenario = argv[2];
    assert(mkdir("/tmp/jiritsu", 0700) == 0);
    unsigned char blob[65537], request[32] = "A7NOPQ01", result[33];
    for (int i = 0; i < 16; ++i) request[8 + i] = (unsigned char)(i + 1);
    int input = open(argv[1], O_RDONLY);
    assert(input >= 0);
    ssize_t size = read(input, blob, sizeof(blob));
    assert(size > 0 && size <= 65536);
    assert(close(input) == 0);
    put("/tmp/jiritsu/libJit.so", blob, (size_t)size);
    if (!strcmp(scenario, "bad-request")) request[0] = '?';
    if (strcmp(scenario, "missing-request"))
        put("/tmp/jiritsu/a7c2.noop.request", request, sizeof(request));
    if (!strcmp(scenario, "existing-result"))
        put("/tmp/jiritsu/a7c2.noop.result", "preserve", 8);
    if (!strcmp(scenario, "symlink-result")) {
        put("/tmp/sentinel", "unchanged", 9);
        assert(symlink("/tmp/sentinel", "/tmp/jiritsu/a7c2.noop.result") == 0);
    }
    pid_t pid = getpid();
    pid_t tid = gettid();
    void *module = dlopen("/tmp/jiritsu/libJit.so", RTLD_NOW | RTLD_LOCAL);
    if (!module) fprintf(stderr, "dlopen: %s\n", dlerror());
    assert(module != NULL);
    /* Reaching here proves constructor returned in this same process/thread. */
    assert(getpid() == pid && gettid() == tid);
    assert(dlclose(module) == 0);
    int fd = open("/tmp/jiritsu/a7c2.noop.result", O_RDONLY);
    if (!strcmp(scenario, "success")) {
        assert(fd >= 0);
        assert(read(fd, result, sizeof(result)) == 32);
        assert(!memcmp(result, "A7NOPR01", 8));
        assert(!memcmp(result + 8, request + 8, 24));
        assert(access("/tmp/jiritsu/libJit.so", F_OK) == -1);
    } else if (!strcmp(scenario, "existing-result")) {
        assert(fd >= 0 && read(fd, result, sizeof(result)) == 8);
        assert(!memcmp(result, "preserve", 8));
    } else if (!strcmp(scenario, "symlink-result")) {
        assert(fd >= 0 && read(fd, result, sizeof(result)) == 9);
        assert(!memcmp(result, "unchanged", 9));
    } else {
        assert(fd == -1);
        assert(access("/tmp/jiritsu/libJit.so", F_OK) == 0);
    }
    if (fd >= 0) assert(close(fd) == 0);
    const char *names[] = {"libJit.so", "a7c2.noop.request", "a7c2.noop.result"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(*names); ++i) {
        char path[128];
        snprintf(path, sizeof(path), "/tmp/jiritsu/%s", names[i]);
        (void)unlink(path);
        assert(access(path, F_OK) == -1);
    }
    assert(rmdir("/tmp/jiritsu") == 0);
    printf("synthetic loader: %s passed; returned, dlclosed, files absent\n", scenario);
    return 0;
}
