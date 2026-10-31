/* Offline candidate only. No camera transport is enabled by this project.
 * DT_INIT runs in the loader's process/thread; always return, never exit.
 * Independent implementation, no firmware, Backup, CP/AP or startup writes.
 */
#define _GNU_SOURCE
#include <asm/unistd.h>
#include <fcntl.h>
#include <linux/magic.h>

typedef long word;
typedef unsigned long size;

static word call(word number, word a, word b, word c, word d)
{
    register word x0 __asm__("x0") = a;
    register word x1 __asm__("x1") = b;
    register word x2 __asm__("x2") = c;
    register word x3 __asm__("x3") = d;
    register word x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory", "cc");
    return x0;
}

static void close_fd(word fd)
{
    /* Never retry close: descriptor ownership may already have changed. */
    if (fd >= 0) (void)call(__NR_close, fd, 0, 0, 0);
}

__attribute__((visibility("default"))) void _init(void)
{
    unsigned char request[33] = {0};
    unsigned char result[32] = {'A','7','N','O','P','R','0','1'};
    const unsigned char magic[8] = {'A','7','N','O','P','Q','0','1'};
    word filesystem[16] = {0};
    word directory = call(__NR_openat, AT_FDCWD, (word)"/tmp/jiritsu",
                          O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (directory < 0) return;
    /* Defense in depth only: host must establish mount/path/boot evidence
     * BEFORE uploading. A check after loading cannot undo an upload. */
    if (call(__NR_fstatfs, directory, (word)filesystem, 0, 0) ||
        filesystem[0] != TMPFS_MAGIC) goto done;
    word fd = call(__NR_openat, directory, (word)"a7c2.noop.request",
                   O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0);
    if (fd < 0) goto done;
    word count = call(__NR_read, fd, (word)request, sizeof(request), 0);
    close_fd(fd);
    if (count != 32) goto done;
    for (size i = 0; i < 8; ++i)
        if (request[i] != magic[i] || request[24 + i]) goto done;
    for (size i = 0; i < 16; ++i) result[8 + i] = request[8 + i];
    /* Do not continue if self-unlink is not acknowledged. The loader may
     * retain the mapping until dlclose even when the pathname is gone. */
    if (call(__NR_unlinkat, directory, (word)"libJit.so", 0, 0)) goto done;
    fd = call(__NR_openat, directory, (word)"a7c2.noop.result",
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) goto done;
    size written = 0;
    for (unsigned attempt = 0; attempt < 4 && written < sizeof(result); ++attempt) {
        word n = call(__NR_write, fd, (word)(result + written), sizeof(result) - written, 0);
        if (n == -4) continue;
        if (n <= 0 || (size)n > sizeof(result) - written) break;
        written += (size)n;
    }
    close_fd(fd);
done:
    close_fd(directory);
    /* A result file alone does not prove this return or dlclose succeeded. */
}
