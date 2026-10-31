/* Synthetic service adapters for one original-handler test. NOT Sony ABI exports
 * for an installable entry. Each is counted; no real DMM/OSAL/mount is simulated
 * as verified hardware behavior. Unexpected arguments terminate only our child. */
#include "sd-route-common.h"
#include "jiritsu-return-pin.h"
#include <sys/mount.h>
#include <sys/vfs.h>
#include <linux/magic.h>
static unsigned char fixture_data[65536 + 3];
static size_t fixture_length;
static unsigned fixture_mounts, fixture_allocs, fixture_logs, fixture_closes;
static int fixture_close_result;
static int fixture_enabled;
static struct stat fixture_root;
static struct { unsigned long reserved; void *bytes; } fixture_buffer;
static struct { void *first; unsigned long reserved[3]; } fixture_dmm;
unsigned fixture_unit(unsigned long length) __asm__("_ZN6DmmMgr13CheckUnitTypeEm");
unsigned fixture_unit(unsigned long length) {
    if (!fixture_enabled || length != fixture_length) _exit(71);
    return 1;
}
int fixture_alloc(void *self, unsigned unit) __asm__("_ZN6DmmMgr9dmm_allocEj");
int fixture_alloc(void *self, unsigned unit) {
    if (!fixture_enabled || self != &fixture_dmm || unit != 1) _exit(72);
    fixture_allocs++; return 0;
}
int sys_mount(const char *device, const char *path) {
    struct statfs fs;
    if (!fixture_enabled || strcmp(device, "/dev/nflasha6") || strcmp(path, "/tmp/jiritsu") ||
        statfs(path, &fs) || fs.f_type != TMPFS_MAGIC) _exit(73);
    fixture_mounts++; return 0;
}
void fixture_log(unsigned char level, const char *text) __asm__("_Z18jiritsu_cpp_logrechPKc");
void fixture_log(unsigned char level, const char *text) { (void)level; (void)text; fixture_logs++; }
void fixture_log_value(unsigned char level, const char *text, unsigned value) __asm__("_Z18jiritsu_cpp_logrechPKcj");
void fixture_log_value(unsigned char level, const char *text, unsigned value) { (void)level; (void)text; (void)value; fixture_logs++; }
void fixture_dump(unsigned char level, const char *text, unsigned char *data, unsigned count) __asm__("_Z22jiritsu_cppdump_logrechPKcPhj");
void fixture_dump(unsigned char level, const char *text, unsigned char *data, unsigned count) { (void)level; (void)text; (void)data; (void)count; fixture_logs++; }
/* Transparent observation, not a simulated successful dlclose. */
int dlclose(void *handle) {
    int (*original)(void *) = dlsym(RTLD_NEXT, "dlclose");
    if (!original) _exit(74);
    int rc = original(handle);
    if (fixture_enabled) { fixture_closes++; fixture_close_result = rc; }
    return rc;
}
static int fixture_prepare(void) {
    int input = open("/simulation/jiritsu-return.so", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (!sr_regular(input) || sr_hash(input, JIRITSU_RETURN_HASH)) { if(input>=0)close(input); return 50; }
    if (lseek(input, 0, SEEK_SET) < 0) { close(input); return 51; }
    ssize_t count = read(input, fixture_data + 3, sizeof(fixture_data) - 3);
    char extra;
    if (count <= 0 || read(input, &extra, 1) != 0) { close(input); return 52; }
    close(input); fixture_length = (size_t)count;
    /* Refuse an existing directory; never hide or delete unknown guest state. */
    if (mkdir("/tmp/jiritsu", 0700)) return 53;
    if (mount("tmpfs", "/tmp/jiritsu", "tmpfs", MS_NOSUID|MS_NODEV, "size=1m,mode=0700")) {
        rmdir("/tmp/jiritsu"); return 54;
    }
    if (chown("/tmp/jiritsu", 65534, 65534)) {
        umount("/tmp/jiritsu"); rmdir("/tmp/jiritsu"); return 55;
    }
    if (__lxstat(0, "/tmp/jiritsu", &fixture_root)) {
        umount("/tmp/jiritsu"); rmdir("/tmp/jiritsu"); return 55;
    }
    return 0;
}
/* The handler creates this file after dropping to 65534. Keep the SD route's
 * root-owned checks unchanged; compare against the already hash-pinned input. */
static int fixture_written_file(int fd) {
    struct stat before, after;
    if (fd < 0 || __fxstat(0, fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != 65534 || before.st_gid != 65534 || before.st_nlink != 1 ||
        (before.st_mode & 022) || !(before.st_mode & 0400) ||
        before.st_size != (off_t)fixture_length) return 0;
    unsigned char block[4096]; size_t offset = 0;
    while (offset < fixture_length) {
        size_t count = fixture_length - offset;
        if (count > sizeof(block)) count = sizeof(block);
        ssize_t got = read(fd, block, count);
        if (got <= 0 || memcmp(block, fixture_data + 3 + offset, (size_t)got)) return 0;
        offset += (size_t)got;
    }
    char extra;
    if (read(fd, &extra, 1) != 0 || __fxstat(0, fd, &after)) return 0;
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size && before.st_mode == after.st_mode &&
        before.st_uid == after.st_uid && before.st_gid == after.st_gid && after.st_nlink == 1;
}
static int fixture_handler(void *handle) {
    void (*handler)(void *, void *, void *) = dlsym(handle, "adj_cmd_set_file2");
    if (!handler) return 56;
    unsigned char packet[64] = {0};
    unsigned length = (unsigned)fixture_length + 3, output_length = 0;
    memcpy(packet + 32, &length, sizeof(length));
    packet[40] = 0; packet[41] = 2; packet[42] = 0;
    fixture_data[0] = 0; fixture_data[1] = 2; fixture_data[2] = 0;
    fixture_buffer.bytes = fixture_data; fixture_dmm.first = &fixture_buffer;
    fixture_enabled = 1;
    handler(packet, &fixture_dmm, &output_length);
    fixture_enabled = 0;
    int fd = open("/tmp/jiritsu/libJit.so", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    int matches = fixture_written_file(fd);
    if (fd >= 0) close(fd);
    printf("JIRITSU_PROBE original_set_handler=1 file_hash=%d mount_stubs=%u dmm_stubs=%u log_stubs=%u dlclose_calls=%u dlclose_result=%d\n",
           matches, fixture_mounts, fixture_allocs, fixture_logs, fixture_closes, fixture_close_result);
    fflush(stdout);
    return matches && fixture_mounts == 1 && fixture_allocs == 1 && fixture_closes == 1 && fixture_close_result == 0 ? 0 : 57;
}
static int fixture_cleanup(void) {
    /* Remove only the tmpfs this process mounted, after its child is reaped.
     * No unlink of unknown names and no persistent filesystem write. */
    struct stat current;
    struct statfs fs;
    if (__lxstat(0, "/tmp/jiritsu", &current) || !S_ISDIR(current.st_mode) ||
        current.st_dev != fixture_root.st_dev || current.st_ino != fixture_root.st_ino ||
        current.st_uid != 65534 || statfs("/tmp/jiritsu", &fs) || fs.f_type != TMPFS_MAGIC) return 58;
    if (umount("/tmp/jiritsu") || rmdir("/tmp/jiritsu")) return 59;
    if (!__lxstat(0, "/tmp/jiritsu", &current) || errno != ENOENT) return 59;
    printf("JIRITSU_FIXTURE_CLEAN=1\n"); fflush(stdout); return 0;
}
