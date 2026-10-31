/* Candidate ABI for OUR synthetic multithreaded service, not Sony's USB ABI.
 * The resident broker owns its worker/lifetime; dlclose of this entry is safe.
 * No plugin dlopen, fork child, exit, path argument or memory interface here. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
extern int sd_route_request_v1(void);
void _init(void) {
    char enabled[2];
    int fd=open("/tmp/sd-route/enable",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0)return;
    ssize_t n=read(fd,enabled,sizeof enabled);
    close(fd);
    if(n==1 && enabled[0]=='1') (void)sd_route_request_v1();
}
