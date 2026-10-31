#ifndef SD_ROUTE_COMMON_H
#define SD_ROUTE_COMMON_H
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "fl23-sha256.h"
extern int sr_scan(const char *,const char *,...) __asm__("__isoc99_sscanf");
extern int __fxstat(int,int,struct stat *);
extern int __lxstat(int,const char *,struct stat *);
#define SR_ROOT "/tmp/sd-route"
#define SR_CARD SR_ROOT "/card"
static int sr_regular(int fd) {
    struct stat st;
    return fd >= 0 && !__fxstat(0,fd,&st) && S_ISREG(st.st_mode)
        && st.st_uid == 0 && !(st.st_mode & 022) && st.st_size > 0 && st.st_size <= 1024*1024;
}
static int sr_hash(int fd, const char *expected) {
    struct fl23_sha256 ctx; unsigned char block[4096], digest[32];
    char hex[65]; ssize_t n;
    if (!sr_regular(fd) || lseek(fd,0,SEEK_SET)) return -1;
    fl23_sha_init(&ctx);
    while ((n=read(fd,block,sizeof block))>0) fl23_sha_update(&ctx,block,(size_t)n);
    if(n<0)return -1;
    fl23_sha_final(&ctx,digest);
    for(int i=0;i<32;i++) snprintf(hex+2*i,3,"%02x",digest[i]);
    return strcmp(hex,expected) || lseek(fd,0,SEEK_SET) ? -1:0;
}
static int sr_card(int readonly) {
    struct stat st;
    if (__lxstat(0,SR_ROOT,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&077))return -1;
    if (__lxstat(0,SR_CARD,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&022))return -1;
    /* This path is a disposable simulated card, never a guessed Sony SD path. */
    FILE *f=fopen("/proc/self/mountinfo","r");
    if(!f)return -1;
    char line[2048], point[256], type[32], options[128]; int found=0;
    while(fgets(line,sizeof line,f)) {
        char *tail=strstr(line," - ");
        if(tail && sr_scan(line,"%*u %*u %*s %*s %255s %127s",point,options)==2
            && sr_scan(tail," - %31s",type)==1 && !strcmp(point,SR_CARD))
            found=!strcmp(type,"tmpfs") && (!readonly || !strcmp(options,"ro") || !strncmp(options,"ro,",3));
    }
    fclose(f);
    return found ? open(SR_CARD,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC):-1;
}
#endif
