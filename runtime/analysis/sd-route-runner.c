/* Trusted, freshly exec'd runner. Restrictions precede dlopen/constructors.
 * Native code still has syscalls: this is NOT a hostile-code sandbox. */
#include "sd-route-common.h"
#include "sd-route-pins.h"
#include <dlfcn.h>
#include <dirent.h>
#include <grp.h>
static int limit(int kind,rlim_t n){struct rlimit r={n,n};return setrlimit(kind,&r);}
static int run(void) {
    const char *name=getenv("SD_ROUTE_FIXTURE");
    unsigned index=0;
    for(;index<5;index++)if(name && !strcmp(name,sr_names[index]))break;
    if(index==5)return 20;
    int card=sr_card(); if(card<0)return 21;
    int meta=openat(card,"plugin.meta",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    char version[9]; ssize_t count=meta<0?-1:read(meta,version,sizeof version);
    if(meta>=0)close(meta);
    if(count!=8 || memcmp(version,"SDP1\1\0\0\0",8)){close(card);return 22;}
    int input=openat(card,"plugin.so",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    close(card);
    unsigned char elf[20];
    if(!sr_regular(input)||read(input,elf,sizeof elf)!=sizeof elf || memcmp(elf,"\177ELF\2\1\1",7)
        || elf[16]!=3 || elf[17]!=0 || elf[18]!=183 || elf[19]!=0)return 23;
    if(sr_hash(input,sr_hashes[index]))return 24;
    if(input!=3){if(dup2(input,3)!=3)return 25;close(input);}
    /* Close inherited service descriptors, including stdin/stderr and runner fd. */
    DIR *d=opendir("/proc/self/fd");if(!d)return 26;
    int own=dirfd(d); struct dirent *e;
    while((e=readdir(d))) {
        char *end; long fd=strtol(e->d_name,&end,10);
        if(*e->d_name && !*end && fd!=1 && fd!=3 && fd!=own)close((int)fd);
    }
    closedir(d);
    if(limit(RLIMIT_CORE,0)||limit(RLIMIT_FSIZE,0)||limit(RLIMIT_NOFILE,16)
       ||limit(RLIMIT_AS,64*1024*1024)||limit(RLIMIT_CPU,5)||limit(RLIMIT_NPROC,1))return 27;
    if(prctl(PR_SET_KEEPCAPS,0,0,0,0))return 28;
    for(int cap=0;cap<64;cap++)if(prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)return 28;
    if(setgroups(0,NULL)||setresgid(65534,65534,65534)||setresuid(65534,65534,65534))return 29;
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct c[2]={{0},{0}};
    if(syscall(SYS_capset,&h,c)||syscall(SYS_capget,&h,c)||c[0].effective||c[1].effective
       ||c[0].permitted||c[1].permitted||c[0].inheritable||c[1].inheritable
       ||getuid()!=65534||geteuid()!=65534||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 30;
    void *library=dlopen("/proc/self/fd/3",RTLD_NOW|RTLD_LOCAL);
    close(3);
    if(!library)return 31;
    int (*plugin)(void)=dlsym(library,"sd_plugin_v1");
    int result=plugin?plugin():32;
    dlclose(library);
    return result;
}
void _start(void){_exit(run());}
