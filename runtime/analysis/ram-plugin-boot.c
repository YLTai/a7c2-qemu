/* Trusted bytecode interpreter/supervisor; never executes native plugin bytes. */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <grp.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ram-bytecode.h"
/* Original firmware glibc 2.25 exposes these versioned stat entry points. */
#ifdef __aarch64__
extern int __fxstat(int,int,struct stat *);
extern int __lxstat(int,const char *,struct stat *);
#define plugin_fstat(fd,st) __fxstat(0,fd,st)
#define plugin_lstat(path,st) __lxstat(0,path,st)
#else
#define plugin_fstat(fd,st) fstat(fd,st)
#define plugin_lstat(path,st) lstat(path,st)
#endif
static int limit(int resource, rlim_t value) { struct rlimit r={value,value};return setrlimit(resource,&r); }
static int close_others(void) {
    DIR *directory=opendir("/proc/self/fd");
    if(!directory)return -1;
    int keep=dirfd(directory);struct dirent *entry;
    for(;;) {
        errno=0;entry=readdir(directory);
        if(!entry){int failed=errno;int closed=closedir(directory);return failed||closed?-1:0;}
        unsigned fd=0;const char *p=entry->d_name;
        if(!*p)continue;
        for(;*p>='0'&&*p<='9';p++) { if(fd>100000000){closedir(directory);return -1;}fd=fd*10+(*p-'0'); }
        if(*p)continue;
        if(fd!=1&&fd!=(unsigned)keep)close((int)fd);
    }
}
static int run(void) {
    const char *mode=getenv("RAM_PLUGIN_CASE");if(!mode)mode="hello";
    const char *cases[]={"hello","malformed","crash","timeout","forbidden","invalid_elf","missing","off"};
    unsigned which;for(which=0;which<8;which++)if(!strcmp(mode,cases[which]))break;
    if(which==8)return 2;
    unlink(RP_FRAME); /* every failed invocation restores the unobscured camera frame */
    if(which==7){puts("RAM_PLUGIN_OFF");return 0;}
    char name[128];snprintf(name,sizeof name,"/simulation/ram-plugin-%s",mode);
    /* Plugin bytes are untrusted; cpio may preserve the build user ownership. */
    int input=open(name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    if(input<0 || plugin_fstat(input,&st) || !S_ISREG(st.st_mode) || (st.st_mode&022) || st.st_size<=0 || st.st_size>BC_MAX) {
      if(input>=0)close(input);
      puts("RAM_PLUGIN_REJECT missing/unsafe bytecode");return 1;
    }
    unsigned char bytes[BC_MAX];ssize_t got=read(input,bytes,sizeof bytes);close(input);
    if(got!=st.st_size)return 2;
    const char *jail="/tmp/ram-plugin-root";
    if(mkdir(jail,0700) && errno!=EEXIST){return 2;}
    if(plugin_lstat(jail,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&077)){return 2;}
    struct __user_cap_header_struct parent_header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct parent_caps[2]={{0},{0}};
    if(syscall(SYS_capget,&parent_header,parent_caps)||!(parent_caps[0].effective&(1u<<CAP_KILL))){return 2;}
    int pipefd[2];if(pipe2(pipefd,O_CLOEXEC)){return 2;}
    pid_t pid=fork();if(pid<0)return 2;
    if(pid==0) {
      if(dup2(pipefd[1],1)<0)_exit(120);
      if(close_others())_exit(120);
      if(limit(RLIMIT_CPU,1)||limit(RLIMIT_AS,16*1024*1024)||limit(RLIMIT_FSIZE,0)||limit(RLIMIT_CORE,0)||limit(RLIMIT_NOFILE,4)||limit(RLIMIT_NPROC,4))_exit(121);
      if(chroot(jail)||chdir("/")||prctl(PR_SET_KEEPCAPS,0,0,0,0))_exit(122);
      for(int cap=0;cap<64;cap++)if(prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)_exit(123);
      if(setgroups(0,NULL)||setresgid(65534,65534,65534)||setresuid(65534,65534,65534)||getuid()!=65534||geteuid()!=65534)_exit(124);
      struct __user_cap_header_struct cap_header={_LINUX_CAPABILITY_VERSION_3,0};
      struct __user_cap_data_struct caps[2]={{0},{0}};
      if(syscall(SYS_capset,&cap_header,caps)||syscall(SYS_capget,&cap_header,caps))_exit(124);
      if(caps[0].effective||caps[0].permitted||caps[0].inheritable||caps[1].effective||caps[1].permitted||caps[1].inheritable)_exit(124);
      if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(125);
      struct rp_frame frame;int result=bc_run(bytes,(size_t)got,&frame);
      if(result)_exit(result);
      _exit(write(1,&frame,sizeof frame)==sizeof frame?0:44);
    }
    close(pipefd[1]);fcntl(pipefd[0],F_SETFL,O_NONBLOCK);
    unsigned char data[RP_BYTES+1];size_t used=0;int status=0,finished=0;
    struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);time_t end=now.tv_sec+3;
    while(!finished) {
      ssize_t n=read(pipefd[0],data+used,sizeof data-used);if(n>0)used+=(size_t)n;
      if(used==sizeof data)break;
      if(waitpid(pid,&status,WNOHANG)==pid){finished=1;break;}
      clock_gettime(CLOCK_MONOTONIC,&now);if(now.tv_sec>=end)break;
      struct pollfd p={pipefd[0],POLLIN,0};poll(&p,1,20);
    }
    if(!finished){kill(pid,SIGKILL);waitpid(pid,&status,0);}
    ssize_t n=read(pipefd[0],data+used,sizeof data-used);if(n>0)used+=(size_t)n;close(pipefd[0]);
    if(!finished||!WIFEXITED(status)||WEXITSTATUS(status)||used!=RP_BYTES||!rp_valid((struct rp_frame*)data)) {
      dprintf(1,"RAM_PLUGIN_REJECT case=%s signal=%d exit=%d timed_out=%d bytes=%zu confined_success=0\n",mode,WIFSIGNALED(status)?WTERMSIG(status):0,WIFEXITED(status)?WEXITSTATUS(status):-1,!finished,used);return 1;
    }
    char temporary[100];snprintf(temporary,sizeof temporary,"/tmp/ram-plugin.%ld",(long)getpid());
    int out=open(temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if(out<0)return 2;
    int ok=write(out,data,used)==(ssize_t)used;close(out);
    if(!ok||rename(temporary,RP_FRAME)){unlink(temporary);return 2;}
    puts("RAM_PLUGIN_OK uid=65534 no_new_privs=1 engine=bytecode-v1 instruction_budget=4096 wall_limit=3 output=bounded_mask");return 0;
}
void _start(void){int result=run();fflush(stdout);_exit(result);}
