/* Trusted RAM-only supervisor. Never opens /dev/mem or enters the IM process. */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/memfd.h>
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
#include "ram-plugin.h"
static int limit(int resource, rlim_t value) { struct rlimit r={value,value};return setrlimit(resource,&r); }
static int sandbox(void) {
    struct sock_filter code[]={
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,93,7,0),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,94,6,0),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,64,0,3),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,1,3,0), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,281,2,0), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
      BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,3,0,3),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[4])),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AT_EMPTY_PATH,0,1),
      BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL)};
    struct sock_fprog program={sizeof code/sizeof code[0],code};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)) return -1;
    return 0;
}
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
        if(fd!=1&&fd!=3&&fd!=(unsigned)keep)close((int)fd);
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
    int input=open(name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    if(input<0 || fstat(input,&st) || !S_ISREG(st.st_mode) || (st.st_mode&022) || st.st_size<=0 || st.st_size>65536) {
      if(input>=0)close(input);
      puts("RAM_PLUGIN_REJECT missing/unsafe executable");return 1;
    }
    int mem=syscall(SYS_memfd_create,"ram-plugin",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(mem<0){close(input);puts("RAM_PLUGIN_UNSUPPORTED memfd");return 2;}
    unsigned char bytes[65536];ssize_t got=read(input,bytes,sizeof bytes);close(input);
    if(got!=st.st_size || write(mem,bytes,got)!=got || fchmod(mem,0555) ||
       fcntl(mem,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)) {close(mem);return 2;}
    const char *jail="/tmp/ram-plugin-root";
    if(mkdir(jail,0700) && errno!=EEXIST){close(mem);return 2;}
    if(lstat(jail,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&077)){close(mem);return 2;}
    struct __user_cap_header_struct parent_header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct parent_caps[2]={{0},{0}};
    if(syscall(SYS_capget,&parent_header,parent_caps)||!(parent_caps[0].effective&(1u<<CAP_KILL))){close(mem);return 2;}
    int pipefd[2];if(pipe2(pipefd,O_CLOEXEC)){close(mem);return 2;}
    pid_t pid=fork();if(pid<0)return 2;
    if(pid==0) {
      if(dup2(pipefd[1],1)<0 || dup2(mem,3)<0 || fcntl(3,F_SETFD,FD_CLOEXEC))_exit(120);
      if(close_others())_exit(120);
      if(limit(RLIMIT_CPU,1)||limit(RLIMIT_AS,16*1024*1024)||limit(RLIMIT_FSIZE,0)||limit(RLIMIT_CORE,0)||limit(RLIMIT_NOFILE,4)||limit(RLIMIT_NPROC,4))_exit(121);
      if(chroot(jail)||chdir("/")||prctl(PR_SET_KEEPCAPS,0,0,0,0))_exit(122);
      for(int cap=0;cap<64;cap++)if(prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)_exit(123);
      if(setgroups(0,NULL)||setresgid(65534,65534,65534)||setresuid(65534,65534,65534)||getuid()!=65534||geteuid()!=65534)_exit(124);
      struct __user_cap_header_struct cap_header={_LINUX_CAPABILITY_VERSION_3,0};
      struct __user_cap_data_struct caps[2]={{0},{0}};
      if(syscall(SYS_capset,&cap_header,caps)||syscall(SYS_capget,&cap_header,caps))_exit(124);
      if(caps[0].effective||caps[0].permitted||caps[0].inheritable||caps[1].effective||caps[1].permitted||caps[1].inheritable)_exit(124);
      if(sandbox())_exit(125);
      char *argv[]={"ram-plugin",NULL};char *envp[]={NULL};
      syscall(SYS_execveat,3,"",argv,envp,AT_EMPTY_PATH);_exit(126);
    }
    close(mem);close(pipefd[1]);fcntl(pipefd[0],F_SETFL,O_NONBLOCK);
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
    puts("RAM_PLUGIN_OK uid=65534 no_new_privs=1 seccomp=filter sealed_exec=1 wall_limit=3 output=bounded_mask");return 0;
}
void _start(void){int result=run();fflush(stdout);_exit(result);}
