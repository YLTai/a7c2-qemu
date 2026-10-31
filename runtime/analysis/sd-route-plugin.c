/* Independent, intentionally faulty native fixtures; never shipped to hardware. */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#ifndef FIXTURE
#define FIXTURE 0
#endif
static int ready;
void _init(void) {
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct c[2]={{0},{0}};
    struct rlimit r;
    int ok=getuid()==65534 && geteuid()==65534 && getgid()==65534
        && prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1
        && !syscall(SYS_capget,&h,c) && !c[0].effective && !c[0].permitted
        && !c[0].inheritable && !c[1].effective && !c[1].permitted && !c[1].inheritable
        && !getrlimit(RLIMIT_CORE,&r) && r.rlim_cur==0;
    for(int fd=0;fd<256;fd++) if(fd!=1 && fd!=3 && fcntl(fd,F_GETFD)>=0)ok=0;
    if(!ok)_exit(91);
    /* Evidence is emitted before the intentional fault, from inside constructor. */
    if(write(1,"CONSTRAINED\n",12)!=12)_exit(92);
    ready=1;
    if(FIXTURE==1)raise(SIGSEGV);
    if(FIXTURE==3)for(;;)pause();
}
int sd_plugin_v1(void) {
    if(!ready)return 93;
    if(FIXTURE==2)raise(SIGSEGV);
    if(FIXTURE==4)for(;;)pause();
    return write(1,"HELLO\n",6)==6?0:94;
}
