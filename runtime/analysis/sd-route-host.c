/* Synthetic service + resident fixed-request broker. Never injected into IM.
 * Only its own child PID is waited/killed; service SIGCHLD handling is unchanged.
 */
#include "sd-route-common.h"
#include "sd-route-runner-pin.h"
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <spawn.h>
#include <pthread.h>
#include <dlfcn.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake=PTHREAD_COND_INITIALIZER;
static int pending,busy,done,stop,duplicate,exit_code,term_signal,timed_out,spawn_error;
static unsigned heartbeat;
static const char *fixture="normal";
static char output[96];
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void *pulse(void *unused){(void)unused;for(;;){pthread_mutex_lock(&lock);heartbeat++;int end=stop;pthread_mutex_unlock(&lock);if(end)return NULL;usleep(1000);}}
/* Fixed ABI: no path, symbol, memory address, arguments or syscall request. */
int sd_route_request_v1(void) {
    pthread_mutex_lock(&lock);
    if(busy){duplicate++;pthread_mutex_unlock(&lock);return 1;}
    busy=1;pending=1;done=0;
    pthread_cond_signal(&wake);
    pthread_mutex_unlock(&lock);
    return 0;
}
static void supervise(void) {
    int card=sr_card(1); if(card<0){spawn_error=101;return;}
    int exe=openat(card,"runner",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    close(card);
    if(sr_hash(exe,SR_RUNNER_HASH)){if(exe>=0)close(exe);spawn_error=102;return;}
    int pipes[2];if(pipe2(pipes,O_CLOEXEC)){close(exe);spawn_error=103;return;}
    posix_spawn_file_actions_t actions;posix_spawnattr_t attr;
    if(posix_spawn_file_actions_init(&actions)||posix_spawnattr_init(&attr)){spawn_error=104;goto close_fds;}
    /* Exec the exact verified inode; no loader work in a fork child. */
    int err=posix_spawn_file_actions_adddup2(&actions,exe,4);
    err|=posix_spawn_file_actions_adddup2(&actions,pipes[1],1);
    err|=posix_spawn_file_actions_addclose(&actions,pipes[0]);
    err|=posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP);
    err|=posix_spawnattr_setpgroup(&attr,0);
    char choice[64];snprintf(choice,sizeof choice,"SD_ROUTE_FIXTURE=%s",fixture);
    char *env[]={choice,"PATH=/nonexistent",NULL};
    char *argv[]={"sd-route-runner",NULL};pid_t pid=0;
    double deadline=now()+2.0;
    if(!err)err=posix_spawn(&pid,"/proc/self/fd/4",&actions,&attr,argv,env);
    posix_spawn_file_actions_destroy(&actions);posix_spawnattr_destroy(&attr);
    if(err){spawn_error=err;goto close_fds;}
    close(exe);exe=-1;close(pipes[1]);pipes[1]=-1;
    fcntl(pipes[0],F_SETFL,O_NONBLOCK);
    size_t used=0;int status=0,reaped=0;
    while(!reaped) {
        ssize_t n=read(pipes[0],output+used,sizeof output-1-used);if(n>0)used+=(size_t)n;
        pid_t got=waitpid(pid,&status,WNOHANG);
        if(got==pid){reaped=1;break;}
        if(got<0 && errno!=EINTR){spawn_error=105;break;}
        if(now()>=deadline){timed_out=1;break;}
        struct pollfd p={pipes[0],POLLIN,0};poll(&p,1,10);
    }
    if(!reaped){
        /* PID cannot be reused while this owned child remains unreaped. */
        kill(-pid,SIGKILL);kill(pid,SIGKILL);
        pid_t got;do{got=waitpid(pid,&status,0);}while(got<0&&errno==EINTR);
        if(got!=pid)spawn_error=106;else reaped=1;
    }
    ssize_t n=read(pipes[0],output+used,sizeof output-1-used);if(n>0)used+=(size_t)n;
    output[used]=0;
    exit_code=WIFEXITED(status)?WEXITSTATUS(status):-1;
    term_signal=WIFSIGNALED(status)?WTERMSIG(status):0;
    /* An exact second wait must find no child: no zombie, no unrelated reap. */
    if(reaped && !(waitpid(pid,&status,WNOHANG)==-1&&errno==ECHILD))spawn_error=107;
close_fds:
    if(exe>=0)close(exe);
    close(pipes[0]);if(pipes[1]>=0)close(pipes[1]);
}
static void *worker(void *unused) {
    (void)unused;
    pthread_mutex_lock(&lock);
    for(;;){
        while(!pending&&!stop)pthread_cond_wait(&wake,&lock);
        if(stop)break;
        pending=0;pthread_mutex_unlock(&lock);
        supervise();
        pthread_mutex_lock(&lock);busy=0;done=1;pthread_cond_broadcast(&wake);
    }
    pthread_mutex_unlock(&lock);return NULL;
}
static int copy(const char *source,int dir,const char *target,mode_t mode) {
    int in=open(source,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    int out=openat(dir,target,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode);
    if(in<0||out<0){if(in>=0)close(in);if(out>=0)close(out);return -1;}
    char data[4096];ssize_t n;int fail=0;
    while((n=read(in,data,sizeof data))>0)if(write(out,data,(size_t)n)!=n){fail=1;break;}
    if(n<0)fail=1;close(in);close(out);return fail?-1:0;
}
static int prepare(const char *name) {
    if(mkdir(SR_ROOT,0700)&&errno!=EEXIST)return -1;
    if(mkdir(SR_CARD,0700)&&errno!=EEXIST)return -1;
    /* No stale requests are consumed: enable must be created by this session. */
    unlink(SR_ROOT "/enable");
    if(!strcmp(name,"missing_card"))return 0;
    if(mount("sd-route-fixture",SR_CARD,"tmpfs",MS_NOSUID|MS_NODEV,"size=4m,mode=0700"))return -1;
    int card=sr_card(0);if(card<0)return -1;
    int ok=copy("/simulation/sd-route-runner",card,"runner",!strcmp(name,"exec_denied")?0600:0700);
    const char *selected="normal";
    if(!strcmp(name,"constructor_crash")||!strcmp(name,"run_crash")||!strcmp(name,"constructor_hang")||!strcmp(name,"run_hang"))selected=name;
    fixture=selected;
    char source[160];snprintf(source,sizeof source,"/simulation/sd-route-%s.so",selected);
    if(strcmp(name,"missing_file")) {
        if(!strcmp(name,"symlink"))ok|=symlinkat(source,card,"plugin.so");
        else ok|=copy(source,card,"plugin.so",0444);
    }
    int meta=openat(card,"plugin.meta",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    const char version[8]={'S','D','P','1',!strcmp(name,"bad_version")?2:1,0,0,0};
    if(meta<0||write(meta,version,8)!=8)ok=-1;if(meta>=0)close(meta);
    if(!strcmp(name,"bad_elf")||!strcmp(name,"bad_hash")) {
        int f=openat(card,"plugin.so",O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
        if(f<0)ok=-1;else{if(lseek(f,!strcmp(name,"bad_elf")?0:256,SEEK_SET)<0||write(f,"BAD",3)!=3)ok=-1;close(f);}
    }
    if(!strcmp(name,"oversize")) {
        int f=openat(card,"plugin.so",O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
        if(f<0)ok=-1;else{if(ftruncate(f,1024*1024+1))ok=-1;close(f);}
    }
    close(card);
    if(ok)return -1;
    unsigned flags=MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV;
    if(!strcmp(name,"noexec"))flags|=MS_NOEXEC;
    if(mount(NULL,SR_CARD,NULL,flags,NULL))return -1;
    if(!strcmp(name,"ejected")&&umount(SR_CARD))return -1;
    return 0;
}
static int one(const char *name) {
    int disabled=!strcmp(name,"disabled");
    if(prepare(name)){printf("SD_ROUTE_FAILURE stage=prepare errno=%d case=%s\n",errno,name);return -1;}
    if(!disabled){int fd=open(SR_ROOT "/enable",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return -1;int ok=write(fd,"1",1)==1;close(fd);if(!ok)return -1;}
    pthread_mutex_lock(&lock);done=0;duplicate=0;exit_code=-1;term_signal=timed_out=spawn_error=0;output[0]=0;unsigned before=heartbeat;pthread_mutex_unlock(&lock);
    double started=now();
    void *entry=dlopen("/simulation/sd-route-entry.so",RTLD_NOW|RTLD_LOCAL);
    if(!entry){printf("SD_ROUTE_FAILURE stage=entry errno=%d case=%s\n",errno,name);return -1;}
    dlclose(entry);
    double returned=now()-started;
    if(!disabled){
        /* Repeat dlopen/dlclose while native constructor/function is pending. */
        if(!strcmp(name,"constructor_hang"))for(int i=0;i<8;i++){
            entry=dlopen("/simulation/sd-route-entry.so",RTLD_NOW|RTLD_LOCAL);
            if(!entry)return -1;dlclose(entry);
        }
        pthread_mutex_lock(&lock);while(!done)pthread_cond_wait(&wake,&lock);pthread_mutex_unlock(&lock);
    } else usleep(30000);
    usleep(10000);
    pthread_mutex_lock(&lock);unsigned ticks=heartbeat-before;int quiet=!busy&&!pending;pthread_mutex_unlock(&lock);
    int constrained=strstr(output,"CONSTRAINED\n")!=NULL;
    int exec_ready=strstr(output,"EXEC_READY\n")!=NULL;
    int preload_ready=strstr(output,"PRELOAD_READY\n")!=NULL;
    int passed=returned<0.5 && ticks>0 && quiet;
    if(constrained)passed&=exec_ready&&preload_ready;
    if(disabled)passed&=!done && !output[0];
    else if(!strcmp(name,"normal"))passed&=!spawn_error && exit_code==0 && constrained && strstr(output,"HELLO\n")!=NULL;
    else if(strstr(name,"crash"))passed&=!spawn_error&&term_signal==SIGSEGV&&constrained&&!timed_out;
    else if(strstr(name,"hang"))passed&=!spawn_error&&term_signal==SIGKILL&&constrained&&timed_out;
    else if(!strcmp(name,"exec_denied")||!strcmp(name,"noexec"))passed&=spawn_error==EACCES&&!constrained;
    else passed&=(spawn_error||exit_code>=20)&&!constrained&&!timed_out;
    if(!strcmp(name,"constructor_hang"))passed&=duplicate==8;
    printf("SD_ROUTE case=%s passed=%d entry_ms=%u ticks=%u exit=%d signal=%d timeout=%d spawn_error=%d duplicates=%d constrained=%d reaped=%d exec_ready=%d preload_ready=%d\n",name,passed,(unsigned)(returned*1000),ticks,exit_code,term_signal,timed_out,spawn_error,duplicate,constrained,!spawn_error&&!disabled,exec_ready,preload_ready);
    fflush(stdout);
    unlink(SR_ROOT "/enable");
    int card=sr_card(1);if(card>=0){close(card);if(umount(SR_CARD))return -1;}
    return passed?0:-1;
}
static int run(void) {
    /* Deliberate inherited descriptor sentinels: directory, device and socket. */
    int directory=open("/simulation",O_RDONLY|O_DIRECTORY);
    int device=open("/dev/null",O_RDWR);
    int sockets[2];
    if(directory<0||device<0||dup2(device,200)!=200||socketpair(AF_UNIX,SOCK_STREAM,0,sockets))return 40;
    pthread_t a,b;if(pthread_create(&a,NULL,pulse,NULL)||pthread_create(&b,NULL,worker,NULL))return 41;
    const char *cases[]={"disabled","normal","missing_card","missing_file","symlink","bad_version","bad_elf","bad_hash","oversize","exec_denied","noexec","ejected","constructor_crash","run_crash","constructor_hang","run_hang","normal","disabled"};
    int result=0;
    for(unsigned i=0;i<sizeof cases/sizeof cases[0];i++)if(one(cases[i])){result=42;break;}
    pthread_mutex_lock(&lock);stop=1;pthread_cond_broadcast(&wake);pthread_mutex_unlock(&lock);
    pthread_join(a,NULL);pthread_join(b,NULL);
    close(200);close(directory);close(device);close(sockets[0]);close(sockets[1]);
    printf("SD_ROUTE_SUITE passed=%d sony_loader=0 overlay=0\n",!result);fflush(stdout);return result;
}
void _start(void){_exit(run());}
