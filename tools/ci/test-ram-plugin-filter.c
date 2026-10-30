/* Host logic test only. Actual guest seccomp enforcement is tested separately. */
#define open captured_open
#define unlink captured_unlink
#define prctl captured_prctl
#define _start boot_entry
#include "../../runtime/analysis/ram-plugin-boot.c"
#undef open
#undef unlink
#undef prctl
#undef _start
#include <assert.h>
#include <stdarg.h>
static char fifo_path[256];
static int input_flags;
int captured_open(const char *path,int flags,...) {
    assert(!strcmp(path,"/simulation/ram-plugin-hello"));
    input_flags=flags;
    return (int)syscall(SYS_openat,AT_FDCWD,fifo_path,flags,0);
}
int captured_unlink(const char *path) { assert(!strcmp(path,RP_FRAME));return 0; }
static struct sock_filter saved[64];
static unsigned saved_count;
int captured_prctl(int option, ...) {
    va_list args; va_start(args,option);
    if(option==PR_SET_SECCOMP) {
        assert(va_arg(args,int)==SECCOMP_MODE_FILTER);
        struct sock_fprog *p=va_arg(args,struct sock_fprog*);
        assert(p->len<=64); saved_count=p->len;memcpy(saved,p->filter,p->len*sizeof saved[0]);
    } else assert(option==PR_SET_NO_NEW_PRIVS);
    va_end(args);return 0;
}
static unsigned evaluate(unsigned arch,unsigned nr,uint64_t fd,uint64_t flags) {
    struct seccomp_data data={.arch=arch,.nr=nr,.args={fd,0,0,0,flags,0}};
    uint32_t accumulator=0;
    for(unsigned pc=0;pc<saved_count;pc++) {
        struct sock_filter op=saved[pc];
        switch(op.code) {
        case BPF_LD|BPF_W|BPF_ABS:
            assert(op.k+4<=sizeof data);memcpy(&accumulator,(char*)&data+op.k,4);break;
        case BPF_JMP|BPF_JEQ|BPF_K:pc+=accumulator==op.k?op.jt:op.jf;break;
        case BPF_RET|BPF_K:return op.k;
        default:assert(0);
        }
    }
    assert(0);return 0;
}
int main(void) {
    assert(!sandbox());
    assert(evaluate(AUDIT_ARCH_AARCH64,64,1,0)==SECCOMP_RET_ALLOW);
    assert(evaluate(AUDIT_ARCH_AARCH64,93,0,0)==SECCOMP_RET_ALLOW);
    assert(evaluate(AUDIT_ARCH_AARCH64,94,0,0)==SECCOMP_RET_ALLOW);
    assert(evaluate(AUDIT_ARCH_AARCH64,281,3,AT_EMPTY_PATH)==SECCOMP_RET_ALLOW);
    assert(evaluate(AUDIT_ARCH_AARCH64,281,4,AT_EMPTY_PATH)==SECCOMP_RET_KILL);
    assert(evaluate(AUDIT_ARCH_AARCH64,281,3,0)==SECCOMP_RET_KILL);
    assert(evaluate(AUDIT_ARCH_AARCH64,64,2,0)==SECCOMP_RET_KILL);
    assert(evaluate(AUDIT_ARCH_X86_64,64,1,0)==SECCOMP_RET_KILL);
    unsigned rejected[]={56,63,220,221,222,117,157,167,279};
    for(unsigned i=0;i<sizeof rejected/sizeof rejected[0];i++)
        assert(evaluate(AUDIT_ARCH_AARCH64,rejected[i],1,0)==SECCOMP_RET_KILL);
    struct rp_frame frame={.magic="A7OVL001",.width=RP_WIDTH,.height=RP_HEIGHT};
    assert(rp_valid(&frame));frame.reserved=1;assert(!rp_valid(&frame));
    frame.reserved=0;frame.mask[0]=1;assert(!rp_valid(&frame));
    char directory[]="/tmp/ram-plugin-input-test-XXXXXX";
    assert(mkdtemp(directory));
    snprintf(fifo_path,sizeof fifo_path,"%s/fifo",directory);
    assert(!mkfifo(fifo_path,0600));
    assert(!setenv("RAM_PLUGIN_CASE","hello",1));
    alarm(2);assert(run()==1);alarm(0);
    assert(input_flags&O_NONBLOCK);
    assert(!syscall(SYS_unlinkat,AT_FDCWD,fifo_path,0));assert(!rmdir(directory));
    puts("HOST_FILTER_AND_FIFO_LOGIC_PASS; guest enforcement still requires real VM testing");
}
