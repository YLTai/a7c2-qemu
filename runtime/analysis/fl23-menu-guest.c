/* Trusted, fixed-purpose QEMU startup broker. No plugin addresses or opcodes.
 * The build and launcher verify original appFw SHA and whole data-page section
 * membership. Recheck live file mappings and bytes before touching private RAM.
 * Caller must abort this disposable guest process on any nonzero result.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "fl23-menu-transaction.h"
#ifdef __aarch64__
/* Match original glibc 2.25, not the build sysroot's newer stat/C23 aliases. */
extern int __fxstat(int,int,struct stat *);
#define guest_fstat(fd,st) __fxstat(0,fd,st)
#else
#define guest_fstat(fd,st) fstat(fd,st)
#endif
extern int guest_scan(const char *,const char *,...) __asm__("sscanf");

static const uintptr_t offsets[7] = {0x4b2ed19,0x4b3b544,0x4b3b54c,
    0x4b4a5e4,0x4b4a5ec,0x59992ca,0x5999382};
static const uintptr_t pages[4] = {0x4b2e000,0x4b3b000,0x4b4a000,0x5999000};
static const unsigned ids[2] = {0x02cf1287,0x02cf1289};
typedef int (*backup_read_fn)(unsigned,void *,int);
typedef int (*backup_write_fn)(unsigned,unsigned,const void *);
struct guest_state { uintptr_t base; int prot[4]; };
static unsigned entered;
#ifdef FL23_HOST_TEST
extern int fl23_test_receipt(void);
extern int fl23_test_mapping(struct guest_state *);
extern int fl23_test_mprotect(void *,size_t,int);
#define mprotect fl23_test_mprotect
#endif

static int read_field(void *p, enum fl23_field id, unsigned char out[4]) {
    struct guest_state *s=p;
    if ((unsigned)id>=7) return -1;
    memset(out,0,4);memcpy(out,(void *)(s->base+offsets[id]),fl23_sizes[id]);return 0;
}
static int write_field(void *p, enum fl23_field id, const unsigned char in[4]) {
    struct guest_state *s=p;
    if ((unsigned)id>=7) return -1;
    memcpy((void *)(s->base+offsets[id]),in,fl23_sizes[id]);return 0;
}
static int volatile_receipt(void) {
#ifdef FL23_HOST_TEST
    return fl23_test_receipt();
#else
    char text[3]={0};struct stat st;
    int fd=open("/tmp/fl23-backup-volatile",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return -1;
    int bad=guest_fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid ||
        (st.st_mode&022) || st.st_size!=2 || read(fd,text,3)!=2 || memcmp(text,"0\n",2);
    if(close(fd))bad=1;
    return bad?-1:0;
#endif
}
static int mapping_line(struct guest_state *s,const char *line,unsigned long expected_inode,unsigned seen[4]) {
    char path[512],mode[5];unsigned long start,end,fileoff,inode;unsigned major,minor;
    if(guest_scan(line,"%lx-%lx %4s %lx %x:%x %lu %511s",
                  &start,&end,mode,&fileoff,&major,&minor,&inode,path)!=8)return 0;
    int bad=0;
    for(unsigned i=0;i<4;i++) {
        uintptr_t page=s->base+pages[i];
        if(start>=page+4096 || end<=page)continue;
        uintptr_t disk=pages[i]-(i==3?0x10000:0);
        int expected=i==3?(PROT_READ|PROT_WRITE):(PROT_READ|PROT_EXEC);
        int prot=(mode[0]=='r'?PROT_READ:0)|(mode[1]=='w'?PROT_WRITE:0)|(mode[2]=='x'?PROT_EXEC:0);
        if(start>page || end<page+4096 || strcmp(path,"/usr/lib/appFw.so") ||
           mode[3]!='p' || inode!=expected_inode || prot!=expected ||
           page-start+fileoff!=disk || ++seen[i]!=1)bad=1;
        s->prot[i]=prot;
    }
    return bad;
}
static int mapping_check(struct guest_state *s) {
#ifdef FL23_HOST_TEST
    return fl23_test_mapping(s);
#else
    struct stat st;int fd=open("/usr/lib/appFw.so",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return -1;
    int bad=guest_fstat(fd,&st)||!S_ISREG(st.st_mode);close(fd);if(bad)return -1;
    FILE *f=fopen("/proc/self/maps","r");if(!f)return -1;
    char line[1024];unsigned seen[4]={0};
    while(fgets(line,sizeof line,f)) {
        if(!strchr(line,'\n')){bad=1;break;}
        if(mapping_line(s,line,(unsigned long)st.st_ino,seen))bad=1;
    }
    if(ferror(f))bad=1;
    if(fclose(f))bad=1;
    for(unsigned i=0;i<4;i++)if(seen[i]!=1)bad=1;
    return bad?-1:0;
#endif
}
static int protect(struct guest_state *s,int restore) {
    int failed=0;
    /* Never grant WRITE+EXEC, even transiently. Fixed data pages only. */
    for(unsigned i=0;i<4;i++)
        if(mprotect((void *)(s->base+pages[i]),4096,
                    restore?s->prot[i]:(PROT_READ|PROT_WRITE)))failed=1;
    return failed?-1:0;
}
static int backup_restore(backup_read_fn rd,backup_write_fn wr,const unsigned char old[2]) {
    int bad=0;unsigned char value;
    for(unsigned i=0;i<2;i++) {
        int rc=wr(0x2cf,ids[i],old+i);
        int rr=rd(ids[i],&value,1);
        if(rc<0||rr!=1||value!=old[i])bad=1;
    }
    return bad?-1:0;
}
static int restore_data(struct guest_state *s) {
    unsigned char zero[4]={0},value[4];int bad=0;
    for(unsigned i=0;i<7;i++) {
        write_field(s,(enum fl23_field)i,zero);read_field(s,(enum fl23_field)i,value);
        if(memcmp(value,zero,fl23_sizes[i]))bad=1;
    }
    return bad?-1:0;
}
int fl23_menu_guest_initialize(uintptr_t base,void *handle,
                              void *(*lookup)(void *,const char *),
                              void (*log)(const char *,const char *)) {
    if(!getenv("MENU_FL23_MENU"))return 0;
    if(strcmp(getenv("MENU_FL23_MENU"),"1") ||
       __atomic_exchange_n(&entered,1,__ATOMIC_ACQ_REL))return 1;
    log("FL23_MENU_BEGIN ","scope=private_guest_RAM application_init_started=0");
    if(!base || (base&4095) || base>UINTPTR_MAX-0x599a000 || sysconf(_SC_PAGESIZE)!=4096 ||
       volatile_receipt())return 2;
    struct guest_state s={.base=base};
    if(mapping_check(&s))return 3;
    backup_read_fn rd=(backup_read_fn)lookup(handle,"Backup_nread");
    backup_write_fn wr=(backup_write_fn)lookup(handle,"Backup_write");
    if(!rd||!wr)return 4;
    unsigned char old[2],actual[4],zero[4]={0};
    for(unsigned i=0;i<2;i++)if(rd(ids[i],old+i,1)!=1 || old[i])return 5;
    for(unsigned i=0;i<7;i++) {
        read_field(&s,(enum fl23_field)i,actual);
        if(memcmp(actual,zero,fl23_sizes[i]))return 6;
    }
    if(protect(&s,0)) {
        int failed=protect(&s,1);
        log("FL23_MENU_ROLLBACK ",failed?"permissions_restored=0":"permissions_restored=1");
        return failed?8:7;
    }
    struct fl23_transaction transaction={FL23_PRISTINE};
    const struct fl23_io io={&s,read_field,write_field};
    int rc=fl23_menu_apply(&transaction,&io);
    if(!rc)for(unsigned i=0;i<2;i++) {
        unsigned char next=(unsigned char)(10+i),value=0;
        if(wr(0x2cf,ids[i],&next)<0 || rd(ids[i],&value,1)!=1 || value!=next){rc=9;break;}
    }
    if(!rc && getenv("MENU_FL23_TEST_ROLLBACK"))rc=9;
    if(rc) {
        int bk=backup_restore(rd,wr,old),data=restore_data(&s),permissions=protect(&s,1);
        log("FL23_MENU_ROLLBACK ",bk||data||permissions?"complete=0":"complete=1");
        return bk||data||permissions?10:11;
    }
    if(protect(&s,1)) {
        /* Try to undo the joint transaction. Any failure remains fatal; caller
         * must exit before invoking original Application_System_Init. */
        int writable=protect(&s,0);
        int data=writable?-1:restore_data(&s);
        int bk=backup_restore(rd,wr,old),permissions=protect(&s,1);
        log("FL23_MENU_ROLLBACK ",data||bk||permissions?"complete=0":"complete=1");
        return 12;
    }
    if(mapping_check(&s))return 13;
    /* No claim about menu/model/CP: those need native UI evidence. */
    log("FL23_MENU_READY ","ap_fields=7 backup_bindings=2 permissions_restored=1 color_verified=0");
    return 0;
}
