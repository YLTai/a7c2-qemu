#define FL23_HOST_TEST
#include "../../runtime/analysis/fl23-menu-guest.c"
#include <assert.h>

static int receipt_bad,map_bad,protect_calls,protect_fail,backup_calls,backup_fail,rollback_bad;
static int ready,rollback,backup_reads;
static unsigned char backup[2];
int fl23_test_receipt(void){return receipt_bad;}
int fl23_test_mapping(struct guest_state *s){
    for(unsigned i=0;i<4;i++)s->prot[i]=i==3?PROT_READ|PROT_WRITE:PROT_READ|PROT_EXEC;
    return map_bad;
}
int fl23_test_mprotect(void *address,size_t size,int prot){
    (void)address;assert(size==4096);assert((prot&(PROT_WRITE|PROT_EXEC))!=(PROT_WRITE|PROT_EXEC));
    return ++protect_calls==protect_fail?-1:0;
}
static int rd(unsigned id,void *out,int count){
    assert(count==1);assert(id==ids[0]||id==ids[1]);backup_reads++;
    *(unsigned char *)out=backup[id==ids[1]];return 1;
}
static int wr(unsigned bank,unsigned id,const void *in){
    assert(bank==0x2cf);assert(id==ids[0]||id==ids[1]);backup_calls++;
    if(rollback_bad && !*(const unsigned char *)in)return -1;
    backup[id==ids[1]]=*(const unsigned char *)in;
    return backup_calls==backup_fail?-1:0; /* Partial mutation before failure. */
}
static void *lookup(void *handle,const char *name){
    (void)handle;
    if(!strcmp(name,"Backup_nread"))return rd;
    if(!strcmp(name,"Backup_write"))return wr;
    assert(0);return NULL;
}
static void logger(const char *name,const char *text){
    (void)text;
    if(!strcmp(name,"FL23_MENU_READY "))ready++;
    if(!strcmp(name,"FL23_MENU_ROLLBACK "))rollback++;
}
static uintptr_t base;
static void reset(void){
    entered=0;receipt_bad=map_bad=protect_calls=protect_fail=backup_calls=backup_fail=rollback_bad=0;
    ready=rollback=backup_reads=0;backup[0]=backup[1]=0;
    for(unsigned i=0;i<7;i++)memset((void *)(base+offsets[i]),0,4);
    unsetenv("MENU_FL23_TEST_ROLLBACK");
}
static int run(void){return fl23_menu_guest_initialize(base,NULL,lookup,logger);}
static void original(void){
    for(unsigned i=0;i<7;i++)assert(!memcmp((void *)(base+offsets[i]),(char[4]){0},fl23_sizes[i]));
    assert(!backup[0]&&!backup[1]&&!ready);
}
int main(void){
    void *memory=mmap(NULL,0x599a000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED);base=(uintptr_t)memory;
    assert(!setenv("MENU_FL23_MENU","1",1));
    reset();assert(!run());assert(ready==1&&protect_calls==8&&backup[0]==10&&backup[1]==11);
    assert(run()==1&&ready==1);
    reset();receipt_bad=1;assert(run()==2&&!backup_calls&&!protect_calls);original();
    reset();map_bad=1;assert(run()==3&&!backup_calls&&!protect_calls);original();
    reset();backup[1]=1;assert(run()==5&&!backup_calls&&!protect_calls);
    reset();*(unsigned char *)(base+offsets[6])=1;assert(run()==6&&!backup_calls&&!protect_calls);
    for(int i=1;i<=4;i++){
        reset();protect_fail=i;assert(run()==7&&rollback==1);original();
    }
    for(int i=5;i<=8;i++){
        reset();protect_fail=i;assert(run()==12&&rollback==1);original();
    }
    for(int i=1;i<=2;i++){
        reset();backup_fail=i;assert(run()==11&&rollback==1);original();
    }
    reset();setenv("MENU_FL23_TEST_ROLLBACK","1",1);
    assert(run()==11&&rollback==1);original();
    reset();backup_fail=2;rollback_bad=1;assert(run()==10&&!ready&&rollback==1);
    assert(!munmap(memory,0x599a000));
    puts("FL23 guest broker host fault-injection passed; no W+X request");
    return 0;
}
