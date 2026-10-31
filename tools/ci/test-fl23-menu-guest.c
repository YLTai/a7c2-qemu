#define FL23_HOST_TEST
#include "../../runtime/analysis/fl23-menu-guest.c"
#include <assert.h>

static int receipt_bad,map_bad,protect_calls,protect_fail,backup_calls,backup_fail,rollback_bad;
static int ready,rollback,backup_reads,relro,originals,live_matches,map_calls,map_changed;
static unsigned char backup[2];
int fl23_test_receipt(void){return receipt_bad;}
int fl23_test_mapping(struct guest_state *s){
    for(unsigned i=0;i<4;i++)s->prot[i]=i==3?PROT_READ|PROT_WRITE:PROT_READ|PROT_EXEC;
    if(relro)s->prot[3]=PROT_READ;
    if(++map_calls>1&&map_changed)s->prot[3]=PROT_READ|PROT_WRITE;
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
    if(!strcmp(name,"FL23_MENU_ORIGINAL "))originals++;
    if(!strcmp(name,"FL23_MENU_LIVE ")&&strstr(text,"ap_fields_match=1"))live_matches++;
}
static uintptr_t base;
static void reset(void){
    entered=0;receipt_bad=map_bad=protect_calls=protect_fail=backup_calls=backup_fail=rollback_bad=0;
    ready=rollback=backup_reads=relro=0;backup[0]=backup[1]=0;
    originals=live_matches=map_calls=map_changed=0;live_base=0;live_log=NULL;live_sampled=live_ready=0;
    for(unsigned i=0;i<7;i++)memset((void *)(base+offsets[i]),0,4);
    unsetenv("MENU_FL23_TEST_ROLLBACK");
}
static int run(void){return fl23_menu_guest_initialize(base,NULL,lookup,logger);}
static void original(void){
    for(unsigned i=0;i<7;i++)assert(!memcmp((void *)(base+offsets[i]),(char[4]){0},fl23_sizes[i]));
    assert(!backup[0]&&!backup[1]&&!ready);
}
static void mapping_tests(void){
    struct guest_state s={.base=0x100000000UL};unsigned seen[4]={0};char line[256];
    for(unsigned i=0;i<4;i++){
        snprintf(line,sizeof line,"%lx-%lx %s %lx 00:01 17 /usr/lib/appFw.so\n",
                 (unsigned long)(s.base+pages[i]),(unsigned long)(s.base+pages[i]+4096),
                 i==3?"rw-p":"r-xp",(unsigned long)(pages[i]-(i==3?0x10000:0)));
        assert(!mapping_line(&s,line,17,1,seen));assert(seen[i]==1);
        assert(mapping_line(&s,line,17,1,seen)); /* duplicate mappings */
        seen[i]=1;
    }
    const char *bad_modes[]={"rwxp","rw-s","rw-p","---p"};
    for(unsigned i=0;i<4;i++){
        memset(seen,0,sizeof seen);
        snprintf(line,sizeof line,"%lx-%lx %s %lx 00:01 17 /usr/lib/appFw.so\n",
                 (unsigned long)(s.base+pages[0]),(unsigned long)(s.base+pages[0]+4096),
                 bad_modes[i],(unsigned long)pages[0]);
        assert(mapping_line(&s,line,17,1,seen));
    }
    for(unsigned i=0;i<4;i++){
        memset(seen,0,sizeof seen);
        snprintf(line,sizeof line,"%lx-%lx r--p %lx 00:01 17 /usr/lib/appFw.so\n",
                 (unsigned long)(s.base+pages[i]),(unsigned long)(s.base+pages[i]+4096),
                 (unsigned long)(pages[i]-(i==3?0x10000:0)));
        assert(!mapping_line(&s,line,17,1,seen));assert(s.prot[i]==PROT_READ);
        memset(seen,0,sizeof seen);
        assert(mapping_line(&s,line,17,2,seen)&8192);
    }
    for(unsigned i=0;i<4;i++){
        memset(seen,0,sizeof seen);
        snprintf(line,sizeof line,"%lx-%lx r-xp %lx 00:01 %u %s\n",
                 (unsigned long)(s.base+pages[0]+(i==0)),
                 (unsigned long)(s.base+pages[0]+4096),
                 (unsigned long)(pages[0]+(i==1?4096:0)),i==2?18:17,
                 i==3?"/usr/lib/other.so":"/usr/lib/appFw.so");
        assert(mapping_line(&s,line,17,1,seen));
    }
}
int main(void){
    mapping_tests();
    void *memory=mmap(NULL,0x599a000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED);base=(uintptr_t)memory;
    assert(!setenv("MENU_FL23_MENU","1",1));
    reset();assert(!run());assert(ready==1&&protect_calls==8&&backup[0]==10&&backup[1]==11);
    fl23_menu_guest_observe();fl23_menu_guest_observe();assert(live_matches==1);
    assert(run()==1&&ready==1);
    reset();relro=1;assert(!run()&&ready==1&&protect_calls==8);
    reset();relro=1;map_changed=1;assert(run()==13&&!ready);
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
    reset();unsetenv("MENU_FL23_MENU");setenv("MENU_FL23_AUDIT","1",1);
    assert(!run()&&originals==1&&!protect_calls&&!backup_calls);original();
    fl23_menu_guest_observe();assert(live_matches==1);
    assert(!munmap(memory,0x599a000));
    puts("FL23 guest broker host fault-injection passed; no W+X request");
    return 0;
}
