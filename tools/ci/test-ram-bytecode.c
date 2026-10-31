/* Host parser/fuel/FIFO tests; actual guest execution is checked separately. */
#define open captured_open
#define unlink captured_unlink
#define _start boot_entry
#include "../../runtime/analysis/ram-plugin-boot.c"
#undef open
#undef unlink
#undef _start
#include <assert.h>
static char fifo_path[256];
static int input_flags;
int captured_open(const char *path,int flags,...) {
    assert(!strcmp(path,"/simulation/ram-plugin-hello"));input_flags=flags;
    return (int)syscall(SYS_openat,AT_FDCWD,fifo_path,flags,0);
}
int captured_unlink(const char *path){assert(!strcmp(path,RP_FRAME));return 0;}
int main(int argc,char **argv) {
    assert(argc==2);
    const char *names[]={"hello","malformed","crash","timeout","forbidden","invalid_elf"};
    int expected[]={0,41,42,43,41,41};
    unsigned char code[BC_MAX+1],original[BC_MAX];struct rp_frame frame;
    for(unsigned i=0;i<6;i++) {
        char path[512];snprintf(path,sizeof path,"%s/ram-plugin-%s",argv[1],names[i]);
        FILE *f=fopen(path,"rb");assert(f);size_t size=fread(code,1,sizeof code,f);assert(!ferror(f));fclose(f);
        memset(&frame,0x55,sizeof frame);
        assert(bc_run(code,size,&frame)==expected[i]);
        if(expected[i]==41)for(unsigned p=0;p<sizeof frame;p++)assert(((unsigned char*)&frame)[p]==0x55);
        if(i)continue;
        assert(rp_valid(&frame));unsigned lit=0;
        for(unsigned p=0;p<sizeof frame.mask;p++)lit+=frame.mask[p]==255;
        assert(lit>400&&lit<1000);memcpy(original,code,size);
        for(size_t n=0;n<size;n++)assert(bc_run(code,n,&frame)==41);
        for(size_t n=0;n<size;n++) {
            memcpy(code,original,size);code[n]^=255;
            int result=bc_run(code,size,&frame);assert(result==0||result==41||result==42||result==43);
            if(!result)assert(rp_valid(&frame));
        }
    }
    unsigned char badjump[20]={'A','7','B','C','0','0','0','1',1,0,0,0,0,0,0,0,2,1,0,0};
    assert(bc_run(badjump,sizeof badjump,&frame)==41);
    memset(code,0,sizeof code);assert(bc_run(code,sizeof code,&frame)==41);
    char directory[]="/tmp/ram-plugin-input-test-XXXXXX";assert(mkdtemp(directory));
    snprintf(fifo_path,sizeof fifo_path,"%s/fifo",directory);assert(!mkfifo(fifo_path,0600));
    assert(!setenv("RAM_PLUGIN_CASE","hello",1));alarm(2);assert(run()==1);alarm(0);
    assert(input_flags&O_NONBLOCK);assert(!syscall(SYS_unlinkat,AT_FDCWD,fifo_path,0));
    assert(!symlink("nonexistent-target",fifo_path));assert(run()==1);
    assert(input_flags&O_NOFOLLOW);assert(!syscall(SYS_unlinkat,AT_FDCWD,fifo_path,0));assert(!rmdir(directory));
    puts("HOST_BYTECODE_TEST_PASS: fixtures, truncation, mutations, bounds, fuel, FIFO; not guest proof");
}
