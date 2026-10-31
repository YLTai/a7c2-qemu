/* Fixed, read-only native Backup binding query; no address or key arguments. */
#include <stdio.h>
#include "fl23-sha256.h"
static int file_digest(const char *path) {
    FILE *f=fopen(path,"rb");if(!f)return -1;
    struct fl23_sha256 state;fl23_sha_init(&state);
    unsigned char buffer[16384],digest[32];size_t n;int bad=0;
    while((n=fread(buffer,1,sizeof buffer,f))) {
        if(state.bytes+n>128U*1024U*1024U){bad=1;break;}
        fl23_sha_update(&state,buffer,n);
    }
    if(ferror(f))bad=1;
    if(fclose(f))bad=1;
    if(bad)return -1;
    fl23_sha_final(&state,digest);
    for(unsigned i=0;i<32;i++)printf("%02x",digest[i]);
    printf("  %s\n",path);return 0;
}
extern int Backup_nread(unsigned,void *,int);
extern int __libc_start_main(int (*)(int,char **),int,char **,void (*)(void),void (*)(void),void (*)(void),void *);
__asm__(".global _start\n.type _start, %function\n_start:\nmov x0, sp\nbl entry\nbrk #0\n");
static int run(int argc,char **argv) {
    (void)argv;if(argc!=1)return 2;
    unsigned char a=0,b=0;
    if(Backup_nread(0x02cf1287,&a,1)!=1 || Backup_nread(0x02cf1289,&b,1)!=1)return 3;
    if((a!=0&&a!=10)||(b!=0&&b!=11))return 4;
    printf("FL23_BINDINGS fl2=%u fl3=%u selection_verified=0 color_verified=0\n",a,b);
    if(file_digest("/usr/lib/appFw.so") || file_digest("/setting/Backup.bin"))return 5;
    return 0;
}
__attribute__((noreturn)) void entry(unsigned long *stack) {
    __libc_start_main(run,(int)stack[0],(char **)(stack+1),0,0,0,stack);
    __builtin_trap();
}
