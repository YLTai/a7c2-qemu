/* Independent static AArch64 plugin. Only bounded output and exit are needed. */
#include "ram-plugin.h"
#ifndef RP_CASE
#define RP_CASE 0
#endif
#if defined(__aarch64__)
static long call(long n,long a,long b,long c) {
    register long x8 __asm__("x8")=n, x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2) : "memory");
    return x0;
}
#else
#error "This plugin must be built for AArch64"
#endif
static struct rp_frame frame = {.magic="A7OVL001",.width=RP_WIDTH,.height=RP_HEIGHT};
void _start(void) {
    /* H E L O W R D and space; 5x7 bitmaps, rendered at 2x in private RAM. */
    static const unsigned char glyphs[][7]={{17,17,17,31,17,17,17},{31,16,16,30,16,16,31},
      {16,16,16,16,16,16,31},{14,17,17,17,17,17,14},{17,17,17,21,21,21,10},
      {30,17,17,30,20,18,17},{30,17,17,17,17,17,30},{0,0,0,0,0,0,0}};
    static const unsigned char text[]={0,1,2,2,3,7,4,3,5,2,6};
    if(RP_CASE==2) __builtin_trap();
    if(RP_CASE==3) for(;;) __asm__ volatile("" ::: "memory");
    if(RP_CASE==4) call(56,-100,(long)"/dev/mem",0); /* must be killed by seccomp */
    for(unsigned k=0;k<11;k++) for(unsigned y=0;y<7;y++) for(unsigned x=0;x<5;x++)
      if(glyphs[text[k]][y] & (16u>>x)) for(unsigned dy=0;dy<2;dy++) for(unsigned dx=0;dx<2;dx++)
        frame.mask[(4+y*2+dy)*RP_WIDTH+8+k*12+x*2+dx]=255;
    if(RP_CASE==1) frame.reserved=1;
    long result=call(64,1,(long)&frame,sizeof frame);
    call(93,result==(long)sizeof frame?0:1,0,0);
    for(;;) {}
}
