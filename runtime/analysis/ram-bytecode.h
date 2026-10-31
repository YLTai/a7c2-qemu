#ifndef A7_RAM_BYTECODE_H
#define A7_RAM_BYTECODE_H
#include "ram-plugin.h"
#define BC_MAX 8208u
#define BC_BUDGET 4096u
/* Data only: 16-byte header, then four-byte instructions. No native/JIT calls. */
static int bc_run(const unsigned char *code, size_t size, struct rp_frame *frame) {
    const unsigned char magic[8]={'A','7','B','C','0','0','0','1'};
    if(size<20 || size>BC_MAX || memcmp(code,magic,8))return 41;
    unsigned count=code[8]|((unsigned)code[9]<<8);
    if(!count || count>2048 || size!=16+4*count)return 41;
    for(unsigned i=10;i<16;i++)if(code[i])return 41;
    /* Validate every instruction, including unreachable code, before execution. */
    for(unsigned pc=0;pc<count;pc++) {
        const unsigned char *p=code+16+4*pc;
        switch(p[0]) {
        case 0: case 3: if(p[1]||p[2]||p[3])return 41;break;
        case 1: if(p[1]>=RP_WIDTH||p[2]>=RP_HEIGHT||(p[3]!=0&&p[3]!=255))return 41;break;
        case 2: if((p[1]|((unsigned)p[2]<<8))>=count||p[3])return 41;break;
        default:return 41;
        }
    }
    memset(frame,0,sizeof *frame);memcpy(frame->magic,"A7OVL001",8);
    frame->width=RP_WIDTH;frame->height=RP_HEIGHT;
    unsigned pc=0;
    for(unsigned fuel=0;fuel<BC_BUDGET;fuel++) {
        if(pc>=count)return 41;
        const unsigned char *p=code+16+4*pc++;
        switch(p[0]) {
        case 0:return 0;
        case 1:frame->mask[(unsigned)p[2]*RP_WIDTH+p[1]]=p[3];break;
        case 2:pc=p[1]|((unsigned)p[2]<<8);break;
        case 3:return 42;
        default:return 41;
        }
    }
    return 43;
}
#endif
