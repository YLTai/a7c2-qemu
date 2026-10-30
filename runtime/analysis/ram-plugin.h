#ifndef A7_RAM_PLUGIN_H
#define A7_RAM_PLUGIN_H
#include <stdint.h>
#define RP_WIDTH 160u
#define RP_HEIGHT 24u
#define RP_BYTES (16u + RP_WIDTH * RP_HEIGHT)
#define RP_FRAME "/tmp/ram-plugin.frame"
struct rp_frame { unsigned char magic[8]; uint16_t width, height; uint32_t reserved; unsigned char mask[RP_WIDTH * RP_HEIGHT]; };
_Static_assert(sizeof(struct rp_frame) == RP_BYTES, "wire layout");
static int rp_valid(const struct rp_frame *f) {
    const unsigned char magic[8] = {'A','7','O','V','L','0','0','1'};
    for (unsigned i=0;i<8;i++) if(f->magic[i]!=magic[i]) return 0;
    if(f->width!=RP_WIDTH || f->height!=RP_HEIGHT || f->reserved) return 0;
    for(unsigned i=0;i<RP_WIDTH*RP_HEIGHT;i++) if(f->mask[i]!=0 && f->mask[i]!=255) return 0;
    return 1;
}
#endif
