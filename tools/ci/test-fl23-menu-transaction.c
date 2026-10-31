#include <assert.h>
#include <stdio.h>
#include "../../runtime/analysis/fl23-menu-transaction.h"

struct fixture {
    unsigned char memory[FL23_FIELD_COUNT][4];
    int writes, reads, fail_write, fail_read, corrupt_write, rollback_fail;
};
static int read_field(void *p, enum fl23_field id, unsigned char out[4]) {
    struct fixture *f = p;
    assert(id < FL23_FIELD_COUNT);
    if (++f->reads == f->fail_read) return -1;
    memcpy(out, f->memory[id], 4);
    return 0;
}
static int write_field(void *p, enum fl23_field id, const unsigned char in[4]) {
    struct fixture *f = p;
    assert(id < FL23_FIELD_COUNT);
    ++f->writes;
    if (f->rollback_fail && f->writes == f->fail_write + 1) return -1;
    /* Failed writes may mutate some bytes before returning failure. */
    if (f->writes == f->fail_write) {
        f->memory[id][0] = in[0];
        return -1;
    }
    memcpy(f->memory[id], in, fl23_sizes[id]);
    if (f->writes == f->corrupt_write) f->memory[id][0] ^= 0x40;
    return 0;
}
static void pristine(const struct fixture *f) {
    for (unsigned i = 0; i < FL23_FIELD_COUNT; i++)
        for (unsigned j = 0; j < 4; j++) assert(!f->memory[i][j]);
}
static enum fl23_result apply(struct fixture *f, struct fl23_transaction *t) {
    const struct fl23_io io = {f, read_field, write_field};
    return fl23_menu_apply(t, &io);
}
int main(void) {
    struct fixture f = {0};
    struct fl23_transaction t = {FL23_PRISTINE};
    assert(apply(&f, &t) == FL23_OK && t.state == FL23_APPLIED);
    assert(f.writes == 7);
    assert(f.memory[0][0] == 1 && f.memory[0][1] == 1);
    assert(f.memory[3][0] == 10 && f.memory[4][0] == 11);
    assert(apply(&f, &t) == FL23_OK && f.writes == 7);
    f.memory[6][0] = 3; /* A repeated request detects external changes. */
    assert(apply(&f, &t) == FL23_ORIGINAL_MISMATCH && f.writes == 7);
    for (int i = 1; i <= FL23_FIELD_COUNT; i++) {
        f = (struct fixture){.fail_read = i};
        t.state = FL23_PRISTINE;
        assert(apply(&f, &t) == FL23_READ_FAILED && !f.writes);
        pristine(&f);
        f = (struct fixture){0}; f.memory[i-1][0] = 9;
        assert(apply(&f, &t) == FL23_ORIGINAL_MISMATCH && !f.writes);
        f = (struct fixture){.fail_write = i};
        assert(apply(&f, &t) == FL23_WRITE_ROLLED_BACK);
        assert(t.state == FL23_PRISTINE); pristine(&f);
        f = (struct fixture){.corrupt_write = i};
        assert(apply(&f, &t) == FL23_WRITE_ROLLED_BACK); pristine(&f);
        f = (struct fixture){.fail_read = FL23_FIELD_COUNT + i};
        assert(apply(&f, &t) == FL23_WRITE_ROLLED_BACK); pristine(&f);
        f = (struct fixture){.fail_write = i, .rollback_fail = 1};
        assert(apply(&f, &t) == FL23_ROLLBACK_FAILED);
        assert(t.state == FL23_POISONED);
        int writes = f.writes;
        assert(apply(&f, &t) == FL23_BAD_STATE && f.writes == writes);
        /* Earlier records still get restored after one rollback failure. */
        for (int j = 0; j < i-1; j++) assert(!memcmp(f.memory[j], (char[4]){0}, 4));
    }
    assert(fl23_menu_apply(NULL, NULL) == FL23_BAD_STATE);
    puts("FL23 transaction host tests passed; guest behavior unverified");
    return 0;
}
