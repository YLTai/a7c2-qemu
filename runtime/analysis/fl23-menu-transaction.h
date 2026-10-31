/* Trusted internal transaction core, not a plugin address or byte-write API.
 * A future guest adapter must resolve all seven semantic IDs from a verified
 * original ELF and live mappings, and hold exclusive startup ownership through
 * apply/rollback. Callbacks are trusted code, never plugin-supplied pointers.
 * No live-model undo is promised: after initialization, disable via fresh VM.
 */
#ifndef A7_FL23_MENU_TRANSACTION_H
#define A7_FL23_MENU_TRANSACTION_H
#include <string.h>

enum fl23_field { FL23_SELECTION, FL23_FL2_FADE, FL23_FL3_FADE,
    FL23_FL2_BINDING, FL23_FL3_BINDING, FL23_FL2_VISIBLE, FL23_FL3_VISIBLE,
    FL23_FIELD_COUNT };
enum fl23_result { FL23_OK, FL23_BAD_STATE, FL23_READ_FAILED,
    FL23_ORIGINAL_MISMATCH, FL23_WRITE_ROLLED_BACK, FL23_ROLLBACK_FAILED };
enum fl23_state { FL23_PRISTINE, FL23_APPLIED, FL23_POISONED };
struct fl23_io {
    void *context;
    /* Read/write exactly the fixed size for id; no caller-controlled length. */
    int (*read)(void *, enum fl23_field, unsigned char [4]);
    int (*write)(void *, enum fl23_field, const unsigned char [4]);
};
struct fl23_transaction { enum fl23_state state; };
static const unsigned char fl23_sizes[FL23_FIELD_COUNT] = {2,4,4,4,4,2,2};
static const unsigned char fl23_values[FL23_FIELD_COUNT][4] = {
    {1,1,0,0}, {1,0,0,0}, {1,0,0,0}, {10,0,0,0}, {11,0,0,0},
    {1,0,0,0}, {1,0,0,0}
};

static enum fl23_result fl23_menu_apply(struct fl23_transaction *t,
                                       const struct fl23_io *io) {
    const unsigned char original[4] = {0};
    unsigned char actual[4];
    if (!t || !io || !io->read || !io->write ||
        (t->state != FL23_PRISTINE && t->state != FL23_APPLIED))
        return FL23_BAD_STATE;
    for (unsigned i = 0; i < FL23_FIELD_COUNT; i++) {
        if (io->read(io->context, (enum fl23_field)i, actual))
            return FL23_READ_FAILED;
        const unsigned char *expected = t->state == FL23_APPLIED ? fl23_values[i] : original;
        if (memcmp(actual, expected, fl23_sizes[i]))
            return FL23_ORIGINAL_MISMATCH;
    }
    if (t->state == FL23_APPLIED) return FL23_OK;
    for (unsigned i = 0; i < FL23_FIELD_COUNT; i++) {
        if (io->write(io->context, (enum fl23_field)i, fl23_values[i]) ||
            io->read(io->context, (enum fl23_field)i, actual) ||
            memcmp(actual, fl23_values[i], fl23_sizes[i])) {
            /* Include the failed write: an adapter may have partially written.
             * Continue restoring other fields even after one rollback failure. */
            int failed = 0;
            for (int j = (int)i; j >= 0; j--) {
                int rc = io->write(io->context, (enum fl23_field)j, original);
                int read_rc = io->read(io->context, (enum fl23_field)j, actual);
                if (rc || read_rc || memcmp(actual, original, fl23_sizes[j])) failed = 1;
            }
            t->state = failed ? FL23_POISONED : FL23_PRISTINE;
            return failed ? FL23_ROLLBACK_FAILED : FL23_WRITE_ROLLED_BACK;
        }
    }
    t->state = FL23_APPLIED;
    return FL23_OK;
}
#endif
