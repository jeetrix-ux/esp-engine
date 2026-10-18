/* ESP anti-replay window (RFC 4303 section 3.4.3), using the ring-of-words bitmap
 * from RFC 6479 so advancing the window never shifts the whole bitmap. */
#ifndef REPLAY_H
#define REPLAY_H

#include <stdint.h>

#define REPLAY_MAX_WINDOW 4096
#define REPLAY_WORDS (REPLAY_MAX_WINDOW / 64 + 1)

typedef struct {
    uint64_t last;          /* highest sequence number accepted so far (0 = none) */
    uint32_t window;        /* packets tracked behind `last`; multiple of 64 */
    uint32_t words;         /* window/64 + 1: the spare word is what RFC 6479 adds */
    uint64_t bits[REPLAY_WORDS];
} replay_window;

enum replay_verdict {
    REPLAY_OK = 0,
    REPLAY_DUP = 1,     /* already seen */
    REPLAY_STALE = 2,   /* fell off the left edge of the window */
};

/* window must be a non-zero multiple of 64, at most REPLAY_MAX_WINDOW. */
int replay_init(replay_window *w, uint32_t window);

/* check() is called before the ICV is verified and must not change state;
 * update() is called only after the packet authenticated (RFC 4303 3.4.3),
 * so a forged packet can never move the window. */
enum replay_verdict replay_check(const replay_window *w, uint64_t seq);
void replay_update(replay_window *w, uint64_t seq);

/* RFC 4303 Appendix A2.2: recover the high 32 bits of an extended sequence number
 * from the low 32 bits on the wire and the current window position. */
uint32_t replay_infer_esn_hi(const replay_window *w, uint32_t seq_lo);

#endif
