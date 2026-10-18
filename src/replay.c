#include "replay.h"

#include <string.h>

int replay_init(replay_window *w, uint32_t window)
{
    if (window == 0 || window % 64 || window > REPLAY_MAX_WINDOW)
        return -1;
    memset(w, 0, sizeof *w);
    w->window = window;
    w->words = window / 64 + 1;
    return 0;
}

enum replay_verdict replay_check(const replay_window *w, uint64_t seq)
{
    if (seq == 0)
        return REPLAY_STALE; /* sequence numbers start at 1 */
    if (seq > w->last)
        return REPLAY_OK;
    if (w->last - seq >= w->window)
        return REPLAY_STALE;
    uint64_t bit = seq % ((uint64_t)w->words * 64);
    if (w->bits[bit / 64] & (1ull << (bit % 64)))
        return REPLAY_DUP;
    return REPLAY_OK;
}

void replay_update(replay_window *w, uint64_t seq)
{
    if (seq > w->last) {
        /* Clear every word the window slides onto. Those words still hold bits
         * from (words-1)*64 = window sequence numbers ago, which are now outside
         * the window, so wiping them loses nothing. */
        uint64_t cur = w->last / 64, next = seq / 64;
        uint64_t steps = next - cur;
        if (steps > w->words)
            steps = w->words;
        for (uint64_t i = 1; i <= steps; i++)
            w->bits[(cur + i) % w->words] = 0;
        w->last = seq;
    }
    uint64_t bit = seq % ((uint64_t)w->words * 64);
    w->bits[bit / 64] |= 1ull << (bit % 64);
}

uint32_t replay_infer_esn_hi(const replay_window *w, uint32_t seq_lo)
{
    uint32_t tl = (uint32_t)w->last, th = (uint32_t)(w->last >> 32);
    uint32_t bottom = tl - w->window + 1; /* left edge of the window, mod 2^32 */
    if (tl >= w->window - 1) {
        /* Case A: window sits inside one 2^32 subspace */
        return seq_lo >= bottom ? th : th + 1;
    }
    /* Case B: window straddles a subspace boundary. The RFC pseudocode returns
     * Th - 1 here even when Th is 0, which underflows to 0xffffffff on a fresh
     * SA; there is no subspace below 0, so stay in the current one. */
    return (seq_lo >= bottom && th > 0) ? th - 1 : th;
}
