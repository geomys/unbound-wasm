// Replaces util/random.c: all randomness comes from the host's entropy
// import, so the guest carries no seed state worth compromising. The state
// object survives only because the ub_randstate API requires one.

#include "config.h"
#include "abi/unbound_wasm_abi.h"
#include "util/random.h"
#include <stdint.h>
#include <stdlib.h>

struct ub_randstate {
    unsigned char unused;
};

struct ub_randstate *ub_initstate(struct ub_randstate *from) {
    (void)from;
    return calloc(1, sizeof(struct ub_randstate));
}

long int ub_random(struct ub_randstate *state) {
    (void)state;
    uint32_t value;
    uw_entropy(&value, sizeof(value));
    return (long int)(value & 0x7fffffffU);
}

// ub_random_max returns a uniform value in [0, upper) by rejection
// sampling, like the arc4random_uniform-based upstream.
long int ub_random_max(struct ub_randstate *state, long int upper) {
    if (upper <= 1)
        return 0;
    uint32_t bound = (uint32_t)upper;
    uint32_t limit = 0x80000000U - (0x80000000U % bound);
    uint32_t value;
    do {
        value = (uint32_t)ub_random(state);
    } while (value >= limit);
    return (long int)(value % bound);
}

void ub_randfree(struct ub_randstate *state) { free(state); }
