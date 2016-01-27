#include "Common.h"

static uint32_t x = 0xf1e86518;
static uint32_t y = 0x817271fa;
static uint32_t z = 0xa8268e81;
static uint32_t w = 0xb8627c85;

uint32_t generateRandom() {
    uint32_t t = x ^ (x << 11);
    x = y; y = z; z = w;
    return w = w ^ (w >> 19) ^ t ^ (t >> 8);
}
