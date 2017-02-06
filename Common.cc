#include "Common.h"

#include <stdexcept>

static uint32_t prngInitVals[16][4] = {
  [0] = { 0xf1e86518, 0x817271fa, 0xa8268e81, 0xb8627c85 },
  [1] = { 0x18cf6e57, 0x4fd04cd5, 0xbe04c069, 0x5bdb71b1 },
  [2] = { 0x57288284, 0x96a16cbd, 0x5ad825fd, 0x2ee095dd },
  [3] = { 0x27b8fd73, 0x9c5522b1, 0x7b892f15, 0x3fd62ade },
  [4] = { 0xd6042fb5, 0x770da04b, 0xb365cd89, 0x24b8a28c },
  [5] = { 0xc8510488, 0xfa9cfd21, 0xd877bd7c, 0xc362561a },
  [6] = { 0xa193af76, 0xd3944098, 0xb4f4dfa5, 0xe6f3b8f6 },
  [7] = { 0xc34656a1, 0xdc26ac9f, 0x2f08558, 0x4a4f3218 },
  [8] = { 0x609a995, 0xaa9cf4ea, 0x12c61d6c, 0x27f5032c },
  [9] = { 0x3dcc729e, 0xd403845f, 0xc6df1f97, 0xa08fdd0a },
  [10] = { 0x28c73a0e, 0xc85fae01, 0xd5a5f5f0, 0x948e0fc7 },
  [11] = { 0x4fc67264, 0x4cf87a59, 0xb97a2454, 0x8e7397ea },
  [12] = { 0x7328b70f, 0x2e371db5, 0x91861fc6, 0xc902495f },
  [13] = { 0xac62f645, 0x3cb37ef9, 0x5cc94852, 0xe9c05fef },
  [14] = { 0x8f2dc1f1, 0x2b6293c0, 0x39b5ad03, 0x1f63e7b1 },
  [15] = { 0x9f74d02d, 0xeecc7194, 0xbfecfa26, 0xda4e3a1e },
};

PRNG::PRNG(size_t seed) {
  if (seed > 15)
    throw std::out_of_range{"Bad seed for PRNG"};
  uint32_t* vals = prngInitVals[seed];
  x = vals[0];
  y = vals[1];
  z = vals[2];
  w = vals[3];
}

uint32_t PRNG::generate() {
    uint32_t t = x ^ (x << 11);
    x = y; y = z; z = w;
    return w = w ^ (w >> 19) ^ t ^ (t >> 8);
}

void PRNG::dump() {
  printf("{ 0x%x, 0x%x, 0x%x, 0x%x },\n", x, y, z, w);
}

std::vector<std::string> split(std::string str, char delimiter) {
    std::vector<std::string> internal;
    std::stringstream ss(str); // Turn the string into a stream.
    std::string tok;

    while(getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }

    return internal;
}
