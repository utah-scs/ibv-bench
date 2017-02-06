#include <cinttypes>
#include <vector>
#include <string>
#include <sstream>

#ifndef COMMON_H
#define COMMON_H

#define LOG(level, fmt, ...)  fprintf(stderr, fmt "\n", ##__VA_ARGS__) 
#define DIE(fmt, ...)  \
    do { \
        fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
        exit(-1); \
    } while (0)

#define ERROR 0
#define WARNING 1

static __inline __attribute__((always_inline))
uint64_t
rdtsc()
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return (((uint64_t)hi << 32) | lo);
}

class PRNG {
 public:
  explicit PRNG(size_t threadId);
  uint32_t generate();
  void dump();

  uint32_t x, y, z, w;
};

std::vector<std::string> split(std::string str, char delimiter);


#endif  // COMMON_H
