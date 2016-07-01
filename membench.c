#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

static __inline __attribute__((always_inline))
uint64_t
rdtsc()
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return (((uint64_t)hi << 32) | lo);
}

uint64_t cyclesPerSec;

int
init() {
    if (cyclesPerSec != 0)
        return 1;

    // Compute the frequency of the fine-grained CPU timer: to do this,
    // take parallel time readings using both rdtsc and gettimeofday.
    // After 10ms have elapsed, take the ratio between these readings.

    struct timeval startTime, stopTime;
    uint64_t startCycles, stopCycles, micros;
    double oldCycles;

    // There is one tricky aspect, which is that we could get interrupted
    // between calling gettimeofday and reading the cycle counter, in which
    // case we won't have corresponding readings.  To handle this (unlikely)
    // case, compute the overall result repeatedly, and wait until we get
    // two successive calculations that are within 0.1% of each other.
    oldCycles = 0;
    while (1) {
        if (gettimeofday(&startTime, NULL) != 0) {
            fprintf(stderr, "Cycles::init couldn't read clock: %s\n",
                    strerror(errno));
            exit(-1);
        }
        startCycles = rdtsc();
        while (1) {
            if (gettimeofday(&stopTime, NULL) != 0) {
                fprintf(stderr, "Cycles::init couldn't read clock: %s\n",
                        strerror(errno));
                exit(-1);
            }
            stopCycles = rdtsc();
            micros = (stopTime.tv_usec - startTime.tv_usec) +
                    (stopTime.tv_sec - startTime.tv_sec)*1000000;
            if (micros > 10000) {
                cyclesPerSec = (double)(stopCycles - startCycles);
                cyclesPerSec = 1000000.0*cyclesPerSec/
                        (double)(micros);
                break;
            }
        }
        double delta = cyclesPerSec/1000.0;
        if ((oldCycles > (cyclesPerSec - delta)) &&
                (oldCycles < (cyclesPerSec + delta))) {
            return 1;
        }
        oldCycles = cyclesPerSec;
    }
}

int
main()
{
    init();

    const uintptr_t target = (1lu << 30);
    void *base = mmap((void*)target, (1lu << 30),
                      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                      -1, 0);
    if (base != (void*)(target)) {
        fprintf(stderr, "Gru!\n");
        exit(-1);
    }

    void* left = base;
    void* right = (char*)base + (1lu << 29);

    const int iters = 100;
    uint64_t start = rdtsc();
    for (int i = 0; i < iters; ++i) {
        memcpy(left, right, (1lu << 29));
    }
    uint64_t end = rdtsc();

    uint64_t copied = (1lu << 29) * iters;
    double cpuS = (double)(end - start) / cyclesPerSec;
    printf("CPU Secs %f\n", cpuS);
    printf("bw %f GB/cpuS\n", copied / cpuS / (1lu << 30));

    return 0;
}
