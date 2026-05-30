/*
 * attack_memspike.c — Anomaly Simulation: Memory Spike / Resource Exhaustion
 *
 * Rapidly calls mmap() and munmap() to trigger memory anomaly alerts.
 *
 * Build: gcc -o attack_memspike attack_memspike.c
 * Run:   ./attack_memspike [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>

#define DEFAULT_ITERS   200
#define MAP_SIZE        (4096 * 16)   // 64 KB per allocation
#define ATTACH_WINDOW   30            // seconds to allow observer attach

int main(int argc, char *argv[]) {
    int iters = (argc > 1) ? atoi(argv[1]) : DEFAULT_ITERS;

    printf("[MEMSPIKE] Memory Spike Simulation (PID %d)\n", getpid());
    printf("[MEMSPIKE] Waiting %d seconds for observer to attach...\n\n", ATTACH_WINDOW);
    sleep(ATTACH_WINDOW);

    printf("[MEMSPIKE] Starting %d mmap/munmap cycles...\n\n", iters);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < iters; i++) {
        void *ptr = mmap(NULL, MAP_SIZE,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
        if (ptr == MAP_FAILED) { perror("mmap"); continue; }

        // Touch pages to cause actual page faults
        memset(ptr, i & 0xFF, MAP_SIZE);

        munmap(ptr, MAP_SIZE);

        if (i % 50 == 0)
            printf("[MEMSPIKE]  cycle %d/%d\n", i+1, iters);

        usleep(2000);  // 2ms
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("\n[MEMSPIKE] Done: %d cycles in %.2fs (%.0f/sec)\n",
           iters, elapsed, iters / elapsed);

    return 0;
}
