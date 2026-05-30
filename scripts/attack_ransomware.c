/*
 * attack_ransomware.c — Anomaly Simulation: Ransomware-Style File I/O
 *
 * Simulates ransomware behaviour: creates many files, writes to them,
 * then renames them with a fake ".enc" extension.
 *
 * Build: gcc -o attack_ransomware attack_ransomware.c
 * Run:   ./attack_ransomware [file_count]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#define DEFAULT_FILES   80
#define MAX_FILES       200
#define PAYLOAD_SIZE    4096
#define ATTACH_WINDOW   30    // seconds to allow observer attach

static char payload[PAYLOAD_SIZE];

int main(int argc, char *argv[]) {
    int n = (argc > 1) ? atoi(argv[1]) : DEFAULT_FILES;
    if (n > MAX_FILES) n = MAX_FILES;

    memset(payload, 0xAB, PAYLOAD_SIZE);

    printf("[RANSOM] Ransomware Simulation (PID %d)\n", getpid());
    printf("[RANSOM] Waiting %d seconds for observer to attach...\n\n", ATTACH_WINDOW);
    sleep(ATTACH_WINDOW);

    printf("[RANSOM] Creating and 'encrypting' %d files in /tmp/\n\n", n);

    char path[128], enc_path[140];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    // PHASE 1: CREATE + WRITE
    printf("[RANSOM] Phase 1: writing files...\n");
    for (int i = 0; i < n; i++) {
        snprintf(path, sizeof(path), "/tmp/sentinel_test_%04d.txt", i);
        int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) { perror("open"); continue; }
        write(fd, payload, PAYLOAD_SIZE);
        close(fd);
        if (i % 10 == 0)
            printf("[RANSOM]   wrote %d/%d files\n", i+1, n);
        usleep(5000);  // 5ms
    }

    // PHASE 2: RENAME (simulate encryption)
    printf("\n[RANSOM] Phase 2: renaming to .enc (encryption simulation)...\n");
    for (int i = 0; i < n; i++) {
        snprintf(path,     sizeof(path),     "/tmp/sentinel_test_%04d.txt", i);
        snprintf(enc_path, sizeof(enc_path), "/tmp/sentinel_test_%04d.txt.enc", i);
        rename(path, enc_path);
        if (i % 10 == 0)
            printf("[RANSOM]   renamed %d/%d\n", i+1, n);
        usleep(3000);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    printf("\n[RANSOM] Attack simulation complete!\n");
    printf("[RANSOM] %d files written+renamed in %.2fs\n", n, elapsed);

    // CLEANUP
    printf("[RANSOM] Cleaning up /tmp/sentinel_test_* files...\n");
    for (int i = 0; i < n; i++) {
        snprintf(enc_path, sizeof(enc_path), "/tmp/sentinel_test_%04d.txt.enc", i);
        unlink(enc_path);
    }
    printf("[RANSOM] Cleanup done.\n");

    return 0;
}
