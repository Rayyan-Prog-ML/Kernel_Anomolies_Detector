#ifndef SENTINEL_H
#define SENTINEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> //fork()
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>//safely cordinate between multiple threads we have use it in ring buffer so the old data donot get overwrite
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>// for using cpu registers
#include <sys/stat.h>
#include <fcntl.h>// defines file access modes
#include <errno.h>// returns -1 and set errno to specific error code
#include <syscall.h>
#include <dirent.h>// for directory reading

// ─────────────────────────────────────────
//  CONFIGURATION
// ─────────────────────────────────────────
#define PIPE_PATH          "/tmp/sentinel_pipe"
#define LOG_PATH           "logs/sentinel.log"
#define BUFFER_SIZE        512
#define RING_BUFFER_SIZE   64
#define MAX_EVENTS         10000

// ─────────────────────────────────────────
//  ALERT THRESHOLDS
// ─────────────────────────────────────────
#define FORK_BOMB_THRESHOLD     20     // forks per second
#define MASS_WRITE_THRESHOLD    50     // writes per second
#define MEM_SPIKE_THRESHOLD     100    // mmap calls per second

// ─────────────────────────────────────────
//  SYSCALL NUMBERS (x86-64 Linux)
// ─────────────────────────────────────────
#define SYS_READ_NR     0//read a file from file descriptor
#define SYS_WRITE_NR    1//write data to a file descriptor from the memory
#define SYS_OPEN_NR     2//open the file
#define SYS_CLOSE_NR    3
#define SYS_FORK_NR     57//duplicates of the process
#define SYS_CLONE_NR    56//craete a new process
#define SYS_MMAP_NR     9//map files in to memory
#define SYS_EXECVE_NR   59//replace current process image with a new program
#define SYS_EXIT_NR     60
#define SYS_OPENAT_NR   257//open file to a directory file descriptor
#define SYS_UNLINK_NR   87//delete a file
#define SYS_RENAME_NR   82//rename a file

// ─────────────────────────────────────────
//  ALERT SEVERITY
// ─────────────────────────────────────────
typedef enum {
    SEV_INFO    = 0,
    SEV_WARNING = 1,
    SEV_DANGER  = 2,
    SEV_CRITICAL= 3
} Severity;

static const char* SEV_LABELS[] = { "INFO", "WARN", "DANGER", "CRITICAL" };
static const char* SEV_COLORS[] = { "\033[36m", "\033[33m", "\033[35m", "\033[31m" };
#define RESET_COLOR "\033[0m"

// ─────────────────────────────────────────
//  EVENT STRUCTURE (shared via named pipe)
// ─────────────────────────────────────────
typedef struct {
    time_t     timestamp;
    pid_t      pid;
    long       syscall_nr;
    Severity   severity;
    char       message[BUFFER_SIZE];
} SentinelEvent;

// ─────────────────────────────────────────
//  RING BUFFER (producer-consumer)
// ─────────────────────────────────────────
typedef struct {
    SentinelEvent  events[RING_BUFFER_SIZE];
    int            head;
    int            tail;
    int            count;
    pthread_mutex_t lock;
    sem_t          items;    // signal: data available
    sem_t          spaces;   // signal: space available
} RingBuffer;

// Inline ring buffer helpers
static inline void rb_init(RingBuffer *rb) {
    rb->head = rb->tail = rb->count = 0;
    pthread_mutex_init(&rb->lock, NULL);
    sem_init(&rb->items,  0, 0);
    sem_init(&rb->spaces, 0, RING_BUFFER_SIZE);
}

static inline void rb_push(RingBuffer *rb, SentinelEvent *ev) {
    sem_wait(&rb->spaces);
    pthread_mutex_lock(&rb->lock);
    rb->events[rb->tail] = *ev;
    rb->tail = (rb->tail + 1) & (RING_BUFFER_SIZE - 1);
    rb->count++;
    pthread_mutex_unlock(&rb->lock);
    sem_post(&rb->items);
}

static inline void rb_pop(RingBuffer *rb, SentinelEvent *ev) {
    sem_wait(&rb->items);
    pthread_mutex_lock(&rb->lock);
    *ev = rb->events[rb->head];
    rb->head = (rb->head + 1) & (RING_BUFFER_SIZE - 1);
    rb->count--;
    pthread_mutex_unlock(&rb->lock);
    sem_post(&rb->spaces);
}

// ─────────────────────────────────────────
//  DEADLOCK AVOIDANCE  (Resource Ordering)
//
//  Sentinel uses 3 internal mutexes:
//    LOCK_LOG  (0) – log file access
//    LOCK_PIPE (1) – named pipe writes
//    LOCK_RB   (2) – ring buffer (already embedded in RingBuffer)
//
//  Rule: always acquire in ascending ID order.
//  dl_lock_ordered() enforces this at runtime and
//  refuses (returns -1) if the caller would violate
//  the order — preventing circular-wait before it starts.
// ─────────────────────────────────────────
#define LOCK_LOG   0   // lowest priority  – grab first
#define LOCK_PIPE  1
#define LOCK_RB    2   // highest priority – grab last
#define NUM_LOCKS  3

typedef struct {
    pthread_mutex_t mutex[NUM_LOCKS];
    int             held[NUM_LOCKS];   // 1 = this thread holds it (TLS would be ideal; simple flag for single-writer design)
} LockManager;

static inline void lm_init(LockManager *lm) {
    for (int i = 0; i < NUM_LOCKS; i++) {
        pthread_mutex_init(&lm->mutex[i], NULL);
        lm->held[i] = 0;
    }
}

/*
 * dl_lock_ordered – acquire lock[id] only if no higher-id lock is already held.
 * Returns  0 on success.
 * Returns -1 and prints a warning if acquiring would violate ordering
 *            (avoidance: request denied before a deadlock can form).
 */
static inline int dl_lock_ordered(LockManager *lm, int id) {
    // Check: caller must not already hold any lock with id > requested id
    for (int i = id + 1; i < NUM_LOCKS; i++) {
        if (lm->held[i]) {
            fprintf(stderr,
                "[SENTINEL-AVOIDANCE] Order violation: tried to acquire lock %d "
                "while holding lock %d — request denied.\n", id, i);
            return -1;  // deny the request; deadlock avoided
        }
    }
    pthread_mutex_lock(&lm->mutex[id]);
    lm->held[id] = 1;
    return 0;
}

static inline void dl_unlock(LockManager *lm, int id) {
    lm->held[id] = 0;
    pthread_mutex_unlock(&lm->mutex[id]);
}

// ─────────────────────────────────────────
//  SYSCALL NAME LOOKUP
// ─────────────────────────────────────────
static inline const char* syscall_name(long nr) {
    switch (nr) {
        case SYS_READ_NR:   return "read";
        case SYS_WRITE_NR:  return "write";
        case SYS_OPEN_NR:   return "open";
        case SYS_CLOSE_NR:  return "close";
        case SYS_FORK_NR:   return "fork";
        case SYS_CLONE_NR:  return "clone";
        case SYS_MMAP_NR:   return "mmap";
        case SYS_EXECVE_NR: return "execve";
        case SYS_EXIT_NR:   return "exit";
        case SYS_OPENAT_NR: return "openat";
        case SYS_UNLINK_NR: return "unlink";
        case SYS_RENAME_NR: return "rename";
        default:            return "syscall";
    }
}

#endif // SENTINEL_H
