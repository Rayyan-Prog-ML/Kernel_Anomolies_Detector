/*
 * observer.c — Kernel Sentinel: System Call Hooking Engine
 *
 * Attaches to a target PID via ptrace, intercepts every syscall,
 * classifies severity, and writes SentinelEvent structs to a named pipe.
 *
 * Usage:  ./observer <target_pid>
 *         ./observer --watch-new        (forks a dummy and watches it)
 */

#include "../include/sentinel.h"

// ─────────────────────────────────────────
//  RATE TRACKERS  (per-second counters)
// ─────────────────────────────────────────
typedef struct {
    long   fork_count;
    long   write_count;
    long   mmap_count;
    long   open_count;
    time_t window_start;
} RateTracker;

static RateTracker rates = {0, 0, 0, 0, 0};
static int         pipe_fd  = -1;
static FILE       *log_file = NULL;
static volatile int running = 1;

// ─────────────────────────────────────────
//  SIGNAL HANDLER
// ─────────────────────────────────────────
// press ctrl +c to stop
static void on_sigint(int sig) { (void)sig; running = 0; }

// ─────────────────────────────────────────
//  SEND EVENT to dashboard via named pipe
// ─────────────────────────────────────────
static void send_event(SentinelEvent *ev) {
    // Write to named pipe (non-blocking best-effort)
    if (pipe_fd != -1)
        write(pipe_fd, ev, sizeof(SentinelEvent));

    // Always write to log file
    if (log_file) {
        char ts[32];
        struct tm *t = localtime(&ev->timestamp);
        strftime(ts, sizeof(ts), "%H:%M:%S", t);
        fprintf(log_file, "[%s] PID=%-6d SYSCALL=%-10s SEV=%-8s %s\n",
                ts, ev->pid, syscall_name(ev->syscall_nr),
                SEV_LABELS[ev->severity], ev->message);
        fflush(log_file);
    }
}

// ─────────────────────────────────────────
//  RATE WINDOW RESET (every second)
// ─────────────────────────────────────────
static void rate_window_tick(pid_t pid) {
    time_t now = time(NULL);
    if (now == rates.window_start) return; //only evaluate when second changes

    // Evaluate last window
    SentinelEvent ev;
    ev.pid = pid;
    ev.timestamp = now;

    if (rates.fork_count >= FORK_BOMB_THRESHOLD) {
        ev.syscall_nr = SYS_FORK_NR;
        ev.severity   = SEV_CRITICAL;
        snprintf(ev.message, BUFFER_SIZE,
                 "FORK BOMB DETECTED — %ld forks in last second!", rates.fork_count);
        send_event(&ev);
    }
    if (rates.write_count >= MASS_WRITE_THRESHOLD) {
        ev.syscall_nr = SYS_WRITE_NR;
        ev.severity   = SEV_DANGER;
        snprintf(ev.message, BUFFER_SIZE,
                 "MASS WRITE ATTACK — %ld writes/sec (ransomware pattern?)", rates.write_count);
        send_event(&ev);
    }
    if (rates.mmap_count >= MEM_SPIKE_THRESHOLD) {
        ev.syscall_nr = SYS_MMAP_NR;
        ev.severity   = SEV_WARNING;
        snprintf(ev.message, BUFFER_SIZE,
                 "MEMORY SPIKE — %ld mmap calls/sec", rates.mmap_count);
        send_event(&ev);
    }

    // Reset window
    rates.fork_count = rates.write_count = rates.mmap_count = rates.open_count = 0;
    rates.window_start = now;
}

// ─────────────────────────────────────────
//  CLASSIFY & EMIT a single syscall event
// ─────────────────────────────────────────
static void classify_syscall(pid_t pid, long syscall_nr,
                              struct user_regs_struct *regs) {
    SentinelEvent ev = {0};
    ev.timestamp  = time(NULL);
    ev.pid        = pid;
    ev.syscall_nr = syscall_nr;
    ev.severity   = SEV_INFO;

    switch (syscall_nr) {
        case SYS_FORK_NR:
        case SYS_CLONE_NR:
            rates.fork_count++;
            ev.severity = (rates.fork_count > 5) ? SEV_WARNING : SEV_INFO;
            snprintf(ev.message, BUFFER_SIZE,
                     "Process spawned new child (total forks this window: %ld)",
                     rates.fork_count);
            break;

        case SYS_OPEN_NR:
        case SYS_OPENAT_NR:
            rates.open_count++;
            ev.severity = (rates.open_count > 30) ? SEV_DANGER : SEV_INFO;
            snprintf(ev.message, BUFFER_SIZE,
                     "File opened (fd count this window: %ld)", rates.open_count);
            break;

        case SYS_WRITE_NR:
            rates.write_count++;
            ev.severity = (rates.write_count > 30) ? SEV_WARNING : SEV_INFO;
            snprintf(ev.message, BUFFER_SIZE,
                     "Write syscall (writes this window: %ld)", rates.write_count);
            break;

        case SYS_MMAP_NR:
            rates.mmap_count++;
            ev.severity = (rates.mmap_count > 50) ? SEV_WARNING : SEV_INFO;
            snprintf(ev.message, BUFFER_SIZE,
                     "Memory mapping requested (mmaps this window: %ld)", rates.mmap_count);
            break;

        case SYS_EXECVE_NR:
            ev.severity = SEV_WARNING;
            snprintf(ev.message, BUFFER_SIZE, "execve() called — new program loaded");
            break;

        case SYS_UNLINK_NR:
            ev.severity = SEV_DANGER;
            snprintf(ev.message, BUFFER_SIZE, "File deletion detected (unlink)");
            break;

        case SYS_RENAME_NR:
            ev.severity = SEV_WARNING;
            snprintf(ev.message, BUFFER_SIZE, "File renamed/moved (possible encryption)");
            break;

        case SYS_EXIT_NR:
            ev.severity = SEV_INFO;
            snprintf(ev.message, BUFFER_SIZE, "Process exit");
            break;

        default:
            return; // Skip noisy, uninteresting syscalls
    }

    send_event(&ev);
}

// ─────────────────────────────────────────
//  MAIN TRACE LOOP
// ─────────────────────────────────────────
static void trace_pid(pid_t target_pid) {
    int   status;
    int   in_syscall = 0;
    struct user_regs_struct regs;

    printf("[OBSERVER] Attaching to PID %d ...\n", target_pid);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("[OBSERVER] ptrace ATTACH failed");
        exit(1);
    }

    waitpid(target_pid, &status, 0);// wait until process stops
    ptrace(PTRACE_SETOPTIONS, target_pid, 0,//set tracing options
           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
           PTRACE_O_TRACECLONE   | PTRACE_O_TRACEEXEC);

    printf("[OBSERVER] Attached. Streaming syscall events to dashboard...\n\n");

    while (running) {
        ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);

        pid_t waited = waitpid(-1, &status, 0); //Wait for event
        if (waited < 0) break;

        if (WIFEXITED(status) && waited == target_pid) {
            printf("[OBSERVER] Target process exited.\n");
            break;
        }

        if (!WIFSTOPPED(status)) continue;
        if (!(WSTOPSIG(status) & 0x80)) continue; // not a syscall stop

        ptrace(PTRACE_GETREGS, waited, NULL, &regs);//get registers important one is  reg.ogix_raax for syscall number

        if (!in_syscall) {
            // Syscall ENTRY
            classify_syscall(waited, regs.orig_rax, &regs);
            rate_window_tick(waited);
        }
        in_syscall = !in_syscall;//toggle state
    }

    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);//release controlofprocess
    printf("[OBSERVER] Detached from PID %d.\n", target_pid);
}


//  ENTRY POINT
// ─────────────────────────────────────────
int main(int argc, char *argv[]) {
    signal(SIGINT, on_sigint);

    // Create log dir
    mkdir("logs", 0755);
    log_file = fopen(LOG_PATH, "a");
    if (!log_file) { perror("Cannot open log file"); exit(1); }

    // Create/open named pipe
    if (mkfifo(PIPE_PATH, 0666) < 0 && errno != EEXIST) {
        perror("[OBSERVER] mkfifo failed");
        exit(1);
    }
    printf("[OBSERVER] Opening named pipe (waiting for dashboard to connect)...\n");
    pipe_fd = open(PIPE_PATH, O_WRONLY);
    if (pipe_fd < 0) { perror("[OBSERVER] pipe open failed"); exit(1); }
    printf("[OBSERVER] Dashboard connected. Ready.\n\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_pid>\n", argv[0]);
        fprintf(stderr, "       %s --self  (watch a simple busy loop for demo)\n", argv[0]);
        fclose(log_file); close(pipe_fd);
        return 1;
    }

    rates.window_start = time(NULL);

    if (strcmp(argv[1], "--self") == 0) {
        // Fork a dummy worker process for demo
        pid_t child = fork();
        if (child == 0) {
            // Child: do harmless work
            while (1) {
                int fd = open("/tmp/.sentinel_test", O_CREAT|O_WRONLY, 0644);
                if (fd >= 0) { write(fd, "x", 1); close(fd); }
                usleep(100000);
            }
        }
        trace_pid(child);
        kill(child, SIGKILL);
    } else {
        pid_t target = (pid_t)atoi(argv[1]);
        trace_pid(target);
    }

    fclose(log_file);
    close(pipe_fd);
    return 0;
}

