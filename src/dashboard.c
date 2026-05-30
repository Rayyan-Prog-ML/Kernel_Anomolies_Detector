/*
 * dashboard.c — Kernel Sentinel: Real-Time Monitoring Dashboard
 *
 * Producer thread reads SentinelEvent structs from named pipe.
 * Consumer thread renders live terminal UI (ncurses-free, pure ANSI).
 * Ring buffer with mutex + semaphores solves the Producer-Consumer problem.
 *
 * Usage: ./dashboard
 */

#include "../include/sentinel.h"

// ─────────────────────────────────────────
//  GLOBAL STATE
// ─────────────────────────────────────────
static RingBuffer    ring;
static volatile int  running   = 1;
static int           pipe_fd   = -1;

// Live counters (protected by stats_lock)
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static long total_events   = 0;
static long total_forks    = 0;
static long total_writes   = 0;
static long total_opens    = 0;
static long total_mmaps    = 0;
static long alert_count    = 0;

// Rolling alert log (last 12 alerts, shown in panel)
#define ALERT_LOG_SIZE 12
static char alert_log[ALERT_LOG_SIZE][256];
static int  alert_log_idx  = 0;
static pthread_mutex_t alert_log_lock = PTHREAD_MUTEX_INITIALIZER;

// ─────────────────────────────────────────
//  TERMINAL HELPERS
// ─────────────────────────────────────────
#define CLEAR_SCREEN  "\033[2J\033[H"
#define BOLD          "\033[1m"
#define DIM           "\033[2m"
#define RESET         "\033[0m"
#define FG_WHITE      "\033[97m"
#define FG_CYAN       "\033[36m"
#define FG_GREEN      "\033[32m"
#define FG_YELLOW     "\033[33m"
#define FG_MAGENTA    "\033[35m"
#define FG_RED        "\033[31m"
#define BG_DARK       "\033[48;5;233m"
#define BG_PANEL      "\033[48;5;235m"
#define FG_GRAY       "\033[90m"

static void print_separator(char ch, int len, const char *color) {
    printf("%s", color);
    for (int i = 0; i < len; i++) putchar(ch);
    printf(RESET "\n");
}

static void print_header(time_t now) {
    char ts[32];
    struct tm *t = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d  %H:%M:%S", t);

    printf(CLEAR_SCREEN);
    print_separator('═', 80, BOLD FG_CYAN);
    printf(BOLD FG_CYAN
           "  ██╗  ██╗███████╗██████╗ ███╗  ██╗███████╗██╗      \n"
           "  ██║ ██╔╝██╔════╝██╔══██╗████╗ ██║██╔════╝██║      \n"
           "  █████╔╝ █████╗  ██████╔╝██╔██╗██║█████╗  ██║      \n"
           "  ██╔═██╗ ██╔══╝  ██╔══██╗██║╚████║██╔══╝  ██║      \n"
           "  ██║ ╚██╗███████╗██║  ██║██║ ╚███║███████╗███████╗ \n"
           "  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝ \n"
           RESET);
    printf(BG_DARK FG_WHITE BOLD
           "  SENTINEL  ─  Real-Time Kernel Auditing Engine          "
           RESET "  " DIM "[%s]" RESET "\n", ts);
    print_separator('═', 80, BOLD FG_CYAN);
}

static void print_stats_panel(void) {
    pthread_mutex_lock(&stats_lock);
    long ev   = total_events;
    long fk   = total_forks;
    long wr   = total_writes;
    long op   = total_opens;
    long mm   = total_mmaps;
    long alrt = alert_count;
    pthread_mutex_unlock(&stats_lock);

    const char *alert_color = alrt == 0 ? FG_GREEN :
                              alrt <  3 ? FG_YELLOW :
                              alrt < 10 ? FG_MAGENTA : FG_RED;

    printf(BG_PANEL "\n  " BOLD FG_WHITE "── LIVE COUNTERS ─────────────────────────────────────" RESET "\n");
    printf("  " FG_CYAN  "Total Events : " RESET BOLD "%6ld" RESET
           "    " FG_YELLOW "Forks  : " RESET BOLD "%6ld" RESET
           "    " FG_MAGENTA "Writes : " RESET BOLD "%6ld" RESET "\n",
           ev, fk, wr);
    printf("  " FG_GREEN "File Opens   : " RESET BOLD "%6ld" RESET
           "    " FG_CYAN   "mmaps  : " RESET BOLD "%6ld" RESET
           "    %s" BOLD "ALERTS : %6ld" RESET "\n\n",
           op, mm, alert_color, alrt);
}

static void print_alert_log(void) {
    pthread_mutex_lock(&alert_log_lock);
    printf("  " BOLD FG_WHITE "── ALERT STREAM ──────────────────────────────────────" RESET "\n");
    for (int i = 0; i < ALERT_LOG_SIZE; i++) {
        int idx = (alert_log_idx - ALERT_LOG_SIZE + i + ALERT_LOG_SIZE) % ALERT_LOG_SIZE;
        if (alert_log[idx][0])
            printf("  %s\n", alert_log[idx]);
    }
    pthread_mutex_unlock(&alert_log_lock);
}

// ─────────────────────────────────────────
//  RENDER THREAD (consumer)
// ─────────────────────────────────────────
static void *render_thread(void *arg) {
    (void)arg;
    while (running) {
        SentinelEvent ev;
        rb_pop(&ring, &ev);        // blocks until item available

        // Update counters
        pthread_mutex_lock(&stats_lock);
        total_events++;
        if (ev.syscall_nr == SYS_FORK_NR || ev.syscall_nr == SYS_CLONE_NR) total_forks++;
        if (ev.syscall_nr == SYS_WRITE_NR)  total_writes++;
        if (ev.syscall_nr == SYS_OPEN_NR || ev.syscall_nr == SYS_OPENAT_NR) total_opens++;
        if (ev.syscall_nr == SYS_MMAP_NR)   total_mmaps++;
        if (ev.severity   >= SEV_WARNING)    alert_count++;
        pthread_mutex_unlock(&stats_lock);

        // Log high-severity alerts
        if (ev.severity >= SEV_WARNING) {
            char ts[12];
            struct tm *t = localtime(&ev.timestamp);
            strftime(ts, sizeof(ts), "%H:%M:%S", t);

            const char *col = SEV_COLORS[ev.severity];
            char buf[256];
            snprintf(buf, sizeof(buf), "%s[%s] %s%-8s" RESET " PID=%-6d  %s",
                     col, ts, BOLD, SEV_LABELS[ev.severity],
                     ev.pid, ev.message);

            pthread_mutex_lock(&alert_log_lock);
            strncpy(alert_log[alert_log_idx], buf, 255);
            alert_log_idx = (alert_log_idx + 1) % ALERT_LOG_SIZE;
            pthread_mutex_unlock(&alert_log_lock);
        }

        // Redraw dashboard
        print_header(ev.timestamp);
        print_stats_panel();
        print_alert_log();
        print_separator('─', 80, FG_GRAY);
        printf(DIM "  Press Ctrl+C to stop\n" RESET);
        fflush(stdout);
    }
    return NULL;
}

// ─────────────────────────────────────────
//  PRODUCER THREAD (reads named pipe)
// ─────────────────────────────────────────
static void *producer_thread(void *arg) {
    (void)arg;
    SentinelEvent ev;
    int attack_count = 0;

    while (running) {
        ssize_t n = read(pipe_fd, &ev, sizeof(SentinelEvent));

        if (n == sizeof(SentinelEvent)) {
            rb_push(&ring, &ev);

        } else if (n == 0) {
            // Observer disconnected — reopen pipe for next observer
            attack_count++;
            printf("\n[DASHBOARD] Observer %d disconnected. Waiting for next...\n",
                   attack_count);

            close(pipe_fd);

            // Block here until next observer connects (opens pipe for writing)
            pipe_fd = open(PIPE_PATH, O_RDONLY);
            if (pipe_fd < 0) {
                // Pipe was deleted = real shutdown
                running = 0;
                break;
            }
            printf("[DASHBOARD] Observer %d connected!\n", attack_count + 1);

        } else if (n < 0 && errno != EINTR) {
            perror("[DASHBOARD] pipe read error");
            break;
        }
    }

    // Unblock render thread on exit
    memset(&ev, 0, sizeof(ev));
    ev.severity = SEV_INFO;
    snprintf(ev.message, BUFFER_SIZE, "Session ended");
    rb_push(&ring, &ev);
    return NULL;
}
static void on_sigint(int sig) {
    (void)sig;
    running = 0;
    unlink(PIPE_PATH);   // deleting the pipe causes open() in producer to fail → clean exit
    close(pipe_fd);
    pipe_fd = -1;
}
// ─────────────────────────────────────────
//  ENTRY POINT
// ─────────────────────────────────────────
int main(void) {
    signal(SIGINT, on_sigint);

    rb_init(&ring);
    memset(alert_log, 0, sizeof(alert_log));

    printf(BOLD FG_CYAN "\n[DASHBOARD] Kernel Sentinel Starting...\n" RESET);

    // Create named pipe if needed
    if (mkfifo(PIPE_PATH, 0666) < 0 && errno != EEXIST) {
        perror("[DASHBOARD] mkfifo failed");
        return 1;
    }

    printf("[DASHBOARD] Waiting for observer to connect on pipe: %s\n", PIPE_PATH);
    pipe_fd = open(PIPE_PATH, O_RDONLY);
    if (pipe_fd < 0) { perror("[DASHBOARD] pipe open failed"); return 1; }

    printf("[DASHBOARD] Observer connected! Starting live display...\n\n");
    sleep(1);

    pthread_t prod_tid, rend_tid;
    pthread_create(&prod_tid, NULL, producer_thread, NULL);
    pthread_create(&rend_tid, NULL, render_thread,   NULL);

    pthread_join(prod_tid, NULL);
    pthread_join(rend_tid, NULL);

    // Final stats
    printf(BOLD FG_CYAN "\n══ SESSION SUMMARY ══════════════════════════════\n" RESET);
    printf("  Total events  : %ld\n", total_events);
    printf("  Total forks   : %ld\n", total_forks);
    printf("  Total writes  : %ld\n", total_writes);
    printf("  Total alerts  : %ld\n", alert_count);
    print_separator('═', 50, FG_CYAN);

    close(pipe_fd);
    unlink(PIPE_PATH);
    return 0;
}

