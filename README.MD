# Kernel Sentinel
### A High-Performance System Auditing & Monitoring Engine
**OS Lab Project — SZABIST**

---

## Project Structure

```
kernel_sentinel/
├── include/
│   └── sentinel.h          # Shared structs, ring buffer, syscall defs
├── src/
│   ├── observer.c           # ptrace engine — hooks syscalls
│   └── dashboard.c          # Multi-threaded live terminal UI
├── scripts/
│   ├── attack_forkbomb.c    # Simulates resource exhaustion
│   ├── attack_ransomware.c  # Simulates mass file I/O
│   └── attack_memspike.c    # Simulates memory spike
├── bin/                     # Compiled binaries (auto-created)
├── logs/                    # sentinel.log output (auto-created)
├── Makefile
├── run_demo.sh              # Automated demo script
└── README.md
```

---

## OS Concepts Implemented

| Concept                     | Where                                      |
|-----------------------------|--------------------------------------------|
| ptrace syscall interception | `observer.c` — `trace_pid()`               |
| Named Pipes (mkfifo) / IPC  | `observer.c` → `dashboard.c` via FIFO      |
| POSIX Threads (pthreads)    | `dashboard.c` — producer + render threads  |
| Mutex locks                 | `dashboard.c` — stats_lock, alert_log_lock |
| Semaphores                  | `sentinel.h` — RingBuffer.items/spaces     |
| Producer-Consumer problem   | `rb_push()` / `rb_pop()` in ring buffer    |
| fork() / wait() / execvp()  | `observer.c --self` mode                   |
| Deadlock avoidance          | Lock ordering: stats_lock always before alert_log_lock |

---

## How to Build

```bash
# Install dependencies (Ubuntu)
sudo apt update
sudo apt install gcc make

# Build all binaries
cd kernel_sentinel
make

# See help
make help
```

---

## How to Run — TWO TERMINAL METHOD

### Terminal 1 — Dashboard
Start this FIRST. It opens the named pipe and waits for the observer.

```bash
./bin/dashboard
```

You will see:
```
[DASHBOARD] Kernel Sentinel Starting...
[DASHBOARD] Waiting for observer to connect on pipe: /tmp/sentinel_pipe
```

---

### Terminal 2 — Observer + Attack

#### Option A: Self-demo (observer watches its own dummy process)
```bash
./bin/observer --self
```

#### Option B: Watch a real attack process
```bash
# Step 1: Start an attack in the background
./bin/attack_forkbomb &
echo "Attack PID: $!"

# Step 2: Observe that PID
./bin/observer <PID_from_above>
```

#### Option C: Run all attacks
```bash
# Fork bomb
./bin/attack_forkbomb 25

# Ransomware simulation
./bin/attack_ransomware 80

# Memory spike
./bin/attack_memspike 200
```

---

## What You Will See in the Dashboard

```
══════════════════════════════════════════════════════════════════════════════════
  ██╗  ██╗███████╗██████╗ ███╗  ██╗███████╗██╗
  ...
══ LIVE COUNTERS ══════════════════════════════════════
  Total Events :    342    Forks  :     28    Writes :    156
  File Opens   :     94    mmaps  :     14    ALERTS :      7

══ ALERT STREAM ═══════════════════════════════════════
  [14:23:01] CRITICAL  PID=12345  FORK BOMB DETECTED — 24 forks in last second!
  [14:23:02] DANGER    PID=12345  MASS WRITE ATTACK — 58 writes/sec
  [14:23:03] WARNING   PID=12345  execve() called — new program loaded
```

---

## Automated Demo (single terminal)

```bash
bash run_demo.sh fork      # fork bomb only
bash run_demo.sh ransom    # ransomware only
bash run_demo.sh mem       # memory spike only
bash run_demo.sh all       # all three attacks
```

---

## Checking Logs

All events are written to `logs/sentinel.log`:

```bash
cat logs/sentinel.log
tail -f logs/sentinel.log   # live tail
```

---

## Stopping

Press `Ctrl+C` in either terminal. The dashboard prints a session summary.

---
