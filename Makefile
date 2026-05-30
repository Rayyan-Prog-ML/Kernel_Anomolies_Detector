# ─────────────────────────────────────────────────────────────────
#  Kernel Sentinel — Makefile
#  Works on Ubuntu 20.04+  (x86-64)
# ─────────────────────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I./include
LIBS    = -lpthread

SRCDIR  = src
SCRIPTS = scripts
BINDIR  = bin
LOGDIR  = logs

# Binaries
OBSERVER   = $(BINDIR)/observer
DASHBOARD  = $(BINDIR)/dashboard
FORKBOMB   = $(BINDIR)/attack_forkbomb
RANSOMWARE = $(BINDIR)/attack_ransomware
MEMSPIKE   = $(BINDIR)/attack_memspike

.PHONY: all clean dirs run-demo help

all: dirs $(OBSERVER) $(DASHBOARD) $(FORKBOMB) $(RANSOMWARE) $(MEMSPIKE)

dirs:
	@mkdir -p $(BINDIR) $(LOGDIR)

# ── Core Engine ──────────────────────────────────────────────────
$(OBSERVER): $(SRCDIR)/observer.c include/sentinel.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	@echo "[BUILD] observer      → $@"

$(DASHBOARD): $(SRCDIR)/dashboard.c include/sentinel.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	@echo "[BUILD] dashboard     → $@"

# ── Attack Scripts ────────────────────────────────────────────────
$(FORKBOMB): $(SCRIPTS)/attack_forkbomb.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] attack_forkbomb   → $@"

$(RANSOMWARE): $(SCRIPTS)/attack_ransomware.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] attack_ransomware → $@"

$(MEMSPIKE): $(SCRIPTS)/attack_memspike.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] attack_memspike   → $@"

clean:
	rm -rf $(BINDIR) $(LOGDIR)
	rm -f /tmp/sentinel_pipe
	@echo "[CLEAN] done"

help:
	@echo ""
	@echo "  ╔══════════════════════════════════════════════════════╗"
	@echo "  ║          KERNEL SENTINEL — Quick Start               ║"
	@echo "  ╚══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  1. Build everything:"
	@echo "       make"
	@echo ""
	@echo "  ── TERMINAL 1 (Dashboard) ──────────────────────────────"
	@echo "  2. Start the dashboard first:"
	@echo "       ./bin/dashboard"
	@echo ""
	@echo "  ── TERMINAL 2 (Attacks) ────────────────────────────────"
	@echo "  3a. Run observer in self-demo mode:"
	@echo "       ./bin/observer --self"
	@echo ""
	@echo "  3b. Or attack a specific PID:"
	@echo "       ./bin/observer <PID>"
	@echo ""
	@echo "  4. In a THIRD terminal, launch attack simulations:"
	@echo "       ./bin/attack_forkbomb"
	@echo "       ./bin/attack_ransomware"
	@echo "       ./bin/attack_memspike"
	@echo ""
	@echo "  Then start the observer on the attack PID to see alerts."
	@echo ""

