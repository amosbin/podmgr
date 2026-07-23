CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2
# Default is intentionally blank so a bare `make` fails the compile (via
# the #error in command_setup.c) instead of silently baking a stale version
# string into the binary. Production builds always set VERSION= on the
# command line (debian/rules does this via $(DEB_VERSION_UPSTREAM)).
VERSION ?= 1.5.1
CFLAGS  += -DPODMGR_VERSION=\"$(VERSION)\"
TARGET_NAME = podmgr
OUTDIR      = ../../bin
TARGET      = $(OUTDIR)/$(TARGET_NAME)

SRCS = main.c config.c logging.c validation.c util.c \
	command_setup.c command_cleanup.c command_runtime.c \
	command_container.c command_report.c
OBJS = $(SRCS:.c=.o)

PREFIX       ?= /usr/local
BINDIR        = $(PREFIX)/bin
DATADIR       = /usr/lib/podmgr
MANDIR        = $(PREFIX)/share/man/man1
TPL_SRC       = ../../assets/podman-workload.service.tpl
MAN_SRC       = ../../assets/podmgr.1
SYSTEMD_UNIT_DIR = /usr/lib/systemd/system
AUTOSTART_SVC_SRC = ../../assets/podmgr-autostart.service
AUTOSTART_TIMER_SRC = ../../assets/podmgr-autostart.timer

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Header dependencies
main.o:       main.c config.h logging.h validation.h util.h commands.h
config.o:     config.c config.h
logging.o:    logging.c logging.h config.h
validation.o: validation.c validation.h logging.h config.h
util.o:       util.c util.h logging.h config.h
command_setup.o:   command_setup.c commands.h command_internal.h config.h logging.h validation.h util.h
command_cleanup.o: command_cleanup.c commands.h config.h logging.h validation.h util.h
command_runtime.o: command_runtime.c commands.h command_internal.h config.h logging.h validation.h util.h
command_container.o: command_container.c commands.h config.h logging.h validation.h util.h
command_report.o: command_report.c commands.h command_internal.h config.h logging.h validation.h util.h

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET_NAME)
	install -d $(DESTDIR)$(DATADIR)
	install -m 644 $(TPL_SRC) $(DESTDIR)$(DATADIR)/podman-workload.service.tpl
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 $(MAN_SRC) $(DESTDIR)$(MANDIR)/podmgr.1
	install -d $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	install -m 644 $(AUTOSTART_SVC_SRC) $(DESTDIR)$(SYSTEMD_UNIT_DIR)/podmgr-autostart.service
	install -m 644 $(AUTOSTART_TIMER_SRC) $(DESTDIR)$(SYSTEMD_UNIT_DIR)/podmgr-autostart.timer
	if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then \
		systemctl daemon-reload >/dev/null 2>&1 || true; \
		systemctl enable --now podmgr-autostart.timer >/dev/null 2>&1 || true; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET_NAME)
	rm -f $(DESTDIR)$(DATADIR)/podman-workload.service.tpl
	rm -f $(DESTDIR)$(MANDIR)/podmgr.1
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/podmgr-autostart.service
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/podmgr-autostart.timer

clean:
	rm -f $(OBJS) $(TARGET) $(TARGET_NAME)

.PHONY: all install uninstall clean
