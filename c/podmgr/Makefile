CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2
VERSION ?= 1.0.1
CFLAGS  += -DPODMGR_VERSION=\"$(VERSION)\"
TARGET_NAME = podmgr
OUTDIR      = ../../bin
TARGET      = $(OUTDIR)/$(TARGET_NAME)

RELAY_COLLECT_NAME   = podmgr-relay-collect
RELAY_RECONCILE_NAME = podmgr-relay-reconcile
RELAY_HUBD_NAME      = podmgr-relay-hubd
RELAY_TENANTD_NAME   = podmgr-relay-tenantd
RELAY_MERGE_NAME     = podmgr-relay-merge
RELAY_COLLECT_TARGET = $(OUTDIR)/$(RELAY_COLLECT_NAME)
RELAY_RECON_TARGET   = $(OUTDIR)/$(RELAY_RECONCILE_NAME)
RELAY_HUBD_TARGET    = $(OUTDIR)/$(RELAY_HUBD_NAME)
RELAY_TENANTD_TARGET = $(OUTDIR)/$(RELAY_TENANTD_NAME)
RELAY_MERGE_TARGET   = $(OUTDIR)/$(RELAY_MERGE_NAME)

SRCS = main.c config.c logging.c validation.c util.c commands.c
OBJS = $(SRCS:.c=.o)

RELAY_COLLECT_SRC = relay_collect.c
RELAY_RECON_SRC   = relay_reconcile.c
RELAY_HUBD_SRC    = relay_hubd.c
RELAY_TENANTD_SRC = relay_tenantd.c
RELAY_MERGE_SRC   = relay_merge.c
RELAY_COLLECT_OBJ = $(RELAY_COLLECT_SRC:.c=.o)
RELAY_RECON_OBJ   = $(RELAY_RECON_SRC:.c=.o)
RELAY_HUBD_OBJ    = $(RELAY_HUBD_SRC:.c=.o)
RELAY_TENANTD_OBJ = $(RELAY_TENANTD_SRC:.c=.o)
RELAY_MERGE_OBJ   = $(RELAY_MERGE_SRC:.c=.o)

PREFIX       ?= /usr/local
BINDIR        = $(PREFIX)/bin
DATADIR       = /usr/lib/podmgr
MANDIR        = $(PREFIX)/share/man/man1
TPL_SRC       = ../../assets/podman-workload.service.tpl
MAN_SRC       = ../../assets/podmgr.1

all: $(TARGET) $(RELAY_COLLECT_TARGET) $(RELAY_RECON_TARGET) $(RELAY_HUBD_TARGET) $(RELAY_TENANTD_TARGET) $(RELAY_MERGE_TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(RELAY_COLLECT_TARGET): $(RELAY_COLLECT_OBJ)
	mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(RELAY_RECON_TARGET): $(RELAY_RECON_OBJ)
	mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(RELAY_HUBD_TARGET): $(RELAY_HUBD_OBJ)
	mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(RELAY_TENANTD_TARGET): $(RELAY_TENANTD_OBJ)
	mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^

$(RELAY_MERGE_TARGET): $(RELAY_MERGE_OBJ)
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
commands.o:   commands.c commands.h config.h logging.h validation.h util.h

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET_NAME)
	install -d $(DESTDIR)$(DATADIR)
	install -m 644 $(TPL_SRC) $(DESTDIR)$(DATADIR)/podman-workload.service.tpl
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 $(MAN_SRC) $(DESTDIR)$(MANDIR)/podmgr.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET_NAME)
	rm -f $(DESTDIR)$(DATADIR)/podman-workload.service.tpl
	rm -f $(DESTDIR)$(MANDIR)/podmgr.1

clean:
	rm -f $(OBJS) $(RELAY_COLLECT_OBJ) $(RELAY_RECON_OBJ) $(RELAY_HUBD_OBJ) $(RELAY_TENANTD_OBJ) $(RELAY_MERGE_OBJ) $(TARGET) $(TARGET_NAME) $(RELAY_COLLECT_TARGET) $(RELAY_RECON_TARGET) $(RELAY_HUBD_TARGET) $(RELAY_TENANTD_TARGET) $(RELAY_MERGE_TARGET)

.PHONY: all install uninstall clean
