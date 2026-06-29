CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2
VERSION ?= 1.0.1
CFLAGS  += -DPODMGR_VERSION=\"$(VERSION)\"
TARGET_NAME = podmgr
OUTDIR      = ../../bin
TARGET      = $(OUTDIR)/$(TARGET_NAME)

SRCS = main.c config.c logging.c validation.c util.c commands.c
OBJS = $(SRCS:.c=.o)

PREFIX       ?= /usr/local
BINDIR        = $(PREFIX)/bin
DATADIR       = /usr/lib/podmgr
MANDIR        = $(PREFIX)/share/man/man1
TPL_SRC       = ../../assets/podman-workload.service.tpl
MAN_SRC       = ../../assets/podmgr.1

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
	rm -f $(OBJS) $(TARGET) $(TARGET_NAME)

.PHONY: all install uninstall clean
