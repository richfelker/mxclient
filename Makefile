srcdir = .
prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin

CFLAGS = -O2 -Wall
LDFLAGS =
LIBS = -lbearssl -lpthread -lresolv
INSTALL = install

-include config.mak

SRCS = $(sort $(wildcard $(srcdir)/*.c))
OBJS = $(SRCS:$(srcdir)/%.c=%.o)

all: mxclient

clean:
	rm -f mxclient *.o

install: $(DESTDIR)$(bindir)/mxclient

mxclient: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: $(srcdir)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(DESTDIR)$(bindir)/mxclient: mxclient
	$(INSTALL) mxclient $@
