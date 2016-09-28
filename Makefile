CFLAGS ?= -O2 -Wall -g
CC ?= gcc
INSTDIR ?= /usr/local/bin
MANDIR ?= /usr/local/share/man/man1
VERSION = 1.0
SOURCES = latency.c tun.c utils.c latency.h tun.h utils.h

all: latency latency.1

latency: $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ -pthread

latency.1: README.md
	ronn < $< > $@

clean::
	rm -f latency latency.1

install:: latency latency.1
	umask 022 && cp $< $(INSTDIR)
	chown root: $(INSTDIR)/$<
	chmod 4751 $(INSTDIR)/$<
	cp latency.1 $(MANDIR)/latency.1
	chown root: $(MANDIR)/latency.1

dist:: latency-$(VERSION).tar.gz

latency-$(VERSION).tar.gz: Makefile $(SOURCES)
	git archive HEAD --prefix latency-$(VERSION)/ | gzip -9 > $@

rpm:: dist
	rpmbuild -D "_sourcedir $$PWD" -ba latency.spec
