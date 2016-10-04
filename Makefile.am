NULL =

bin_PROGRAMS = latency
latency_SOURCES = \
	latency.c \
	tun.c \
	utils.c \
	latency.h \
	tun.h \
	utils.h \
	$(NULL)
latency_LDFLAGS = -pthread

man1_MANS = latency.1

latency.1: README.md
	ronn < $< > $@.tmp
	mv -f $@.tmp $@

EXTRA_DIST = \
	latency.spec \
	README.md \
	latency.1 \
	$(NULL)
CLEANFILES = latency.1
