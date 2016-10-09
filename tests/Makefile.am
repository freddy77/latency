NULL =

TESTS = \
	$(check_PROGRAMS) \
	test_closure \
	$(NULL)
noinst_PROGRAMS = $(check_PROGRAMS)
check_PROGRAMS =

# common code
noinst_LIBRARIES = libtest.a
libtest_a_SOURCES = \
	common.c \
	common.h \
	$(NULL)
LDADD = \
	libtest.a \
	$(NULL)

check_PROGRAMS += delay
delay_SOURCES = delay.c

check_PROGRAMS += bandwidth
bandwidth_SOURCES = bandwidth.c
bandwidth_LDFLAGS = -pthread

check_PROGRAMS += ping
ping_SOURCES = ping.c
