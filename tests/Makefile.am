NULL =

TESTS =
noinst_PROGRAMS = $(TESTS)
check_PROGRAMS = $(TESTS)

# common code
noinst_LIBRARIES = libtest.a
libtest_a_SOURCES = \
	common.c \
	common.h \
	$(NULL)
LDADD = \
	libtest.a \
	$(NULL)

TESTS += delay
delay_SOURCES = delay.c

TESTS += bandwidth
bandwidth_SOURCES = bandwidth.c
bandwidth_LDFLAGS = -pthread
