AC_INIT([latency], [1.3], [freddy77@gmail.com])
AM_INIT_AUTOMAKE([serial-tests -Wall -Werror foreign])
AC_PROG_CC
AM_PROG_AR
AC_PROG_RANLIB
AC_CONFIG_HEADERS([config.h])
AC_CHECK_MEMBERS(
	[struct tcphdr.th_sum, struct tcphdr.check, struct udphdr.uh_sum, struct udphdr.check],
	[], [],
	[[#include <netinet/udp.h>
#include <netinet/tcp.h>]])
AC_CONFIG_FILES([Makefile tests/Makefile latency.spec])
AC_OUTPUT
