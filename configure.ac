# Need at least 2.64 for PACKAGE_URL
AC_PREREQ([2.71])
AC_INIT([darkstat],[3.0.0-git],[],[],[https://unix4lyfe.org/darkstat/])
AC_CONFIG_SRCDIR([darkstat.c])
AC_CONFIG_HEADERS([config.h])

RULE="------------------------------------------------------------"

# Allow configure-time override of PRIVDROP_USER.
AC_ARG_WITH(privdrop-user, AS_HELP_STRING([--with-privdrop-user],
 [specify which user to drop privileges to (default: nobody)]),
 [_pdu="$withval"],
 [_pdu="nobody"])
AC_DEFINE_UNQUOTED(PRIVDROP_USER, "$_pdu", [User to privdrop to.])

# Checks for programs.
AC_PROG_INSTALL
AC_PROG_CC

# Compiler's language features.
AC_C_RESTRICT

m4_pattern_allow([^AM_DEFAULT_VERBOSITY$])
AC_ARG_ENABLE([silent-rules],
[  --enable-silent-rules          less verbose build output (undo: 'make V=1')
  --disable-silent-rules         verbose build output (undo: 'make V=0')])
case $enable_silent_rules in
no)  AM_DEFAULT_VERBOSITY=1;;
*)   AM_DEFAULT_VERBOSITY=0;;
esac
AC_SUBST([AM_DEFAULT_VERBOSITY])

# Let user disable debugging symbols so we create smaller binaries.
AC_MSG_CHECKING(if we want debug code)
AC_ARG_ENABLE(debug, AS_HELP_STRING([--disable-debug],
 [turn off debugging code and asserts]),
 [if test "x$enableval" = "xno" ; then
   CFLAGS="$CFLAGS -DNDEBUG -g0"
   AC_MSG_RESULT(nope)
  elif test "x$enableval" = "xyes" ; then
   AC_MSG_RESULT(sure)
  else
   CFLAGS="$CFLAGS -g$enableval"
   AC_MSG_RESULT(sure ($enableval))
  fi],
 [AC_MSG_RESULT(sure)])

# Augment CFLAGS for fun.
echo "int main(void){return 1;}" > conftest.$ac_ext

AC_MSG_CHECKING(if your C compiler wants a hit off the pipe)
save_cflags="$CFLAGS"
CFLAGS="-pipe $CFLAGS"
if (eval $ac_link) 2>/dev/null; then
 AC_MSG_RESULT(sure does)
else
 AC_MSG_RESULT(no)
 CFLAGS="$save_cflags"
fi

AC_MSG_CHECKING(if your C compiler has a link-time optimizer)
if test x$GCC = xyes; then
 save_cflags="$CFLAGS"
 CFLAGS="-flto $CFLAGS"
 if (eval $ac_link) 2>/dev/null; then
  AC_MSG_RESULT(sure does)
 else
  AC_MSG_RESULT(no)
  CFLAGS="$save_cflags"
 fi
else
 AC_MSG_RESULT(skipped)
fi

AC_ARG_ENABLE(warnings, AS_HELP_STRING([--enable-warnings],
 [turn on lots of compile-time warnings,
  these are only useful for development]),
 [if test "x$enableval" = "xyes" ; then
   AC_MSG_CHECKING(if your C compiler has gcc-like --extra-warnings)
   save_cflags="$CFLAGS"
   CFLAGS="$CFLAGS -fdiagnostics-show-option --all-warnings --extra-warnings"
   if (eval $ac_link) 2>/dev/null; then
    AC_MSG_RESULT(yes)
   else
    AC_MSG_RESULT(no)
    CFLAGS="$save_cflags"
   fi

   AC_MSG_CHECKING(if your C compiler has clang-like -Weverything)
   save_cflags="$CFLAGS"
   CFLAGS="$CFLAGS -Weverything"
   if (eval $ac_link) 2>/dev/null; then
    AC_MSG_RESULT(yes)
   else
    AC_MSG_RESULT(no)
    CFLAGS="$save_cflags"
   fi
  fi])

rm -f conftest.$ac_objext conftest.$ac_ext



# Check for zlib.
AC_CHECK_LIB(z, deflate,, [
 cat <<END
$RULE

I can't link to zlib.  You really can't have a modern
operating system without zlib.

On Debian or a derivative, try: sudo apt-get install zlib1g-dev

On an RPM system, see if there is a zlib-devel package.

$RULE
END
 AC_MSG_ERROR([can't find usable zlib])])



# Check for Solaris.
# Must do at least socket and nsl before checking for libpcap.
AC_SEARCH_LIBS(gethostbyname, [nsl], [],
  [AC_MSG_ERROR([gethostbyname() not found])])
AC_SEARCH_LIBS(socket, [socket], [],
  [AC_MSG_ERROR([socket() not found])])
AC_SEARCH_LIBS(hstrerror, [resolv], [],
  [AC_MSG_ERROR([hstrerror() not found])])

# Solaris need sys/filio.h for FIONBIO
AC_CHECK_HEADERS(sys/filio.h)

# This is the modern way.  Older systems use the ioctl method.
AC_SEARCH_LIBS(getifaddrs, [c],
  [AC_CHECK_HEADERS(ifaddrs.h)])



# Some OSes (Solaris) need sys/sockio.h for SIOCGIFADDR
AC_CHECK_HEADERS(sys/sockio.h)

# Check for libpcap
AC_ARG_WITH(pcap, AS_HELP_STRING([--with-pcap=DIR],
 [prefix to libpcap installation]),
 [if test "$withval" = yes ; then
   AC_MSG_ERROR([must specify a path, as in --with-pcap=DIR])
  fi
  if test "$withval" != no ; then
   PCAP_HOME="$withval"
  fi])

if test -n "$PCAP_HOME" ; then
 LDFLAGS="$LDFLAGS -L$PCAP_HOME/lib"
 CPPFLAGS2="$CPPFLAGS -I$PCAP_HOME/include/pcap"
 CPPFLAGS="$CPPFLAGS -I$PCAP_HOME/include"
else
 CPPFLAGS2="$CPPFLAGS -I/usr/include/pcap"
fi

AC_CHECK_LIB(pcap, pcap_loop,, PCAP_BROKEN="yes")

if test -z "$PCAP_BROKEN" ; then
  AC_CHECK_HEADERS(pcap.h,,
  [# Couldn't find headers, try include/pcap
   CPPFLAGS="$CPPFLAGS2"
   AC_MSG_NOTICE([checking in include/pcap])
   unset ac_cv_header_pcap_h
   AC_CHECK_HEADERS(pcap.h,
    AC_MSG_RESULT([I hate you.]),
    PCAP_BROKEN="yes")])
fi

if test -n "$PCAP_BROKEN" ; then
 cat <<END_MSG
$RULE

darkstat absolutely requires libpcap to be installed.  On Debian
systems, apt-get install libpcap-dev.  On RPM systems like RedHat, try
installing the libpcap-devel package.

If libpcap is installed into a prefix that isn't being picked up by
configure, for example /usr/local, re-run configure and add
--with-pcap=/usr/local

Failing all of the above, go to http://www.tcpdump.org/ and download the
source distribution of libpcap and build it yourself.

$RULE
END_MSG
 AC_MSG_ERROR([can't find usable libpcap])
fi

# If not in libc, we might find these in libbsd.
AC_SEARCH_LIBS(setproctitle, [bsd],
 AC_DEFINE(HAVE_SETPROCTITLE, 1,
  [Define to 1 if you have setproctitle().]))
AC_SEARCH_LIBS(strlcpy, [bsd],
 AC_DEFINE(HAVE_STRLCPY, 1,
  [Define to 1 if you have strlcpy().]))
AC_SEARCH_LIBS(strlcat, [bsd],
 AC_DEFINE(HAVE_STRLCAT, 1,
  [Define to 1 if you have strlcat().]))

AC_CHECK_HEADERS(bsd/string.h)
AC_CHECK_HEADERS(bsd/unistd.h)

AC_SEARCH_LIBS(clock_gettime, rt)

AC_CONFIG_FILES([Makefile darkstat.8])
AC_OUTPUT
