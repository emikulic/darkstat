AC_INIT(darkstat, 3.0.0-git, , , http://dmr.ath.cx/net/darkstat/)
AC_CONFIG_SRCDIR([darkstat.c])
AC_CONFIG_HEADER([config.h])

RULE="------------------------------------------------------------"

# Let user specify CHROOT_DIR, or else autodetect it, or else die.
AC_ARG_WITH(chroot-dir, AS_HELP_STRING([--with-chroot-dir],
 [specify the chroot directory (default: /var/empty)]),
 [if test "x$withval" = "xyes"; then
   AC_MSG_ERROR([please specify --with-chroot-dir=/path/to/darkstat/chroot])
  fi
  _chd="$withval"],
 [# Find an "empty" directory to serve as the chroot.
  _chd="/var/empty"
  AC_MSG_CHECKING([for $_chd])
  if test -d $_chd ; then
   AC_MSG_RESULT(found it)
  else
   AC_MSG_RESULT(not there)
   _chd="/var/lib/empty"
   AC_MSG_CHECKING([for $_chd])
   if test -d $_chd ; then
    AC_MSG_RESULT(found it)
   else
    AC_MSG_RESULT(not there either)
    AC_MSG_ERROR([please specify --with-chroot-dir=/path/to/darkstat/chroot])
   fi
  fi])
AC_DEFINE_UNQUOTED(CHROOT_DIR, "$_chd", [Default chroot directory.])

# Allow configure-time override of PRIVDROP_USER.
AC_ARG_WITH(privdrop-user, AS_HELP_STRING([--with-privdrop-user],
 [specify which user to drop privileges to (default: nobody)]),
 [_pdu="$withval"],
 [_pdu="nobody"])
AC_DEFINE_UNQUOTED(PRIVDROP_USER, "$_pdu", [User to privdrop to.])

# Checks for programs.
AC_PROG_INSTALL
AC_PROG_CC

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

AC_ARG_ENABLE(mad-warnings, AS_HELP_STRING([--enable-mad-warnings],
 [turn on lots of compile-time warnings, this needs GCC and is only
 really useful for development]),
 [if test "x$enableval" = "xyes" ; then
   AC_MSG_CHECKING(if your C compiler throws mad warnings)
   save_cflags="$CFLAGS"
   CFLAGS="$CFLAGS -fdiagnostics-show-option \
-Wabi \
-Waddress \
-Waggregate-return \
-Wall \
-Warray-bounds \
-Wbad-function-cast \
-Wcast-align \
-Wcast-qual \
-Wchar-subscripts \
-Wclobbered \
-Wcomment \
-Wcoverage-mismatch \
-Wdeclaration-after-statement \
-Wdisabled-optimization \
-Wempty-body \
-Wextra \
-Wfloat-equal \
-Wformat \
-Wformat=2 \
-Wformat-nonliteral \
-Wformat-security \
-Wformat-y2k \
-Wignored-qualifiers \
-Wimplicit \
-Wimplicit-function-declaration \
-Wimplicit-int \
-Winit-self \
-Winline \
-Winvalid-pch \
-Wlogical-op \
-Wlong-long \
-Wmain \
-Wmissing-braces \
-Wmissing-declarations \
-Wmissing-field-initializers \
-Wmissing-format-attribute \
-Wmissing-include-dirs \
-Wmissing-noreturn \
-Wmissing-parameter-type \
-Wmissing-prototypes \
-Wnested-externs \
-Wnonnull \
-Wold-style-declaration \
-Wold-style-definition \
-Wpacked \
-Wpacked-bitfield-compat \
-Wparentheses \
-Wpointer-arith \
-Wpointer-sign \
-Wredundant-decls \
-Wreturn-type \
-Wsequence-point \
-Wshadow \
-Wsign-compare \
-Wstrict-aliasing -fstrict-aliasing \
-Wstrict-overflow=5 -fstrict-overflow \
-Wstrict-prototypes \
-Wswitch \
-Wswitch-default \
-Wswitch-enum \
-Wsync-nand \
-Wtrigraphs \
-Wtype-limits \
-Wundef \
-Wuninitialized \
-Wunknown-pragmas \
-Wunsafe-loop-optimizations \
-Wunused \
-Wunused-function \
-Wunused-label \
-Wunused-parameter \
-Wunused-value \
-Wunused-variable \
-Wvariadic-macros \
-Wvla \
-Wvolatile-register-var \
-Wwrite-strings \
"

# the above are valid for gcc version 4.4.3
# we skip:
#-pedantic
#-Wc++-compat
#-Wconversion
#-Wfatal-errors
#-Wpadded
#-Wsign-conversion
#-Wstack-protector
#-Wsystem-headers
#-Wtraditional
#-Wtraditional-conversion
#-Wunreachable-code

   if (eval $ac_link) 2>/dev/null; then
    AC_MSG_RESULT(sure does)
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

If you are using a package-based operating system (like
something with RPMs), see if there is a zlib-devel package
that you can install, to provide the zlib headers and
libraries.

$RULE
END
 AC_MSG_ERROR([can't find usable zlib])])



# Check for Solaris.
# Must do at least socket and nsl before checking for libpcap.
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(resolv, inet_aton)



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

darkstat absolutely requires libpcap to be installed.  If
it's installed into a prefix that isn't being picked up by
configure, for example /usr/local, re-run configure and add
--with-pcap=/usr/local

If you are using a package-based operating system (like
something with RPMs), see if there is a pcap-devel or
libpcap-devel package that you can install, to provide the
pcap headers and libraries.

Failing all of the above, go to http://www.tcpdump.org/ and
download the source distribution of libpcap and build it
yourself.

$RULE
END_MSG
 AC_MSG_ERROR([can't find usable libpcap])
fi



# A real OS will have setproctitle()
AC_SEARCH_LIBS(setproctitle, [bsd],
 AC_DEFINE(HAVE_SETPROCTITLE, 1,
  [Define to 1 if you have setproctitle().]))

# A real OS will have safe string functions
AC_SEARCH_LIBS(strlcpy, [bsd],
 AC_DEFINE(HAVE_STRLCPY, 1,
  [Define to 1 if you have strlcpy().]))

AC_SEARCH_LIBS(strlcat, [bsd],
 AC_DEFINE(HAVE_STRLCAT, 1,
  [Define to 1 if you have strlcat().]))

AC_SEARCH_LIBS(strtonum, [bsd],
 AC_DEFINE(HAVE_STRTONUM, 1,
  [Define to 1 if you have strtonum(3).]))

# Some OSes (Solaris) need sys/sockio.h for SIOCGIFADDR
AC_CHECK_HEADERS(sys/sockio.h)

# Some OSes (Solaris) need sys/filio.h for FIONBIO
AC_CHECK_HEADERS(sys/filio.h)

# GNU/kfreebsd needs net/if_ether.h for ETH_P_IPV6
AC_CHECK_HEADERS(net/if_ether.h)

AC_CONFIG_FILES([Makefile darkstat.8])
AC_OUTPUT
