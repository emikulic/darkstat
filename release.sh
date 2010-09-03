#!/bin/sh
#
# release.sh: script to roll a release tarball of darkstat.
# copyright (c) 2006-2009 Emil Mikulic.
#
# This is for developer use only and lives in the repo but
# shouldn't end up in a tarball.
#
# Remember to run "./test_headers.sh *.h"
# Remember to run "make depend" to update deps in Makefile.in
#

if [ $# -ne 1 ]; then
  echo "usage: $0 version" >&2
  exit 1
fi

NAME=darkstat
VERSION="$1"

files="\
AUTHORS \
ChangeLog \
COPYING.GPL \
INSTALL \
LICENSE \
Makefile.in \
NEWS \
README \
acct.c \
acct.h \
addr.c \
addr.h \
cap.c \
cap.h \
contrib \
conv.c \
conv.h \
darkstat.8.in \
darkstat.c \
darkstat.h \
daylog.c \
daylog.h \
db.c \
db.h \
decode.c \
decode.h \
dns.c \
dns.h \
err.c \
err.h \
export-format.txt \
graph_db.c \
graph_db.h \
graphjs.h \
hosts_db.c \
hosts_db.h \
hosts_sort.c \
html.c \
html.h \
http.c \
http.h \
install-sh \
localip.c \
localip.h \
ncache.c \
ncache.h \
now.h \
pidfile.c \
pidfile.h \
queue.h \
static \
str.c \
str.h \
stylecss.h \
tree.h \
"
# end packing list

say() {
  echo ==\> "$@" >&2
}

PKG=$NAME-$VERSION
say releasing $PKG

run() {
  say "$@"
  "$@" || { say ERROR!; exit 1; }
}

run mkdir $PKG
run cp -r $files $PKG/.

# set the version number
(echo "AC_INIT(darkstat, $VERSION)"
 grep -v "^AC_INIT" configure.ac) > $PKG/configure.ac

say set version: `grep '^AC_INIT' $PKG/configure.ac`
(
 cd $PKG
 run autoconf
 run autoheader
 run rm -r autom4te.cache
)

# package it up
run tar -cf $PKG.tar $PKG
run bzip2 -9vv $PKG.tar
say output:
ls -l $PKG.tar.bz2
say FINISHED!
