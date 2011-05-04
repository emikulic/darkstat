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
hosts_db.c \
hosts_db.h \
hosts_sort.c \
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
tree.h \
"
# end packing list

PKG=$NAME-$VERSION
echo ==\> releasing $PKG

run() {
  echo ==\> $@
  eval $@ || { echo ERROR!; exit 1; }
}

run mkdir $PKG
run cp -r $files $PKG/.

# set the version number
(echo "AC_INIT(darkstat, $VERSION)"
 grep -v "^AC_INIT" configure.ac) > $PKG/configure.ac

echo ==\> set version: `grep '^AC_INIT' $PKG/configure.ac`
(
 cd $PKG
 run autoconf
 run autoheader
 run rm -r autom4te.cache
)

# package it up
run tar -cf $PKG.tar $PKG
run bzip2 -9vv $PKG.tar
echo ==\> output:
ls -l $PKG.tar.bz2
echo ==\> FINISHED!
