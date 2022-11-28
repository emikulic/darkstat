#!/bin/sh
#
# release.sh: script to roll a release tarball of darkstat.
# copyright (c) 2006-2016 Emil Mikulic.
#
# This is for developer use only and lives in the repo but
# shouldn't end up in a tarball.
#
# Release checklist:
#  - git tag 3.0.xxx
#  - git push --tags
#  - Update website
#  - Mail announcement to darkstat-announce@googlegroups.com
#  - Update FreeBSD port, e.g.:
#    https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=200425
#
if [ $# -ne 1 ]; then
  echo "usage: $0 3.0.0rc0" >&2
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
README.md \
acct.c \
acct.h \
addr.c \
addr.h \
bsd.c \
bsd.h \
cap.c \
cap.h \
cdefs.h \
contrib \
conv.c \
conv.h \
darkstat.8.in \
darkstat.c \
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
favicon.h \
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
now.c \
now.h \
opt.h \
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
  echo "==>" "$@" >&2
}

run() {
  say "$@"
  "$@" || { say ERROR!; exit 1; }
}

PKG=$NAME-$VERSION
say releasing "$PKG"
run make depend
run make graphjs.h stylecss.h
run autoconf
run autoheader
run ./config.status
run ./test_headers.sh
if git status --porcelain | grep -vE '^\?\?' -q; then
  say ERROR: uncommitted changes:
  git status
  exit 1
fi
run mkdir "$PKG"
run cp -r "$files" "$PKG"/.
run sed -e "/AC_INIT/s/3.0.0-git/$VERSION/" configure.ac > "$PKG"/configure.ac
say version set to: "$(grep '^AC_INIT' "$PKG"/configure.ac)"
(cd "$PKG"
 run autoconf
 run autoheader
 run rm -r autom4te.cache
) || exit 1

# package it up
run tar chof "$PKG".tar "$PKG"
run bzip2 -9vv "$PKG".tar
say output:
ls -l "$PKG".tar.bz2
say FINISHED!
