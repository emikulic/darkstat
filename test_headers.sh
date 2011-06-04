#!/bin/sh
# copyright (c) 2011 Emil Mikulic.

a="\033[31;1m"
z="\033[m"

# Except for the c-ify output, every header should bring in all of its
# dependencies, and be able to be included multiple times.
src=_test_hdr.c
obj=_test_hdr.o
files=`ls *.h | fgrep -v -e graphjs.h -e stylecss.h`

for f in $files; do
  cat >$src <<EOF
#include "$f"
void test_hdr_do_nothing(void) { }
EOF
  if ! gcc -c $src 2>/dev/null; then
    echo "${a}===> $f can't be included by itself${z}"
    gcc -c $src
  else
    cat >$src <<EOF
#include "$f"
#include "$f"
void test_hdr_do_nothing(void) { }
EOF
    if ! gcc -c $src 2>/dev/null; then
      echo "${a}===> $f can't be included twice${z}"
      gcc -c $src
    fi
  fi
done

rm $src $obj
