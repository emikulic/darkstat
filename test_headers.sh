#!/bin/sh
# copyright (c) 2011 Emil Mikulic.
#
# The rule is that every header has to bring in all of its dependencies.
#
# This script tests to make sure it's true: for each header file,
# test-compile a C source file that includes just the header.
#
# Also test that it can be included twice without problems.
#
src=_test_hdr.c
obj=_test_hdr.o

if [ $# -eq 0 ]; then
  echo "usage: $0 *.h" >&2
  exit 1
fi

for f in $*; do
  cat >$src <<EOF
#include "$f"
void test_hdr_do_nothing(void) { }
EOF
  if gcc -c $src 2>/dev/null; then
    true
  else
    echo "===> FAIL: $f <==="
    gcc -c $src
  fi

  cat >$src <<EOF
#include "$f"
#include "$f"
void test_hdr_do_nothing(void) { }
EOF
  if gcc -c $src 2>/dev/null; then
    true
  else
    echo "===> FAIL DOUBLE: $f <==="
    gcc -c $src
  fi
done

rm $src $obj
