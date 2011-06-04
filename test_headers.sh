#!/bin/sh
# copyright (c) 2011 Emil Mikulic.

a="\033[31;1m"
z="\033[m"

echo checking header dependencies...
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

echo checking config.h users...
# Make list of possible defines from config.h
defines=`grep \# config.h | cut -d# -f2 | cut -d' ' -f2`
defines=`echo $defines | tr ' ' '|'`

files=`ls *.[ch] | fgrep -v config.h`

# Check that files expecting defines from config.h include it.
for file in `egrep -l $defines $files`; do
 if ! fgrep -q '#include "config.h"' $file; then
  echo "${a}===> $file should include config.h${z}"
  egrep $defines $file
 fi
done

# And that others don't.
for file in `fgrep -l '#include "config.h"' *.[ch]`; do
 if ! egrep -q $defines $file; then
  echo "${a}===> $file should not include config.h${z}"
 fi
done
