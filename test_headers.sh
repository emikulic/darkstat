#!/bin/sh
# copyright (c) 2011-2012 Emil Mikulic.

a="\033[33;1m"
z="\033[m"
problem=0

check_deps() {
  echo checking header dependencies...
  # Except for the c-ify output, every header should bring in all of its
  # dependencies, and be able to be included multiple times.
  src=_test_hdr.c
  obj=_test_hdr.o
  files=`ls *.h | fgrep -v -e graphjs.h -e stylecss.h -e favicon.h`

  for f in $files; do
    echo " * $f"
    cat >$src <<EOF
#include "$f"
void test_hdr_do_nothing(void) { }
EOF
    if ! gcc -c $src 2>/dev/null; then
      echo "${a}===> $f can't be included by itself${z}"
      problem=1
      gcc -c $src
    else
      cat >$src <<EOF
#include "$f"
#include "$f"
void test_hdr_do_nothing(void) { }
EOF
      if ! gcc -c $src 2>/dev/null; then
        echo "${a}===> $f can't be included twice${z}"
        problem=1
        gcc -c $src
      fi
    fi
  done

  rm $src $obj
}

check_defines() {
  header=$1
  defines="(^|[^a-zA-Z_])($2)"
  files=$3

  echo checking $header users...

  # Check that files expecting defines include it.
  for file in `egrep -l "$defines" $files`; do
    if ! fgrep -q '#include "'$header'"' $file; then
      echo "${a}===> $file should include $header${z}"
      problem=1
      egrep --color=always "$defines" $file
    fi
  done

  # And that others don't.
  for file in `fgrep -l '#include "'$header'"' *.[ch]`; do
   if ! egrep -q "$defines" $file; then
    echo "${a}===> $file should not include $header${z}"
    problem=1
   fi
  done
}

# -=-

check_deps

# Check config.h: build a list of macros that are or could be defined.
defines=`egrep '#define|#undef' config.h | cut -d# -f2 | cut -d' ' -f2 |
  sort -u | tr '\n' '|' | sed -e 's/|$//'`
# Check against all files except itself.
files=`ls *.[ch] | fgrep -v config.h`
#echo "config.h defines: ($defines)"
check_defines config.h "$defines" "$files"

defines=`sed -e 's/# \+/#/;' < cdefs.h | grep '#define' | cut -d' ' -f2 |
  sed -e 's/(.\+/\\\\(/' | tr '\n' '|' | sed -e 's/|$//'`
files=`ls *.[ch] | fgrep -v -e cdefs.h -e graphjs.h -e stylecss.h`
check_defines cdefs.h "$defines" "$files"

exit $problem

# vim:set ts=2 sw=2 et:
