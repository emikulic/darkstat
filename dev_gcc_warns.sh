#!/bin/sh -x
#
# Build with lots of GCC warnings enabled.
#
TARGET=dev_all.c

gcc -O -c -fstrict-aliasing --all-warnings --extra-warnings $TARGET
