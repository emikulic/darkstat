#!/bin/sh -x
#
# Build with lots of Clang warnings enabled.
#
TARGET=dev_all.c

# Adjust to suit:
LLVM=$HOME/llvm
CLANG=$LLVM/install/bin/clang

$CLANG -Weverything -O -c $TARGET
