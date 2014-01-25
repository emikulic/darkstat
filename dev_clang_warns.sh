#!/bin/sh -x
#
# Build with lots of Clang warnings enabled.
#
TARGET=dev_all.c

# Adjust to suit:
LLVM=$HOME/llvm
CLANG=$LLVM/install/bin/clang

$CLANG -Weverything -Wno-padded -Wno-format-non-iso -Wno-cast-align \
  -Wno-disabled-macro-expansion -O -c $TARGET
