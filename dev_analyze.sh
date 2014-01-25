#!/bin/sh -x
#
# Run the clang static analyzer.
#
TARGET=dev_all.c

# Adjust to suit:
LLVM=$HOME/llvm
CHECKER=$LLVM/llvm/tools/clang/tools/scan-build/ccc-analyzer
CLANG=$LLVM/install/bin/clang

$LLVM/llvm/tools/clang/tools/scan-build/scan-build \
  -analyze-headers \
  --use-analyzer=$LLVM/install/bin/clang \
  $CLANG -c $TARGET
