#!/bin/bash -x
#
# Run the clang static analyzer.
#
time $HOME/llvm/install/bin/scan-build \
  -analyze-headers \
\
  -enable-checker alpha.core.BoolAssignment \
  -enable-checker alpha.core.CallAndMessageUnInitRefArg \
  -enable-checker alpha.core.CastSize \
  -enable-checker alpha.core.CastToStruct \
  -enable-checker alpha.core.DynamicTypeChecker \
  -enable-checker alpha.core.FixedAddr \
  -enable-checker alpha.core.IdenticalExpr \
  -enable-checker alpha.core.PointerArithm \
  -enable-checker alpha.core.PointerSub \
  -enable-checker alpha.core.SizeofPtr \
  -enable-checker alpha.core.TestAfterDivZero \
  -enable-checker alpha.cplusplus.VirtualCall \
  -enable-checker alpha.deadcode.UnreachableCode \
  -enable-checker alpha.security.ArrayBound \
  -enable-checker alpha.security.ArrayBoundV2 \
  -enable-checker alpha.security.MallocOverflow \
  -enable-checker alpha.security.ReturnPtrRange \
  -enable-checker alpha.security.taint.TaintPropagation \
  -enable-checker alpha.unix.Chroot \
  -enable-checker alpha.unix.PthreadLock \
  -enable-checker alpha.unix.SimpleStream \
  -enable-checker alpha.unix.Stream \
  -enable-checker alpha.unix.cstring.BufferOverlap \
  -enable-checker alpha.unix.cstring.NotNullTerminated \
  -enable-checker alpha.unix.cstring.OutOfBounds \
  -enable-checker llvm.Conventions \
  -enable-checker nullability.NullableDereferenced \
  -enable-checker nullability.NullablePassedToNonnull \
  -enable-checker nullability.NullablePassedToNonnull \
  -enable-checker optin.performance.Padding \
  -enable-checker security.FloatLoopCounter \
  -enable-checker security.insecureAPI.rand \
  -enable-checker security.insecureAPI.strcpy \
\
  '$CC -c dev_all.c'
