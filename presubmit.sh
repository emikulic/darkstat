#!/bin/sh
# darkstat 3
# copyright (c) 2022 Emil Mikulic.
#
# Run ./presubmit.sh before committing code.

say() {
  echo "==>" "$@" >&2
}

run() {
  say "$@"
  "$@" || { say ERROR!; exit 1; }
}

run ./config.status
run ./tidy_linktypes_list.sh
run make depend
run ./test_headers.sh
run make clean
run make check
