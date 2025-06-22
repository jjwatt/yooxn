#!/bin/sh -e

clang-format -i circle128.c
rm -f circle128
cc -lm -o circle128 circle128.c
./circle128 64
