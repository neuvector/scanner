#!/bin/bash

# This script is invoked by build container

./unitest.sh || exit $?

echo "==> Making binary"
make || exit $?
