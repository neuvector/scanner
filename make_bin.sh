#!/bin/bash

# This script is invoked by build container

./unitest.sh || exit $?

echo "==> Making monitor"
cd monitor; make || exit $?; cd ..

echo "==> Making scanner"
make || exit $?
cd task; make || exit $?; cd ../..
