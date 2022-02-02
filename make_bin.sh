#!/bin/bash

# This script is invoked by build container

go test github.com/neuvector/scanner/... || exit $?

echo "==> Making monitor"
cd monitor; make || exit $?; cd ..

echo "==> Making scanner"
make || exit $?; cd ..
cd task; make || exit $?; cd ../..
