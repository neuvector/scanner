#!/bin/bash

go test github.com/neuvector/scanner/... || exit $?
