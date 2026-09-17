#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
if [ "$(protoc --version)" != 'libprotoc 35.1' ]; then
    echo 'protoc 35.1 is required' >&2
    exit 1
fi
tools_dir=$(mktemp -d)
trap 'rm -rf "$tools_dir"' EXIT HUP INT TERM
GOBIN="$tools_dir" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
GOBIN="$tools_dir" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
PATH="$tools_dir:$PATH" protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative api/spf/v1/spf.proto
