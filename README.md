# Sender Policy Framework

A comprehensive RFC7208 implementation

[![Build Status](https://github.com/zaccone/spf/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/zaccone/spf/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/zaccone/spf)](https://goreportcard.com/report/github.com/zaccone/spf)
[![GoDoc](https://godoc.org/github.com/zaccone/spf?status.svg)](https://godoc.org/github.com/zaccone/spf)

## About
The SPF Library implements Sender Policy Framework described in RFC 7208. It aims to cover all rough edge cases from RFC 7208.
Hence, the library does not operate on strings only, rather "understands" SPF records and reacts properly to valid and invalid 
input. Wherever I found it useful, I added comments with RFC sections and quotes directly in the source code, so the readers can follow 
implemented logic.

## Current status
The library is still under development. API may change, including function/methods names and signatures. I will consider it correct and stable once it passess all tests described in the most popular SPF implementation - pyspf.

## Building and testing

Go 1.27 or later is required. Use the latest patch release of Go 1.27;
this build setup was verified with Go 1.27.1.

From the repository root:

```sh
go mod download
go mod verify
go build ./...
go test -count=1 -timeout=60s ./...
go vet ./...
```

DNS tests each own a server on an ephemeral UDP port on loopback. They require
local socket access, but no public DNS or installed BIND server. The `_etc/bind`
files are historical fixtures.

To check for races:

```sh
go test -race -count=1 -timeout=60s ./...
```

GitHub Actions runs ordinary tests on Linux, macOS, and Windows, plus race
tests, vet, formatting, and module consistency checks on Linux. Resolver
callbacks finish before a lookup returns. Passing these checks does not
establish complete RFC 7208 conformance; see the modernization plan for the
remaining correctness work.

## Dependencies
The library uses [miekg/dns](https://github.com/miekg/dns) for its configurable
DNS resolver. The SPF lexer, parser, and macro implementation remain part of
this project. Dependency versions and checksums are recorded in `go.mod` and
`go.sum`; normal builds do not need `go get` or a GOPATH checkout.

## Pull requests & code review
If you have any comments about code structure feel free to reach out or simply make a Pull Request
