package spf

import (
	"os"
	"testing"
)

var testResolver Resolver

func TestMain(m *testing.M) {
	testResolver = NewMiekgDNSResolver(localDNSAddr)
	os.Exit(m.Run())
}
