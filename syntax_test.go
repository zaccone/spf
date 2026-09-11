package spf

import "testing"

func TestDomainSpecSyntax(t *testing.T) {
	tests := []struct {
		value string
		valid bool
	}{
		{"example.com", true}, {"example.com.", true}, {"_spf.example.com", true},
		{"%{d}", true}, {"%{l1r+-}._spf.%{d}", true}, {"%{D2R/}.example.com", true},
		{"example.1-a", true}, {"example.a--1", true}, {"example.123", false},
		{"example.-a", false}, {"example.a-", false}, {"example.c_m", false},
		{"localhost", false}, {"%{z}", false}, {"%{d0}", false}, {"%{d01}", true},
		{"%{d999999999999999999999999}", true}, {"%{d2r-+/=}", true},
		{"%{d2rr}", false}, {"%{d2!}", false}, {"%{c}", false}, {"%", false},
		{"%%", true}, {"%_", true}, {"%-", true},
		// RFC 7208 section 7.1 permits visible macro literals. Expanded DNS
		// name validity is a separate evaluation concern (section 5).
		{"foo/bar.example.com", true}, {"foo..example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := validDomainSpec(tt.value); got != tt.valid {
				t.Fatalf("got %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestDualCIDRSyntax(t *testing.T) {
	tests := []struct {
		value, domain string
		v4, v6        int
	}{
		{"", "", 32, 128}, {"/24", "", 24, 128}, {"//64", "", 32, 64},
		{"/0//0", "", 0, 0}, {"example.com/32//128", "example.com", 32, 128},
		{"%{d/}/24//64", "%{d/}", 24, 64},
		{"foo/bar.example.com/24", "foo/bar.example.com", 24, 128},
		{"example.a1/24//64", "example.a1", 24, 64},
		{"example.a1//64", "example.a1", 32, 64},
		{"example.a1/24", "example.a1", 24, 128},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			domain, m4, m6, err := splitDomainDualCIDR(tt.value)
			n4, _ := m4.Size()
			n6, _ := m6.Size()
			if err != nil || domain != tt.domain || n4 != tt.v4 || n6 != tt.v6 {
				t.Fatalf("got (%q, %d, %d, %v)", domain, n4, n6, err)
			}
		})
	}
	for _, value := range []string{"/", "//", "/01", "//00", "/24/64", "/24/", "/24///64", "/33", "//129", "/+1", "/-1"} {
		if _, _, _, err := splitDomainDualCIDR(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func FuzzLexer(f *testing.F) {
	for _, seed := range []string{"", "v=spf1 +all", "v=spf1 a/24 mx//64", "v=spf1 exists:%{l1r+-}._spf.%{d}", "\xff\t\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, query string) {
		tokens := lex(query)
		if len(tokens) > len(query) {
			t.Fatal("lexer emitted more tokens than input bytes")
		}
	})
}

func FuzzParserSyntax(f *testing.F) {
	for _, seed := range []string{"", "v=spf1 +all ip4:garbage", "v=spf1 x= x=again +all", "v=spf1 a:%{d/}/24//64", "v=spf1 exp=%{d999999999999999999}"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, query string) {
		tokens := lex(query)
		if validateRecord(query, tokens) == nil {
			// Exercise the complete parser syntax stage without DNS evaluation,
			// recursion, or macro expansion (separate modernization steps).
			p := newParser("sender@example.com", "example.com", nil, query, nil)
			_ = p.sortTokens(tokens)
		}
	})
}
