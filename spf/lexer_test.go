package spf

import (
	"reflect"
	"testing"
)

type LexerTest struct {
	input  string
	tokens []*Token
}

func TestLexerNext(t *testing.T) {
	spfRecord := "a:127.0.0.1"
	lexer := &Lexer{0, 0, 0, len(spfRecord), spfRecord}

	for i, char := range spfRecord {
		if i != lexer.pos {
			t.Error("At position ", i, " lexer.pos is ", lexer.pos)
		}
		lexChar, _ := lexer.next()
		if char != lexChar {
			t.Error("Expected character ", char, " got ", lexChar)
		}
	}

	if lexer.eof() == false {
		t.Error("Expected lexer to indicate EOF (didn't happen).")
	}
	if lexer.start != 0 {
		t.Error("For record ", spfRecord, " lexer.start should be equal to 0")
	}

}

func TestLexerScanIdent(t *testing.T) {

	type TestPair struct {
		Record string
		Token  *Token
	}

	testpairs := []TestPair{
		TestPair{"v=spf1", &Token{tVersion, qPlus, "spf1"}},
		TestPair{"v=spf1 ", &Token{tVersion, qPlus, "spf1"}},
		TestPair{"a:127.0.0.1", &Token{tA, qPlus, "127.0.0.1"}},
		TestPair{"a", &Token{tA, qPlus, ""}},
		TestPair{"a:127.0.0.1 ", &Token{tA, qPlus, "127.0.0.1"}},
		TestPair{"?a:127.0.0.1   ", &Token{tA, qQuestionMark, "127.0.0.1"}},
		TestPair{"?ip6:2001::43   ", &Token{tIp6, qQuestionMark, "2001::43"}},
		TestPair{"+ip6:::1", &Token{tIp6, qPlus, "::1"}},
		TestPair{"^ip6:2001::4", &Token{tErr, qErr, ""}},
		TestPair{"-all", &Token{tAll, qMinus, ""}},
		TestPair{"-all ", &Token{tAll, qMinus, ""}},
		TestPair{"~all", &Token{tAll, qTilde, ""}},
		TestPair{"-mx:localhost", &Token{tMX, qMinus, "localhost"}},
		TestPair{"mx", &Token{tMX, qPlus, ""}},
		TestPair{"a:", &Token{tErr, qErr, ""}},
		TestPair{"?mx:localhost", &Token{tMX, qQuestionMark, "localhost"}},
		TestPair{"?random:localhost", &Token{tErr, qErr, ""}},
		TestPair{"-:localhost", &Token{tErr, qErr, ""}},
		TestPair{"", &Token{tErr, qErr, ""}},
		TestPair{"qowie", &Token{tErr, qErr, ""}},
	}

	for _, testpair := range testpairs {

		l := &Lexer{0, len(testpair.Record), len(testpair.Record) - 1,
			len(testpair.Record), testpair.Record}

		ltok := l.scanIdent()
		if reflect.DeepEqual(*testpair.Token, *ltok) == false {
			t.Error("Expected token ", *testpair.Token, " got ", *ltok, " lexer: ", l)
		}
	}
}

func TestLexFunc(t *testing.T) {
	type TestPair struct {
		Record string
		Tokens []*Token
	}
	version_token := &Token{tVersion, qPlus, "spf1"}

	testpairs := []TestPair{
		TestPair{"v=spf1 a:127.0.0.1",
			[]*Token{
				version_token,
				&Token{tA, qPlus, "127.0.0.1"}}},
		TestPair{"v=spf1 ip4:127.0.0.1 -all",
			[]*Token{
				version_token,
				&Token{tIp4, qPlus, "127.0.0.1"},
				&Token{tAll, qMinus, ""}}},
		TestPair{"v=spf1  -ptr:arpa.1.0.0.127   -all  ",
			[]*Token{
				version_token,
				&Token{tPTR, qMinus, "arpa.1.0.0.127"},
				&Token{tAll, qMinus, ""}}},
		TestPair{"v=spf1  ~ip6:2001:db8::cd30 ?all  ",
			[]*Token{
				version_token,
				&Token{tIp6, qTilde, "2001:db8::cd30"},
				&Token{tAll, qQuestionMark, ""}}},
		TestPair{"v=spf1  include:example.org -all  ",
			[]*Token{
				version_token,
				&Token{tInclude, qPlus, "example.org"},
				&Token{tAll, qMinus, ""}}},
		TestPair{"v=spf1  include=example.org -all  ",
			[]*Token{
				version_token,
				&Token{tErr, qErr, ""},
				&Token{tAll, qMinus, ""}}},
		TestPair{"v=spf1  exists:%{ir}.%{l1r+-}._spf.%{d} +all",
			[]*Token{
				version_token,
				&Token{tExists, qPlus, "%{ir}.%{l1r+-}._spf.%{d}"},
				&Token{tAll, qPlus, ""}}},
		TestPair{"v=spf1  redirect=_spf.example.org",
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.org"}}},
		TestPair{"v=spf1 mx -all exp=explain._spf.%{d}",
			[]*Token{
				version_token,
				&Token{tMX, qPlus, ""},
				&Token{tAll, qMinus, ""},
				&Token{tExp, qPlus, "explain._spf.%{d}"}}},
	}

	for _, testpair := range testpairs {

		ltok := Lex(testpair.Record)
		if reflect.DeepEqual(testpair.Tokens, ltok) == false {
			t.Error("Expected tokens ", testpair.Tokens, " got ", ltok)
		}
	}

}
