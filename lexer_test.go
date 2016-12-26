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
		{"v=spf1", &Token{tVersion, qPlus, "spf1"}},
		{"v=spf1 ", &Token{tVersion, qPlus, "spf1"}},
		{"a:127.0.0.1", &Token{tA, qPlus, "127.0.0.1"}},
		{"a", &Token{tA, qPlus, ""}},
		{"a:127.0.0.1 ", &Token{tA, qPlus, "127.0.0.1"}},
		{"?a:127.0.0.1   ", &Token{tA, qQuestionMark, "127.0.0.1"}},
		{"?ip6:2001::43   ", &Token{tIP6, qQuestionMark, "2001::43"}},
		{"+ip6:::1", &Token{tIP6, qPlus, "::1"}},
		{"^ip6:2001::4", &Token{tErr, qErr, ""}},
		{"-all", &Token{tAll, qMinus, ""}},
		{"-all ", &Token{tAll, qMinus, ""}},
		{"~all", &Token{tAll, qTilde, ""}},
		{"-mx:localhost", &Token{tMX, qMinus, "localhost"}},
		{"mx", &Token{tMX, qPlus, ""}},
		{"a:", &Token{tErr, qErr, ""}},
		{"?mx:localhost", &Token{tMX, qQuestionMark, "localhost"}},
		{"?random:localhost", &Token{tErr, qErr, ""}},
		{"-:localhost", &Token{tErr, qErr, ""}},
		{"", &Token{tErr, qErr, ""}},
		{"qowie", &Token{tErr, qErr, ""}},
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
	versionToken := &Token{tVersion, qPlus, "spf1"}

	testpairs := []TestPair{
		{"v=spf1 a:127.0.0.1",
			[]*Token{
				versionToken,
				{tA, qPlus, "127.0.0.1"}}},
		{"v=spf1 ip4:127.0.0.1 -all",
			[]*Token{
				versionToken,
				{tIP4, qPlus, "127.0.0.1"},
				{tAll, qMinus, ""}}},
		{"v=spf1  -ptr:arpa.1.0.0.127   -all  ",
			[]*Token{
				versionToken,
				{tPTR, qMinus, "arpa.1.0.0.127"},
				{tAll, qMinus, ""}}},
		{"v=spf1  ~ip6:2001:db8::cd30 ?all  ",
			[]*Token{
				versionToken,
				{tIP6, qTilde, "2001:db8::cd30"},
				{tAll, qQuestionMark, ""}}},
		{"v=spf1  include:example.org -all  ",
			[]*Token{
				versionToken,
				{tInclude, qPlus, "example.org"},
				{tAll, qMinus, ""}}},
		{"v=spf1  include=example.org -all  ",
			[]*Token{
				versionToken,
				{tErr, qErr, ""},
				{tAll, qMinus, ""}}},
		{"v=spf1  exists:%{ir}.%{l1r+-}._spf.%{d} +all",
			[]*Token{
				versionToken,
				{tExists, qPlus, "%{ir}.%{l1r+-}._spf.%{d}"},
				{tAll, qPlus, ""}}},
		{"v=spf1  redirect=_spf.example.org",
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.org"}}},
		{"v=spf1 mx -all exp=explain._spf.%{d}",
			[]*Token{
				versionToken,
				{tMX, qPlus, ""},
				{tAll, qMinus, ""},
				{tExp, qPlus, "explain._spf.%{d}"}}},
	}

	for _, testpair := range testpairs {

		ltok := Lex(testpair.Record)
		if reflect.DeepEqual(testpair.Tokens, ltok) == false {
			t.Error("Expected tokens ", testpair.Tokens, " got ", ltok)
		}
	}

}
