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
		TestPair{"a:127.0.0.1", &Token{tA, qPlus, "127.0.0.1"}},
		TestPair{"a", &Token{tA, qPlus, ""}},
		TestPair{"a:127.0.0.1 ", &Token{tA, qPlus, "127.0.0.1"}},
		TestPair{"?a:127.0.0.1   ", &Token{tA, qQuestionMark, "127.0.0.1"}},
		TestPair{"?ip6:2001::43   ", &Token{tIp6, qQuestionMark, "2001::43"}},
		TestPair{"-all", &Token{tAll, qMinus, ""}},
		TestPair{"-all ", &Token{tAll, qMinus, ""}},
		TestPair{"~all", &Token{tAll, qTilde, ""}},
		TestPair{"-mx:localhost", &Token{tMX, qMinus, "localhost"}},
		TestPair{"mx", &Token{tMX, qPlus, ""}},
		TestPair{"a:", &Token{tErr, qError, ""}},
		TestPair{"?mx:localhost", &Token{tMX, qQuestionMark, "localhost"}},
		TestPair{"?random:localhost", &Token{tErr, qError, ""}},
		TestPair{"-:localhost", &Token{tErr, qError, ""}},
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

	testpairs := []TestPair{
		TestPair{"a:127.0.0.1", []*Token{&Token{tA, qPlus, "127.0.0.1"}}},
		TestPair{"a:127.0.0.1 -all",
			[]*Token{&Token{tA, qPlus, "127.0.0.1"},
				&Token{tAll, qMinus, ""}}},
		TestPair{"a:127.0.0.1   -all  ",
			[]*Token{&Token{tA, qPlus, "127.0.0.1"},
				&Token{tAll, qMinus, ""}}},
	}

	for _, testpair := range testpairs {

		ltok := Lex(testpair.Record)
		if reflect.DeepEqual(testpair.Tokens, ltok) == false {
			t.Error("Expected tokens ", testpair.Tokens, " got ", ltok)
		}
	}

}
