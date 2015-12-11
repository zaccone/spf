package spf

import (
	"net"
	"reflect"
	"testing"
)

var ip net.IP = net.IP{127, 0, 0, 1}

const stub string = "stub"

func testNewParserFunction(t *testing.T) {
	//stub := "stub"
	p := NewParser(stub, stub, ip, stub)

	if p.Sender != stub {
		t.Error("Sender mismatch, got: ", p.Sender, " expected ", stub)
	}
	if p.Domain != stub {
		t.Error("Domain mismatch, got: ", p.Domain, " expected ", stub)
	}
	if p.Query != stub {
		t.Error("Query mismatch, got: ", p.Query, " expected ", stub)
	}
	if !ip.Equal(p.Ip) {
		t.Error("IP mismatch, got: ", p.Ip, " expected ", ip)
	}
	if p.Redirect != nil || p.Explanation != nil {
		t.Error("Parser Redirect and Explanation must be nil, ", p)
	}
}

func TestMatchingResult(t *testing.T) {

	type TestCase struct {
		Qualifier tokenType
		Result    SPFResult
	}

	testcases := []TestCase{
		TestCase{qPlus, Pass},
		TestCase{qMinus, Fail},
		TestCase{qQuestionMark, Neutral},
		TestCase{qTilde, Softfail},
	}

	var result SPFResult
	var err error
	for _, testcase := range testcases {
		result, err = matchingResult(testcase.Qualifier)
		if err != nil {
			t.Error("Qualifier ", testcase.Qualifier, " returned error: ",
				err, " (it shouldn't)")
		}
		if result != testcase.Result {
			t.Error("Expected result ", testcase.Result, " got ", result)
		}
	}

	// ensure an error will be returned upon invalid qualifier
	result, err = matchingResult(tAll)
	if err == nil {
		t.Error("matchingResult expected to fail")
	}

	if result != SPFEnd {
		t.Error(`Upon failure matchingResult expected to return result SPFEnd,
                 instead got `, result)
	}
}

func TestTokensSoriting(t *testing.T) {
	//stub := "stub"
	version_token := &Token{tVersion, qPlus, "spf1"}
	type TestCase struct {
		Tokens      []*Token
		ExpTokens   []*Token
		Redirect    *Token
		Explanation *Token
	}

	testcases := []TestCase{
		TestCase{
			[]*Token{
				version_token,
				&Token{tAll, qMinus, ""},
			},
			[]*Token{
				version_token,
				&Token{tAll, qMinus, ""},
			},
			nil,
			nil,
		},
		TestCase{
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qTilde, "example.org"},
			},
			[]*Token{
				version_token,
				&Token{tMX, qTilde, "example.org"},
			},
			&Token{tRedirect, qPlus, "_spf.example.com"},
			nil,
		},
		TestCase{
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tIp4, qTilde, "192.168.1.2"},
				&Token{tExp, qPlus, "Something went wrong"},
			},
			[]*Token{
				version_token,
				&Token{tIp4, qTilde, "192.168.1.2"},
			},
			&Token{tRedirect, qPlus, "_spf.example.com"},
			&Token{tExp, qPlus, "Something went wrong"},
		},
		TestCase{
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
			},
			[]*Token{
				version_token,
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
			},
			nil,
			nil,
		},
		TestCase{
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
				&Token{tExp, qPlus, "You are wrong"},
			},
			[]*Token{
				version_token,
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
			},
			nil,
			&Token{tExp, qPlus, "You are wrong"},
		},
	}

	for _, testcase := range testcases {
		p := NewParser(stub, stub, ip, stub)
		p.sortTokens(testcase.Tokens)

		if !reflect.DeepEqual(p.Mechanisms, testcase.ExpTokens) {
			t.Error("Mechanisms mistmatch, got: ", p.Mechanisms,
				" expected: ", testcase.ExpTokens)
		}
		if !reflect.DeepEqual(p.Redirect, testcase.Redirect) {
			t.Error("Expected Redirect to be", testcase.Redirect,
				" got ", p.Redirect)
		}
		if !reflect.DeepEqual(p.Explanation, testcase.Explanation) {
			t.Error("Expected Explanation to be", testcase.Explanation,
				" got ", p.Explanation, " testcase ", p.Explanation, p.Redirect)
		}

	}

}

func TestTokensSoritingHandleErrors(t *testing.T) {
	stub := "stub"
	version_token := &Token{tVersion, qPlus, "spf1"}
	type TestCase struct {
		Tokens []*Token
	}

	testcases := []TestCase{
		TestCase{
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qMinus, "example.org"},
				&Token{tRedirect, qPlus, "_spf.example.com"},
			},
		},
		TestCase{
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qMinus, "example.org"},
				&Token{tExp, qPlus, "Explanation"},
				&Token{tExp, qPlus, "Explanation"},
			},
		},
		TestCase{
			[]*Token{
				version_token,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tAll, qMinus, ""},
				&Token{tExp, qPlus, "_spf.example.com"},
				&Token{tRedirect, qPlus, "mydomain.com"},
			},
		},
	}

	for _, testcase := range testcases {
		p := NewParser(stub, stub, ip, stub)
		if err := p.sortTokens(testcase.Tokens); err == nil {
			t.Error("We should have gotten an error, ")
		}
	}
}

/* Test Parse.parse* methods here */

type TokenTestCase struct {
	Input  *Token
	Result SPFResult
	Match  bool
}

// TODO(marek): Add testfunction for tVersion token

func TestParseAll(t *testing.T) {
	p := NewParser(stub, stub, ip, stub)
	testcases := []TokenTestCase{
		TokenTestCase{&Token{tAll, qPlus, ""}, Pass, true},
		TokenTestCase{&Token{tAll, qMinus, ""}, Fail, true},
		TokenTestCase{&Token{tAll, qQuestionMark, ""}, Neutral, true},
		TokenTestCase{&Token{tAll, qTilde, ""}, Softfail, true},
		TokenTestCase{&Token{tAll, tErr, ""}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseAll(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseIp4(t *testing.T) {
	p := NewParser(stub, stub, ip, stub)
	testcases := []TokenTestCase{
		TokenTestCase{&Token{tIp4, qPlus, "127.0.0.1"}, Pass, true},
		TokenTestCase{&Token{tIp4, qMinus, "127.0.0.1"}, Fail, true},
		TokenTestCase{&Token{tIp4, qQuestionMark, "127.0.0.1"}, Neutral, true},
		TokenTestCase{&Token{tIp4, qTilde, "127.0.0.1"}, Softfail, true},

		TokenTestCase{&Token{tIp4, qTilde, "127.0.0.0/16"}, Softfail, true},

		TokenTestCase{&Token{tIp4, qTilde, "192.168.1.2"}, Softfail, false},
		TokenTestCase{&Token{tIp4, qMinus, "192.168.1.5/16"}, Fail, false},

		TokenTestCase{&Token{tIp4, qMinus, "random string"}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseIp4(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}
