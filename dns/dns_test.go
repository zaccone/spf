package dns

import (
	"testing"
)

type spfTestpair struct {
	query    []string
	expected bool
}

func TestSPFValidator(t *testing.T) {
	queries := []spfTestpair{
		{[]string{"v=spf1"}, true},
		{[]string{"v=spf1 "}, true},
		{[]string{"v=spf10"}, false},
		{[]string{"v=spf11 "}, false},
		{[]string{"v=spf1 mx -all"}, true},
		{[]string{"v=spf1", "mx", "-all"}, true},
		{[]string{"random string"}, false},
	}

	for _, testcase := range queries {
		result := checkSPFVersion(testcase.query)
		if result != testcase.expected {
			t.Error(
				"Query: ", testcase.query, "got",
				result, "instead of", testcase.expected)
		}
	}
}
