package spf

import "testing"

func TestResultString(t *testing.T) {
	results := []Result{None, Neutral, Pass, Fail, Softfail,
		Temperror, Permerror}
	strs := []string{"none", "neutral", "pass", "fail", "softfail",
		"temperror", "permerror"}

	if len(results) != len(strs) {
		t.Errorf("Input lengts unqueal: results(%d), strs(%d)",
			len(results), len(strs))
	}
	for idx := 0; idx < len(results); idx++ {

		if results[idx].String() != strs[idx] {
			t.Errorf("Error calling Result.String(), got %s, expected %s",
				results[idx].String(), strs[idx])
		}
	}

}
