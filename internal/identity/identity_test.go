package identity

import "testing"

func TestDomain(t *testing.T) {
	for _, tt := range []struct {
		sender, helo, want string
		invalid            bool
	}{
		{"alice@example.com", "other.example", "example.com", false},
		{`"a@b"@example.com`, "", "example.com", false},
		{"", "helo.example", "helo.example", false},
		{"<>", "helo.example", "helo.example", false},
		{"", "", "", true}, {"bad", "helo.example", "", true},
		{"@example.com", "", "", true}, {"a@", "", "", true},
		{"a\n@example.com", "", "", true},
	} {
		got, err := Domain(tt.sender, tt.helo)
		if got != tt.want || (err != nil) != tt.invalid {
			t.Errorf("%q: %q, %v", tt.sender, got, err)
		}
	}
}
func TestNormalizeSender(t *testing.T) {
	for _, sender := range []string{"", "<>", "alice@example.com", `"a<>b"@example.com`} {
		want := sender
		if sender == "<>" {
			want = ""
		}
		if got := NormalizeSender(sender); got != want {
			t.Errorf("%q: %q", sender, got)
		}
	}
}
