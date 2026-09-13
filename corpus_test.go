package spf

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type corpusRecord struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Text       []string `json:"text"`
	Preference uint16   `json:"preference"`
}
type corpusCase struct {
	HELO        string   `json:"helo"`
	Host        string   `json:"host"`
	MailFrom    string   `json:"mailfrom"`
	Result      []string `json:"result"`
	Explanation *string  `json:"explanation"`
	Receiver    string   `json:"receiver"`
	Header      string   `json:"header"`
	Strict      *int     `json:"strict"`
	Spec        string   `json:"spec"`
}
type corpusScenario struct {
	Description string                    `json:"description"`
	Tests       map[string]corpusCase     `json:"tests"`
	Zone        map[string][]corpusRecord `json:"zone"`
}
type corpus struct {
	Revision  string           `json:"revision"`
	Source    string           `json:"source"`
	SHA256    string           `json:"sha256"`
	Scenarios []corpusScenario `json:"scenarios"`
}

// corpusResolver is an isolated logical-DNS fixture. It never uses a system or
// public resolver. Transport behavior is tested separately on local UDP/TCP.
type corpusResolver struct{ zone map[string][]corpusRecord }

func corpusName(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }
func (r corpusResolver) lookup(ctx context.Context, name, kind string) ([]corpusRecord, error) {
	seen := map[string]bool{}
	for hops := 0; hops <= 10; hops++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name = corpusName(name)
		if seen[name] {
			return nil, fmt.Errorf("CNAME cycle: %w", ErrDNSTemperror)
		}
		seen[name] = true
		records, exists := r.zone[name]
		if !exists && strings.HasPrefix(name, "error.") {
			return nil, ErrDNSTemperror
		}
		var answers []corpusRecord
		alias := ""
		for _, rr := range records {
			if rr.Type == kind {
				answers = append(answers, rr)
			}
			if rr.Type == "CNAME" {
				alias = rr.Value
			}
			if rr.Type == "TIMEOUT" && len(answers) == 0 {
				return nil, ErrDNSTemperror
			}
		}
		if len(answers) > 0 {
			return answers, nil
		}
		if alias == "" {
			return nil, nil
		}
		name = alias
	}
	return nil, ErrDNSTemperror
}
func (r corpusResolver) LookupTXTContext(ctx context.Context, name string) ([]string, error) {
	records, err := r.lookup(ctx, name, "TXT")
	var result []string
	for _, rr := range records {
		result = append(result, strings.Join(rr.Text, ""))
	}
	return result, err
}
func (r corpusResolver) LookupIPContext(ctx context.Context, network, name string) ([]net.IP, error) {
	kind := "A"
	if network == "ip6" {
		kind = "AAAA"
	} else if network != "ip4" {
		return nil, fmt.Errorf("unexpected family %q", network)
	}
	records, err := r.lookup(ctx, name, kind)
	var result []net.IP
	for _, rr := range records {
		ip := net.ParseIP(rr.Value)
		if ip == nil {
			return nil, fmt.Errorf("bad corpus IP %q", rr.Value)
		}
		result = append(result, ip)
	}
	return result, err
}
func (r corpusResolver) LookupMXContext(ctx context.Context, name string) ([]*net.MX, error) {
	records, err := r.lookup(ctx, name, "MX")
	var result []*net.MX
	for _, rr := range records {
		if rr.Value != "" {
			result = append(result, &net.MX{Host: NormalizeFQDN(rr.Value), Pref: rr.Preference})
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Pref < result[j].Pref })
	return result, err
}
func (r corpusResolver) LookupAddrContext(ctx context.Context, addr string) ([]string, error) {
	name, err := dns.ReverseAddr(addr)
	if err != nil {
		return nil, err
	}
	records, err := r.lookup(ctx, name, "PTR")
	var result []string
	for _, rr := range records {
		result = append(result, NormalizeFQDN(rr.Value))
	}
	return result, err
}

type corpusDisposition struct {
	Skip         bool    `json:"skip"`
	OmitHeader   bool    `json:"omit_header"`
	IgnoreStrict bool    `json:"ignore_strict"`
	Explanation  *string `json:"explanation"`
	Reason       string  `json:"reason"`
}

func TestConformanceCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/pyspf/dispositions.json")
	if err != nil {
		t.Fatal(err)
	}
	var dispositions map[string]corpusDisposition
	if err := json.Unmarshal(data, &dispositions); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	defer func() {
		for id := range dispositions {
			if !seen[id] {
				t.Errorf("stale corpus disposition: %s", id)
			}
		}
	}()

	for _, suite := range []struct {
		file  string
		count int
	}{{"rfc7208-tests", 203}, {"test", 16}} {
		t.Run(suite.file, func(t *testing.T) {
			data, err := os.ReadFile("testdata/pyspf/" + suite.file + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var c corpus
			if err := json.Unmarshal(data, &c); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile("testdata/pyspf/" + c.Source)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(raw)) != c.SHA256 || c.Revision != "1042e9e15dd29047dc9b0a1bb77437e2fd81e775" {
				t.Fatal("corpus provenance mismatch")
			}
			count := 0
			for _, scenario := range c.Scenarios {
				names := make([]string, 0, len(scenario.Tests))
				for name := range scenario.Tests {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					tc := scenario.Tests[name]
					count++
					t.Run(name, func(t *testing.T) {
						id := suite.file + "/" + name
						if seen[id] {
							t.Fatalf("duplicate case ID %s", id)
						}
						seen[id] = true
						disposition, annotated := dispositions[id]
						if annotated && disposition.Reason == "" {
							t.Fatal("disposition requires a reason")
						}
						if (tc.Header != "") != disposition.OmitHeader {
							t.Fatal("header assertion must be explicitly accounted for")
						}
						if (tc.Strict != nil) != disposition.IgnoreStrict {
							t.Fatal("strict-mode assertion must be explicitly accounted for")
						}
						if disposition.Explanation != nil && (tc.Explanation == nil || *disposition.Explanation == *tc.Explanation) {
							t.Fatal("stale explanation disposition")
						}
						if disposition.Skip {
							t.Skip(disposition.Reason)
						}

						domain := tc.HELO
						if tc.MailFrom != "" {
							if at := strings.LastIndexByte(tc.MailFrom, '@'); at >= 0 {
								domain = tc.MailFrom[at+1:]
							} else {
								domain = tc.MailFrom
							}
						}
						got, exp, err := CheckHostWithOptions(context.Background(), net.ParseIP(tc.Host), domain, tc.MailFrom, Options{Resolver: corpusResolver{scenario.Zone}, HELO: tc.HELO, Receiver: tc.Receiver, Time: time.Unix(0, 0)})
						found := false
						for _, want := range tc.Result {
							if got.String() == want {
								found = true
							}
						}
						if !found {
							t.Errorf("result=%s want=%v; cause=%v (RFC %s)", got, tc.Result, err, tc.Spec)
						}
						if tc.Explanation != nil {
							want := *tc.Explanation
							if want == "DEFAULT" {
								want = ""
							} // This API's documented default explanation is empty.
							if disposition.Explanation != nil {
								want = *disposition.Explanation
							}
							if exp != want {
								t.Errorf("explanation=%q want=%q", exp, want)
							}
						}
					})
				}
			}
			if count != suite.count {
				t.Fatalf("got %d cases, want %d; account for every source case", count, suite.count)
			}
		})
	}
}

func TestCorpusIntegrity(t *testing.T) {
	data, err := os.ReadFile("testdata/pyspf/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.ContainsAny(fields[1], "/\\") || files[fields[1]] {
			t.Fatalf("invalid checksum line %q", line)
		}
		files[fields[1]] = true
		raw, err := os.ReadFile("testdata/pyspf/" + fields[1])
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != fields[0] {
			t.Errorf("changed corpus file %s; regenerate with tools/import_pyspf.py", fields[1])
		}
	}
	for _, name := range []string{"rfc7208-tests.yml", "test.yml", "rfc7208-tests.json", "test.json", "pyspf.LICENSE", "rfc7208-tests.LICENSE", "dispositions.json", "CASES.md"} {
		if !files[name] {
			t.Errorf("unaccounted corpus file: %s", name)
		}
	}
}
