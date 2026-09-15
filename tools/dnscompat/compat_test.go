// Package dnscompat contains isolated, executable migration evidence. It is not
// imported by SPF and does not change SPF's production dependency graph.
package dnscompat

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"slices"
	"strings"
	"testing"

	dnsv2 "codeberg.org/miekg/dns"
	dnsv1 "github.com/miekg/dns"
)

var requireCompatible = flag.Bool("require-compatible", false, "fail on unresolved Codeberg DNS compatibility blockers")

// Blockers are reported in ordinary diagnostic runs. A release-gate run must
// explicitly enable -require-compatible; a diagnostic PASS is not approval to port.
func blocker(t *testing.T, format string, args ...any) {
	t.Helper()
	if *requireCompatible {
		t.Errorf("BLOCKER: "+format, args...)
	} else {
		t.Logf("BLOCKER: "+format, args...)
	}
}

func TestLabelBoundaries(t *testing.T) {
	for _, field := range []string{"question", "owner", "CNAME", "MX", "PTR"} {
		for _, compressed := range []bool{false, true} {
			// A single question has no earlier name to point to. Compression
			// coverage uses an earlier answer owner as a valid pointer target.
			if field == "question" && compressed {
				continue
			}
			t.Run(fmt.Sprintf("%s/compressed=%v", field, compressed), func(t *testing.T) {
				malicious := packet(field, []string{"attacker.example", "test"}, compressed)
				ordinary := packet(field, []string{"attacker", "example", "test"}, compressed)
				oldMalicious, err := decodeV1(malicious, field)
				if err != nil {
					t.Fatal(err)
				}
				oldOrdinary, err := decodeV1(ordinary, field)
				if err != nil || oldMalicious == oldOrdinary {
					t.Fatalf("invalid baseline: %q versus %q, %v", oldMalicious, oldOrdinary, err)
				}
				// Prove the v1 presentation retains the original label bytes.
				assertV1Labels(t, oldMalicious, []string{"attacker.example", "test"})
				newOrdinary, err := decodeV2(ordinary, field)
				if err != nil || newOrdinary != "attacker.example.test." {
					t.Fatalf("ordinary name failed: %q, %v", newOrdinary, err)
				}
				newMalicious, err := decodeV2(malicious, field)
				if err != nil {
					t.Logf("embedded-dot packet rejected: %v", err)
					return
				}
				if newMalicious == newOrdinary {
					blocker(t, "v1 distinguishes %q from %q; v2 decodes both as %q", oldMalicious, oldOrdinary, newMalicious)
				}
			})
		}
	}
}

func TestLiteralNameControls(t *testing.T) {
	for _, labels := range [][]string{
		{"normal", "test"}, {"foo:bar/baz", "test"},
		{"macro%percent  space%20url", "test"}, {`literal\032`, "test"},
		{`semi;quote"`, "test"}, {"-leading", "test"}, {},
		{strings.Repeat("a", 63), "test"},
		{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)},
	} {
		t.Run(fmt.Sprintf("%q", labels), func(t *testing.T) {
			wire := packet("PTR", labels, false)
			oldName, err := decodeV1(wire, "PTR")
			if err != nil {
				t.Fatal(err)
			}
			assertV1Labels(t, oldName, labels)
			newName, err := decodeV2(wire, "PTR")
			want := strings.Join(labels, ".") + "."
			if err != nil || newName != want {
				t.Fatalf("v2 literal name = %q, %v; want %q", newName, err, want)
			}
			// Check the outgoing path too: encode with v2 and independently
			// inspect the wire with v1. No textual RR parser is involved.
			q := dnsv2.NewMsg(want, dnsv2.TypePTR)
			if err := q.Pack(); err != nil {
				t.Fatal(err)
			}
			oldName, err = decodeV1(q.Data, "question")
			if err != nil {
				t.Fatal(err)
			}
			assertV1Labels(t, oldName, labels)
		})
	}
}

func TestMalformedNameControls(t *testing.T) {
	header := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
	for name, wire := range map[string][]byte{
		"oversized-label": packet("question", []string{strings.Repeat("a", 64), "test"}, false),
		"oversized-name": packet("question", []string{
			strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 63),
		}, false),
		"truncated-label": append(slices.Clone(header), 5, 'a'),
		"self-pointer":    append(slices.Clone(header), 0xc0, 12, 0, 1, 0, 1),
		"outside-pointer": append(slices.Clone(header), 0xff, 0xff, 0, 1, 0, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var old dnsv1.Msg
			if err := old.Unpack(wire); err == nil {
				t.Fatal("invalid fixture: baseline accepted malformed name")
			}
			m := dnsv2.Msg{Data: slices.Clone(wire)}
			if err := m.Unpack(); err == nil {
				blocker(t, "v2 accepted malformed %s", name)
			}
		})
	}
}

func assertV1Labels(t *testing.T, name string, labels []string) {
	t.Helper()
	wire := make([]byte, 255)
	end, err := dnsv1.PackDomainName(name, wire, 0, nil, false)
	if err != nil || !bytes.Equal(wire[:end], wireName(labels)) {
		t.Fatalf("v1 did not preserve labels %q: %q, %v", labels, name, err)
	}
}

func decodeV1(wire []byte, field string) (string, error) {
	var m dnsv1.Msg
	if err := m.Unpack(wire); err != nil {
		return "", err
	}
	if field == "question" {
		return m.Question[0].Name, nil
	}
	rr := m.Answer[len(m.Answer)-1]
	switch field {
	case "CNAME":
		return rr.(*dnsv1.CNAME).Target, nil
	case "MX":
		return rr.(*dnsv1.MX).Mx, nil
	case "PTR":
		return rr.(*dnsv1.PTR).Ptr, nil
	default:
		return rr.Header().Name, nil
	}
}

func decodeV2(wire []byte, field string) (string, error) {
	m := dnsv2.Msg{Data: slices.Clone(wire)}
	if err := m.Unpack(); err != nil {
		return "", err
	}
	if field == "question" {
		return m.Question[0].Header().Name, nil
	}
	rr := m.Answer[len(m.Answer)-1]
	switch field {
	case "CNAME":
		return rr.(*dnsv2.CNAME).Target, nil
	case "MX":
		return rr.(*dnsv2.MX).Mx, nil
	case "PTR":
		return rr.(*dnsv2.PTR).Ptr, nil
	default:
		return rr.Header().Name, nil
	}
}

// packet constructs raw DNS bytes without either library's encoder. Numeric
// constants below are DNS wire values, so the fixtures cannot share an encoding
// mistake with the implementation being evaluated.
func packet(field string, labels []string, compressed bool) []byte {
	wire := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
	name := wireName(labels)
	if field == "question" {
		return append(append(wire, name...), 0, 1, 0, 1)
	}
	wire = append(wire, wireName([]string{"query", "test"})...)
	wire = append(wire, 0, 1, 0, 1)
	answers := uint16(1)
	if compressed {
		offset := len(wire)
		// Preceding TXT RR provides the backwards compression target.
		wire = appendRR(wire, name, 16, []byte{1, 'x'})
		name = []byte{0xc0 | byte(offset>>8), byte(offset)}
		answers++
	}
	owner := wireName([]string{"query", "test"})
	rrtype := uint16(1)
	rdata := []byte{192, 0, 2, 1}
	switch field {
	case "owner":
		owner = name
	case "CNAME":
		rrtype, rdata = 5, name
	case "MX":
		rrtype, rdata = 15, append([]byte{0, 10}, name...)
	case "PTR":
		rrtype, rdata = 12, name
	default:
		panic("unknown fixture field: " + field)
	}
	wire = appendRR(wire, owner, rrtype, rdata)
	binary.BigEndian.PutUint16(wire[6:8], answers)
	return wire
}

func appendRR(wire, owner []byte, rrtype uint16, rdata []byte) []byte {
	wire = append(wire, owner...)
	wire = binary.BigEndian.AppendUint16(wire, rrtype)
	wire = append(wire, 0, 1, 0, 0, 0, 60) // IN, TTL=60
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(rdata)))
	return append(wire, rdata...)
}

func wireName(labels []string) []byte {
	var wire []byte
	for _, label := range labels {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	return append(wire, 0)
}
