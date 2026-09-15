# Proposed upstream issue

Title: `Msg.Unpack collapses an embedded dot byte into a label separator`

Tested with `codeberg.org/miekg/dns v0.6.109`.

These are two different question names on the wire:

- one label `attacker.example`, followed by `test`
- three labels `attacker`, `example`, and `test`

`Msg.Unpack` returns `attacker.example.test.` for both, so a caller cannot tell
which name was received.

```go
package main

import (
	"encoding/hex"
	"fmt"

	"codeberg.org/miekg/dns"
)

func main() {
	for _, packet := range []string{
		// [attacker.example, test]
		"1234010000010000000000001061747461636b65722e6578616d706c6504746573740000010001",
		// [attacker, example, test]
		"1234010000010000000000000861747461636b6572076578616d706c6504746573740000010001",
	} {
		wire, _ := hex.DecodeString(packet)
		m := dns.Msg{Data: wire}
		err := m.Unpack()
		fmt.Printf("%q %v\n", m.Question[0].Header().Name, err)
	}
}
```

Output:

```text
"attacker.example.test." <nil>
"attacker.example.test." <nil>
```

The same collision occurs in answer owners and CNAME, MX, and PTR targets,
including compressed names. `github.com/miekg/dns` represents the first form as
`attacker\.example.test.`, retaining the boundary.

I hit this while porting an SPF resolver. It needs to compare the returned
question and owner with the query, follow CNAMEs, and validate PTR candidates by
suffix. Treating the first wire name as the second can therefore change which
record is trusted.

I understand that v2 intentionally does not support presentation escapes in
domain names. Would you accept another way for a client to retain or inspect the
wire label boundaries, perhaps an opt-in unpack option or a label-aware accessor?

Rejecting the entire message when any name contains an embedded dot avoids the
collision, but does not cover clients that must ignore an unrelated answer or an
excess record. For example, SPF ignores PTR candidates after the first ten; an
unrepresentable eleventh candidate must not invalidate the first ten.

Our raw-wire comparison and selection cases are here:
https://github.com/zaccone/spf/tree/master/tools/dnscompat
