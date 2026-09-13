# Pinned pySPF test data

Source: [sdgathman/pyspf](https://github.com/sdgathman/pyspf/tree/1042e9e15dd29047dc9b0a1bb77437e2fd81e775/test),
commit `1042e9e15dd29047dc9b0a1bb77437e2fd81e775`.

- `rfc7208-tests.yml`: complete 203-case OpenSPF RFC 7208 suite (release 2014.04).
  The original file and [BSD-style three-clause license](rfc7208-tests.LICENSE)
  are retained unchanged, including contributors and copyright notices.
- `test.yml`: complete 16-case pySPF development suite. It is distributed under
  the repository's [Python Software Foundation License Version 2](pyspf.LICENSE),
  retained unchanged with its author notices. The source YAML is unchanged.
- The JSON files are generated adaptations: YAML scenarios become JSON, scalar
  expected results become lists, and DNS fixture shorthand is normalized. Only
  source SPF/TXT fixture representation changes; policy text and expectations
  remain intact. No pySPF Python implementation or test-driver code is copied.
- `dispositions.json` records every excluded or adapted assertion, with reasons.
  `CASES.md` lists all 219 cases. `SHA256SUMS` covers source, licenses, generated
  data, inventory, and dispositions; Go tests verify it.

This test-only material does not change the license of the Go implementation.
Keep the applicable notices when redistributing the corpus or generated forms;
retain the disclaimers and do not use contributor names as endorsements.

No Python/YAML library is required for `go test`. To regenerate with a temporary
Python environment (Python 3.10+):

```sh
python3 -m venv /tmp/spf-corpus-tools
/tmp/spf-corpus-tools/bin/pip install PyYAML==6.0.3
/tmp/spf-corpus-tools/bin/python tools/import_pyspf.py
/tmp/spf-corpus-tools/bin/python tools/import_pyspf.py --check
go test -run 'TestConformanceCorpus|TestCorpusIntegrity' ./...
```

Run commands from the repository root. The importer verifies the pinned source
and license hashes before conversion. It does not download new upstream content.
To update the pin, review the new source and licenses, update the importer hashes
and revision, regenerate JSON/inventory/checksums, account for changed cases and
dispositions, and rerun conformance plus the full validation suite. Do not change
an expected result merely to make an implementation failure pass.

Scope, driver semantics, exceptions, and release limitations are documented in
[CONFORMANCE.md](../../CONFORMANCE.md). Upstream RFC 4408 and implementation-only
Python doctests are outside this import for the reasons stated there.
