# Run provenance

Date: 2026-09-15. VM: Ubuntu 26.04.1 LTS x86-64, Linux 7.0.0-31-generic,
KVM/QEMU Virtual CPU 2.5+, four vCPUs, one thread per core, 7.2 GiB RAM.
Unbound 1.24.2 shares these cores. No CPU pinning or hypervisor isolation.

- Go source: `4b2195ea06fb5d7510ea54001e4b02f0456e3e3d`.
- Rust source: `fc60beec99e5ec12ea8abf26603f1aad0fbafef0`, manifest 0.13.2.
- Go: `go1.27.1 linux/amd64`, normal build, `GOMAXPROCS=4`.
- Rust: `rustc 1.93.1 (01f6ddf75 2026-02-11)`, Cargo 1.93.1, release profile,
  default mail-auth features, four Tokio worker threads.
- Rust resolver dependency: Hickory 0.26.3. Full resolution is in `Cargo.lock`.
- Go binary SHA-256:
  `30641741038c27e84f369953ca81c4ac3fa6725c8503880615f65ae1a326cbf3`.
- Rust driver binary SHA-256:
  `2afb43baec95cec8eb4428d51e72b5ab55290feb50871e037effe620f086bd77`.

Sources were staged in `/home/marek/spf-comparison-20260915/`.
Neither SPF implementation was changed. Rspamd's prior comparison daemon was
stopped before timing. Rust compilation and correctness tests completed before
the performance runs. Paired trials run sequentially, never concurrently.

Verification: Go `go test ./...` passed. Rust `cargo test --release --lib spf::`
passed all five matching test functions (including the verification function
which reads 170 expected-result entries in 13 SPF resource files).
Those are different upstream test corpora and do not prove equal conformance.

The initial shared-resolver attempt failed the exact DNS query-count assertion;
its seven completed rows remain on the VM in `mailauth/initial-shared-partial.jsonl`
and are excluded from the equal-DNS matrix. This exposed Hickory's concurrent
query sharing and motivated measuring independent and shared resolvers separately.
