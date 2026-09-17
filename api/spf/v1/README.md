# SPF gRPC v1 contract

`SPFService.Check` returns SPF evaluation results, not SMTP policy decisions.
All seven SPF outcomes, including DNS temperror and policy permerror, use gRPC
OK. Unusable SPF domains produce RESULT_NONE. RESULT_UNSPECIFIED is never emitted
by the server; clients must tolerate future enum values.

Malformed IPs, sender syntax, control characters, missing identities, and oversized
identity fields yield InvalidArgument. Overload yields ResourceExhausted with no
application queue. Caller cancellation/deadline uses Canceled/DeadlineExceeded.
The server's evaluation timeout yields RESULT_TEMPERROR unless evaluation already
produced a definitive result. Explanation lookup failure cannot replace SPF fail.
The earlier of caller deadline and server evaluation timeout bounds DNS work.

Sender accepts an unbracketed envelope mailbox or the null reverse path (empty
or `<>`). The optional domain overrides policy selection, not sender validation.
Without it, the domain is derived from the sender, or HELO for the null sender.
The initial API uses the library's ASCII identity support; SMTPUTF8/IDNA conversion
is not provided. Each identity field is limited to 4096 bytes. Explanation is
untrusted DNS text; raw internal diagnostics are deliberately not part of the API.

Generate from the repository root with `sh tools/proto/generate.sh` using protoc
35.1. Go plugin versions are pinned in that script. Generated files are committed;
normal builds do not require protoc. Never renumber/reuse fields or enum values;
reserve deleted values and introduce incompatible changes in a new API version.
