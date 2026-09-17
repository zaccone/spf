# Deploy the local gRPC service

Build `spfd` as described in the [command guide](../cmd/spfd/README.md). The
Postfix and gRPC services run as separate processes using the same executable;
they have independent capacity and can be restarted independently. Their combined
DNS load must fit the recursive resolver's capacity.

Use the [existing Unbound setup](README.md) for a local caching resolver on
127.0.0.1:5335, or configure another recursive resolver. This service does not
require Postfix. The initial listener accepts literal loopback TCP or Unix
sockets only. It has no TLS or client authentication; any process able to reach
the socket can call it. Remote deployment requires a separate security design.

After building the binary, install the dedicated configuration and unit:

```sh
sudo install -m 0755 /tmp/spfd /usr/local/bin/spfd
sudo install -m 0644 deploy/spfd-grpc.env /etc/default/spfd-grpc
sudo install -m 0644 deploy/spfd-grpc.service /etc/systemd/system/spfd-grpc.service
sudoedit /etc/default/spfd-grpc
sudo systemd-analyze verify /etc/systemd/system/spfd-grpc.service
sudo systemctl daemon-reload
sudo systemctl enable --now spfd-grpc
sudo journalctl -u spfd-grpc -n 30
```

Set the receiver hostname and DNS address before starting. The supplied unit uses
TCP at 127.0.0.1:50051. `spfd grpc -network unix -listen /run/spfd-grpc/api.sock`
is also supported; provision the parent directory and client group access in a
custom unit. Socket permissions are 0660 and existing paths are never removed on
startup. The supplied DynamicUser unit does not configure shared Unix socket access.

Test the complete binary with deterministic local DNS before deployment:

```sh
go build -o /tmp/spfd ./cmd/spfd
go run ./tools/smoke_grpc /tmp/spfd
```

Then call your running service using real SMTP identities:

```sh
go run ./examples/grpc-client -target 127.0.0.1:50051 \
  -ip 192.0.2.1 -sender sender@example.com -helo mail.example.com
```

The example sets a five-second deadline and prints a typed SPF result. Reuse the
client connection in applications and set an appropriate deadline on every call.
Choose acceptance policy explicitly; RPC success does not mean SPF pass.
ResourceExhausted signals overload; avoid immediate unbounded retries.

The standard gRPC health service supports the empty service name and
`spf.v1.SPFService`. Health indicates that the daemon is serving, not that DNS is
reachable. Reflection is disabled; tooling must use the committed proto file.
Logs contain results and duration, not sender identities or explanations.
Existing benchmark reports cover the library and Postfix, not gRPC capacity.

To stop or roll back only this endpoint:

```sh
sudo systemctl disable --now spfd-grpc
```

The independent Postfix process continues running. Replacing the shared executable
changes the version each service uses on its next restart.
