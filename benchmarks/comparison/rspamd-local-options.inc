# Isolated benchmark resolver: use the local Unbound fixture directly.
dns {
  nameserver = ["127.0.0.1:53"];
}
control_socket = "/tmp/rspamd-spf-comparison.sock mode=0600";
rrd = false;

spf {
  # Match the wttw direct evaluator: parse/evaluate each request without
  # reusing a cross-message parsed-record cache.
  spf_cache_size = 0;
}
