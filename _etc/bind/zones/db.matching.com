;
; BIND reverse data file for local loopback interface
;
$TTL    604800
@       IN      SOA     matching.com. admin.matching.com. (
                              13        ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.matching.com.
1.0.0   IN      PTR     localhost.

matching.com.   IN      MX      5 mail.matching.com.
matching.com.   IN      MX      10 mail2.matching.com.
matching.com.   IN      MX      15 mail3.matching.com.

@                       IN      A 172.18.0.2
ns.matching.com.        IN      A 172.17.0.2
positive.matching.com.  IN      A 172.18.0.2
positive.matching.com.  IN      A 172.20.20.1
positive.matching.com.  IN      A 172.20.21.1
range.matching.com.     IN      A 172.18.0.2
lb.matching.com.        IN      A 172.18.0.2

positive.matching.com.  IN      AAAA 2001:4860:0:2001::68


negative.matching.com.  IN      A 172.18.100.100
mail.matching.com.      IN      A 172.18.0.2
mail.matching.com.      IN      AAAA 2001:4860:1:2001::80
mail2.matching.com.     IN      A 172.20.20.20
mail3.matching.com.     IN      A 172.100.0.1
matching.com.           IN      TXT "v=spf1 mx:matching.com -all"

multi.spf.matching.com. IN      TXT     "v=spf1 mx -all"
multi.spf.matching.com. IN      TXT     "v=spf1 ip6:2001:db8:a0b:12f0::1 -all"
1.spf.matching.com.     IN      TXT     "v=spf1 a mx -all"
2.spf.matching.com.     IN      TXT     "v=spf1 ip4:172.100.100.100 -all"
3.spf.matching.com.     IN      TXT     "v=spf1 ip4:172.100.100.1/24 ?all"
incorrect.spf.matching.com.     IN      TXT "incorrect SPF"

include.matching.com.           IN      TXT "v=spf1 include:matching.net -all"
invinclude.matching.com.        IN      TXT "v=spf1 include -all"
redirect.matching.com.          IN      TXT "v=spf1 redirect=redirect.matching.net"
static.exp.matching.com.        IN      TXT "Invalid SPF record"
ip.exp.matching.com.            IN      TXT "%{i} is not one of %{d}'s designated mail servers."
redirect.exp.matching.com.      IN      TXT "See http://%{d}/why.html?s=%{S}&i=%{I}"
