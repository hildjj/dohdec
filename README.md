# dohdec

Retrieve and decode DNS records using [DNS-over-HTTPS](https://tools.ietf.org/html/rfc8484) (DoH) or [DNS-over-TLS](https://tools.ietf.org/html/rfc7858) (DoT).


## Install

```bash
npm i -S dohdec
```

## Command Line Usage

```txt
Usage: dohdec [options] [name] [rrtype]

Arguments:
  name                        DNS name to look up (e.g. domain name) or IP
                              address to reverse lookup.  If not specified, a
                              read-execute-print loop (REPL) is started.
  rrtype                      Resource record name or number (default: "A")

Options:
  -V, --version               output the version number
  -c, --contentType <type>    MIME type for POST (default:
                              "application/dns-message")
  -d, --dns                   Use DNS format instead of JSON (ignored for TLS)
  -s, --dnssec                Request DNSsec records
  -e, --ecs <number>          Use this many bits for EDNS Client Subnet (ECS)
  -b, --ecsSubnet <address>   Use this IP address for EDNS Client Subnet (ECS)
  -f, --full                  Full response, not just answers
  -g, --get                   Force http GET for DNS-format lookups (default:
                              true)
  -n, --no-decode             Do not decode JSON or DNS wire format
  -2, --no-http2              Disable http2 support
  -t, --tls                   Use DNS-over-TLS instead of DNS-over-HTTPS
  -i, --tlsServer <serverIP>  Connect to this DNS-over-TLS server (default:
                              "1.1.1.1")
  -p, --tlsPort <number>      Connect to this TCP port for DNS-over-TLS
                              (default: 853)
  -u, --url <URL>             The URL of the DoH service (default:
                              "https://cloudflare-dns.com/dns-query")
  -v, --verbose               Increase verbosity of debug information.  May be
                              specified multiple times. (default: 0)
  -h, --help                  display help for command

For more debug information:

  $ NODE_DEBUG=http,https,http2 dohdec -v [arguments]
```

## API Usage

```js
const { DNSoverHTTP, DNSoverTLS } = require('dohdec')

const doh = new DNSoverHTTP()
await doh.lookup('ietf.org', 'AAAA') // JSON result from CloudFlare
await doh.lookup('ietf.org', {
  rrtype: 'MX',
  json: false,       // Use DNS wire format
  decode: false,     // do not decode results
  dnssec: true,      // request DNS records
})
const dot = new DNSoverTLS({host: '1.1.1.1'})
await dot.lookup('ietf.org')
```

Full documents [here](https://hildjj.github.io/dohdec/)

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)

[![Tests](https://github.com/hildjj/dohdec/actions/workflows/node.js.yml/badge.svg)](https://github.com/hildjj/dohdec/actions/workflows/node.js.yml)
[![codecov](https://codecov.io/gh/hildjj/dohdec/branch/main/graph/badge.svg?token=qYy1UyK9S5)](https://codecov.io/gh/hildjj/dohdec)
