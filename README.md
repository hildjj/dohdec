# dohdec

Retrieve and decode DNS records using [DNS-over-HTTPS](https://tools.ietf.org/html/rfc8484) (DoH) or [DNS-over-TLS](https://tools.ietf.org/html/rfc7858) (DoT).


## Install

```bash
npm i -S dohdec
```

## Command Line Usage

```txt
dohdec [name] [rrtype]

Look up DNS name using DNS-over-HTTPS (DoH)

Positionals:
  name    The name to look up.  If not specified, use a readline loop to look up
          multiple names.                                               [string]
  rrtype  Resource Record type to look up                [string] [default: "A"]

Options:
  --version        Show version number                                 [boolean]
  --dns, -d        Use DNS format instead of JSON                      [boolean]
  --subnet, -b     Use this IP address for EDNS Client Subnet (ECS)     [string]
  --ecs, -e        Use this many bits for EDNS Client Subnet (ECS)      [number]
  --full, -f       Full response, not just answers                     [boolean]
  --get, -g        Force http GET for DNS-format lookups               [boolean]
  --no-decode, -n  Do not decode JSON or DNS wire format               [boolean]
  --dnssec, -s     Request DNSsec records                              [boolean]
  --url, -u        The URL of the DoH service
                      [string] [default: "https://cloudflare-dns.com/dns-query"]
  --tls, -t        Use DNS-over-TLS instead of DNS-over-HTTPS          [boolean]
  --tlsServer, -i  Connect to this DNS-over-TLS server      [default: "1.1.1.1"]
  --tlsPort, -p    Connect to this TCP port for DNS-over-TLS      [default: 853]
  --verbose, -v    Print debug info                                    [boolean]
  -h, --help       Show help                                           [boolean]
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

[![Build Status](https://travis-ci.org/hildjj/dohdec.svg?branch=master)](https://travis-ci.org/hildjj/dohdec)
[![Coverage Status](https://coveralls.io/repos/github/hildjj/dohdec/badge.svg?branch=master)](https://coveralls.io/github/hildjj/dohdec?branch=master)
