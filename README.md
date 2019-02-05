# dohdec

Retrieve and decode DNS records using [DNS-over-HTTPS](https://tools.ietf.org/html/rfc8484) (DOH)


## Install

```bash
npm i -S dohdec
```

## Command Line Usage

```
dohdec <name> [rrtype]

Look up DNS name using DNS-over-HTTPS (DoH)

Positionals:
  name    The name to look up                                           [string]
  rrtype  Resource Record type to look up                [string] [default: "A"]

Options:
  --version        Show version number                                 [boolean]
  --dns, -d        Use DNS format instead of JSON                      [boolean]
  --get, -g        Force http GET for DNS-format lookups               [boolean]
  --no-decode, -n  Do not decode JSON or DNS wire format               [boolean]
  --dnssec, -s     Request DNSsec records                              [boolean]
  --url, -u        The URL of the DoH service
                      [string] [default: "https://cloudflare-dns.com/dns-query"]
  --verbose, -v    Print debug info                                    [boolean]
  -h, --help       Show help                                           [boolean]
```

## API Usage

```js
const lookup = require('dohdec')

await lookup('ietf.org', 'AAAA') // JSON result from CloudFlare
await lookup('ietf.org', {
  rrtype: 'MX',
  json: false,       // Use DNS wire format
  decode: false,     // do not decode results
  preferPost: false, // use GET instead of POST for DNS wire format
  dnssec: true,      // request DNS records
  url: 'https://dns.google.com/resolve'
})

```

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)

[![Build Status](https://travis-ci.org/hildjj/dohdec.svg?branch=master)](https://travis-ci.org/hildjj/dohdec)
[![Coverage Status](https://coveralls.io/repos/github/hildjj/dohdec/badge.svg?branch=master)](https://coveralls.io/github/hildjj/dohdec?branch=master)
