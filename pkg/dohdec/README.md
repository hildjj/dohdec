# dohdec

Retrieve and decode DNS records using [DNS-over-HTTPS](https://tools.ietf.org/html/rfc8484) (DoH) or [DNS-over-TLS](https://tools.ietf.org/html/rfc7858) (DoT).


## Install

```bash
npm install --save dohdec
```

## Command Line Usage

You must now install [`dohdec-cli`](../dohdec-cli) to use the command line:

```bash
npm install -g dohdec-cli
```

## API Usage

```js
const { DNSoverHTTPS, DNSoverTLS } = require('dohdec')

const doh = new DNSoverHTTPS()
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

## Notes

- All queries will be padded to the next multiple of 128 bytes (see [RFC 8467](https://datatracker.ietf.org/doc/html/rfc8467#section-4.1))
- The JSON protocols are not standardized.  The best we have is Google's [documentation](https://developers.google.com/speed/public-dns/docs/doh/json), which Cloudlflare seems to have followed.

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)

[![Tests](https://github.com/hildjj/dohdec/actions/workflows/node.js.yml/badge.svg)](https://github.com/hildjj/dohdec/actions/workflows/node.js.yml)
[![codecov](https://codecov.io/gh/hildjj/dohdec/branch/main/graph/badge.svg?token=qYy1UyK9S5)](https://codecov.io/gh/hildjj/dohdec)
