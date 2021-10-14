# dohdec

Retrieve and decode DNS records using [DNS-over-HTTPS](https://tools.ietf.org/html/rfc8484) (DoH) or [DNS-over-TLS](https://tools.ietf.org/html/rfc7858) (DoT).

## Pointers

This is a monorepo that holds a few related packages:

 - [dohdec](pkg/dohdec): A Node library for DoH and DoT.
 - [dohdec-cli](pkg/dohdec-cli): A command line interface for dohdec
 - [mock-dns-server](pkg/mock-dns-server): A DoT server that is only used for testing.

If you want to use the command line, you MUST now install `dohdec-cli`:

```bash
npm install -g dohdec-cli
```

Apologies; I didn't think anyone would want to use the library on its own when
I built this originally.

## Tooling

 - Install with `pnpm install -r`, [see](https://pnpm.js.org/).  The important
   thing (for example) is that the `dohdec-cli` package ends up depending on the
   local version of `dohdec`.

## Supported Node.js versions

This project now only supports versions of Node that the Node team is
[currently supporting](https://github.com/nodejs/Release#release-schedule).
Ava's [support
statement](https://github.com/avajs/ava/blob/main/docs/support-statement.md)
is what we will be using as well.  Currently, that means Node `12`+ is
required.  Only ES6 modules (import) are supported.

[![Tests](https://github.com/hildjj/dohdec/actions/workflows/node.js.yml/badge.svg)](https://github.com/hildjj/dohdec/actions/workflows/node.js.yml)
[![codecov](https://codecov.io/gh/hildjj/dohdec/branch/main/graph/badge.svg?token=qYy1UyK9S5)](https://codecov.io/gh/hildjj/dohdec)

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)
