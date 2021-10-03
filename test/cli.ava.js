import {Buf, prepNock} from './utils.js'
import {DnsCli} from '../lib/cli.js'
import {MockDNSserver} from './mockServer.js'
import nock from 'nock'
import stream from 'stream'
import test from 'ava'

prepNock(test, nock, import.meta.url)
const mockServer = new MockDNSserver('localhost')

const HELP = `\
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
`

async function cliMain(...args) {
  const setup = []
  let inp = process.stdin
  let code = undefined
  const out = new Buf({encoding: 'utf8'})
  const err = new Buf({encoding: 'utf8'})

  if ((args.length > 0) && (typeof args[0] === 'function')) {
    setup.push(args.shift())
  }

  if ((args.length > 0) && (args[0] instanceof stream.Readable)) {
    inp = args.shift()
  }

  try {
    const cli = new DnsCli([process.execPath, 'dohdec', ...args], {in: inp, out, err})

    for (const s of setup) {
      await s(cli)
    }

    await cli.main()
  } catch (e) {
    ({code} = e)
  }
  return {
    out: out.read(),
    err: err.read(),
    code,
  }
}

async function cliMainTLS(...args) {
  const res = await cliMain(cli => {
    const m = mockServer.instance()
    cli.transport.opts.socket = m.rawClientSocket
    cli.transport.opts.ca = mockServer.chain.ca_pem
    cli.transport.opts.host = 'localhost'
  }, ...args)
  return res
}

test('help', async t => {
  let {err, out, code} = await cliMain('--help')
  t.falsy(err)
  t.is(out, HELP)
  t.is(code, 'commander.helpDisplayed')

  ;({err, out, code} = await cliMain('-h'))
  t.falsy(err)
  t.is(out, HELP)
  t.is(code, 'commander.helpDisplayed')
})

test('main', async t => {
  const {out, err, code} = await cliMain('-2n', 'ietf.org', 'AAAA')
  t.falsy(code)
  t.falsy(err)
  t.regex(out, /"data":\s*"2001:1900:3001:11::2c"/)
})

test('tls', async t => {
  const {out, err, code} = await cliMainTLS('-t', 'ietf.org', 'AAAA')
  t.is(err, null)
  t.is(code, undefined)
  t.is(out, `\
[
  {
    name: 'ietf.org',
    type: 'AAAA',
    ttl: 1000,
    class: 'IN',
    flush: false,
    data: '2001:1900:3001:11::2c'
  }
]
`)
})

test('bad args', async t => {
  let res = await cliMain('-e', 'foo')
  t.is(res.code, 'commander.invalidArgument')

  res = await cliMain('-e', '24', '-b', '24')
  t.is(res.code, 'commander.invalidArgument')

  res = await cliMain('-b', '::1', '-e', 'foo')
  t.is(res.code, 'commander.invalidArgument')
})

test('TLS NXDOMAIN', async t => {
  const {code} = await cliMainTLS('-t', 'unknown.example')
  t.is(code, 'dns.NXDOMAIN')
})

test('HTTPS NXDOMAIN', async t => {
  const {code} = await cliMain('-2', 'unknown.example')
  t.is(code, 'dns.NXDOMAIN')
})

test('no decode', async t => {
  const {out, code, err} = await cliMainTLS('-tnv', 'ietf.org')
  t.is(code, undefined)
  t.false(out[out.length - 1] === '\n')
  t.true(err.length > 0)
})

test('prompt', async t => {
  const inp = new Buf({encoding: 'utf8'})
  inp.end('\nunknown.example\nietf.org AAAA\n')
  const {out, code, err} = await cliMainTLS(inp, '-t')
  t.is(code, undefined)
  t.is(err, 'DNS error: NXDOMAIN\n\n1/2 errors\n')
  t.is(out, `\
domain (rrtype)> domain (rrtype)> domain (rrtype)> [
  {
    name: 'ietf.org',
    type: 'AAAA',
    ttl: 1000,
    class: 'IN',
    flush: false,
    data: '2001:1900:3001:11::2c'
  }
]
domain (rrtype)> `)
})

test('prompt error', async t => {
  const inp = new Buf({encoding: 'utf8'})
  inp.end('unknown.example\n')
  const {out, code, err} = await cliMainTLS(inp, '-t')
  t.is(code, undefined)
  t.is(err, 'DNS error: NXDOMAIN\n\n1/1 error\n')
  t.is(out, 'domain (rrtype)> domain (rrtype)> ')
})

test('reverse ipv4', async t => {
  const {out, code} = await cliMainTLS('-t', '4.31.198.44')
  t.is(code, undefined)
  t.is(out, `\
[
  {
    name: '44.198.31.4.in-addr.arpa',
    type: 'PTR',
    ttl: 1000,
    class: 'IN',
    flush: false,
    data: 'mail.ietf.org'
  }
]
`)
})

test('reverse ipv6', async t => {
  const {out, code} = await cliMainTLS('-t', '2001:1900:3001:11::2c')
  t.is(code, undefined)
  t.is(out, `\
[
  {
    name: 'c.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.0.1.0.0.3.0.0.9.1.1.0.0.2.ip6.arpa',
    type: 'PTR',
    ttl: 1000,
    class: 'IN',
    flush: false,
    data: 'mail.ietf.org'
  }
]
`)
})
