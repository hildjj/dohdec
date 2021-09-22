import {Buf} from './utils.js'
import {DnsCli} from '../lib/cli.js'
import {MockDNSserver} from './mockServer.js'
import nock from 'nock'
import path from 'path'
import test from 'ava'
import url from 'url'

const mockServer = new MockDNSserver('localhost')

function parse(cli, args) {
  return new Promise((resolve, reject) => {
    cli.parse(args, (err, argv, output) => resolve({err, argv, output}))
  })
}

const HELP = `\
dohdec [name] [rrtype]

Look up DNS name using DNS-over-HTTPS (DoH)

Positionals:
  name    The name to look up.  If not specified, use a readline loop to look up
           multiple names.                                              [string]
  rrtype  Resource Record type to look up                [string] [default: "A"]

Options:
      --version      Show version number                               [boolean]
  -c, --contentType  MIME type for POST     [default: "application/dns-message"]
  -d, --dns          Use DNS format instead of JSON                    [boolean]
  -s, --dnssec       Request DNSsec records                            [boolean]
  -e, --ecs          Use this many bits for EDNS Client Subnet (ECS)    [number]
  -b, --ecsSubnet    Use this IP address for EDNS Client Subnet (ECS)   [string]
  -f, --full         Full response, not just answers                   [boolean]
  -g, --get          Force http GET for DNS-format lookups             [boolean]
  -n, --no-decode    Do not decode JSON or DNS wire format             [boolean]
  -2, --no-http2     Disable http2 support                             [boolean]
  -t, --tls          Use DNS-over-TLS instead of DNS-over-HTTPS        [boolean]
  -i, --tlsServer    Connect to this DNS-over-TLS server    [default: "1.1.1.1"]
  -p, --tlsPort      Connect to this TCP port for DNS-over-TLS    [default: 853]
  -u, --url          The URL of the DoH service
                      [string] [default: "https://cloudflare-dns.com/dns-query"]
  -v, --verbose      Print debug info                                    [count]
  -h, --help         Show help                                         [boolean]

    For more debug information:

      $ NODE_DEBUG=http,https,http2 dohdec -v [arguments]`

test.before(async t => {
  nock.back.fixtures = url.fileURLToPath(new URL('fixtures/', import.meta.url))
  if (!process.env.NOCK_BACK_MODE) {
    nock.back.setMode('lockdown')
  }

  const title = escape(path.basename(url.fileURLToPath(import.meta.url)))
  const { nockDone, context } = await nock.back(`${title}.json`)
  if (context.scopes.length === 0) {
    // Set the NOCK_BACK_MODE variable to "record" when needed
    if (nock.back.currentMode !== 'record') {
      console.error(`WARNING: Nock recording needed for "${title}".
Set NOCK_BACK_MODE=record`)
    }
  }
  t.context.nockDone = nockDone

  if (nock.back.currentMode === 'record') {
    nock.enableNetConnect()
  } else {
    nock.disableNetConnect()
  }
})

test.after(t => {
  t.context.nockDone()
  t.truthy(nock.isDone())
})

test('create cli', async t => {
  const cli = new DnsCli()
  t.truthy(cli)

  let {err, output} = await parse(cli, '--help')
  t.falsy(err)
  t.is(output, HELP)

  process.argv.push('-h')
  ;({err, output} = await parse(cli))

  t.falsy(err)
  t.is(output, HELP)
})

test('main', async t => {
  const cli = new DnsCli()
  t.truthy(cli)
  cli.out = new Buf()
  cli.err = new Buf()
  cli.parse('-2 ietf.org AAAA')
  await cli.main()

  t.is(cli.err.read(), null)
  t.is(cli.out.read().toString(), `\
[
  {
    name: 'ietf.org',
    type: 28,
    TTL: 1615,
    data: '2001:1900:3001:11::2c'
  }
]
`)
})

test('tls', async t => {
  const cli = new DnsCli()
  t.truthy(cli)
  cli.out = new Buf()
  cli.err = new Buf()
  await parse(cli, '-t ietf.org AAAA')

  const m = mockServer.instance()
  cli.transport.opts.socket = m.rawClientSocket
  cli.transport.opts.ca = mockServer.chain.ca_pem
  cli.transport.opts.host = 'localhost'
  await cli.main()
  t.is(cli.err.read(), null)
  t.is(cli.out.read().toString(), `\
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
