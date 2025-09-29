import {Buf, prepNock} from '../../../test/utils.js';
import {createServer, plainConnect} from 'mock-dns-server';
import {DNS} from '../../../test/zones.js';
import {DnsCli} from '../lib/cli.js';
import nock from 'nock';
import stream from 'node:stream';
import test from 'ava';

prepNock(test, nock, import.meta.url);
let mockServer = null;

test.before(() => {
  mockServer = createServer({zones: DNS});
});

test.after.always(() => new Promise((resolve, reject) => {
  mockServer.close(er => {
    mockServer = null;
    if (er) {
      reject(er);
    } else {
      resolve(true);
    }
  });
}));

const HELP = `\
Usage: dohdec [options] [name] [rrtype]

Arguments:
  name                          DNS name to look up (e.g. domain name) or IP
                                address to reverse lookup.  If not specified, a
                                read-execute-print loop (REPL) is started.
  rrtype                        Resource record name or number (default: "A")

Options:
  -V, --version                 output the version number
  -c, --contentType <type>      MIME type for POST (default:
                                "application/dns-message")
  -d, --dns                     Use DNS format instead of JSON (ignored for TLS)
  -s, --dnssec                  Request DNSsec records
  -k, --dnssecCheckingDisabled  Disable DNSsec validation
  -e, --ecs <number>            Use this many bits for EDNS Client Subnet (ECS)
  -b, --ecsSubnet <address>     Use this IP address for EDNS Client Subnet (ECS)
  -f, --full                    Full response, not just answers
  -g, --get                     Force http GET for DNS-format lookups
  -n, --no-decode               Do not decode JSON or DNS wire format
  -2, --no-http2                Disable http2 support
  -t, --tls                     Use DNS-over-TLS instead of DNS-over-HTTPS
  -i, --host <serverIP>         Connect to this server when not using HTTP
                                (default: "1.1.1.1")
  -p, --tlsPort <number>        Connect to this TCP port for DNS-over-TLS
                                (default: 853)
  -P, --dnsPort <number>        Connect to this UDP or TCP port when not using
                                TLS (default: 53)
  -u, --url <URL>               The URL of the DoH service (default:
                                "https://cloudflare-dns.com/dns-query")
  -T, --tcp                     Use plaintext TCP for query
  -U, --udp                     Use UDP for query
  -v, --verbose                 Increase verbosity of debug information.  May be
                                specified multiple times.
  -h, --help                    display help for command

For more debug information:

  $ NODE_DEBUG=fetch dohdec -v [arguments]
`;

async function cliMain(...args) {
  const setup = [];
  let inp = process.stdin;
  let code = undefined;
  const out = new Buf({encoding: 'utf8'});
  const err = new Buf({encoding: 'utf8'});

  if ((args.length > 0) && (typeof args[0] === 'function')) {
    setup.push(args.shift());
  }

  if ((args.length > 0) && (args[0] instanceof stream.Readable)) {
    inp = args.shift();
  }

  try {
    const cli = new DnsCli([process.execPath, 'dohdec', ...args], {in: inp, out, err, helpWidth: 80});

    for (const s of setup) {
      await s(cli);
    }

    await cli.main();
  } catch (e) {
    ({code} = e);
  }
  return {
    out: out.read(),
    err: err.read(),
    code,
  };
}

async function cliMainTLS(...args) {
  const res = await cliMain(cli => {
    const m = plainConnect(mockServer.port);
    cli.transport.tlsOpts.socket = m;
    cli.transport.tlsOpts.ca = mockServer.ca;
    cli.transport.tlsOpts.host = 'localhost';
  }, ...args);
  return res;
}

test('help', async t => {
  let {err, out, code} = await cliMain('--help');
  t.falsy(err);
  t.is(out, HELP);
  t.is(code, 'commander.helpDisplayed');

  ({err, out, code} = await cliMain('-h'));
  t.falsy(err);
  t.is(out, HELP);
  t.is(code, 'commander.helpDisplayed');
});

test('main', async t => {
  const {out, err, code} = await cliMain('-2n', 'ietf.org', 'AAAA');
  t.falsy(code);
  t.falsy(err);
  t.regex(out, /"data":\s*"2606:4700::6810:2d63"/);
});

test('main get', async t => {
  const {out, err, code} = await cliMain('-2g', 'tools.ietf.org', 'AAAA');
  t.falsy(code);
  t.falsy(err);
  t.regex(out, /data:\s*'2606:4700::6810:2c63'/);
});

test('tls', async t => {
  const {out, err, code} = await cliMainTLS('-t', 'ietf.org', 'AAAA');
  t.is(err, null);
  t.is(code, undefined);
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
`);
});

test('bad args', async t => {
  let res = await cliMain('-e', 'foo');
  t.is(res.code, 'commander.invalidArgument');

  res = await cliMain('-e', '24', '-b', '24');
  t.is(res.code, 'commander.invalidArgument');

  res = await cliMain('-b', '::1', '-e', 'foo');
  t.is(res.code, 'commander.invalidArgument');
});

test('TLS NXDOMAIN', async t => {
  const {code} = await cliMainTLS('-t', 'unknown.example');
  t.is(code, 'dns.NXDOMAIN');
});

test('HTTPS NXDOMAIN', async t => {
  const {code} = await cliMain('-2g', 'unknown.example');
  t.is(code, 'dns.NXDOMAIN');
});

test('no decode', async t => {
  const {out, code, err} = await cliMainTLS('-tnv', 'ietf.org');
  t.is(code, undefined);
  t.false(out[out.length - 1] === '\n');
  t.true(err.length > 0);
});

test('prompt', async t => {
  const inp = new Buf({encoding: 'utf8'});
  inp.end('\nunknown.example\nietf.org AAAA\n');
  const {out, code, err} = await cliMainTLS(inp, '-t');
  t.is(code, undefined);
  t.is(err, 'DNS error: NXDOMAIN\n\n1/2 errors\n');
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
domain (rrtype)> `);
});

test('prompt error', async t => {
  const inp = new Buf({encoding: 'utf8'});
  inp.end('unknown.example\n');
  const {out, code, err} = await cliMainTLS(inp, '-t');
  t.is(code, undefined);
  t.is(err, 'DNS error: NXDOMAIN\n\n1/1 error\n');
  t.is(out, 'domain (rrtype)> domain (rrtype)> ');
});

test('reverse ipv4', async t => {
  const {out, code} = await cliMainTLS('-t', '4.31.198.44');
  t.is(code, undefined);
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
`);
});

test('reverse ipv6', async t => {
  const {out, code} = await cliMainTLS('-t', '2001:1900:3001:11::2c', 'PTR');
  t.is(code, undefined);
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
`);
});

test('bad format', async t => {
  nock('http://moo.example')
    .get(uri => uri.includes('badformat.example'))
    .reply(200, {bad: 'format'});
  const {out} = await cliMain('-g', '-u', 'http://moo.example/dns', 'badformat.example');
  t.is(out, "{ bad: 'format' }\n");
});

test('deprecated options', async t => {
  const {err, code} = await cliMain('--tlsServer', '1.1.1.1');
  t.is(err, "error: option '--tlsServer <serverIP>' argument '1.1.1.1' is invalid. Use '--host 1.1.1.1' instead\n");
  t.is(code, 'commander.invalidArgument');
});

test('udp', async t => {
  const {err, out, code} = await cliMain('--udp', '-v', 'ietf.org', 'MX');
  t.is(code, undefined);
  t.regex(out, /name: 'ietf.org'/);
});

test('tcp', async t => {
  const {err, out, code} = await cliMain('--tcp', 'ietf.org', 'MX');
  t.is(err, null);
  t.is(code, undefined);
  t.regex(out, /name: 'ietf.org'/);
});
