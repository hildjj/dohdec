import * as packet from 'dns-packet';
import {
  DNSError,
  DNSutils,
  printableString,
  stylizeWithColor,
} from '../lib/dnsUtils.js';
import {Buf} from '../../../test/utils.js';
import {Buffer} from 'node:buffer';
import {NoFilter} from 'nofilter';
import test from 'ava';

test('makePacket', t => {
  const pkt = DNSutils.makePacket({name: 'foo'});
  const dns = packet.decode(pkt);
  t.is(dns.id, 0);
  t.is(dns.questions[0].type, 'A');
  t.is(dns.questions[0].name, 'foo');

  t.throws(() => DNSutils.makePacket());
  t.throws(() => DNSutils.makePacket({}));
});

test('makePacket - subnet', t => {
  const ecsSubnet = '1.1.1.1';
  const pkt = DNSutils.makePacket({name: 'foo', ecsSubnet});
  const dns = packet.decode(pkt);
  const [additionals] = dns.additionals;
  const [options] = additionals.options;
  t.is(additionals.type, 'OPT');
  t.is(options.type, 'CLIENT_SUBNET');
  t.is(options.ip, ecsSubnet.slice(0, -1).concat('0')); // 1.1.1.0
  t.is(options.sourcePrefixLength, 24);
});

test('makePacket - subnet & ecs = 0', t => {
  const ecsSubnet = '1.1.1.1';
  const ecs = 0;
  const pkt = DNSutils.makePacket({name: 'foo', ecsSubnet, ecs});
  const dns = packet.decode(pkt);
  const [additionals] = dns.additionals;
  const [options] = additionals.options;
  t.is(additionals.type, 'OPT');
  t.is(options.type, 'CLIENT_SUBNET');
  t.is(options.ip, '0.0.0.0');
  t.is(options.sourcePrefixLength, ecs);
});

test('makePacket - subnet & ecs = 16', t => {
  const ecsSubnet = '1.1.1.1';
  const ecs = 16;
  const pkt = DNSutils.makePacket({name: 'foo', ecsSubnet, ecs});
  const dns = packet.decode(pkt);
  const [additionals] = dns.additionals;
  const [options] = additionals.options;
  t.is(additionals.type, 'OPT');
  t.is(options.type, 'CLIENT_SUBNET');
  t.is(options.ip, ecsSubnet.slice(0, -3).concat('0.0')); // 1.1.0.0
  t.is(options.sourcePrefixLength, ecs);
});

test('makePacket - dnssec disabled', t => {
  const pkt = DNSutils.makePacket({name: 'foo'});
  const dns = packet.decode(pkt);
  t.false(dns.flag_ad);
  t.false(dns.flag_cd);
});

test('makePacket - dnssec', t => {
  const pkt = DNSutils.makePacket({name: 'foo', dnssec: true});
  const dns = packet.decode(pkt);
  t.true(dns.flag_ad);
  t.false(dns.flag_cd);
});

test('makePacket - dnssec with cd=1', t => {
  const pkt = DNSutils.makePacket({name: 'foo', dnssec: true, dnssecCheckingDisabled: true});
  const dns = packet.decode(pkt);
  t.true(dns.flag_ad);
  t.true(dns.flag_cd);
});

test('normalizeArgs', t => {
  t.deepEqual(DNSutils.normalizeArgs('foo', 'mx'), {
    name: 'foo',
    rrtype: 'MX',
  });
  t.deepEqual(DNSutils.normalizeArgs('foo', {rrtype: 'mx'}, {}), {
    name: 'foo',
    rrtype: 'MX',
  });
  t.deepEqual(DNSutils.normalizeArgs({name: 'foo', rrtype: 'mx'}, {}), {
    name: 'foo',
    rrtype: 'MX',
  });
  t.deepEqual(DNSutils.normalizeArgs(null, {name: 'foo'}), {
    name: 'foo',
    rrtype: 'A',
  });
  t.deepEqual(DNSutils.normalizeArgs('españa.icom.museum', undefined, {
    rrtype: 'A',
  }), {
    name: 'xn--espaa-rta.icom.museum',
    rrtype: 'A',
  });
  t.deepEqual(DNSutils.normalizeArgs('名がドメイン.com', undefined, {
    rrtype: 'A',
  }), {
    name: 'xn--v8jxj3d1dzdz08w.com',
    rrtype: 'A',
  });
  t.throws(() => DNSutils.normalizeArgs(false));
  t.throws(() => DNSutils.normalizeArgs(null, false));
});

test('base64urlEncode', t => {
  t.is(DNSutils.base64urlEncode(Buffer.from('fbff', 'hex')), '-_8');
});

test('hexDump', t => {
  const verboseStream = new Buf({encoding: 'utf8'});
  const du = new DNSutils({verbose: 1, verboseStream});
  for (const sz of [0, 1, 4, 8, 12, 16, 24, 32]) {
    du.hexDump(1, Buffer.alloc(sz));
  }
  t.is(verboseStream.read(), `\
00000000
00000000  00                                                |.|
00000001
00000000  00 00 00 00                                       |....|
00000004
00000000  00 00 00 00 00 00 00 00                           |........|
00000008
00000000  00 00 00 00 00 00 00 00  00 00 00 00              |............|
0000000c
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00                           |........|
00000018
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020
`);
  du.verboseStream = new Buf();
  du.verboseStream.isTTY = true;
  du.hexDump(1, Buffer.from('666f6f7fa2adae'));
  t.deepEqual(du.verboseStream.read(), Buffer.from(
    '1b5b39306d30303030303030301b5b33396d2020333620333620333620363620' +
    '3336203636203337203636202036312033322036312036342036312036352020' +
    '2020202020207c1b5b33326d361b5b33396d1b5b33326d361b5b33396d1b5b33' +
    '326d361b5b33396d1b5b33326d661b5b33396d1b5b33326d361b5b33396d1b5b' +
    '33326d661b5b33396d1b5b33326d371b5b33396d1b5b33326d661b5b33396d1b' +
    '5b33326d611b5b33396d1b5b33326d321b5b33396d1b5b33326d611b5b33396d' +
    '1b5b33326d641b5b33396d1b5b33326d611b5b33396d1b5b33326d651b5b3339' +
    '6d7c0a1b5b39306d30303030303030651b5b33396d0a', 'hex'
  ));
});

test('buffersToB64', t => {
  const a = {
    b: Buffer.alloc(2),
    d: [Buffer.alloc(2)],
    e: null,
  };
  a.c = a;
  const d = DNSutils.buffersToB64(a);
  t.deepEqual(d, {
    b: 'AAA=',
    d: ['AAA='],
    e: null,
    c: '[Circular reference]',
  });
  t.is(Object.getOwnPropertySymbols(a).length, 0);
  t.is(Object.getOwnPropertySymbols(d).length, 0);
});

test('ecs', t => {
  const du = new DNSutils();
  t.falsy(du._verbose);
  let pkt = DNSutils.makePacket({
    name: 'ietf.org',
    ecsSubnet: 'fe80::fffb:fffc:fffd:fffe',
  });
  t.truthy(Buffer.isBuffer(pkt));
  pkt = DNSutils.makePacket({
    name: 'ietf.org',
    ecs: 12,
  });
  t.truthy(Buffer.isBuffer(pkt));
});

test('verbose', t => {
  const du = new DNSutils({
    verbose: false,
  });
  t.truthy(du);
  t.throws(() => new DNSutils({verbose: true}));
});

test('reverse', t => {
  t.is(DNSutils.reverse('1.2.3.4'), '4.3.2.1.in-addr.arpa.');
  t.is(DNSutils.reverse('::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.');

  t.throws(() => DNSutils.reverse('INVALID IP'));
});

test('stylizeWithColor', t => {
  const f = stylizeWithColor('foo', '___INVALID___');
  t.is(f, 'foo');
});

test('printableString', t => {
  const str = new NoFilter();
  printableString(str, [0xa1]);
  t.is(str.read().toString(), '\xa1');
});

test('DNSError', t => {
  let er = DNSError.getError({rcode: 'NXDOMAIN'});
  t.truthy(er);
  t.is(er.code, 'dns.NXDOMAIN');

  er = DNSError.getError({Status: 5});
  t.truthy(er);
  t.is(er.code, 'dns.REFUSED');

  er = DNSError.getError({});
  t.falsy(er);

  t.throws(() => DNSError.getError(null));
  t.throws(() => DNSError.getError(4));
});

test('abstract', async t => {
  const du = new DNSutils();
  let er = 0;
  du.on('error', () => er++);

  t.throws(() => du._send());
  await t.throwsAsync(() => du._connect());
  du._recv(Buffer.alloc(0));
  t.is(er, 1);
});
