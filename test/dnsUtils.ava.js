'use strict'

const stream = require('stream')
const test = require('ava')
const DNSutils = require('../lib/dnsUtils')
const packet = require('dns-packet')

test('makePacket', t => {
  const pkt = DNSutils.makePacket({ name: 'foo' })
  const dns = packet.decode(pkt)
  t.is(dns.id, 0)
  t.is(dns.questions[0].type, 'A')
  t.is(dns.questions[0].name, 'foo')
})

test('makePacket - subnet', t => {
  const subnet = '1.1.1.1'
  const pkt = DNSutils.makePacket({ name: 'foo', subnet })
  const dns = packet.decode(pkt)
  const additionals = dns.additionals[0]
  const options = additionals.options[0]
  t.is(additionals.type, 'OPT')
  t.is(options.type, 'CLIENT_SUBNET')
  t.is(options.ip, subnet.slice(0, -1).concat('0')) // 1.1.1.0
  t.is(options.sourcePrefixLength, 24)
})

test('makePacket - subnet & ecs = 0', t => {
  const subnet = '1.1.1.1'
  const ecs = 0
  const pkt = DNSutils.makePacket({ name: 'foo', subnet, ecs })
  const dns = packet.decode(pkt)
  const additionals = dns.additionals[0]
  const options = additionals.options[0]
  t.is(additionals.type, 'OPT')
  t.is(options.type, 'CLIENT_SUBNET')
  t.is(options.ip, '0.0.0.0')
  t.is(options.sourcePrefixLength, ecs)
})

test('makePacket - subnet & ecs = 16', t => {
  const subnet = '1.1.1.1'
  const ecs = 16
  const pkt = DNSutils.makePacket({ name: 'foo', subnet, ecs })
  const dns = packet.decode(pkt)
  const additionals = dns.additionals[0]
  const options = additionals.options[0]
  t.is(additionals.type, 'OPT')
  t.is(options.type, 'CLIENT_SUBNET')
  t.is(options.ip, subnet.slice(0, -3).concat('0.0')) // 1.1.0.0
  t.is(options.sourcePrefixLength, ecs)
})

test('normalizeArgs', t => {
  t.deepEqual(DNSutils.normalizeArgs('foo', 'mx'), {
    name: 'foo',
    rrtype: 'MX'
  })
  t.deepEqual(DNSutils.normalizeArgs('foo', { rrtype: 'mx' }, {}), {
    name: 'foo',
    rrtype: 'MX'
  })
  t.deepEqual(DNSutils.normalizeArgs({ name: 'foo', rrtype: 'mx' }, {}), {
    name: 'foo',
    rrtype: 'MX'
  })
  t.deepEqual(DNSutils.normalizeArgs('españa.icom.museum', undefined, {
    rrtype: 'A'
  }), {
    name: 'xn--espaa-rta.icom.museum',
    rrtype: 'A'
  })
})

test('base64urlEncode', t => {
  t.is(DNSutils.base64urlEncode(Buffer.from('fbff', 'hex')), '-_8')
})

test('hexDump', t => {
  const s = new stream.Transform({
    encoding: 'utf8',
    transform (chunk, enc, cb) {
      cb(null, chunk)
    }
  })
  for (const sz of [0, 1, 4, 8, 12, 16, 24, 32]) {
    DNSutils.hexDump(Buffer.alloc(sz), s)
  }
  t.is(s.read(), `\
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
`)
  const tt = new stream.Transform({
    transform (chunk, enc, cb) {
      cb(null, chunk)
    }
  })
  tt.isTTY = true
  DNSutils.hexDump(Buffer.from('666f6f7fa2adae'), tt)
  t.deepEqual(tt.read(), Buffer.from(
    '1b5b39306d30303030303030301b5b33396d2020333620333620333620363620' +
    '3336203636203337203636202036312033322036312036342036312036352020' +
    '2020202020207c1b5b33326d361b5b33396d1b5b33326d361b5b33396d1b5b33' +
    '326d361b5b33396d1b5b33326d661b5b33396d1b5b33326d361b5b33396d1b5b' +
    '33326d661b5b33396d1b5b33326d371b5b33396d1b5b33326d661b5b33396d1b' +
    '5b33326d611b5b33396d1b5b33326d321b5b33396d1b5b33326d611b5b33396d' +
    '1b5b33326d641b5b33396d1b5b33326d611b5b33396d1b5b33326d651b5b3339' +
    '6d7c0a1b5b39306d30303030303030651b5b33396d0a', 'hex'))
})

test('buffersToB64', t => {
  const a = {
    b: Buffer.alloc(2),
    d: [Buffer.alloc(2)],
    e: null
  }
  a.c = a
  const d = DNSutils.buffersToB64(a)
  t.deepEqual(d, {
    b: 'AAA=',
    d: ['AAA='],
    e: null,
    c: '[Circular reference]'
  })
  t.is(Object.getOwnPropertySymbols(a).length, 0)
  t.is(Object.getOwnPropertySymbols(d).length, 0)
})
