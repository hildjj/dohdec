'use strict'

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
