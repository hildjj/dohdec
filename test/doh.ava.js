import {Buf, prepNock} from './utils.js'
import {Buffer} from 'buffer'
import {DNSoverHTTPS} from '../lib/doh.js'
import nock from 'nock'
import test from 'ava'

prepNock(test, nock, import.meta.url)

test('dns put', async t => {
  const doh = new DNSoverHTTPS()
  const r = await doh.lookup('ietf.org', {
    json: false,
    dnssec: true,
    http2: false,
  })
  t.truthy(r)

  t.is(r.answers[0].type, 'RRSIG')
  t.is(r.answers[1].name, 'ietf.org')
  t.truthy(r.answers[1].type, 'A')
})

test('dns get', async t => {
  const verboseStream = new Buf({encoding: 'utf8'})
  const doh = new DNSoverHTTPS({
    preferPost: false,
    verbose: 1,
    verboseStream,
    http2: false,
  })
  const r = await doh.lookup('ietf.org', {
    json: false,
    rrtype: 'AAAA',
  })
  t.truthy(r)
  t.is(r.answers[0].name, 'ietf.org')
  t.truthy(r.answers[0].type, 'AAAA')

  const vres = verboseStream.read()
  t.is(typeof vres, 'string')
  t.truthy(vres.length > 0)
})

test('json get', async t => {
  const doh = new DNSoverHTTPS({http2: false})
  let r = await doh.lookup('ietf.org')
  t.truthy(r)
  t.is(r.Answer[0].name, 'ietf.org')
  t.is(r.Answer[0].type, 1)

  r = await doh.lookup('ietf.org', 'MX')
  t.truthy(r)
  t.is(r.Answer[0].name, 'ietf.org')
  t.is(r.Answer[0].type, 15)
})

test('no decode', async t => {
  const doh = new DNSoverHTTPS({http2: false})
  let r = await doh.lookup('ietf.org', {
    json: false,
    decode: false,
  })
  t.truthy(Buffer.isBuffer(r))

  const dohGoog = new DNSoverHTTPS({
    url: 'https://dns.google.com/resolve',
    http2: false,
  })
  r = await dohGoog.lookup('ietf.org', {
    json: true,
    decode: false,
  })
  t.is(typeof r, 'string')
})

test('getJSON', async t => {
  const verboseStream = new Buf()
  const doh = new DNSoverHTTPS({verbose: 1, verboseStream, http2: false})
  const r = await doh.getJSON({name: 'ietf.org'})
  t.is(typeof r, 'object')
})
