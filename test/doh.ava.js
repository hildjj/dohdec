import {Buf} from './utils.js'
import {Buffer} from 'buffer'
import {DNSoverHTTPS} from '../lib/doh.js'
import nock from 'nock'
import path from 'path'
import process from 'process'
import test from 'ava'
import url from 'url'

test.before(async t => {
  nock.back.fixtures = url.fileURLToPath(new URL('fixtures/', import.meta.url))
  if (!process.env.NOCK_BACK_MODE) {
    nock.back.setMode('lockdown')
  }

  const title = escape(path.basename(url.fileURLToPath(import.meta.url)))
  const { nockDone, context } = await nock.back(`${title}.json`)
  if (context.scopes.length === 0) {
    // Set the NOCK_BACK_MODE variable to "record" when needed
    if (process.env.NOCK_BACK_MODE !== 'record') {
      console.error(`WARNING: Nock recording needed for "${title}".
Set NOCK_BACK_MODE=record`)
    }
  }
  t.context.nockDone = nockDone
})

test.after(t => {
  t.context.nockDone()
  t.truthy(nock.isDone())
})

test('dns put', async t => {
  const doh = new DNSoverHTTPS()
  const r = await doh.lookup('ietf.org', {
    json: false,
    dnssec: true,
  })
  t.truthy(r)
  t.is(r.answers[0].name, 'ietf.org')
  t.truthy(r.answers[0].type, 'A')
  t.is(r.answers[1].type, 'RRSIG')
})

test('dns get', async t => {
  const verboseStream = new Buf({encoding: 'utf8'})
  const doh = new DNSoverHTTPS({
    preferPost: false,
    verbose: 1,
    verboseStream,
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
  const doh = new DNSoverHTTPS()
  let r = await doh.lookup('ietf.org')
  t.truthy(r)
  t.is(r.Answer[0].name, 'ietf.org.')
  t.is(r.Answer[0].type, 1)

  r = await doh.lookup('ietf.org', 'MX')
  t.truthy(r)
  t.is(r.Answer[0].name, 'ietf.org.')
  t.is(r.Answer[0].type, 15)
})

test('no decode', async t => {
  const doh = new DNSoverHTTPS()
  let r = await doh.lookup('ietf.org', {
    json: false,
    decode: false,
  })
  t.truthy(Buffer.isBuffer(r))

  const dohGoog = new DNSoverHTTPS({
    url: 'https://dns.google.com/resolve',
  })
  r = await dohGoog.lookup('ietf.org', {
    json: true,
    decode: false,
  })
  t.is(typeof r, 'string')
})

test('getJSON', async t => {
  const verboseStream = new Buf()
  const doh = new DNSoverHTTPS({verbose: 1, verboseStream})
  const r = await doh.getJSON({ name: 'ietf.org' })
  t.is(typeof r, 'object')
})
