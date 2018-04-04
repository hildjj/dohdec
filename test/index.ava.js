'use strict'

const test = require('ava')
const lookup = require('../')

test('dns put', async t => {
  const r = await lookup('ietf.org', {
    json: false,
    dnssec: true
  })
  t.truthy(r)
  t.is(r.answers[0].name, 'ietf.org')
  t.truthy(r.answers[0].type, 'A')
  t.is(r.answers[1].type, 'RRSIG')
})

test('dns get', async t => {
  const r = await lookup('ietf.org', {
    json: false,
    preferPost: false,
    rrtype: 'AAAA'
  })
  t.truthy(r)
  t.is(r.answers[0].name, 'ietf.org')
  t.truthy(r.answers[0].type, 'AAAA')
})

test('json get', async t => {
  let r = await lookup('ietf.org')
  t.truthy(r)
  t.is(r.Answer[0].name, 'ietf.org.')
  t.is(r.Answer[0].type, 1)

  r = await lookup('ietf.org', 'MX')
  t.truthy(r)
  t.is(r.Answer[0].name, 'ietf.org.')
  t.is(r.Answer[0].type, 15)
})

test('no decode', async t => {
  let r = await lookup('ietf.org', {
    json: false,
    decode: false
  })
  t.truthy(Buffer.isBuffer(r))

  r = await lookup('ietf.org', {
    json: true,
    decode: false,
    url: 'https://dns.google.com/resolve'
  })
  t.is(typeof r, 'string')
})
