
import {Buffer} from 'buffer'
import {DNSoverTLS} from '../lib/dot.js'
import {MockDNSserver} from './mockServer.js'
import crypto from 'crypto'
import test from 'ava'

const mockServer = new MockDNSserver('localhost')

test('lookup', async t => {
  const dot = mockServer.dnsOverTLS()
  const res = await dot.lookup('ietf.org')
  const [{name, type, data}] = res.answers
  t.is(name, 'ietf.org')
  t.is(type, 'A')
  t.is(data, '4.31.198.44')
  const srv = await dot.lookup('_xmpp-server._tcp.jabber.org', 'srv')
  t.deepEqual(srv.answers[0].data, {
    port: 5269,
    priority: 30,
    target: 'hermes2.jabber.org',
    weight: 30,
  })
  const buf = await dot.lookup('ietf.org', {decode: false})
  t.truthy(Buffer.isBuffer(buf))
  dot.close()
})

test('close with in-flight requests', async t => {
  const dot = mockServer.dnsOverTLS()
  // eslint-disable-next-line no-empty-function
  dot._data = () => {} // Ignore any data received
  dot.on('send', buf => {
    // Close after the request has been written, but hopefully
    // before the response
    if (buf.length > 2) {
      dot.close()
    }
  })
  await t.throwsAsync(dot.lookup('ietf.org'))
})

test('immediate close', async t => {
  const dot = mockServer.dnsOverTLS()
  dot.on('error', e => {
    t.fail(`Should not get error: ${e.message}`)
  })
  await dot.close()
  t.is(dot.socket, null)
})

test('hash fail', async t => {
  const buf = Buffer.from('foo')
  t.throws(() => DNSoverTLS.hashCert(buf, 'badAlg'))
  t.throws(() => DNSoverTLS.hashCert('badCert'))
  t.is(DNSoverTLS.hashCert(buf),
    '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae')

  const dot = mockServer.dnsOverTLS({
    hash: 'WRONG',
  })
  await t.throwsAsync(dot.lookup('ietf.org'))
})

test('bad cert', async t => {
  const dot = mockServer.dnsOverTLS({
    host: 'untrusted-root.badssl.com',
  })
  await t.throwsAsync(dot.lookup('ietf.org'), null, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE')
})

test('pin cert', async t => {
  if (!crypto.X509Certificate) {
    // X509Certificate added in node 15.6.0
    t.pass()
    return
  }
  const dot = mockServer.dnsOverTLS({
    host: 'untrusted-root.badssl.com',
    hash: DNSoverTLS.hashCert(
      new crypto.X509Certificate(mockServer.chain.srv_pem)
    ),
  })
  const res = await dot.lookup('ietf.org')
  t.is(res.rcode, 'NOERROR')
})

test('chunked reads', async t => {
  const dot = mockServer.dnsOverTLS()
  const resp = await dot.lookup('chunky.example', {id: 123})
  t.is(resp.id, 123)
  t.is(resp.rcode, 'NOERROR')
})

test('bad id', async t => {
  const dot = mockServer.dnsOverTLS(null, {badId: 4})
  await t.throwsAsync(dot.lookup('ietf.org', {id: 123}))
})
