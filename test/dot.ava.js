
import {Buffer} from 'buffer'
import {DNSoverTLS} from '../lib/dot.js'
import NoFilter from 'nofilter'
import packet from 'dns-packet'
import test from 'ava'

// NOTE: no network mocks for these yet.  Possible approach: write a quick
// and dirty server

test('lookup', async t => {
  const dot = new DNSoverTLS()
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
  const buf = await dot.lookup('ietf.org', { decode: false })
  t.truthy(Buffer.isBuffer(buf))
  dot.close()
})

test('close with in-flight requests', async t => {
  const dot = new DNSoverTLS()
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
  const dot = new DNSoverTLS()
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

  const dot = new DNSoverTLS({
    hash: 'WRONG',
  })
  await t.throwsAsync(dot.lookup('ietf.org'))
})

test('bad cert', async t => {
  const dot = new DNSoverTLS({
    host: 'untrusted-root.badssl.com',
    port: 443,
    rejectUnauthorized: false,
  })
  let hash = null
  dot.on('certificate', c => {
    ({hash} = c)
  })
  let wait = null
  const prom = new Promise((resolve, reject) => {
    wait = { resolve, reject }
  })
  dot.once('disconnect', () => {
    // Second try, now with hash.
    dot.opts.hash = hash
    dot.lookup('ietf.org').then(wait.resolve, wait.reject)
  })
  await t.throwsAsync(dot.lookup('ietf.org'), null, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE')
  await t.throwsAsync(prom, null, 'Timeout looking up "ietf.org":A')
})

class MockedTLS extends DNSoverTLS {
  constructor(opts = {}) {
    super(opts)
    this.socket = new NoFilter()
    this.socket.on('finish', () => this._disconnected())
    this.nof = new NoFilter()
    this.on('send', b => {
      if (b.length > 2) {
        const sz = this.socket.readUInt16BE()
        const buf = this.socket.read(sz)
        const pkt = packet.decode(buf)
        this.respond(pkt)
      }
    })
  }

  respond(req) {
    const resp = {
      id: this.opts.badid || req.id,
      type: 'response',
      rcode: 'NOERROR',
      questions: req.questions,
      answers: [{
        name: req.questions[0].name,
        type: req.questions[0].type,
        ttl: 1,
        class: req.questions[0].class,
        data: '1.2.3.4',
      }],
    }
    const rbuf = packet.encode(resp)
    const rbufsz = Buffer.alloc(2)
    rbufsz.writeUInt16BE(rbuf.length)
    this._data(rbufsz.slice(0, 1))
    this._data(rbufsz.slice(1))
    this._data(rbuf.slice(0, 5))
    this._data(rbuf.slice(5))
  }
}

test('chunked reads', async t => {
  const dot = new MockedTLS()
  const resp = await dot.lookup('ietf.org', { id: 123 })
  t.is(resp.id, 123)
})

test('bad id', async t => {
  const dot = new MockedTLS({ badid: 4 })
  await t.throwsAsync(dot.lookup('ietf.org', { id: 123 }))
})
